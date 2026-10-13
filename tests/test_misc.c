/*
 * QR regression, streaming protobuf walker, history sync parser, config,
 * terminal helpers, and a mutation smoke test for every network parser.
 */
#include "test.h"

#include "zapc/binary_node.h"
#include "zapc/config.h"
#include "zapc/crypto.h"
#include "zapc/history_sync.h"
#include "zapc/inflate.h"
#include "zapc/jid.h"
#include "zapc/platform.h"
#include "zapc/protobuf.h"
#include "zapc/qr.h"
#include "zapc/terminal.h"
#include "zapc/websocket.h"

static qr_code g_qr;

/* Expected matrices produced by segno (an independent QR library). */
static void check_qr(const char *data, int ecl, int mask, int version,
                     const char *sha_hex)
{
    static char bits[QR_MAX_SIZE * QR_MAX_SIZE + 1];
    uint8_t sha[32], exp[32];
    CHECK(qr_encode(&g_qr, (const uint8_t *)data, strlen(data), ecl, 1, mask) == 0);
    CHECK(g_qr.version == version);
    size_t n = 0;
    for (int y = 0; y < g_qr.size; y++)
        for (int x = 0; x < g_qr.size; x++)
            bits[n++] = (char)('0' + qr_module(&g_qr, x, y));
    crypto_sha256(bits, n, sha);
    unhex(sha_hex, exp, 32);
    CHECK_MEM(sha, exp, 32);
}

static void test_qr(void)
{
    check_qr("https://wa.me/settings/linked_devices#2@abc,def,ghi,jkl,9",
             QR_ECC_LOW, 3, 4,
             "1f451fb27e28e5c72fadc984745306a331a5bb7e6e0a38926466ffc5cea7d735");
    char big[300] = "";
    for (int i = 0; i < 10; i++)
        strcat(big, "ZapC QR test 0123456789");
    check_qr(big, QR_ECC_MEDIUM, 6, 11,
             "d73e61471edc8071fdf8bfe4e55b6dda967656e9ff42948ce60a4a73c8be43a2");
    char huge[2000];
    memset(huge, 'x', sizeof huge - 1);
    huge[sizeof huge - 1] = '\0';
    CHECK(qr_encode(&g_qr, (const uint8_t *)huge, strlen(huge), QR_ECC_LOW, 1, -1) != 0);
    /* automatic mask selection produces a valid mask */
    CHECK(qr_encode(&g_qr, (const uint8_t *)"abc", 3, QR_ECC_LOW, 1, -1) == 0);
    CHECK(g_qr.mask >= 0 && g_qr.mask < 8);
}

/* ---- streaming walker ---------------------------------------------------- */

typedef struct {
    uint64_t sum_varint;
    int bytes_seen;
    int ends;
    char last_str[64];
} walk_obs;

static pbw_action w_len(pb_walker *w, uint32_t field, uint64_t len)
{
    (void)len;
    if (w->depth == 0 && field == 2)
        return PBW_DESCEND;
    if (w->depth == 1 && field == 3)
        return PBW_BUFFER;
    return PBW_SKIP;
}
static void w_varint(pb_walker *w, uint32_t field, uint64_t v)
{
    (void)field;
    ((walk_obs *)w->user)->sum_varint += v;
}
static void w_bytes(pb_walker *w, uint32_t field, const uint8_t *d, size_t n)
{
    (void)field;
    walk_obs *o = w->user;
    o->bytes_seen++;
    zstrlcpyn(o->last_str, (const char *)d, n, sizeof o->last_str);
}
static void w_end(pb_walker *w, uint32_t field)
{
    (void)field;
    ((walk_obs *)w->user)->ends++;
}

static void test_walker(void)
{
    uint8_t msg[512], sub[128];
    zbuf b, s;
    zbuf_init(&b, msg, sizeof msg);
    pb_put_uint(&b, 1, 5);
    for (int i = 0; i < 3; i++) {
        zbuf_init(&s, sub, sizeof sub);
        pb_put_uint(&s, 1, 100);
        pb_put_string(&s, 3, i == 2 ? "last" : "x");
        pb_put_bytes(&s, 4, "skipme", 6);
        pb_put_fixed32(&s, 5, 1);
        pb_put_bytes(&b, 2, sub, s.len);
    }
    pb_put_string(&b, 9, "trailing");
    uint8_t wbuf[64];
    for (int chunk = 1; chunk <= 7; chunk += 3) {
        pb_walker w;
        walk_obs o;
        memset(&o, 0, sizeof o);
        memset(&w, 0, sizeof w);
        w.on_len = w_len;
        w.on_varint = w_varint;
        w.on_bytes = w_bytes;
        w.on_end = w_end;
        w.user = &o;
        pbw_init(&w, wbuf, sizeof wbuf);
        int ok = 1;
        for (size_t i = 0; i < b.len; i += (size_t)chunk) {
            size_t n = b.len - i < (size_t)chunk ? b.len - i : (size_t)chunk;
            if (pbw_feed(&w, msg + i, n) != 0)
                ok = 0;
        }
        CHECK(ok);
        CHECK(pbw_finish(&w) == 0);
        CHECK(o.sum_varint == 5 + 300 + 3); /* fixed32 values counted too */
        CHECK(o.bytes_seen == 3 && o.ends == 3);
        CHECK_STR(o.last_str, "last");
    }
    /* truncated stream is not a clean finish; bad length is an error */
    pb_walker w;
    memset(&w, 0, sizeof w);
    pbw_init(&w, wbuf, sizeof wbuf);
    CHECK(pbw_feed(&w, msg, b.len - 3) == 0);
    CHECK(pbw_finish(&w) != 0);
    const uint8_t bad[] = {0x12, 0x05, 0x0a, 0x10, 'a'}; /* inner len exceeds outer */
    memset(&w, 0, sizeof w);
    w.on_len = w_len;
    pbw_init(&w, wbuf, sizeof wbuf);
    CHECK(pbw_feed(&w, bad, sizeof bad) != 0);
}

/* ---- history sync parser (with a stored-block zlib stream) ------------- */

static size_t zlib_store(const uint8_t *in, size_t len, uint8_t *out)
{
    size_t o = 0;
    uint32_t a = 1, b2 = 0;
    out[o++] = 0x78;
    out[o++] = 0x01;
    out[o++] = 1;
    out[o++] = (uint8_t)len;
    out[o++] = (uint8_t)(len >> 8);
    out[o++] = (uint8_t)~len;
    out[o++] = (uint8_t)(~len >> 8);
    memcpy(out + o, in, len);
    o += len;
    for (size_t i = 0; i < len; i++) {
        a = (a + in[i]) % 65521u;
        b2 = (b2 + a) % 65521u;
    }
    uint32_t ad = (b2 << 16) | a;
    out[o++] = (uint8_t)(ad >> 24);
    out[o++] = (uint8_t)(ad >> 16);
    out[o++] = (uint8_t)(ad >> 8);
    out[o++] = (uint8_t)ad;
    return o;
}

typedef struct {
    const uint8_t *p;
    size_t left;
} slow_reader;

static long slow_read(void *u, uint8_t *buf, size_t cap)
{
    slow_reader *r = u;
    size_t n = r->left < 3 ? r->left : 3; /* tiny reads */
    (void)cap;
    memcpy(buf, r->p, n);
    r->p += n;
    r->left -= n;
    return (long)n;
}

static int g_chats, g_msgs_in_chat, g_names;
static char g_chat_name[64], g_text[64];

static void hs_chat(void *u, const wa_jid *chat, const char *name, int64_t ts,
                    unsigned unread, const wa_message *msgs, int n)
{
    (void)u;
    (void)chat;
    (void)ts;
    (void)unread;
    g_chats++;
    g_msgs_in_chat = n;
    zstrlcpy(g_chat_name, name, sizeof g_chat_name);
    if (n > 0)
        zstrlcpy(g_text, msgs[n - 1].text, sizeof g_text);
}

static void hs_name(void *u, const wa_jid *j, const char *name)
{
    (void)u;
    (void)j;
    (void)name;
    g_names++;
}

static void test_history_parser(void)
{
    uint8_t hist[2048], conv[1024], hm[512], wmi[400], m[64], z[2200];
    zbuf b, c, h, w, mm;
    zbuf_init(&b, hist, sizeof hist);
    pb_put_uint(&b, 1, 3);
    zbuf_init(&c, conv, sizeof conv);
    pb_put_string(&c, 1, "5511@s.whatsapp.net");
    for (int i = 0; i < 2; i++) {
        zbuf_init(&w, wmi, sizeof wmi);
        size_t k = pb_begin(&w, 1);
        pb_put_string(&w, 1, "5511@s.whatsapp.net");
        pb_put_string(&w, 3, "X");
        pb_end(&w, k);
        zbuf_init(&mm, m, sizeof m);
        pb_put_string(&mm, 1, i ? "segunda" : "primeira");
        pb_put_bytes(&w, 2, m, mm.len);
        pb_put_uint(&w, 3, (uint64_t)(50 + i));
        zbuf_init(&h, hm, sizeof hm);
        pb_put_bytes(&h, 1, wmi, w.len);
        pb_put_bytes(&c, 2, hm, h.len);
    }
    /* a protocol-only message (nothing displayable) is ignored */
    zbuf_init(&w, wmi, sizeof wmi);
    size_t k = pb_begin(&w, 1);
    pb_put_string(&w, 1, "5511@s.whatsapp.net");
    pb_end(&w, k);
    zbuf_init(&mm, m, sizeof m);
    size_t pk = pb_begin(&mm, 12);
    pb_put_uint(&mm, 2, 3);
    pb_end(&mm, pk);
    pb_put_bytes(&w, 2, m, mm.len);
    zbuf_init(&h, hm, sizeof hm);
    pb_put_bytes(&h, 1, wmi, w.len);
    pb_put_bytes(&c, 2, hm, h.len);
    pb_put_string(&c, 13, "Fulano");
    pb_put_bytes(&b, 2, conv, c.len);
    uint8_t pn[64];
    zbuf pz;
    zbuf_init(&pz, pn, sizeof pn);
    pb_put_string(&pz, 1, "77@s.whatsapp.net");
    pb_put_string(&pz, 2, "Zeca");
    pb_put_bytes(&b, 7, pn, pz.len);
    size_t zl = zlib_store(hist, b.len, z);

    wa_hist_sink sink;
    memset(&sink, 0, sizeof sink);
    sink.on_chat = hs_chat;
    sink.on_push_name = hs_name;
    jid_parse(&sink.self, "999@s.whatsapp.net");
    wa_hist_stats st;
    slow_reader r = {z, zl};
    CHECK(wa_history_process(slow_read, &r, &sink, &st) == 0);
    CHECK(st.sync_type == 3 && st.chats == 1 && st.messages == 2);
    CHECK(g_chats == 1 && g_msgs_in_chat == 2 && g_names == 1);
    CHECK_STR(g_chat_name, "Fulano");
    CHECK_STR(g_text, "segunda");

    /* corrupt checksum is rejected */
    z[zl - 1] ^= 1;
    slow_reader r2 = {z, zl};
    CHECK(wa_history_process(slow_read, &r2, &sink, &st) != 0);
}

static void test_config(void)
{
    zapc_config c;
    config_defaults(&c);
    CHECK(config_set(&c, "log_level", "debug") == 0 && c.log_level == LOG_DEBUG);
    CHECK(config_set(&c, "history_cache", "32") == 0 && c.history_cache == 32);
    CHECK(config_set(&c, "history_cache", "100000") != 0);
    CHECK(config_set(&c, "wa_version", "2.3000.123") == 0 && c.wa_version[2] == 123);
    CHECK(config_set(&c, "wa_version", "2.3000") != 0);
    CHECK(config_set(&c, "ascii", "yes") == 0 && c.ascii == 1);
    CHECK(config_set(&c, "wa_port", "0") != 0);
    CHECK(config_set(&c, "nope", "1") != 0);
}

static void test_terminal_helpers(void)
{
    CHECK(utf8_width("abc", 3) == 3);
    CHECK(utf8_width("Jo\xc3\xa3o", 5) == 4);
    CHECK(utf8_width("\xf0\x9f\x98\x80", 4) == 2); /* emoji is wide */
    CHECK(utf8_fit("Jo\xc3\xa3o", 5, 3) == 4);      /* never splits a code point */
    term_line l;
    line_clear(&l);
    line_insert(&l, "ol", 2);
    line_insert(&l, "\xc3\xa1", 2);
    CHECK_STR(l.buf, "ol\xc3\xa1");
    line_left(&l);
    CHECK(l.cursor == 2);
    line_backspace(&l);
    CHECK_STR(l.buf, "o\xc3\xa1");
    line_delete(&l);
    CHECK_STR(l.buf, "o");
    line_insert(&l, " mundo", 6);
    line_delete_word(&l);
    CHECK_STR(l.buf, "o ");
}

/* ---- mutation smoke test for untrusted-input parsers --------------------- */

static uint32_t g_rng = 12345;
static uint32_t rnd(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

static int ws_sink(void *u, int op, const uint8_t *d, size_t n, int f, int l)
{
    (void)u; (void)op; (void)d; (void)n; (void)f; (void)l;
    return 0;
}
static long null_read(void *c, void *b, size_t n) { (void)c; (void)b; (void)n; return ZC_IO_AGAIN; }
static long null_write(void *c, const void *b, size_t n) { (void)c; (void)b; return (long)n; }
static size_t null_pending(void *c) { (void)c; return 0; }

static void test_mutation_smoke(void)
{
    /* seed: a valid node */
    uint8_t seed[256], buf[256], arena_mem[8192], out[4096];
    zbuf b;
    wa_attr attrs[] = {WA_ATTR_JID("from", "123:4@s.whatsapp.net"),
                       WA_ATTR("id", "ABCD"), WA_ATTR("type", "text")};
    wa_attr ea[] = {WA_ATTR("v", "2"), WA_ATTR("type", "pkmsg")};
    wa_node enc = {"enc", ea, 2, NULL, 0, (const uint8_t *)"\x33\x0a\x01", 3,
                   WA_CONTENT_BYTES};
    wa_node msg = {"message", attrs, 3, &enc, 1, NULL, 0, WA_CONTENT_CHILDREN};
    zbuf_init(&b, seed, sizeof seed);
    wa_node_encode(&msg, &b);
    size_t seed_len = b.len;

    static ws_client ws;
    zc_stream st = {NULL, -1, null_read, null_write, null_pending};
    for (int iter = 0; iter < 20000; iter++) {
        size_t len = seed_len;
        memcpy(buf, seed, len);
        int flips = 1 + (int)(rnd() % 4);
        for (int f = 0; f < flips; f++) {
            uint32_t op = rnd() % 3;
            size_t pos = rnd() % len;
            if (op == 0)
                buf[pos] = (uint8_t)rnd();
            else if (op == 1 && len > 1)
                len = pos + 1; /* truncate */
            else
                buf[pos] ^= (uint8_t)(1u << (rnd() % 8));
        }
        zap_arena a;
        zap_arena_init(&a, arena_mem, sizeof arena_mem);
        wa_node *n;
        (void)wa_node_decode(buf, len, &a, &n);

        pb_reader r;
        pb_field fld;
        pb_reader_init(&r, buf, len);
        while (pb_next(&r, &fld) == 1) {
        }
        (void)zc_inflate_zlib(buf, len, out, sizeof out);
        (void)wa_extract_text(buf, len, (char *)out, 256);

        ws_init(&ws, st, ws_sink, NULL);
        ws.open = 1;
        (void)ws_feed(&ws, buf, len);

        wa_jid j;
        buf[len < sizeof buf ? len : sizeof buf - 1] = '\0';
        (void)jid_parse(&j, (const char *)buf);
    }
    CHECK(1); /* reaching here without sanitizer errors is the test */
}

int main(void)
{
    RUN(test_qr);
    RUN(test_walker);
    RUN(test_history_parser);
    RUN(test_config);
    RUN(test_terminal_helpers);
    RUN(test_mutation_smoke);
    return test_done("test_misc");
}
