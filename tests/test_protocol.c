/*
 * Tests for the protocol building blocks: JID, binary nodes, protobuf,
 * Noise, framing and inflate.
 */
#include "test.h"

#include "zapc/binary_node.h"
#include "zapc/crypto.h"
#include "zapc/frame.h"
#include "zapc/inflate.h"
#include "zapc/jid.h"
#include "zapc/noise.h"
#include "zapc/protobuf.h"

#include "zvectors.h"

static void test_jid(void)
{
    wa_jid j;
    char buf[WA_JID_STR_MAX];

    CHECK(jid_parse(&j, "5511999998888@s.whatsapp.net") == 0);
    CHECK_STR(j.user, "5511999998888");
    CHECK_STR(j.server, "s.whatsapp.net");
    CHECK(j.device == 0 && j.agent == 0);

    CHECK(jid_parse(&j, "5511999998888:12@s.whatsapp.net") == 0);
    CHECK(j.device == 12);
    CHECK(jid_format(&j, buf, sizeof buf) > 0);
    CHECK_STR(buf, "5511999998888:12@s.whatsapp.net");

    CHECK(jid_parse(&j, "123.1:3@s.whatsapp.net") == 0);
    CHECK(j.agent == 1 && j.device == 3);
    jid_format(&j, buf, sizeof buf);
    CHECK_STR(buf, "123.1:3@s.whatsapp.net");

    CHECK(jid_parse(&j, "s.whatsapp.net") == 0);
    CHECK(j.user[0] == '\0');
    jid_format(&j, buf, sizeof buf);
    CHECK_STR(buf, "s.whatsapp.net");

    CHECK(jid_parse(&j, "1203630@g.us") == 0);
    CHECK(jid_is_group(&j));

    CHECK(jid_parse(&j, "a:b@s.whatsapp.net") != 0);
    CHECK(jid_parse(&j, "1:99999@s.whatsapp.net") != 0);
    CHECK(jid_parse(&j, "1@2@3") != 0);

    uint64_t u;
    CHECK(jid_parse(&j, "5511999998888:2@s.whatsapp.net") == 0);
    CHECK(jid_user_u64(&j, &u) == 0 && u == 5511999998888ull);
    CHECK(jid_signal_address(&j, buf, sizeof buf) > 0);
    CHECK_STR(buf, "5511999998888:2");
    CHECK(jid_parse(&j, "12345:4@lid") == 0);
    jid_signal_address(&j, buf, sizeof buf);
    CHECK_STR(buf, "12345_1:4");
}

static void test_tokens(void)
{
    unsigned d, i;
    CHECK(wa_token_lookup("iq", 2, &d, &i) == 1);
    CHECK_STR(wa_token_single(i), "iq");
    CHECK(wa_token_lookup("s.whatsapp.net", 14, &d, &i) == 1 && i == 3);
    CHECK(wa_token_lookup("definitely-not-a-token", 22, &d, &i) == 0);
    /* every double token must round-trip */
    int ok = 1;
    for (unsigned dict = 0; dict < 4; dict++)
        for (unsigned k = 0; k < 256; k++) {
            const char *s = wa_token_double(dict, k);
            unsigned dd = 9, ii = 999;
            int t = wa_token_lookup(s, strlen(s), &dd, &ii);
            const char *back = t == 1 ? wa_token_single(ii)
                                      : wa_token_double(dd, ii);
            if (t == 0 || strcmp(back, s) != 0)
                ok = 0;
        }
    CHECK(ok);
}

static void test_node_roundtrip(void)
{
    uint8_t enc[1024];
    uint8_t arena_mem[4096];
    zbuf b;
    zap_arena arena;
    const uint8_t blob[] = {1, 2, 3, 0, 255};

    wa_attr ref_attrs[] = {WA_ATTR("id", "ABCDEF0123")};
    wa_node grandchildren[] = {
        {"ref", ref_attrs, 1, NULL, 0, blob, sizeof blob, WA_CONTENT_BYTES},
    };
    wa_attr child_attrs[] = {
        WA_ATTR("jid", "5511999998888:3@s.whatsapp.net"),
        WA_ATTR("name", "Jo\xc3\xa3o"),
        WA_ATTR("t", "1700000000"),
    };
    child_attrs[0].is_jid = 1;
    wa_node children[] = {
        {"pair-device", child_attrs, 3, grandchildren, 1, NULL, 0,
         WA_CONTENT_CHILDREN},
        {"ping", NULL, 0, NULL, 0, NULL, 0, WA_CONTENT_NONE},
    };
    wa_attr attrs[] = {
        WA_ATTR_JID("to", "s.whatsapp.net"),
        WA_ATTR("type", "result"),
        WA_ATTR("id", "3EB0-1.2"),
        WA_ATTR("skipped", ""),
        WA_ATTR_JID("participant", "120363@g.us"),
        WA_ATTR_JID("lid", "999:1@lid"),
    };
    wa_node root = {"iq", attrs, WA_COUNT(attrs), children, 2, NULL, 0,
                    WA_CONTENT_CHILDREN};

    zbuf_init(&b, enc, sizeof enc);
    CHECK(wa_node_encode(&root, &b) == 0);

    zap_arena_init(&arena, arena_mem, sizeof arena_mem);
    wa_node *out = NULL;
    CHECK(wa_node_decode(enc, b.len, &arena, &out) == 0);
    if (out == NULL)
        return;
    CHECK_STR(out->tag, "iq");
    CHECK(out->attr_count == 5); /* empty attr skipped */
    CHECK_STR(wa_node_attr(out, "to"), "s.whatsapp.net");
    CHECK_STR(wa_node_attr(out, "type"), "result");
    CHECK_STR(wa_node_attr(out, "id"), "3EB0-1.2");
    CHECK_STR(wa_node_attr(out, "participant"), "120363@g.us");
    CHECK_STR(wa_node_attr(out, "lid"), "999:1@lid");
    CHECK(out->child_count == 2);
    const wa_node *pd = wa_node_child(out, "pair-device");
    CHECK(pd != NULL);
    CHECK_STR(wa_node_attr(pd, "jid"), "5511999998888:3@s.whatsapp.net");
    CHECK_STR(wa_node_attr(pd, "name"), "Jo\xc3\xa3o");
    CHECK_STR(wa_node_attr(pd, "t"), "1700000000");
    const wa_node *ref = wa_node_path(out, "pair-device", "ref", NULL);
    CHECK(ref != NULL && ref->content == WA_CONTENT_BYTES);
    CHECK(ref != NULL && ref->data_len == sizeof blob);
    CHECK(ref != NULL && memcmp(ref->data, blob, sizeof blob) == 0);
    CHECK_STR(wa_node_attr(ref, "id"), "ABCDEF0123");
    CHECK(wa_node_child(out, "ping") != NULL);

    /* re-encoding the decoded tree gives identical bytes */
    uint8_t enc2[1024];
    zbuf b2;
    zbuf_init(&b2, enc2, sizeof enc2);
    CHECK(wa_node_encode(out, &b2) == 0);
    CHECK(b2.len == b.len && memcmp(enc, enc2, b.len) == 0);

    char text[512];
    wa_node_to_text(out, text, sizeof text);
    CHECK(strstr(text, "<iq ") == text);

    /* every truncation of the input must fail cleanly */
    int all_fail = 1;
    for (size_t n = 0; n < b.len; n++) {
        zap_arena_init(&arena, arena_mem, sizeof arena_mem);
        if (wa_node_decode(enc, n, &arena, &out) == 0)
            all_fail = 0;
    }
    CHECK(all_fail);
}

/* Known encoding produced by the reference implementation's rules. */
static void test_node_known_bytes(void)
{
    /* <iq id="7777" type="get" xmlns="w:p"><ping/></iq> */
    wa_attr attrs[] = {WA_ATTR("id", "7777"), WA_ATTR("type", "get"),
                       WA_ATTR("xmlns", "w:p")};
    wa_node ping = {"ping", NULL, 0, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    wa_node iq = {"iq", attrs, 3, &ping, 1, NULL, 0, WA_CONTENT_CHILDREN};
    uint8_t enc[64];
    zbuf b;
    zbuf_init(&b, enc, sizeof enc);
    CHECK(wa_node_encode(&iq, &b) == 0);
    unsigned d, idx_iq, idx_id, idx_type, idx_get, idx_xmlns, idx_wp, idx_ping;
    wa_token_lookup("iq", 2, &d, &idx_iq);
    wa_token_lookup("id", 2, &d, &idx_id);
    wa_token_lookup("type", 4, &d, &idx_type);
    wa_token_lookup("get", 3, &d, &idx_get);
    wa_token_lookup("xmlns", 5, &d, &idx_xmlns);
    wa_token_lookup("w:p", 3, &d, &idx_wp);
    wa_token_lookup("ping", 4, &d, &idx_ping);
    const uint8_t expect[] = {
        WA_TAG_LIST8, 8, (uint8_t)idx_iq,
        (uint8_t)idx_id, WA_TAG_NIBBLE8, 0x02, 0x77, 0x77,
        (uint8_t)idx_type, (uint8_t)idx_get,
        (uint8_t)idx_xmlns, (uint8_t)idx_wp,
        WA_TAG_LIST8, 1,
        WA_TAG_LIST8, 1, (uint8_t)idx_ping};
    CHECK(b.len == sizeof expect);
    CHECK(memcmp(enc, expect, sizeof expect) == 0);
}

static void test_node_malicious(void)
{
    uint8_t arena_mem[2048];
    zap_arena arena;
    wa_node *out;
    /* deep nesting: LIST8 2 "iq" LIST8 1 LIST8 2 "iq" ... */
    uint8_t deep[600];
    size_t n = 0;
    unsigned d, iq;
    wa_token_lookup("iq", 2, &d, &iq);
    while (n + 5 < sizeof deep) {
        deep[n++] = WA_TAG_LIST8;
        deep[n++] = 2;
        deep[n++] = (uint8_t)iq;
        deep[n++] = WA_TAG_LIST8;
        deep[n++] = 1;
    }
    zap_arena_init(&arena, arena_mem, sizeof arena_mem);
    CHECK(wa_node_decode(deep, n, &arena, &out) != 0);

    /* huge declared binary length */
    const uint8_t big[] = {WA_TAG_LIST8, 2, (uint8_t)iq, WA_TAG_BINARY32,
                           0x7f, 0xff, 0xff, 0xff, 1, 2};
    zap_arena_init(&arena, arena_mem, sizeof arena_mem);
    CHECK(wa_node_decode(big, sizeof big, &arena, &out) != 0);

    /* huge list count */
    const uint8_t many[] = {WA_TAG_LIST8, 2, (uint8_t)iq, WA_TAG_LIST16,
                            0xff, 0xff, 0};
    zap_arena_init(&arena, arena_mem, sizeof arena_mem);
    CHECK(wa_node_decode(many, sizeof many, &arena, &out) != 0);

    /* invalid token */
    const uint8_t badtok[] = {WA_TAG_LIST8, 1, 240};
    zap_arena_init(&arena, arena_mem, sizeof arena_mem);
    CHECK(wa_node_decode(badtok, sizeof badtok, &arena, &out) != 0);
}

static void test_protobuf(void)
{
    uint8_t mem[512];
    zbuf b;
    zbuf_init(&b, mem, sizeof mem);
    pb_put_uint(&b, 1, 150);
    size_t m = pb_begin(&b, 5);
    pb_put_string(&b, 1, "nested");
    uint8_t big[200];
    memset(big, 0xAB, sizeof big);
    pb_put_bytes(&b, 2, big, sizeof big); /* forces 2-byte outer length */
    pb_end(&b, m);
    pb_put_bool(&b, 3, 1);
    pb_put_fixed32(&b, 9, 0x01020304);
    CHECK(!b.overflow);
    CHECK(mem[0] == 0x08 && mem[1] == 0x96 && mem[2] == 0x01);

    pb_reader r;
    pb_field f;
    pb_reader_init(&r, mem, b.len);
    CHECK(pb_next(&r, &f) == 1 && f.num == 1 && f.u64 == 150);
    CHECK(pb_next(&r, &f) == 1 && f.num == 5 && f.wire == PB_LEN);
    const uint8_t *s;
    size_t sl;
    CHECK(pb_find_bytes(f.data, f.len, 1, &s, &sl) == 1 && sl == 6 &&
          memcmp(s, "nested", 6) == 0);
    CHECK(pb_find_bytes(f.data, f.len, 2, &s, &sl) == 1 && sl == 200);
    CHECK(pb_next(&r, &f) == 1 && f.num == 3 && f.u64 == 1);
    CHECK(pb_next(&r, &f) == 1 && f.num == 9 && f.u64 == 0x01020304);
    CHECK(pb_next(&r, &f) == 0);

    /* malformed inputs */
    const uint8_t trunc_len[] = {0x0A, 0x05, 'a'};
    pb_reader_init(&r, trunc_len, sizeof trunc_len);
    CHECK(pb_next(&r, &f) == -1);
    const uint8_t long_varint[] = {0x08, 0xff, 0xff, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0x01};
    pb_reader_init(&r, long_varint, sizeof long_varint);
    CHECK(pb_next(&r, &f) == -1);
    const uint8_t field0[] = {0x00, 0x01};
    pb_reader_init(&r, field0, sizeof field0);
    CHECK(pb_next(&r, &f) == -1);
    const uint8_t group[] = {0x0B};
    pb_reader_init(&r, group, sizeof group);
    CHECK(pb_next(&r, &f) == -1);
}

/* Run a full Noise XX handshake between our initiator and a test responder. */
static void test_noise_xx(void)
{
    const uint8_t header[4] = {'W', 'A', 6, 3};
    uint8_t ie_priv[32], ie_pub[32], is_priv[32], is_pub[32];
    uint8_t re_priv[32], re_pub[32], rs_priv[32], rs_pub[32];
    curve25519_keypair(ie_priv, ie_pub);
    curve25519_keypair(is_priv, is_pub);
    curve25519_keypair(re_priv, re_pub);
    curve25519_keypair(rs_priv, rs_pub);

    noise_handshake I, R;
    CHECK(noise_hs_start(&I, WA_NOISE_PATTERN, 32, header, 4) == 0);
    CHECK(noise_hs_start(&R, WA_NOISE_PATTERN, 32, header, 4) == 0);
    /* -> e */
    noise_hs_authenticate(&I, ie_pub, 32);
    noise_hs_authenticate(&R, ie_pub, 32);
    /* <- e, ee, s, es, payload */
    uint8_t s_ct[48], cert_ct[16 + 16], tmp[64];
    noise_hs_authenticate(&R, re_pub, 32);
    CHECK(noise_hs_mix_dh(&R, re_priv, ie_pub) == 0);
    CHECK(noise_hs_encrypt(&R, rs_pub, 32, s_ct) == 0);
    CHECK(noise_hs_mix_dh(&R, rs_priv, ie_pub) == 0);
    CHECK(noise_hs_encrypt(&R, "certificate!!!!!", 16, cert_ct) == 0);

    noise_hs_authenticate(&I, re_pub, 32);
    CHECK(noise_hs_mix_dh(&I, ie_priv, re_pub) == 0);
    memcpy(tmp, s_ct, 48);
    CHECK(noise_hs_decrypt(&I, tmp, 48, tmp) == 0); /* in place */
    CHECK_MEM(tmp, rs_pub, 32);
    CHECK(noise_hs_mix_dh(&I, ie_priv, rs_pub) == 0);
    CHECK(noise_hs_decrypt(&I, cert_ct, 32, tmp) == 0);
    CHECK_MEM(tmp, "certificate!!!!!", 16);

    /* -> s, se, payload */
    uint8_t is_ct[48], pl_ct[5 + 16];
    CHECK(noise_hs_encrypt(&I, is_pub, 32, is_ct) == 0);
    CHECK(noise_hs_mix_dh(&I, is_priv, re_pub) == 0);
    CHECK(noise_hs_encrypt(&I, "hello", 5, pl_ct) == 0);

    CHECK(noise_hs_decrypt(&R, is_ct, 48, tmp) == 0);
    CHECK_MEM(tmp, is_pub, 32);
    CHECK(noise_hs_mix_dh(&R, re_priv, is_pub) == 0);
    CHECK(noise_hs_decrypt(&R, pl_ct, 21, tmp) == 0);
    CHECK_MEM(tmp, "hello", 5);

    noise_cipher iw, ir, rw, rr;
    CHECK(noise_hs_finish(&I, &iw, &ir) == 0);
    CHECK(noise_hs_finish(&R, &rw, &rr) == 0);
    /* responder's first key is the client's write key */
    uint8_t frame[32 + 16];
    for (int round = 0; round < 3; round++) {
        memcpy(frame, "transport frame payload 32 bytes", 32);
        CHECK(noise_encrypt(&iw, frame, 32) == 0);
        CHECK(noise_decrypt(&rw, frame, 48) == 32);
        CHECK_MEM(frame, "transport frame payload 32 bytes", 32);
    }
    /* counter mismatch must fail */
    memcpy(frame, "transport frame payload 32 bytes", 32);
    CHECK(noise_encrypt(&iw, frame, 32) == 0);
    rw.counter++;
    CHECK(noise_decrypt(&rw, frame, 48) == -1);
}

typedef struct {
    int count;
    size_t lens[8];
    uint8_t first[8];
    int nulls;
} frame_sink;

static int on_frame(void *user, uint8_t *frame, size_t len)
{
    frame_sink *s = user;
    if (s->count < 8) {
        s->lens[s->count] = len;
        s->first[s->count] = (frame != NULL && len > 0) ? frame[0] : 0;
    }
    if (frame == NULL)
        s->nulls++;
    s->count++;
    return 0;
}

static void test_framer(void)
{
    uint8_t buf[16];
    wa_framer f;
    frame_sink sink;
    memset(&sink, 0, sizeof sink);
    wa_framer_init(&f, buf, sizeof buf, on_frame, &sink);
    /* two frames in one message, then one split across feeds */
    const uint8_t stream[] = {0, 0, 3, 'a', 'b', 'c', 0, 0, 1, 'z',
                              0, 0, 5, '1', '2', '3', '4', '5'};
    CHECK(wa_framer_feed(&f, stream, 10) == 0);
    CHECK(sink.count == 2 && sink.lens[0] == 3 && sink.first[0] == 'a');
    CHECK(sink.lens[1] == 1 && sink.first[1] == 'z');
    for (size_t i = 10; i < sizeof stream; i++)
        CHECK(wa_framer_feed(&f, stream + i, 1) == 0);
    CHECK(sink.count == 3 && sink.lens[2] == 5 && sink.first[2] == '1');

    /* oversized frame gets dropped, next frame still parsed */
    uint8_t big[3 + 20 + 4];
    big[0] = 0;
    big[1] = 0;
    big[2] = 20;
    memset(big + 3, 'x', 20);
    big[23] = 0;
    big[24] = 0;
    big[25] = 1;
    big[26] = 'q';
    CHECK(wa_framer_feed(&f, big, sizeof big) == 0);
    CHECK(sink.count == 5 && sink.nulls == 1 && sink.first[4] == 'q');
}

static void test_inflate(void)
{
    static uint8_t out[8192];
    CHECK(zc_inflate_zlib(z_stored, sizeof z_stored, out, sizeof out) ==
          Z_STORED_PLAIN_LEN);
    CHECK(memcmp(out, "hello hello hello", 17) == 0);
    CHECK(zc_inflate_zlib(z_fixed, sizeof z_fixed, out, sizeof out) ==
          Z_FIXED_PLAIN_LEN);
    CHECK(memcmp(out, "hello hello hello hello hello", 29) == 0);
    long n = zc_inflate_zlib(z_dynamic, sizeof z_dynamic, out, sizeof out);
    CHECK(n == Z_DYNAMIC_PLAIN_LEN);
    int ok = 1;
    for (int i = 0; i < 3000; i++)
        if (out[i] != (uint8_t)((i * 7 + (i >> 3)) % 251))
            ok = 0;
    CHECK(ok);
    CHECK(memcmp(out + 3000, "abcabc", 6) == 0);
    /* output buffer too small */
    CHECK(zc_inflate_zlib(z_dynamic, sizeof z_dynamic, out, 1000) == -1);
    /* corrupted checksum */
    uint8_t bad[sizeof z_fixed];
    memcpy(bad, z_fixed, sizeof bad);
    bad[sizeof bad - 1] ^= 1;
    CHECK(zc_inflate_zlib(bad, sizeof bad, out, sizeof out) == -1);
    /* every truncation fails */
    int all = 1;
    for (size_t i = 0; i < sizeof z_dynamic; i += 7)
        if (zc_inflate_zlib(z_dynamic, i, out, sizeof out) >= 0)
            all = 0;
    CHECK(all);
}

int main(void)
{
    RUN(test_jid);
    RUN(test_tokens);
    RUN(test_node_roundtrip);
    RUN(test_node_known_bytes);
    RUN(test_node_malicious);
    RUN(test_protobuf);
    RUN(test_noise_xx);
    RUN(test_framer);
    RUN(test_inflate);
    return test_done("test_protocol");
}
