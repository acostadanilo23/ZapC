/*
 * ZapC - WhatsApp client core: connection, Noise handshake, frame and node
 * pipeline, dispatch, keepalive and reconnect.
 */
#include "zapc/wa.h"
#include "zapc/crypto.h"
#include "zapc/inflate.h"
#include "zapc/log.h"
#include "zapc/platform.h"
#include "zapc/protobuf.h"
#include "zapc/storage.h"
#include "zapc/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WA_ORIGIN "https://web.whatsapp.com"
#define WA_MAGIC 6
#define CONNECT_TIMEOUT_MS 15000
#define KEEPALIVE_DEADLINE_MS 20000
#define IQ_TIMEOUT_MS 60000

/* Root key of WhatsApp's Noise certificate chain. */
static const uint8_t WA_CERT_PUBKEY[32] = {
    0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7,
    0x1e, 0xbe, 0x51, 0x64, 0x37, 0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69,
    0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b};
#define WA_CERT_ISSUER_SERIAL 0

/* Test hook: alternative root key (NULL = the real one). */
static const uint8_t *g_cert_root = WA_CERT_PUBKEY;

void wa_set_noise_root_key(const uint8_t key[32])
{
    g_cert_root = key != NULL ? key : WA_CERT_PUBKEY;
}

static const uint8_t WA_CONN_HEADER[4] = {'W', 'A', WA_MAGIC, WA_DICT_VERSION};

const char *wa_state_name(wa_state st)
{
    switch (st) {
    case WA_ST_DISCONNECTED: return "disconnected";
    case WA_ST_CONNECTING: return "connecting";
    case WA_ST_HANDSHAKE: return "handshake";
    case WA_ST_PAIRING: return "pairing";
    case WA_ST_AUTHENTICATING: return "authenticating";
    case WA_ST_LOGGED_IN: return "logged in";
    }
    return "?";
}

static void set_state(wa_client *c, wa_state st, const char *detail)
{
    if (c->state == st && detail == NULL)
        return;
    c->state = st;
    LOGD("wa", "state: %s%s%s", wa_state_name(st), detail ? " - " : "",
         detail ? detail : "");
    if (c->ev.on_state != NULL)
        c->ev.on_state(c->ev.user, st, detail);
}

/* ======================================================================== */
/* ids                                                                      */
/* ======================================================================== */

void wa_new_request_id(wa_client *c, char *out, size_t cap)
{
    snprintf(out, cap, "%s%u", c->id_prefix, ++c->id_counter);
}

void wa_new_message_id(wa_client *c, char *out, size_t cap)
{
    uint8_t data[8 + 64 + 16];
    size_t n = 0;
    int64_t now = plat_time_unix();
    for (int i = 7; i >= 0; i--)
        data[n++] = (uint8_t)((uint64_t)now >> (8 * i));
    if (c->dev.paired) {
        size_t ul = strlen(c->dev.jid.user);
        if (ul > 40)
            ul = 40;
        memcpy(data + n, c->dev.jid.user, ul);
        n += ul;
        memcpy(data + n, "@c.us", 5);
        n += 5;
    }
    plat_random(data + n, 16);
    n += 16;
    uint8_t hash[32];
    crypto_sha256(data, n, hash);
    char hex[19];
    hex_encode(hash, 9, hex);
    for (char *p = hex; *p; p++)
        if (*p >= 'a' && *p <= 'f')
            *p = (char)(*p - 'a' + 'A');
    snprintf(out, cap, "3EB0%s", hex);
}

/* ======================================================================== */
/* sending                                                                  */
/* ======================================================================== */

static int send_frame(wa_client *c, const uint8_t *payload, size_t len)
{
    uint8_t lenb[3];
    zc_iov parts[3];
    size_t n = 0;
    if (len >= WA_FRAME_MAX_WIRE)
        return -1;
    if (!c->header_sent) {
        parts[n].data = WA_CONN_HEADER;
        parts[n++].len = sizeof WA_CONN_HEADER;
        c->header_sent = 1;
    }
    lenb[0] = (uint8_t)(len >> 16);
    lenb[1] = (uint8_t)(len >> 8);
    lenb[2] = (uint8_t)len;
    parts[n].data = lenb;
    parts[n++].len = 3;
    parts[n].data = payload;
    parts[n++].len = len;
    if (ws_send_v(&c->ws, WS_OP_BINARY, parts, n) != 0) {
        LOGW("wa", "failed to send frame");
        return -1;
    }
    c->frames_tx++;
    c->bytes_tx += len + 3;
    return 0;
}

int wa_send_node(wa_client *c, const wa_node *n)
{
    zbuf b;
    if (c->state < WA_ST_PAIRING || c->fd < 0)
        return -1;
    c->enc_buf[0] = 0; /* flags: uncompressed */
    zbuf_init(&b, c->enc_buf + 1, ZAPC_NODE_ENC_SIZE);
    if (wa_node_encode(n, &b) != 0) {
        LOGE("wa", "node <%s> too large to encode", n->tag);
        return -1;
    }
    if (log_get_level() >= LOG_TRACE) {
        char text[512];
        wa_node_to_text(n, text, sizeof text);
        LOGT("wa", "--> %s", text);
    }
    size_t len = b.len + 1;
    if (noise_encrypt(&c->wcs, c->enc_buf, len) != 0)
        return -1;
    return send_frame(c, c->enc_buf, len + WA_NOISE_TAG_LEN);
}

int wa_send_iq(wa_client *c, wa_node *iq, wa_iq_kind kind, int slot,
               char *id_out, size_t id_cap)
{
    char id[24];
    wa_attr *attrs = (wa_attr *)iq->attrs;
    wa_new_request_id(c, id, sizeof id);
    /* the iq must have an "id" attribute slot with an empty value */
    for (size_t i = 0; i < iq->attr_count; i++)
        if (strcmp(attrs[i].key, "id") == 0)
            attrs[i].value = id;
    wa_pending_iq *p = NULL;
    for (int i = 0; i < WA_MAX_PENDING_IQ; i++)
        if (c->pending[i].kind == IQ_NONE) {
            p = &c->pending[i];
            break;
        }
    if (p == NULL) {
        LOGW("wa", "too many pending requests");
        return -1;
    }
    if (wa_send_node(c, iq) != 0)
        return -1;
    zstrlcpy(p->id, id, sizeof p->id);
    p->kind = kind;
    p->slot = slot;
    p->sent_ms = plat_now_ms();
    if (id_out != NULL)
        zstrlcpy(id_out, id, id_cap);
    return 0;
}

void wa_send_ack(wa_client *c, const wa_node *node, const char *error_code)
{
    wa_attr attrs[7];
    size_t n = 0;
    const char *v;
    attrs[n++] = (wa_attr)WA_ATTR("class", node->tag);
    attrs[n++] = (wa_attr)WA_ATTR("id", wa_node_attr(node, "id"));
    attrs[n++] = (wa_attr)WA_ATTR_JID("to", wa_node_attr(node, "from"));
    if ((v = wa_node_attr(node, "participant")) != NULL)
        attrs[n++] = (wa_attr)WA_ATTR_JID("participant", v);
    if ((v = wa_node_attr(node, "recipient")) != NULL)
        attrs[n++] = (wa_attr)WA_ATTR_JID("recipient", v);
    if (strcmp(node->tag, "message") != 0 &&
        (v = wa_node_attr(node, "type")) != NULL)
        attrs[n++] = (wa_attr)WA_ATTR("type", v);
    if (error_code != NULL)
        attrs[n++] = (wa_attr)WA_ATTR("error", error_code);
    if (attrs[1].value == NULL || attrs[2].value == NULL)
        return;
    wa_node ack = {"ack", attrs, n, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    if (wa_send_node(c, &ack) != 0)
        LOGW("wa", "failed to send ack for %s", node->tag);
}

static void send_iq_result(wa_client *c, const wa_node *iq)
{
    wa_attr attrs[] = {WA_ATTR_JID("to", wa_node_attr(iq, "from")),
                       WA_ATTR("id", wa_node_attr(iq, "id")),
                       WA_ATTR("type", "result")};
    wa_node res = {"iq", attrs, WA_COUNT(attrs), NULL, 0, NULL, 0,
                   WA_CONTENT_NONE};
    if (attrs[0].value == NULL || attrs[1].value == NULL)
        return;
    (void)wa_send_node(c, &res);
}

/* ======================================================================== */
/* handshake                                                                */
/* ======================================================================== */

static void put_app_version(zbuf *b, uint32_t field, const uint32_t v[3])
{
    size_t m = pb_begin(b, field);
    pb_put_uint(b, 1, v[0]);
    pb_put_uint(b, 2, v[1]);
    pb_put_uint(b, 3, v[2]);
    pb_end(b, m);
}

static void put_user_agent(wa_client *c, zbuf *b)
{
    size_t m = pb_begin(b, 5);
    pb_put_uint(b, 1, 14); /* platform = WEB */
    put_app_version(b, 2, c->cfg->wa_version);
    pb_put_string(b, 3, "000");      /* mcc */
    pb_put_string(b, 4, "000");      /* mnc */
    pb_put_string(b, 5, "0.1");      /* osVersion */
    pb_put_string(b, 6, "");         /* manufacturer */
    pb_put_string(b, 7, "Desktop");  /* device */
    pb_put_string(b, 8, "0.1");      /* osBuildNumber */
    pb_put_uint(b, 10, 0);           /* releaseChannel = RELEASE */
    pb_put_string(b, 11, "en");
    pb_put_string(b, 12, "US");
    pb_end(b, m);
    m = pb_begin(b, 6); /* webInfo */
    pb_put_uint(b, 4, 0); /* webSubPlatform = WEB_BROWSER */
    pb_end(b, m);
}

static size_t build_device_props(wa_client *c, uint8_t *out, size_t cap)
{
    zbuf b;
    static const uint32_t ver[3] = {0, 1, 0};
    zbuf_init(&b, out, cap);
    pb_put_string(&b, 1, c->cfg->device_name);
    put_app_version(&b, 2, ver);
    pb_put_uint(&b, 3, 0); /* platformType = UNKNOWN */
    pb_put_bool(&b, 4, 0); /* requireFullSync */
    size_t m = pb_begin(&b, 5);  /* historySyncConfig */
    pb_put_uint(&b, 3, 10240);   /* storageQuotaMb */
    pb_put_bool(&b, 4, 0);       /* no inline history payloads (RAM) */
    pb_put_bool(&b, 6, 1);       /* supportCallLogHistory */
    pb_put_bool(&b, 7, 1);       /* supportBotUserAgentChatHistory */
    pb_put_bool(&b, 8, 1);       /* supportCagReactionsAndPolls */
    pb_put_bool(&b, 9, 1);       /* supportBizHostedMsg */
    pb_put_bool(&b, 10, 1);      /* supportRecentSyncChunkMessageCountTuning */
    pb_put_bool(&b, 11, 1);      /* supportHostedGroupMsg */
    pb_put_bool(&b, 12, 1);      /* supportFbidBotChatHistory */
    pb_put_bool(&b, 14, 1);      /* supportMessageAssociation */
    pb_put_bool(&b, 15, 1);      /* supportGroupHistory */
    pb_put_uint(&b, 19, 60);     /* thumbnailSyncDaysLimit */
    pb_end(&b, m);
    return b.overflow ? 0 : b.len;
}

static size_t build_client_payload(wa_client *c, uint8_t *out, size_t cap)
{
    zbuf b;
    zbuf_init(&b, out, cap);
    if (c->dev.paired) {
        uint64_t user = 0;
        if (jid_user_u64(&c->dev.jid, &user) != 0)
            return 0;
        pb_put_uint(&b, 1, user);
        pb_put_bool(&b, 3, 1); /* passive */
        put_user_agent(c, &b);
        pb_put_uint(&b, 12, 1); /* connectType = WIFI_UNKNOWN */
        pb_put_uint(&b, 13, 1); /* connectReason = USER_ACTIVATED */
        pb_put_uint(&b, 18, c->dev.jid.device);
        pb_put_uint(&b, 24, 1); /* lc */
        pb_put_bool(&b, 33, 1); /* pull */
        pb_put_bool(&b, 41, 1); /* lidDbMigrated */
    } else {
        uint8_t props[256];
        size_t plen = build_device_props(c, props, sizeof props);
        char ver[48];
        uint8_t build_hash[16];
        uint8_t regid[4], skid[4];
        uint8_t keytype = WA_KEY_TYPE_DJB;
        snprintf(ver, sizeof ver, "%u.%u.%u", (unsigned)c->cfg->wa_version[0],
                 (unsigned)c->cfg->wa_version[1],
                 (unsigned)c->cfg->wa_version[2]);
        crypto_md5(ver, strlen(ver), build_hash);
        wr_be32(regid, c->dev.registration_id);
        wr_be32(skid, c->dev.signed_prekey_id);

        pb_put_bool(&b, 3, 0); /* passive */
        put_user_agent(c, &b);
        pb_put_uint(&b, 12, 1);
        pb_put_uint(&b, 13, 1);
        size_t m = pb_begin(&b, 19); /* devicePairingData */
        pb_put_bytes(&b, 1, regid, 4);
        pb_put_bytes(&b, 2, &keytype, 1);
        pb_put_bytes(&b, 3, c->dev.identity_key.pub, 32);
        pb_put_bytes(&b, 4, skid + 1, 3);
        pb_put_bytes(&b, 5, c->dev.signed_prekey.pub, 32);
        pb_put_bytes(&b, 6, c->dev.signed_prekey_sig, 64);
        pb_put_bytes(&b, 7, build_hash, 16);
        pb_put_bytes(&b, 8, props, plen);
        pb_end(&b, m);
        pb_put_bool(&b, 33, 0); /* pull */
    }
    return b.overflow ? 0 : b.len;
}

static int send_client_hello(wa_client *c)
{
    uint8_t msg[64];
    zbuf b;
    if (wa_keypair_generate(&c->ephemeral) != 0)
        return -1;
    if (noise_hs_start(&c->hs, WA_NOISE_PATTERN, WA_NOISE_PATTERN_LEN,
                       WA_CONN_HEADER, sizeof WA_CONN_HEADER) != 0 ||
        noise_hs_authenticate(&c->hs, c->ephemeral.pub, 32) != 0)
        return -1;
    zbuf_init(&b, msg, sizeof msg);
    size_t m = pb_begin(&b, 2); /* clientHello */
    pb_put_bytes(&b, 1, c->ephemeral.pub, 32);
    pb_end(&b, m);
    return send_frame(c, msg, b.len);
}

typedef struct {
    uint32_t serial;
    uint32_t issuer_serial;
    const uint8_t *key;
    size_t key_len;
    uint64_t not_before;
    uint64_t not_after;
} cert_details;

static int parse_cert_details(const uint8_t *p, size_t n, cert_details *d)
{
    pb_reader r;
    pb_field f;
    int rc;
    memset(d, 0, sizeof *d);
    pb_reader_init(&r, p, n);
    while ((rc = pb_next(&r, &f)) == 1) {
        switch (f.num) {
        case 1: d->serial = (uint32_t)f.u64; break;
        case 2: d->issuer_serial = (uint32_t)f.u64; break;
        case 3: d->key = f.data; d->key_len = f.len; break;
        case 4: d->not_before = f.u64; break;
        case 5: d->not_after = f.u64; break;
        default: break;
        }
    }
    return rc;
}

static int check_validity(const cert_details *d, const char *which)
{
    int64_t now = plat_time_unix();
    if (now < 1577836800) { /* clock before 2020: cannot judge */
        LOGW("wa", "system clock looks wrong; skipping %s cert dates", which);
        return 0;
    }
    if ((d->not_before && (uint64_t)now < d->not_before) ||
        (d->not_after && (uint64_t)now > d->not_after)) {
        LOGE("wa", "%s certificate not valid at current time", which);
        return -1;
    }
    return 0;
}

static int split_cert(const uint8_t *p, size_t n, const uint8_t **details,
                      size_t *dlen, const uint8_t **sig, size_t *slen)
{
    if (pb_find_bytes(p, n, 1, details, dlen) != 1 ||
        pb_find_bytes(p, n, 2, sig, slen) != 1 || *slen != 64)
        return -1;
    return 0;
}

static int verify_server_cert(const uint8_t *chain, size_t len,
                              const uint8_t server_static[32])
{
    const uint8_t *leaf, *inter, *ld, *ls, *id, *is;
    size_t leaf_len, inter_len, ldl, lsl, idl, isl;
    cert_details idet, ldet;

    if (pb_find_bytes(chain, len, 1, &leaf, &leaf_len) != 1 ||
        pb_find_bytes(chain, len, 2, &inter, &inter_len) != 1 ||
        split_cert(leaf, leaf_len, &ld, &ldl, &ls, &lsl) != 0 ||
        split_cert(inter, inter_len, &id, &idl, &is, &isl) != 0) {
        LOGE("wa", "malformed noise certificate");
        return -1;
    }
    if (xeddsa_verify(g_cert_root, id, idl, is) != 0) {
        LOGE("wa", "intermediate certificate signature invalid");
        return -1;
    }
    if (parse_cert_details(id, idl, &idet) < 0 ||
        idet.issuer_serial != WA_CERT_ISSUER_SERIAL || idet.key_len != 32) {
        LOGE("wa", "intermediate certificate details invalid");
        return -1;
    }
    if (xeddsa_verify(idet.key, ld, ldl, ls) != 0) {
        LOGE("wa", "leaf certificate signature invalid");
        return -1;
    }
    if (check_validity(&idet, "intermediate") != 0)
        return -1;
    if (parse_cert_details(ld, ldl, &ldet) < 0 ||
        ldet.issuer_serial != idet.serial || ldet.key_len != 32 ||
        zap_ct_memcmp(ldet.key, server_static, 32) != 0) {
        LOGE("wa", "leaf certificate does not match server key");
        return -1;
    }
    return check_validity(&ldet, "leaf");
}

static int handle_server_hello(wa_client *c, uint8_t *frame, size_t len)
{
    const uint8_t *hello, *eph, *stat, *payload;
    size_t hello_len, eph_len, stat_len, payload_len;
    uint8_t server_static[32 + 16];
    static uint8_t cert[4096];
    uint8_t cpayload[1024];
    uint8_t enc_static[32 + 16];
    static uint8_t enc_payload[1024 + 16];
    uint8_t finish[1200 + 64];
    zbuf b;

    if (pb_find_bytes(frame, len, 3, &hello, &hello_len) != 1 ||
        pb_find_bytes(hello, hello_len, 1, &eph, &eph_len) != 1 ||
        pb_find_bytes(hello, hello_len, 2, &stat, &stat_len) != 1 ||
        pb_find_bytes(hello, hello_len, 3, &payload, &payload_len) != 1 ||
        eph_len != 32 || stat_len != 48 || payload_len < 16 ||
        payload_len - 16 > sizeof cert) {
        LOGE("wa", "invalid server hello");
        return -1;
    }
    if (noise_hs_authenticate(&c->hs, eph, 32) != 0 ||
        noise_hs_mix_dh(&c->hs, c->ephemeral.priv, eph) != 0 ||
        noise_hs_decrypt(&c->hs, stat, stat_len, server_static) != 0 ||
        noise_hs_mix_dh(&c->hs, c->ephemeral.priv, server_static) != 0 ||
        noise_hs_decrypt(&c->hs, payload, payload_len, cert) != 0) {
        LOGE("wa", "noise handshake decryption failed");
        return -1;
    }
    if (verify_server_cert(cert, payload_len - 16, server_static) != 0)
        return -1;

    size_t plen = build_client_payload(c, cpayload, sizeof cpayload);
    if (plen == 0)
        return -1;
    if (noise_hs_encrypt(&c->hs, c->dev.noise_key.pub, 32, enc_static) != 0 ||
        noise_hs_mix_dh(&c->hs, c->dev.noise_key.priv, eph) != 0 ||
        noise_hs_encrypt(&c->hs, cpayload, plen, enc_payload) != 0)
        return -1;

    zbuf_init(&b, finish, sizeof finish);
    size_t m = pb_begin(&b, 4); /* clientFinish */
    pb_put_bytes(&b, 1, enc_static, sizeof enc_static);
    pb_put_bytes(&b, 2, enc_payload, plen + 16);
    pb_end(&b, m);
    if (b.overflow || send_frame(c, finish, b.len) != 0)
        return -1;
    if (noise_hs_finish(&c->hs, &c->wcs, &c->rcs) != 0)
        return -1;
    noise_hs_wipe(&c->hs);
    memset(&c->ephemeral, 0, sizeof c->ephemeral);
    LOGI("wa", "noise handshake complete");
    set_state(c, c->dev.paired ? WA_ST_AUTHENTICATING : WA_ST_PAIRING, NULL);
    return 0;
}

/* ======================================================================== */
/* node dispatch                                                            */
/* ======================================================================== */

static void schedule_reconnect(wa_client *c, uint64_t delay_ms)
{
    if (!c->want_connected)
        return;
    c->reconnect_at = plat_now_ms() + delay_ms;
    LOGI("wa", "reconnecting in %llu s", (unsigned long long)(delay_ms / 1000));
}

static void close_transport(wa_client *c)
{
    if (c->fd >= 0) {
        if (c->ws.open && !c->ws.close_sent)
            (void)ws_close(&c->ws, 1000);
        tls_close(c->tls);
        tcp_close(c->fd);
    }
    c->fd = -1;
    c->ws.open = 0;
    c->keepalive_at = 0;
    c->keepalive_sent = 0;
    c->qr_next_at = 0;
    memset(c->pending, 0, sizeof c->pending);
    if (c->send_job != NULL)
        wa_message_job_abort(c, "disconnected");
    noise_hs_wipe(&c->hs);
    memset(&c->wcs, 0, sizeof c->wcs);
    memset(&c->rcs, 0, sizeof c->rcs);
}

static void connection_lost(wa_client *c, const char *why)
{
    int expected = c->expect_disconnect;
    close_transport(c);
    c->expect_disconnect = 0;
    set_state(c, WA_ST_DISCONNECTED, why);
    if (expected) {
        schedule_reconnect(c, 500);
    } else if (c->want_connected) {
        unsigned a = c->reconnect_attempts < 5 ? c->reconnect_attempts : 5;
        c->reconnect_attempts++;
        schedule_reconnect(c, 2000ull << a); /* 2s .. 64s */
    }
}

static void do_logout(wa_client *c, const char *reason)
{
    LOGW("wa", "logged out: %s", reason);
    credentials_delete();
    c->want_connected = 0;
    close_transport(c);
    wa_device_wipe(&c->dev);
    if (wa_device_generate(&c->dev) == 0 && credentials_save(&c->dev) == 0)
        c->have_device = 1;
    set_state(c, WA_ST_DISCONNECTED, reason);
    if (c->ev.on_logged_out != NULL)
        c->ev.on_logged_out(c->ev.user, reason);
}

static void handle_success(wa_client *c, const wa_node *n)
{
    const char *t = wa_node_attr(n, "t");
    const char *lid = wa_node_attr(n, "lid");
    if (!c->dev.paired) {
        LOGW("wa", "connect success without pairing");
        return;
    }
    if (t != NULL)
        c->server_time_offset = strtoll(t, NULL, 10) - plat_time_unix();
    if (lid != NULL && lid[0] != '\0') {
        wa_jid l;
        if (jid_parse(&l, lid) == 0 && !jid_equal(&l, &c->dev.lid)) {
            c->dev.lid = l;
            credentials_save(&c->dev);
            LOGI("wa", "updated LID");
        }
    }
    c->reconnect_attempts = 0;
    LOGI("wa", "logged in");

    /* <iq xmlns="encrypt" type="get"><count/></iq> */
    wa_attr a1[] = {WA_ATTR("id", ""), WA_ATTR("xmlns", "encrypt"),
                    WA_ATTR("type", "get"), WA_ATTR_JID("to", WA_SERVER_USER)};
    wa_node count = {"count", NULL, 0, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    wa_node iq1 = {"iq", a1, WA_COUNT(a1), &count, 1, NULL, 0,
                   WA_CONTENT_CHILDREN};
    (void)wa_send_iq(c, &iq1, IQ_PREKEY_COUNT, -1, NULL, 0);

    /* <iq xmlns="passive" type="set"><active/></iq> */
    wa_attr a2[] = {WA_ATTR("id", ""), WA_ATTR("xmlns", "passive"),
                    WA_ATTR("type", "set"), WA_ATTR_JID("to", WA_SERVER_USER)};
    wa_node active = {"active", NULL, 0, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    wa_node iq2 = {"iq", a2, WA_COUNT(a2), &active, 1, NULL, 0,
                   WA_CONTENT_CHILDREN};
    (void)wa_send_iq(c, &iq2, IQ_GENERIC, -1, NULL, 0);

    c->keepalive_at = plat_now_ms() + (uint64_t)c->cfg->keepalive_s * 1000u;
    set_state(c, WA_ST_LOGGED_IN, NULL);
}

static void handle_failure(wa_client *c, const wa_node *n)
{
    const char *reason = wa_node_attr(n, "reason");
    int code = reason != NULL ? atoi(reason) : 0;
    LOGW("wa", "connect failure: reason %d", code);
    switch (code) {
    case 401: /* logged out */
    case 403: /* banned / logged out */
    case 406: /* main device gone */
        do_logout(c, code == 403 ? "account banned or logged out"
                                 : "device was unlinked");
        break;
    case 405:
        LOGE("wa", "client version outdated; set wa_version in config");
        c->want_connected = 0;
        break;
    case 402:
        LOGE("wa", "account temporarily banned");
        c->want_connected = 0;
        break;
    default:
        break; /* 500/503: normal reconnect */
    }
}

static void handle_stream_error(wa_client *c, const wa_node *n)
{
    const char *code = wa_node_attr(n, "code");
    const wa_node *conflict = wa_node_child(n, "conflict");
    const char *ctype = wa_node_attr(conflict, "type");
    if (code != NULL && strcmp(code, "515") == 0) {
        LOGI("wa", "server requested restart (515)");
        c->expect_disconnect = 1;
    } else if (code != NULL && strcmp(code, "401") == 0 && ctype != NULL &&
               strcmp(ctype, "device_removed") == 0) {
        do_logout(c, "device removed");
    } else if (ctype != NULL && strcmp(ctype, "replaced") == 0) {
        LOGW("wa", "session replaced by another connection");
        c->want_connected = 0;
    } else {
        LOGW("wa", "stream error %s", code ? code : "?");
    }
}

static void handle_notification(wa_client *c, const wa_node *n)
{
    const char *type = wa_node_attr(n, "type");
    const char *from = wa_node_attr(n, "from");
    wa_send_ack(c, n, NULL);
    if (type == NULL)
        return;
    if (strcmp(type, "encrypt") == 0 && from != NULL &&
        strcmp(from, WA_SERVER_USER) == 0) {
        const char *v = wa_node_attr(wa_node_child(n, "count"), "value");
        if (v != NULL && atoi(v) < 5)
            wa_upload_prekeys(c, ZAPC_PREKEY_BATCH);
    } else if (strcmp(type, "encrypt") == 0 &&
               wa_node_child(n, "identity") != NULL && from != NULL) {
        /* the contact changed devices: drop their sessions */
        wa_jid j;
        char addr[96];
        if (jid_parse(&j, from) == 0) {
            for (unsigned d = 0; d < 100; d++) {
                j.device = (uint16_t)d;
                if (jid_signal_address(&j, addr, sizeof addr) > 0)
                    storage_blob_delete("sessions", addr);
            }
            j.device = 0;
            if (jid_signal_address(&j, addr, sizeof addr) > 0)
                storage_blob_delete("identities", addr);
        }
    } else if (strcmp(type, "w:gp2") == 0) {
        const wa_node *sub = wa_node_child(n, "subject");
        const char *name = wa_node_attr(sub, "subject");
        wa_jid j;
        if (name != NULL && from != NULL && jid_parse(&j, from) == 0 &&
            c->ev.on_chat_name != NULL)
            c->ev.on_chat_name(c->ev.user, &j, name);
    }
}

static wa_pending_iq *find_pending(wa_client *c, const char *id)
{
    if (id == NULL)
        return NULL;
    for (int i = 0; i < WA_MAX_PENDING_IQ; i++)
        if (c->pending[i].kind != IQ_NONE && strcmp(c->pending[i].id, id) == 0)
            return &c->pending[i];
    return NULL;
}

static void handle_iq(wa_client *c, const wa_node *n)
{
    const char *type = wa_node_attr(n, "type");
    const char *from = wa_node_attr(n, "from");
    if (type == NULL)
        return;
    if (strcmp(type, "result") == 0 || strcmp(type, "error") == 0) {
        wa_pending_iq *p = find_pending(c, wa_node_attr(n, "id"));
        if (p == NULL)
            return;
        wa_pending_iq req = *p;
        memset(p, 0, sizeof *p);
        if (req.kind == IQ_KEEPALIVE) {
            c->keepalive_sent = 0;
            return;
        }
        wa_handle_iq_result(c, n, &req);
        return;
    }
    if (from == NULL || strcmp(from, WA_SERVER_USER) != 0)
        return;
    if (wa_node_child(n, "pair-device") != NULL) {
        wa_handle_pair_device(c, n);
    } else if (wa_node_child(n, "pair-success") != NULL) {
        wa_handle_pair_success(c, n);
    } else if (strcmp(type, "get") == 0) {
        const char *xmlns = wa_node_attr(n, "xmlns");
        if (xmlns != NULL && strcmp(xmlns, "urn:xmpp:ping") == 0)
            send_iq_result(c, n);
    }
}

static void handle_ib(wa_client *c, const wa_node *n)
{
    (void)c;
    for (size_t i = 0; n->content == WA_CONTENT_CHILDREN && i < n->child_count;
         i++) {
        const wa_node *ch = &n->children[i];
        if (strcmp(ch->tag, "offline") == 0)
            LOGI("wa", "offline sync done (%s items)",
                 wa_node_attr(ch, "count") ? wa_node_attr(ch, "count") : "0");
        else if (strcmp(ch->tag, "offline_preview") == 0)
            LOGI("wa", "syncing offline messages...");
    }
}

static void handle_ack(wa_client *c, const wa_node *n)
{
    const char *cls = wa_node_attr(n, "class");
    const char *id = wa_node_attr(n, "id");
    const char *from = wa_node_attr(n, "from");
    wa_jid chat;
    if (cls == NULL || id == NULL || strcmp(cls, "message") != 0)
        return;
    if (from == NULL || jid_parse(&chat, from) != 0)
        jid_clear(&chat);
    const char *err = wa_node_attr(n, "error");
    if (c->ev.on_receipt != NULL)
        c->ev.on_receipt(c->ev.user, &chat, id, err ? "error" : "sent");
}

static void dispatch(wa_client *c, const wa_node *n)
{
    if (log_get_level() >= LOG_TRACE) {
        char text[512];
        wa_node_to_text(n, text, sizeof text);
        LOGT("wa", "<-- %s", text);
    }
    const char *tag = n->tag;
    if (strcmp(tag, "iq") == 0)
        handle_iq(c, n);
    else if (strcmp(tag, "message") == 0)
        wa_handle_message(c, n);
    else if (strcmp(tag, "receipt") == 0)
        wa_handle_receipt(c, n);
    else if (strcmp(tag, "notification") == 0)
        handle_notification(c, n);
    else if (strcmp(tag, "success") == 0)
        handle_success(c, n);
    else if (strcmp(tag, "failure") == 0)
        handle_failure(c, n);
    else if (strcmp(tag, "stream:error") == 0)
        handle_stream_error(c, n);
    else if (strcmp(tag, "ib") == 0)
        handle_ib(c, n);
    else if (strcmp(tag, "ack") == 0)
        handle_ack(c, n);
    else if (strcmp(tag, "call") == 0)
        wa_send_ack(c, n, NULL);
    else if (strcmp(tag, "xmlstreamend") == 0)
        LOGD("wa", "stream end");
    else
        LOGD("wa", "unhandled node <%s>", tag);
}

/* ======================================================================== */
/* frame pipeline                                                           */
/* ======================================================================== */

static int on_frame(void *user, uint8_t *frame, size_t len)
{
    wa_client *c = user;
    c->frames_rx++;
    c->bytes_rx += len + 3;
    if (frame == NULL) {
        /* dropped (too large): keep the receive counter in sync */
        if (c->state == WA_ST_HANDSHAKE)
            return -1;
        c->rcs.counter++;
        return 0;
    }
    if (c->state == WA_ST_HANDSHAKE)
        return handle_server_hello(c, frame, len) == 0 ? 0 : -1;

    long plen = noise_decrypt(&c->rcs, frame, len);
    if (plen < 1) {
        LOGW("wa", "failed to decrypt frame");
        return -1;
    }
    const uint8_t *data = frame + 1;
    size_t dlen = (size_t)plen - 1;
    if (frame[0] & 2) {
        long n = zc_inflate_zlib(data, dlen, c->inflate_buf,
                                 sizeof c->inflate_buf);
        if (n < 0) {
            LOGW("wa", "failed to decompress frame (%zu bytes)", dlen);
            return 0;
        }
        data = c->inflate_buf;
        dlen = (size_t)n;
    }
    zap_arena_reset(&c->arena);
    wa_node *node;
    if (wa_node_decode(data, dlen, &c->arena, &node) != 0) {
        LOGW("wa", "failed to decode node (%zu bytes)", dlen);
        return 0;
    }
    if (c->arena.peak > c->arena_peak)
        c->arena_peak = c->arena.peak;
    dispatch(c, node);
    return 0;
}

static int on_ws_message(void *user, int opcode, const uint8_t *data,
                         size_t len, int first, int last)
{
    wa_client *c = user;
    (void)first;
    (void)last;
    if (opcode != WS_OP_BINARY)
        return 0;
    return wa_framer_feed(&c->framer, data, len);
}

/* ======================================================================== */
/* public API                                                               */
/* ======================================================================== */

int wa_client_init(wa_client *c, const zapc_config *cfg, const wa_events *ev)
{
    uint8_t rnd[2];
    memset(c, 0, offsetof(wa_client, arena_mem));
    c->cfg = cfg;
    if (ev != NULL)
        c->ev = *ev;
    c->fd = -1;
    c->tls = tls_new();
    if (c->tls == NULL)
        return -1;
    zap_arena_init(&c->arena, c->arena_mem, sizeof c->arena_mem);
    if (plat_random(rnd, sizeof rnd) != 0)
        return -1;
    snprintf(c->id_prefix, sizeof c->id_prefix, "%u.%u-", (unsigned)rnd[0],
             (unsigned)rnd[1]);

    int r = credentials_load(&c->dev);
    if (r == 1 || r < 0) {
        if (r < 0)
            LOGW("wa", "starting with a fresh identity");
        if (wa_device_generate(&c->dev) != 0 || credentials_save(&c->dev) != 0) {
            LOGE("wa", "cannot create device identity");
            return -1;
        }
    }
    c->have_device = 1;
    return 0;
}

void wa_client_free(wa_client *c)
{
    c->want_connected = 0;
    close_transport(c);
    tls_free(c->tls);
    c->tls = NULL;
    wa_device_wipe(&c->dev);
}

int wa_client_connect(wa_client *c)
{
    char detail[160];
    if (c->state != WA_ST_DISCONNECTED)
        return 0;
    c->want_connected = 1;
    c->reconnect_at = 0;
    snprintf(detail, sizeof detail, "%s:%u", c->cfg->wa_host,
             (unsigned)c->cfg->wa_port);
    set_state(c, WA_ST_CONNECTING, detail);

    c->fd = tcp_connect(c->cfg->wa_host, c->cfg->wa_port, CONNECT_TIMEOUT_MS);
    if (c->fd < 0) {
        connection_lost(c, "connect failed");
        return -1;
    }
    if (tls_connect(c->tls, c->fd, c->cfg->wa_host, c->cfg->ca_file,
                    CONNECT_TIMEOUT_MS) != 0) {
        connection_lost(c, "TLS failed");
        return -1;
    }
    ws_init(&c->ws, tls_stream(c->tls), on_ws_message, c);
    if (ws_handshake(&c->ws, c->cfg->wa_host, c->cfg->wa_path, WA_ORIGIN,
                     CONNECT_TIMEOUT_MS) != 0) {
        connection_lost(c, "WebSocket upgrade failed");
        return -1;
    }
    wa_framer_init(&c->framer, c->frame_buf, sizeof c->frame_buf, on_frame, c);
    c->header_sent = 0;
    set_state(c, WA_ST_HANDSHAKE, NULL);
    if (send_client_hello(c) != 0) {
        connection_lost(c, "handshake failed");
        return -1;
    }
    /* frames that arrived together with the upgrade response */
    if (c->ws.rx_len > 0 && wa_client_on_readable(c) != 0)
        return -1;
    return 0;
}

void wa_client_disconnect(wa_client *c)
{
    c->want_connected = 0;
    c->reconnect_at = 0;
    if (c->state != WA_ST_DISCONNECTED) {
        close_transport(c);
        set_state(c, WA_ST_DISCONNECTED, "by user");
    }
}

int wa_client_logout(wa_client *c)
{
    if (c->state == WA_ST_LOGGED_IN && c->dev.paired) {
        /* <iq xmlns="md" type="set"><remove-companion-device jid=.. reason="user_initiated"/></iq> */
        char jid[WA_JID_STR_MAX];
        jid_format(&c->dev.jid, jid, sizeof jid);
        wa_attr ra[] = {WA_ATTR_JID("jid", jid),
                        WA_ATTR("reason", "user_initiated")};
        wa_node rm = {"remove-companion-device", ra, 2, NULL, 0, NULL, 0,
                      WA_CONTENT_NONE};
        wa_attr a[] = {WA_ATTR("id", ""), WA_ATTR("xmlns", "md"),
                       WA_ATTR("type", "set"),
                       WA_ATTR_JID("to", WA_SERVER_USER)};
        wa_node iq = {"iq", a, WA_COUNT(a), &rm, 1, NULL, 0,
                      WA_CONTENT_CHILDREN};
        (void)wa_send_iq(c, &iq, IQ_GENERIC, -1, NULL, 0);
    }
    do_logout(c, "logged out by user");
    return 0;
}

int wa_client_fd(const wa_client *c) { return c->fd; }

int wa_client_on_readable(wa_client *c)
{
    if (c->fd < 0)
        return -1;
    if (ws_pump(&c->ws) != 0) {
        const char *why = c->ws.close_received ? "closed by server"
                                               : "connection lost";
        connection_lost(c, why);
        return -1;
    }
    if (!c->want_connected && c->state != WA_ST_DISCONNECTED) {
        /* e.g. logged out or replaced while processing */
        close_transport(c);
        set_state(c, WA_ST_DISCONNECTED, NULL);
        return -1;
    }
    return 0;
}

static void send_keepalive(wa_client *c)
{
    wa_attr a[] = {WA_ATTR("id", ""), WA_ATTR("xmlns", "w:p"),
                   WA_ATTR("type", "get"), WA_ATTR_JID("to", WA_SERVER_USER)};
    wa_node ping = {"ping", NULL, 0, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    wa_node iq = {"iq", a, WA_COUNT(a), &ping, 1, NULL, 0,
                  WA_CONTENT_CHILDREN};
    if (wa_send_iq(c, &iq, IQ_KEEPALIVE, -1, NULL, 0) == 0)
        c->keepalive_sent = plat_now_ms();
}

void wa_client_tick(wa_client *c)
{
    uint64_t now = plat_now_ms();
    if (c->state == WA_ST_DISCONNECTED) {
        if (c->want_connected && c->reconnect_at != 0 && now >= c->reconnect_at) {
            c->reconnect_at = 0;
            (void)wa_client_connect(c);
        }
        return;
    }
    if (c->state == WA_ST_LOGGED_IN && c->keepalive_at != 0 &&
        now >= c->keepalive_at) {
        if (c->keepalive_sent != 0 &&
            now - c->keepalive_sent > KEEPALIVE_DEADLINE_MS * 2u) {
            LOGW("wa", "keepalive timed out");
            connection_lost(c, "keepalive timeout");
            return;
        }
        if (c->keepalive_sent == 0)
            send_keepalive(c);
        c->keepalive_at = now + (uint64_t)c->cfg->keepalive_s * 1000u;
    }
    if (c->state == WA_ST_PAIRING && c->qr_next_at != 0 && now >= c->qr_next_at) {
        c->qr_ref_index++;
        if (c->qr_ref_index >= c->qr_ref_count) {
            LOGW("wa", "QR codes expired; reconnecting for new ones");
            c->qr_next_at = 0;
            connection_lost(c, "QR timeout");
            return;
        }
        c->qr_next_at = now + 20000;
        wa_handle_pair_device(c, NULL); /* show next code */
    }
    for (int i = 0; i < WA_MAX_PENDING_IQ; i++) {
        wa_pending_iq *p = &c->pending[i];
        if (p->kind != IQ_NONE && now - p->sent_ms > IQ_TIMEOUT_MS) {
            LOGW("wa", "request %s timed out", p->id);
            if (p->slot >= 0)
                wa_message_job_timeout(c);
            memset(p, 0, sizeof *p);
        }
    }
}

int wa_client_next_timeout(const wa_client *c)
{
    uint64_t now = plat_now_ms();
    uint64_t next = 0;
    uint64_t cand[4] = {c->state == WA_ST_LOGGED_IN ? c->keepalive_at : 0,
                        c->state == WA_ST_DISCONNECTED ? c->reconnect_at : 0,
                        c->state == WA_ST_PAIRING ? c->qr_next_at : 0, 0};
    for (int i = 0; i < 4; i++)
        if (cand[i] != 0 && (next == 0 || cand[i] < next))
            next = cand[i];
    if (next == 0)
        return c->state == WA_ST_DISCONNECTED ? -1 : 5000;
    return next <= now ? 0 : (int)(next - now > 60000 ? 60000 : next - now);
}
