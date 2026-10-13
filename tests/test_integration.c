/*
 * End-to-end test against a fake WhatsApp server running in a child process.
 *
 * The real client code (TCP, TLS with certificate verification, WebSocket,
 * Noise handshake, binary nodes, pairing, login, prekey upload, Signal
 * sessions in both directions) talks to a local server implemented here with
 * the same building blocks, using a test certificate chain.
 *
 * Flow:
 *   1. connect #1: Noise handshake, registration payload, pair-device (QR)
 *   2. the QR payload goes to the server through a pipe ("the phone scans")
 *   3. pair-success with a valid HMAC and account signature; the server
 *      checks the device signature, then sends stream:error 515
 *   4. connect #2: login payload, success, prekey count, prekey upload
 *   5. server ("Maria") opens a Signal session from the uploaded bundle and
 *      sends a pkmsg; the client must decrypt it and send receipt + ack
 *   6. client replies: usync -> prekey fetch (for the account's phone) ->
 *      message with a msg for Maria and a pkmsg (DeviceSentMessage) for the
 *      phone; the server decrypts both, then sends ack + delivery receipt
 */
#include "test.h"

#include "zapc/binary_node.h"
#include "zapc/crypto.h"
#include "zapc/log.h"
#include "zapc/noise.h"
#include "zapc/platform.h"
#include "zapc/protobuf.h"
#include "zapc/signal.h"
#include "zapc/storage.h"
#include "zapc/wa.h"
#include "zapc/websocket.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PHONE_USER "5511999990000"
#define CLIENT_DEVICE 5
#define CLIENT_JID PHONE_USER ":5@s.whatsapp.net"
#define CLIENT_ADDR PHONE_USER ":5"
#define MARIA_JID "5511888887777@s.whatsapp.net"
#define MARIA_TEXT "oi do servidor \xc3\xa9 \xf0\x9f\x98\x80"
#define REPLY_TEXT "resposta do cliente"
#define GROUP_JID "120363001@g.us"
#define GROUP_TEXT "mensagem no grupo"
#define GROUP_IN_TEXT "oi grupo, aqui \xc3\xa9 a Maria"
#define MARIA_ADDR "5511888887777:0"

static char g_dir[256];
static EVP_PKEY *g_tls_key;
static X509 *g_tls_cert;
static wa_keypair g_root, g_inter, g_server_static;
static int g_qr_pipe[2];

/* ======================================================================== */
/* test certificate for TLS                                                 */
/* ======================================================================== */

static int make_tls_cert(const char *path)
{
    g_tls_key = EVP_EC_gen("P-256");
    g_tls_cert = X509_new();
    if (g_tls_key == NULL || g_tls_cert == NULL)
        return -1;
    X509_set_version(g_tls_cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(g_tls_cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(g_tls_cert), -3600);
    X509_gmtime_adj(X509_getm_notAfter(g_tls_cert), 3600);
    X509_set_pubkey(g_tls_cert, g_tls_key);
    X509_NAME *name = X509_get_subject_name(g_tls_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(g_tls_cert, name);
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, g_tls_cert, g_tls_cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name,
                                              "DNS:localhost,IP:127.0.0.1");
    X509_add_ext(g_tls_cert, ext, -1);
    X509_EXTENSION_free(ext);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(g_tls_cert, ext, -1);
    X509_EXTENSION_free(ext);
    if (X509_sign(g_tls_cert, g_tls_key, EVP_sha256()) == 0)
        return -1;
    FILE *f = fopen(path, "w");
    if (f == NULL)
        return -1;
    PEM_write_X509(f, g_tls_cert);
    fclose(f);
    return 0;
}

/* ======================================================================== */
/* fake server                                                              */
/* ======================================================================== */

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "  [server] FAIL: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    _exit(1);
}

typedef struct {
    SSL *ssl;
    int fd;
    noise_cipher rcs;
    noise_cipher wcs;
    int header_seen;
    zap_arena arena;
    uint8_t arena_mem[65536];
} srv_conn;

static void ssl_read_full(SSL *ssl, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n > 0) {
        int r = SSL_read(ssl, p, (int)n);
        if (r <= 0)
            die("connection closed while reading");
        p += r;
        n -= (size_t)r;
    }
}

static void ssl_write_full(SSL *ssl, const void *buf, size_t n)
{
    if (SSL_write(ssl, buf, (int)n) != (int)n)
        die("write failed");
}

/* Read one complete (unfragmented, masked) client WebSocket message. */
static size_t ws_read(srv_conn *c, uint8_t *buf, size_t cap)
{
    for (;;) {
        uint8_t h[2], ext[8], mask[4];
        ssl_read_full(c->ssl, h, 2);
        uint64_t len = h[1] & 0x7F;
        if (len == 126) {
            ssl_read_full(c->ssl, ext, 2);
            len = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (len == 127) {
            ssl_read_full(c->ssl, ext, 8);
            len = 0;
            for (int i = 0; i < 8; i++)
                len = (len << 8) | ext[i];
        }
        if (!(h[1] & 0x80))
            die("client frame not masked");
        ssl_read_full(c->ssl, mask, 4);
        if (len > cap)
            die("client frame too large");
        ssl_read_full(c->ssl, buf, (size_t)len);
        for (uint64_t i = 0; i < len; i++)
            buf[i] ^= mask[i & 3];
        int op = h[0] & 0x0F;
        if (!(h[0] & 0x80))
            die("unexpected fragmentation");
        if (op == WS_OP_BINARY)
            return (size_t)len;
        if (op == WS_OP_CLOSE)
            die("client closed websocket");
        /* ignore ping/pong/text */
    }
}

static void ws_write(srv_conn *c, const uint8_t *data, size_t len)
{
    uint8_t h[10];
    size_t hl = 0;
    h[hl++] = 0x82;
    if (len < 126) {
        h[hl++] = (uint8_t)len;
    } else if (len < 65536) {
        h[hl++] = 126;
        h[hl++] = (uint8_t)(len >> 8);
        h[hl++] = (uint8_t)len;
    } else {
        h[hl++] = 127;
        for (int i = 7; i >= 0; i--)
            h[hl++] = (uint8_t)((uint64_t)len >> (8 * i));
    }
    ssl_write_full(c->ssl, h, hl);
    ssl_write_full(c->ssl, data, len);
}

/* Read one WhatsApp frame (one per WebSocket message from our client). */
static size_t wa_read_frame(srv_conn *c, uint8_t *buf, size_t cap)
{
    static uint8_t msg[300000];
    size_t n = ws_read(c, msg, sizeof msg);
    size_t off = 0;
    if (!c->header_seen) {
        if (n < 4 || memcmp(msg, "WA\x06\x03", 4) != 0)
            die("missing connection header");
        c->header_seen = 1;
        off = 4;
    }
    if (n - off < 3)
        die("short frame");
    size_t flen = ((size_t)msg[off] << 16) | ((size_t)msg[off + 1] << 8) | msg[off + 2];
    if (flen != n - off - 3 || flen > cap)
        die("frame length mismatch (%zu vs %zu)", flen, n - off - 3);
    memcpy(buf, msg + off + 3, flen);
    return flen;
}

static void wa_write_frame(srv_conn *c, const uint8_t *data, size_t len)
{
    static uint8_t msg[300000];
    msg[0] = (uint8_t)(len >> 16);
    msg[1] = (uint8_t)(len >> 8);
    msg[2] = (uint8_t)len;
    memcpy(msg + 3, data, len);
    ws_write(c, msg, len + 3);
}

static void send_node(srv_conn *c, const wa_node *n)
{
    static uint8_t buf[200000];
    zbuf b;
    buf[0] = 0;
    zbuf_init(&b, buf + 1, sizeof buf - 64);
    if (wa_node_encode(n, &b) != 0)
        die("encode failed");
    size_t len = b.len + 1;
    if (noise_encrypt(&c->wcs, buf, len) != 0)
        die("encrypt failed");
    wa_write_frame(c, buf, len + 16);
}

static wa_node *recv_node(srv_conn *c)
{
    static uint8_t buf[300000];
    size_t n = wa_read_frame(c, buf, sizeof buf);
    long pl = noise_decrypt(&c->rcs, buf, n);
    if (pl < 1)
        die("cannot decrypt client frame");
    if (buf[0] != 0)
        die("unexpected compressed client frame");
    wa_node *node;
    zap_arena_reset(&c->arena);
    /* keep the decrypted data alive in a second buffer for the node views */
    static uint8_t keep[300000];
    memcpy(keep, buf + 1, (size_t)pl - 1);
    if (wa_node_decode(keep, (size_t)pl - 1, &c->arena, &node) != 0)
        die("cannot decode client node");
    return node;
}

/* Receive nodes until one with `tag` (and optional xmlns) arrives. */
static wa_node *expect_node(srv_conn *c, const char *tag, const char *xmlns)
{
    for (int i = 0; i < 20; i++) {
        wa_node *n = recv_node(c);
        if (strcmp(n->tag, tag) != 0)
            continue;
        if (xmlns != NULL) {
            const char *x = wa_node_attr(n, "xmlns");
            if (x == NULL || strcmp(x, xmlns) != 0)
                continue;
        }
        return n;
    }
    die("expected <%s> never arrived", tag);
    return NULL;
}

static void send_iq_result(srv_conn *c, const wa_node *req, wa_node *kids,
                           size_t nkids)
{
    char id[64];
    zstrlcpy(id, wa_node_attr(req, "id"), sizeof id);
    wa_attr a[] = {WA_ATTR_JID("from", "s.whatsapp.net"), WA_ATTR("id", id),
                   WA_ATTR("type", "result")};
    wa_node r = {"iq", a, 3, kids, nkids, NULL, 0,
                 nkids ? WA_CONTENT_CHILDREN : WA_CONTENT_NONE};
    send_node(c, &r);
}

static size_t build_cert_chain(uint8_t *out, size_t cap)
{
    uint8_t di[256], dl[256], sig_i[64], sig_l[64];
    zbuf b;
    int64_t now = plat_time_unix();
    zbuf_init(&b, di, sizeof di);
    pb_put_uint(&b, 1, 1);
    pb_put_uint(&b, 2, 0);
    pb_put_bytes(&b, 3, g_inter.pub, 32);
    pb_put_uint(&b, 4, (uint64_t)(now - 100));
    pb_put_uint(&b, 5, (uint64_t)(now + 100000));
    size_t dil = b.len;
    zbuf_init(&b, dl, sizeof dl);
    pb_put_uint(&b, 1, 2);
    pb_put_uint(&b, 2, 1);
    pb_put_bytes(&b, 3, g_server_static.pub, 32);
    pb_put_uint(&b, 4, (uint64_t)(now - 100));
    pb_put_uint(&b, 5, (uint64_t)(now + 100000));
    size_t dll = b.len;
    xeddsa_sign(sig_i, g_root.priv, di, dil);
    xeddsa_sign(sig_l, g_inter.priv, dl, dll);
    zbuf_init(&b, out, cap);
    size_t m = pb_begin(&b, 1);
    pb_put_bytes(&b, 1, dl, dll);
    pb_put_bytes(&b, 2, sig_l, 64);
    pb_end(&b, m);
    m = pb_begin(&b, 2);
    pb_put_bytes(&b, 1, di, dil);
    pb_put_bytes(&b, 2, sig_i, 64);
    pb_end(&b, m);
    return b.len;
}

/* Accept a TLS + WebSocket + Noise connection. Returns the ClientPayload. */
static size_t srv_accept(srv_conn *c, int lfd, uint8_t *payload, size_t cap)
{
    memset(c, 0, offsetof(srv_conn, arena_mem));
    zap_arena_init(&c->arena, c->arena_mem, sizeof c->arena_mem);
    c->fd = accept(lfd, NULL, NULL);
    if (c->fd < 0)
        die("accept");
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, g_tls_cert);
    SSL_CTX_use_PrivateKey(ctx, g_tls_key);
    c->ssl = SSL_new(ctx);
    SSL_set_fd(c->ssl, c->fd);
    if (SSL_accept(c->ssl) != 1)
        die("TLS accept failed");

    /* HTTP upgrade */
    char req[2048];
    size_t have = 0;
    while (have < sizeof req - 1) {
        int r = SSL_read(c->ssl, req + have, 1);
        if (r <= 0)
            die("upgrade read");
        have++;
        req[have] = '\0';
        if (have >= 4 && memcmp(req + have - 4, "\r\n\r\n", 4) == 0)
            break;
    }
    if (strncmp(req, "GET /ws/chat HTTP/1.1\r\n", 23) != 0)
        die("bad upgrade request");
    if (strstr(req, "Origin: https://web.whatsapp.com\r\n") == NULL)
        die("missing Origin header");
    const char *k = strstr(req, "Sec-WebSocket-Key: ");
    if (k == NULL)
        die("missing key");
    char key[64];
    k += 19;
    size_t kl = strcspn(k, "\r");
    zstrlcpyn(key, k, kl, sizeof key);
    char accept_key[32];
    ws_accept_key(key, accept_key);
    char resp[256];
    int rl = snprintf(resp, sizeof resp,
                      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
                      accept_key);
    ssl_write_full(c->ssl, resp, (size_t)rl);

    /* Noise XX responder */
    uint8_t frame[4096];
    size_t n = wa_read_frame(c, frame, sizeof frame);
    const uint8_t *hello, *ceph;
    size_t hl, cl;
    if (pb_find_bytes(frame, n, 2, &hello, &hl) != 1 ||
        pb_find_bytes(hello, hl, 1, &ceph, &cl) != 1 || cl != 32)
        die("bad client hello");
    uint8_t client_eph[32];
    memcpy(client_eph, ceph, 32);

    noise_handshake hs;
    wa_keypair eph;
    curve25519_keypair(eph.priv, eph.pub);
    noise_hs_start(&hs, WA_NOISE_PATTERN, 32, "WA\x06\x03", 4);
    noise_hs_authenticate(&hs, client_eph, 32);
    noise_hs_authenticate(&hs, eph.pub, 32);
    noise_hs_mix_dh(&hs, eph.priv, client_eph);
    uint8_t static_ct[48], cert[1024], cert_ct[1024 + 16];
    noise_hs_encrypt(&hs, g_server_static.pub, 32, static_ct);
    noise_hs_mix_dh(&hs, g_server_static.priv, client_eph);
    size_t certl = build_cert_chain(cert, sizeof cert);
    noise_hs_encrypt(&hs, cert, certl, cert_ct);

    uint8_t out[2048];
    zbuf b;
    zbuf_init(&b, out, sizeof out);
    size_t m = pb_begin(&b, 3);
    pb_put_bytes(&b, 1, eph.pub, 32);
    pb_put_bytes(&b, 2, static_ct, 48);
    pb_put_bytes(&b, 3, cert_ct, certl + 16);
    pb_end(&b, m);
    wa_write_frame(c, out, b.len);

    n = wa_read_frame(c, frame, sizeof frame);
    const uint8_t *fin, *s_ct, *p_ct;
    size_t fl, sl, pl;
    if (pb_find_bytes(frame, n, 4, &fin, &fl) != 1 ||
        pb_find_bytes(fin, fl, 1, &s_ct, &sl) != 1 ||
        pb_find_bytes(fin, fl, 2, &p_ct, &pl) != 1 || sl != 48 || pl < 16 ||
        pl - 16 > cap)
        die("bad client finish");
    uint8_t client_static[48];
    if (noise_hs_decrypt(&hs, s_ct, sl, client_static) != 0)
        die("cannot decrypt client static");
    noise_hs_mix_dh(&hs, eph.priv, client_static);
    if (noise_hs_decrypt(&hs, p_ct, pl, payload) != 0)
        die("cannot decrypt client payload");
    noise_hs_finish(&hs, &c->rcs, &c->wcs);
    return pl - 16;
}

static void srv_close(srv_conn *c)
{
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
    close(c->fd);
}

static size_t padded_message(const char *text, uint8_t *out, size_t cap)
{
    zbuf b;
    zbuf_init(&b, out, cap);
    pb_put_string(&b, 1, text);
    return wa_pad_message(out, b.len, cap);
}

static int run_server(int lfd)
{
    static uint8_t payload[4096];
    srv_conn *c = calloc(1, sizeof *c);
    char addr_dir_phone[600], addr_dir_maria[600];
    snprintf(addr_dir_maria, sizeof addr_dir_maria, "%s/server-maria", g_dir);
    snprintf(addr_dir_phone, sizeof addr_dir_phone, "%s/server-phone", g_dir);
    alarm(60);

    /* ---------------- connection 1: pairing ---------------- */
    size_t pl = srv_accept(c, lfd, payload, sizeof payload);
    const uint8_t *pair_data, *ident, *regid, *skey_id, *skey_val, *skey_sig;
    size_t pdl, il, rl, kil, kvl, ksl;
    uint64_t user;
    if (pb_find_varint(payload, pl, 1, &user) == 1)
        die("registration payload must not contain a username");
    if (pb_find_bytes(payload, pl, 19, &pair_data, &pdl) != 1 ||
        pb_find_bytes(pair_data, pdl, 3, &ident, &il) != 1 || il != 32 ||
        pb_find_bytes(pair_data, pdl, 1, &regid, &rl) != 1 || rl != 4 ||
        pb_find_bytes(pair_data, pdl, 4, &skey_id, &kil) != 1 || kil != 3 ||
        pb_find_bytes(pair_data, pdl, 5, &skey_val, &kvl) != 1 || kvl != 32 ||
        pb_find_bytes(pair_data, pdl, 6, &skey_sig, &ksl) != 1 || ksl != 64)
        die("bad registration payload");
    uint8_t client_ident[32];
    memcpy(client_ident, ident, 32);
    {
        uint8_t m33[33];
        m33[0] = 5;
        memcpy(m33 + 1, skey_val, 32);
        if (xeddsa_verify(client_ident, m33, 33, skey_sig) != 0)
            die("signed prekey signature in registration is invalid");
    }

    /* pair-device with two refs */
    static const uint8_t ref1[] = "2@REFONE+abc/xyz==";
    static const uint8_t ref2[] = "2@REFTWO+def/uvw==";
    wa_node refs[2] = {
        {"ref", NULL, 0, NULL, 0, ref1, sizeof ref1 - 1, WA_CONTENT_BYTES},
        {"ref", NULL, 0, NULL, 0, ref2, sizeof ref2 - 1, WA_CONTENT_BYTES},
    };
    wa_node pd = {"pair-device", NULL, 0, refs, 2, NULL, 0, WA_CONTENT_CHILDREN};
    wa_attr pda[] = {WA_ATTR_JID("from", "s.whatsapp.net"), WA_ATTR("id", "pd1"),
                     WA_ATTR("type", "set"), WA_ATTR("xmlns", "md")};
    wa_node pdiq = {"iq", pda, 4, &pd, 1, NULL, 0, WA_CONTENT_CHILDREN};
    send_node(c, &pdiq);
    wa_node *ack = expect_node(c, "iq", NULL);
    if (strcmp(wa_node_attr(ack, "id"), "pd1") != 0 ||
        strcmp(wa_node_attr(ack, "type"), "result") != 0)
        die("pair-device not acknowledged");

    /* "scan" the QR code */
    char qr[1024];
    size_t qn = 0;
    while (qn < sizeof qr - 1) {
        if (read(g_qr_pipe[0], qr + qn, 1) != 1)
            die("qr pipe");
        if (qr[qn] == '\n')
            break;
        qn++;
    }
    qr[qn] = '\0';
    const char *prefix = "https://wa.me/settings/linked_devices#";
    if (strncmp(qr, prefix, strlen(prefix)) != 0)
        die("QR payload has no link prefix: %s", qr);
    char *f[5];
    char *p = qr + strlen(prefix);
    for (int i = 0; i < 5; i++) {
        f[i] = p;
        p = strchr(p, ',');
        if (p != NULL)
            *p++ = '\0';
        else if (i < 4)
            die("QR payload has too few fields");
    }
    if (strcmp(f[0], (const char *)ref1) != 0 || strcmp(f[4], "9") != 0)
        die("unexpected QR ref/client type");
    uint8_t qr_ident[64], adv[64];
    if (base64_decode(f[2], strlen(f[2]), qr_ident, sizeof qr_ident) != 32 ||
        memcmp(qr_ident, client_ident, 32) != 0)
        die("QR identity key mismatch");
    if (base64_decode(f[3], strlen(f[3]), adv, sizeof adv) != 32)
        die("bad adv secret");

    /* pair-success */
    wa_keypair account;
    curve25519_keypair(account.priv, account.pub);
    uint8_t details[64], sidi[512], container[700], acc_sig[64];
    zbuf b;
    zbuf_init(&b, details, sizeof details);
    pb_put_uint(&b, 1, 1234);
    pb_put_uint(&b, 2, (uint64_t)plat_time_unix());
    pb_put_uint(&b, 3, 7); /* keyIndex */
    size_t dlen = b.len;
    zc_iov sv[3] = {{"\x06\x00", 2}, {details, dlen}, {client_ident, 32}};
    xeddsa_sign_v(acc_sig, account.priv, sv, 3);
    zbuf_init(&b, sidi, sizeof sidi);
    pb_put_bytes(&b, 1, details, dlen);
    pb_put_bytes(&b, 2, account.pub, 32);
    pb_put_bytes(&b, 3, acc_sig, 64);
    size_t sidil = b.len;
    uint8_t hmac[32];
    crypto_hmac_sha256(adv, 32, sidi, sidil, hmac);
    zbuf_init(&b, container, sizeof container);
    pb_put_bytes(&b, 1, sidi, sidil);
    pb_put_bytes(&b, 2, hmac, 32);
    size_t contl = b.len;

    wa_attr deva[] = {WA_ATTR_JID("jid", CLIENT_JID), WA_ATTR_JID("lid", "777:5@lid")};
    wa_attr plat[] = {WA_ATTR("name", "android")};
    wa_node ps_kids[3] = {
        {"device-identity", NULL, 0, NULL, 0, container, contl, WA_CONTENT_BYTES},
        {"device", deva, 2, NULL, 0, NULL, 0, WA_CONTENT_NONE},
        {"platform", plat, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE},
    };
    wa_node ps = {"pair-success", NULL, 0, ps_kids, 3, NULL, 0, WA_CONTENT_CHILDREN};
    char tbuf[24];
    snprintf(tbuf, sizeof tbuf, "%lld", (long long)plat_time_unix());
    wa_attr psa[] = {WA_ATTR_JID("from", "s.whatsapp.net"), WA_ATTR("id", "ps1"),
                     WA_ATTR("type", "set"), WA_ATTR("t", tbuf)};
    wa_node psiq = {"iq", psa, 4, &ps, 1, NULL, 0, WA_CONTENT_CHILDREN};
    send_node(c, &psiq);

    wa_node *sign = expect_node(c, "iq", NULL);
    const wa_node *di = wa_node_path(sign, "pair-device-sign", "device-identity", NULL);
    if (di == NULL || di->content != WA_CONTENT_BYTES)
        die("missing pair-device-sign");
    if (strcmp(wa_node_attr(di, "key-index"), "7") != 0)
        die("wrong key-index");
    const uint8_t *d1, *s3, *s4, *k2;
    size_t d1l, s3l, s4l, k2l;
    if (pb_find_bytes(di->data, di->data_len, 1, &d1, &d1l) != 1 ||
        pb_find_bytes(di->data, di->data_len, 3, &s3, &s3l) != 1 ||
        pb_find_bytes(di->data, di->data_len, 4, &s4, &s4l) != 1 || s4l != 64)
        die("bad signed device identity");
    if (pb_find_bytes(di->data, di->data_len, 2, &k2, &k2l) == 1)
        die("account signature key must be stripped");
    zc_iov dv[4] = {{"\x06\x01", 2}, {d1, d1l}, {client_ident, 32}, {account.pub, 32}};
    if (xeddsa_verify_v(client_ident, dv, 4, s4) != 0)
        die("device signature invalid");

    wa_attr sea[] = {WA_ATTR("code", "515")};
    wa_node se = {"stream:error", sea, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    send_node(c, &se);
    srv_close(c);
    fprintf(stderr, "  [server] pairing ok\n");

    /* ---------------- connection 2: login ---------------- */
    pl = srv_accept(c, lfd, payload, sizeof payload);
    uint64_t dev = 0, passive = 0;
    if (pb_find_varint(payload, pl, 1, &user) != 1 || user != 5511999990000ull ||
        pb_find_varint(payload, pl, 18, &dev) != 1 || dev != CLIENT_DEVICE ||
        pb_find_varint(payload, pl, 3, &passive) != 1 || passive != 1)
        die("bad login payload");
    wa_attr sa[] = {WA_ATTR("t", tbuf), WA_ATTR_JID("lid", "777:5@lid")};
    wa_node success = {"success", sa, 2, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    send_node(c, &success);

    wa_node *cnt = expect_node(c, "iq", "encrypt");
    if (wa_node_child(cnt, "count") == NULL)
        die("expected prekey count request");
    wa_attr ca[] = {WA_ATTR("value", "0")};
    wa_node count = {"count", ca, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    send_iq_result(c, cnt, &count, 1);

    sig_bundle bundle;
    memset(&bundle, 0, sizeof bundle);
    for (;;) {
        wa_node *n = expect_node(c, "iq", NULL);
        const char *x = wa_node_attr(n, "xmlns");
        if (x != NULL && strcmp(x, "passive") == 0) {
            send_iq_result(c, n, NULL, 0);
            continue;
        }
        if (x == NULL || strcmp(x, "encrypt") != 0 ||
            strcmp(wa_node_attr(n, "type"), "set") != 0)
            continue;
        /* prekey upload */
        const wa_node *reg = wa_node_child(n, "registration");
        const wa_node *idn = wa_node_child(n, "identity");
        const wa_node *list = wa_node_child(n, "list");
        const wa_node *skey = wa_node_child(n, "skey");
        if (reg == NULL || reg->data_len != 4 || idn == NULL || idn->data_len != 32 ||
            list == NULL || list->child_count < 5 || skey == NULL)
            die("bad prekey upload");
        if (memcmp(idn->data, client_ident, 32) != 0)
            die("upload identity mismatch");
        bundle.registration_id = rd_be32(reg->data);
        memcpy(bundle.identity, idn->data, 32);
        const wa_node *sid = wa_node_child(skey, "id");
        const wa_node *sval = wa_node_child(skey, "value");
        const wa_node *ssig = wa_node_child(skey, "signature");
        bundle.signed_prekey_id = ((uint32_t)sid->data[0] << 16) |
                                  ((uint32_t)sid->data[1] << 8) | sid->data[2];
        memcpy(bundle.signed_prekey, sval->data, 32);
        memcpy(bundle.signed_prekey_sig, ssig->data, 64);
        const wa_node *k0 = &list->children[2];
        const wa_node *kid = wa_node_child(k0, "id");
        bundle.prekey_id = ((uint32_t)kid->data[0] << 16) |
                           ((uint32_t)kid->data[1] << 8) | kid->data[2];
        memcpy(bundle.prekey, wa_node_child(k0, "value")->data, 32);
        send_iq_result(c, n, NULL, 0);
        break;
    }
    fprintf(stderr, "  [server] login + prekey upload ok\n");

    /* Maria opens a session (X3DH as initiator) and sends a pkmsg */
    wa_device maria;
    wa_device_generate(&maria);
    storage_init(addr_dir_maria);
    if (signal_session_from_bundle(&maria, CLIENT_ADDR, &bundle) != 0)
        die("cannot build session from uploaded bundle");
    static uint8_t pt[2048], ct[4096];
    size_t ptl = padded_message(MARIA_TEXT, pt, sizeof pt);
    int pk = 0;
    long ctl = signal_encrypt(&maria, CLIENT_ADDR, pt, ptl, ct, sizeof ct, &pk);
    if (ctl < 0 || !pk)
        die("encrypt for client failed");
    wa_attr ea[] = {WA_ATTR("v", "2"), WA_ATTR("type", "pkmsg")};
    wa_node enc = {"enc", ea, 2, NULL, 0, ct, (size_t)ctl, WA_CONTENT_BYTES};
    wa_attr ma[] = {WA_ATTR_JID("from", MARIA_JID), WA_ATTR("id", "MSG1"),
                    WA_ATTR("t", tbuf), WA_ATTR("type", "text"),
                    WA_ATTR("notify", "Maria")};
    wa_node msg = {"message", ma, 5, &enc, 1, NULL, 0, WA_CONTENT_CHILDREN};
    send_node(c, &msg);

    wa_node *rc = expect_node(c, "receipt", NULL);
    if (strcmp(wa_node_attr(rc, "id"), "MSG1") != 0 ||
        strcmp(wa_node_attr(rc, "to"), MARIA_JID) != 0)
        die("bad receipt for MSG1");
    wa_node *mack = expect_node(c, "ack", NULL);
    if (strcmp(wa_node_attr(mack, "class"), "message") != 0 ||
        strcmp(wa_node_attr(mack, "id"), "MSG1") != 0)
        die("bad ack for MSG1");
    fprintf(stderr, "  [server] client decrypted pkmsg, receipt+ack ok\n");

    /* client reply: usync */
    wa_node *us = expect_node(c, "iq", "usync");
    {
        static wa_attr da0[] = {WA_ATTR("id", "0")};
        static wa_attr da5[] = {WA_ATTR("id", "5")};
        wa_node maria_devs[1] = {{"device", da0, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE}};
        wa_node own_devs[2] = {{"device", da0, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE},
                               {"device", da5, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE}};
        wa_node mdl = {"device-list", NULL, 0, maria_devs, 1, NULL, 0, WA_CONTENT_CHILDREN};
        wa_node odl = {"device-list", NULL, 0, own_devs, 2, NULL, 0, WA_CONTENT_CHILDREN};
        wa_node mdv = {"devices", NULL, 0, &mdl, 1, NULL, 0, WA_CONTENT_CHILDREN};
        wa_node odv = {"devices", NULL, 0, &odl, 1, NULL, 0, WA_CONTENT_CHILDREN};
        wa_attr mu[] = {WA_ATTR_JID("jid", MARIA_JID)};
        wa_attr ou[] = {WA_ATTR_JID("jid", PHONE_USER "@s.whatsapp.net")};
        wa_node users[2] = {{"user", mu, 1, &mdv, 1, NULL, 0, WA_CONTENT_CHILDREN},
                            {"user", ou, 1, &odv, 1, NULL, 0, WA_CONTENT_CHILDREN}};
        wa_node list = {"list", NULL, 0, users, 2, NULL, 0, WA_CONTENT_CHILDREN};
        wa_node usync = {"usync", NULL, 0, &list, 1, NULL, 0, WA_CONTENT_CHILDREN};
        send_iq_result(c, us, &usync, 1);
    }

    /* prekey fetch for the account's phone (device 0) */
    wa_device phone;
    wa_device_generate(&phone);
    phone.identity_key = account;
    wa_sign_prekey(&phone.identity_key, phone.signed_prekey.pub,
                   phone.signed_prekey_sig);
    wa_keypair otk;
    curve25519_keypair(otk.priv, otk.pub);
    storage_init(addr_dir_phone);
    prekeys_append(42, otk.priv);

    wa_node *pf = expect_node(c, "iq", "encrypt");
    const wa_node *keyreq = wa_node_child(pf, "key");
    if (keyreq == NULL || keyreq->child_count != 1 ||
        strcmp(wa_node_attr(&keyreq->children[0], "jid"),
               PHONE_USER "@s.whatsapp.net") != 0)
        die("unexpected prekey request");
    {
        uint8_t reg[4], spid[3] = {0, 0, 1}, pid[3] = {0, 0, 42}, type = 5;
        wr_be32(reg, phone.registration_id);
        wa_node sk[3] = {
            {"id", NULL, 0, NULL, 0, spid, 3, WA_CONTENT_BYTES},
            {"value", NULL, 0, NULL, 0, phone.signed_prekey.pub, 32, WA_CONTENT_BYTES},
            {"signature", NULL, 0, NULL, 0, phone.signed_prekey_sig, 64, WA_CONTENT_BYTES},
        };
        wa_node kk[2] = {
            {"id", NULL, 0, NULL, 0, pid, 3, WA_CONTENT_BYTES},
            {"value", NULL, 0, NULL, 0, otk.pub, 32, WA_CONTENT_BYTES},
        };
        wa_node ukids[5] = {
            {"registration", NULL, 0, NULL, 0, reg, 4, WA_CONTENT_BYTES},
            {"type", NULL, 0, NULL, 0, &type, 1, WA_CONTENT_BYTES},
            {"identity", NULL, 0, NULL, 0, phone.identity_key.pub, 32, WA_CONTENT_BYTES},
            {"skey", NULL, 0, sk, 3, NULL, 0, WA_CONTENT_CHILDREN},
            {"key", NULL, 0, kk, 2, NULL, 0, WA_CONTENT_CHILDREN},
        };
        wa_attr ua[] = {WA_ATTR_JID("jid", PHONE_USER "@s.whatsapp.net")};
        wa_node u = {"user", ua, 1, ukids, 5, NULL, 0, WA_CONTENT_CHILDREN};
        wa_node list = {"list", NULL, 0, &u, 1, NULL, 0, WA_CONTENT_CHILDREN};
        send_iq_result(c, pf, &list, 1);
    }

    /* the message itself */
    wa_node *out = expect_node(c, "message", NULL);
    char out_id[64];
    zstrlcpy(out_id, wa_node_attr(out, "id"), sizeof out_id);
    if (strcmp(wa_node_attr(out, "to"), MARIA_JID) != 0 ||
        strncmp(out_id, "3EB0", 4) != 0)
        die("bad outgoing message attributes");
    const wa_node *parts = wa_node_child(out, "participants");
    if (parts == NULL || parts->child_count != 2)
        die("expected 2 participants");
    if (wa_node_child(out, "device-identity") == NULL)
        die("pkmsg without device-identity");
    int got_maria = 0, got_phone = 0;
    for (size_t i = 0; i < parts->child_count; i++) {
        const wa_node *to = &parts->children[i];
        const char *jid = wa_node_attr(to, "jid");
        const wa_node *e = wa_node_child(to, "enc");
        const char *type = wa_node_attr(e, "type");
        static uint8_t plain[4096];
        long n;
        if (strcmp(jid, MARIA_JID) == 0) {
            if (strcmp(type, "msg") != 0)
                die("expected msg for Maria, got %s", type);
            storage_init(addr_dir_maria);
            n = signal_decrypt(&maria, CLIENT_ADDR, 0, e->data, e->data_len,
                               plain, sizeof plain);
            if (n < 0)
                die("Maria cannot decrypt the reply");
            n = wa_unpad_message(plain, (size_t)n);
            const uint8_t *txt;
            size_t tl;
            if (pb_find_bytes(plain, (size_t)n, 1, &txt, &tl) != 1 ||
                tl != strlen(REPLY_TEXT) || memcmp(txt, REPLY_TEXT, tl) != 0)
                die("reply text mismatch");
            got_maria = 1;
        } else if (strcmp(jid, PHONE_USER "@s.whatsapp.net") == 0) {
            if (strcmp(type, "pkmsg") != 0)
                die("expected pkmsg for phone, got %s", type);
            storage_init(addr_dir_phone);
            n = signal_decrypt(&phone, CLIENT_ADDR, 1, e->data, e->data_len,
                               plain, sizeof plain);
            if (n < 0)
                die("phone cannot decrypt the DSM");
            n = wa_unpad_message(plain, (size_t)n);
            const uint8_t *dsm, *dest, *inner, *txt;
            size_t dl2, destl, innerl, tl;
            if (pb_find_bytes(plain, (size_t)n, 31, &dsm, &dl2) != 1 ||
                pb_find_bytes(dsm, dl2, 1, &dest, &destl) != 1 ||
                pb_find_bytes(dsm, dl2, 2, &inner, &innerl) != 1 ||
                pb_find_bytes(inner, innerl, 1, &txt, &tl) != 1)
                die("bad device sent message");
            if (destl != strlen(MARIA_JID) || memcmp(dest, MARIA_JID, destl) != 0 ||
                tl != strlen(REPLY_TEXT) || memcmp(txt, REPLY_TEXT, tl) != 0)
                die("DSM content mismatch");
            got_phone = 1;
        }
    }
    if (!got_maria || !got_phone)
        die("missing participant");
    fprintf(stderr, "  [server] reply decrypted by Maria and by the phone\n");

    wa_attr aa[] = {WA_ATTR("class", "message"), WA_ATTR("id", out_id),
                    WA_ATTR_JID("from", MARIA_JID), WA_ATTR("t", tbuf)};
    wa_node sack = {"ack", aa, 4, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    send_node(c, &sack);
    wa_attr ra[] = {WA_ATTR_JID("from", MARIA_JID), WA_ATTR("id", out_id),
                    WA_ATTR("t", tbuf)};
    wa_node rcpt = {"receipt", ra, 3, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    send_node(c, &rcpt);
    wa_node *rack = expect_node(c, "ack", NULL);
    if (strcmp(wa_node_attr(rack, "class"), "receipt") != 0)
        die("receipt not acknowledged");

    /* ---------------- group: client -> group ---------------- */
    wa_node *gq = expect_node(c, "iq", "w:g2");
    if (strcmp(wa_node_attr(gq, "to"), GROUP_JID) != 0 ||
        wa_node_child(gq, "query") == NULL)
        die("bad group info query");
    {
        wa_attr p1[] = {WA_ATTR_JID("jid", MARIA_JID)};
        wa_attr p2[] = {WA_ATTR_JID("jid", PHONE_USER "@s.whatsapp.net"),
                        WA_ATTR("type", "admin")};
        wa_node parts2[2] = {{"participant", p1, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE},
                             {"participant", p2, 2, NULL, 0, NULL, 0, WA_CONTENT_NONE}};
        wa_attr ga[] = {WA_ATTR("id", "120363001"), WA_ATTR("subject", "Familia"),
                        WA_ATTR("addressing_mode", "pn")};
        wa_node group = {"group", ga, 3, parts2, 2, NULL, 0, WA_CONTENT_CHILDREN};
        char gid[64];
        zstrlcpy(gid, wa_node_attr(gq, "id"), sizeof gid);
        wa_attr ra2[] = {WA_ATTR_JID("from", GROUP_JID), WA_ATTR("id", gid),
                         WA_ATTR("type", "result")};
        wa_node res = {"iq", ra2, 3, &group, 1, NULL, 0, WA_CONTENT_CHILDREN};
        send_node(c, &res);
    }
    us = expect_node(c, "iq", "usync");
    {
        const wa_node *ul = wa_node_path(us, "usync", "list", NULL);
        if (ul == NULL || ul->child_count != 2)
            die("group usync should list 2 users");
        static wa_attr da0[] = {WA_ATTR("id", "0")};
        static wa_attr da5[] = {WA_ATTR("id", "5")};
        wa_node maria_devs[1] = {{"device", da0, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE}};
        wa_node own_devs[2] = {{"device", da0, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE},
                               {"device", da5, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE}};
        wa_node mdl = {"device-list", NULL, 0, maria_devs, 1, NULL, 0, WA_CONTENT_CHILDREN};
        wa_node odl = {"device-list", NULL, 0, own_devs, 2, NULL, 0, WA_CONTENT_CHILDREN};
        wa_node mdv = {"devices", NULL, 0, &mdl, 1, NULL, 0, WA_CONTENT_CHILDREN};
        wa_node odv = {"devices", NULL, 0, &odl, 1, NULL, 0, WA_CONTENT_CHILDREN};
        wa_attr mu[] = {WA_ATTR_JID("jid", MARIA_JID)};
        wa_attr ou[] = {WA_ATTR_JID("jid", PHONE_USER "@s.whatsapp.net")};
        wa_node users[2] = {{"user", mu, 1, &mdv, 1, NULL, 0, WA_CONTENT_CHILDREN},
                            {"user", ou, 1, &odv, 1, NULL, 0, WA_CONTENT_CHILDREN}};
        wa_node list = {"list", NULL, 0, users, 2, NULL, 0, WA_CONTENT_CHILDREN};
        wa_node usync = {"usync", NULL, 0, &list, 1, NULL, 0, WA_CONTENT_CHILDREN};
        send_iq_result(c, us, &usync, 1);
    }
    wa_node *gm = expect_node(c, "message", NULL);
    char gm_id[64];
    zstrlcpy(gm_id, wa_node_attr(gm, "id"), sizeof gm_id);
    const char *ph = wa_node_attr(gm, "phash");
    if (strcmp(wa_node_attr(gm, "to"), GROUP_JID) != 0 || ph == NULL ||
        strncmp(ph, "2:", 2) != 0 || strlen(ph) != 10)
        die("bad group message attributes");
    const wa_node *gparts = wa_node_child(gm, "participants");
    const wa_node *skenc = NULL;
    for (size_t i = 0; i < gm->child_count; i++)
        if (strcmp(gm->children[i].tag, "enc") == 0)
            skenc = &gm->children[i];
    if (gparts == NULL || gparts->child_count != 2 || skenc == NULL ||
        strcmp(wa_node_attr(skenc, "type"), "skmsg") != 0)
        die("group message structure");
    static uint8_t skbuf[4096];
    size_t sklen = skenc->data_len;
    memcpy(skbuf, skenc->data, sklen);
    int skdm_seen = 0;
    for (size_t i = 0; i < gparts->child_count; i++) {
        const wa_node *to = &gparts->children[i];
        const char *jid = wa_node_attr(to, "jid");
        const wa_node *e = wa_node_child(to, "enc");
        static uint8_t plain[4096];
        long n;
        int is_maria = strcmp(jid, MARIA_JID) == 0;
        storage_init(is_maria ? addr_dir_maria : addr_dir_phone);
        n = signal_decrypt(is_maria ? &maria : &phone, CLIENT_ADDR,
                           strcmp(wa_node_attr(e, "type"), "pkmsg") == 0,
                           e->data, e->data_len, plain, sizeof plain);
        if (n < 0)
            die("cannot decrypt SKDM envelope for %s", jid);
        n = wa_unpad_message(plain, (size_t)n);
        const uint8_t *skd, *gidp, *ax;
        size_t skdl, gidl, axl;
        if (pb_find_bytes(plain, (size_t)n, 2, &skd, &skdl) != 1 ||
            pb_find_bytes(skd, skdl, 1, &gidp, &gidl) != 1 ||
            pb_find_bytes(skd, skdl, 2, &ax, &axl) != 1 ||
            gidl != strlen(GROUP_JID) || memcmp(gidp, GROUP_JID, gidl) != 0)
            die("bad SKDM message");
        if (is_maria) {
            if (senderkey_process(GROUP_JID, CLIENT_ADDR, ax, axl) != 0)
                die("Maria cannot process SKDM");
            long gn = senderkey_decrypt(GROUP_JID, CLIENT_ADDR, skbuf, sklen,
                                        plain, sizeof plain);
            if (gn < 0)
                die("Maria cannot decrypt skmsg");
            gn = wa_unpad_message(plain, (size_t)gn);
            const uint8_t *txt;
            size_t tl;
            if (pb_find_bytes(plain, (size_t)gn, 1, &txt, &tl) != 1 ||
                tl != strlen(GROUP_TEXT) || memcmp(txt, GROUP_TEXT, tl) != 0)
                die("group text mismatch");
            skdm_seen = 1;
        }
    }
    if (!skdm_seen)
        die("Maria never got the group message");
    fprintf(stderr, "  [server] group message decrypted via sender key\n");
    {
        wa_attr ga2[] = {WA_ATTR("class", "message"), WA_ATTR("id", gm_id),
                         WA_ATTR_JID("from", GROUP_JID), WA_ATTR("t", tbuf)};
        wa_node gack = {"ack", ga2, 4, NULL, 0, NULL, 0, WA_CONTENT_NONE};
        send_node(c, &gack);
        wa_attr gr[] = {WA_ATTR_JID("from", GROUP_JID), WA_ATTR("id", gm_id),
                        WA_ATTR_JID("participant", MARIA_JID), WA_ATTR("t", tbuf)};
        wa_node grc = {"receipt", gr, 4, NULL, 0, NULL, 0, WA_CONTENT_NONE};
        send_node(c, &grc);
        expect_node(c, "ack", NULL);
    }

    /* ---------------- group: Maria -> group ---------------- */
    {
        static uint8_t dist[256], skd_msg[512], pad2[1024], env[2048], gsk[2048];
        storage_init(addr_dir_maria);
        long dl = senderkey_distribution(GROUP_JID, MARIA_ADDR, dist, sizeof dist);
        zbuf zb;
        zbuf_init(&zb, skd_msg, sizeof skd_msg);
        size_t mk = pb_begin(&zb, 2);
        pb_put_string(&zb, 1, GROUP_JID);
        pb_put_bytes(&zb, 2, dist, (size_t)dl);
        pb_end(&zb, mk);
        memcpy(pad2, skd_msg, zb.len);
        size_t p2 = wa_pad_message(pad2, zb.len, sizeof pad2);
        int pk2 = 0;
        long envl = signal_encrypt(&maria, CLIENT_ADDR, pad2, p2, env, sizeof env, &pk2);
        size_t gl = padded_message(GROUP_IN_TEXT, pad2, sizeof pad2);
        long gskl = senderkey_encrypt(GROUP_JID, MARIA_ADDR, pad2, gl, gsk, sizeof gsk);
        if (dl < 0 || envl < 0 || gskl < 0)
            die("cannot build incoming group message");
        wa_attr e1[] = {WA_ATTR("v", "2"), WA_ATTR("type", pk2 ? "pkmsg" : "msg")};
        wa_attr e2[] = {WA_ATTR("v", "2"), WA_ATTR("type", "skmsg")};
        wa_node encs2[2] = {{"enc", e1, 2, NULL, 0, env, (size_t)envl, WA_CONTENT_BYTES},
                            {"enc", e2, 2, NULL, 0, gsk, (size_t)gskl, WA_CONTENT_BYTES}};
        wa_attr ma2[] = {WA_ATTR_JID("from", GROUP_JID), WA_ATTR("id", "GMSG1"),
                         WA_ATTR_JID("participant", MARIA_JID), WA_ATTR("t", tbuf),
                         WA_ATTR("type", "text"), WA_ATTR("notify", "Maria")};
        wa_node gmsg = {"message", ma2, 6, encs2, 2, NULL, 0, WA_CONTENT_CHILDREN};
        send_node(c, &gmsg);
        wa_node *grr = expect_node(c, "receipt", NULL);
        if (strcmp(wa_node_attr(grr, "id"), "GMSG1") != 0 ||
            wa_node_attr(grr, "participant") == NULL ||
            strcmp(wa_node_attr(grr, "participant"), MARIA_JID) != 0)
            die("bad receipt for group message");
        expect_node(c, "ack", NULL);
        fprintf(stderr, "  [server] client decrypted incoming group message\n");
    }

    /* stay until the client hangs up */
    uint8_t tmp[16];
    while (SSL_read(c->ssl, tmp, sizeof tmp) > 0) {
    }
    srv_close(c);
    return 0;
}

/* ======================================================================== */
/* client side                                                              */
/* ======================================================================== */

typedef struct {
    int qr_count;
    int paired;
    int logged_in_count;
    int got_message;
    char msg_text[256];
    char msg_from[64];
    char push[64];
    char sent_id[64];
    int sent_acked;
    int delivered;
    char group_id[64];
    int group_delivered;
    int group_msg;
    char group_text[256];
    char group_sender[64];
    char chat_name[64];
} client_obs;

static client_obs g_obs;

static void ev_state(void *u, wa_state st, const char *d)
{
    (void)u;
    (void)d;
    if (st == WA_ST_LOGGED_IN)
        g_obs.logged_in_count++;
}

static void ev_qr(void *u, const char *payload)
{
    (void)u;
    g_obs.qr_count++;
    if (g_obs.qr_count == 1) {
        ssize_t w = write(g_qr_pipe[1], payload, strlen(payload));
        w += write(g_qr_pipe[1], "\n", 1);
        (void)w;
    }
}

static void ev_paired(void *u, const wa_jid *j, const char *p)
{
    (void)u;
    (void)p;
    char s[WA_JID_STR_MAX];
    jid_format(j, s, sizeof s);
    if (strcmp(s, CLIENT_JID) == 0)
        g_obs.paired = 1;
}

static void ev_message(void *u, const wa_message *m)
{
    (void)u;
    if (jid_is_group(&m->chat)) {
        g_obs.group_msg++;
        zstrlcpy(g_obs.group_text, m->text, sizeof g_obs.group_text);
        jid_format(&m->sender, g_obs.group_sender, sizeof g_obs.group_sender);
        return;
    }
    g_obs.got_message++;
    zstrlcpy(g_obs.msg_text, m->text, sizeof g_obs.msg_text);
    jid_format(&m->chat, g_obs.msg_from, sizeof g_obs.msg_from);
    zstrlcpy(g_obs.push, m->push_name, sizeof g_obs.push);
}

static void ev_receipt(void *u, const wa_jid *chat, const char *id,
                       const char *type)
{
    (void)u;
    (void)chat;
    if (strcmp(id, g_obs.group_id) == 0 && strcmp(type, "delivered") == 0)
        g_obs.group_delivered = 1;
    if (strcmp(id, g_obs.sent_id) != 0)
        return;
    if (strcmp(type, "sent") == 0)
        g_obs.sent_acked = 1;
    if (strcmp(type, "delivered") == 0)
        g_obs.delivered = 1;
}

static void ev_chat_name(void *u, const wa_jid *chat, const char *name)
{
    (void)u;
    if (jid_is_group(chat))
        zstrlcpy(g_obs.chat_name, name, sizeof g_obs.chat_name);
}

static wa_client g_client;

static void test_end_to_end(void)
{
    snprintf(g_dir, sizeof g_dir, "/tmp/zapc-it-%d", (int)getpid());
    char cert_path[300], client_dir[300];
    snprintf(cert_path, sizeof cert_path, "%s/cert.pem", g_dir);
    snprintf(client_dir, sizeof client_dir, "%s/client", g_dir);
    CHECK(plat_mkdir_p(g_dir, 0700) == 0);
    CHECK(make_tls_cert(cert_path) == 0);
    curve25519_keypair(g_root.priv, g_root.pub);
    curve25519_keypair(g_inter.priv, g_inter.pub);
    curve25519_keypair(g_server_static.priv, g_server_static.pub);
    CHECK(pipe(g_qr_pipe) == 0);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(lfd, (struct sockaddr *)&sa, sizeof sa) == 0);
    CHECK(listen(lfd, 4) == 0);
    socklen_t sl = sizeof sa;
    getsockname(lfd, (struct sockaddr *)&sa, &sl);
    unsigned port = ntohs(sa.sin_port);

    pid_t pid = fork();
    if (pid == 0) {
        log_set_level(LOG_ERROR);
        _exit(run_server(lfd));
    }
    close(lfd);

    log_set_level(LOG_WARN);
    log_set_stderr(1);
    zapc_config cfg;
    config_defaults(&cfg);
    snprintf(cfg.wa_host, sizeof cfg.wa_host, "localhost");
    cfg.wa_port = (uint16_t)port;
    snprintf(cfg.ca_file, sizeof cfg.ca_file, "%s", cert_path);
    snprintf(cfg.state_dir, sizeof cfg.state_dir, "%s", client_dir);
    CHECK(storage_init(client_dir) == 0);
    wa_set_noise_root_key(g_root.pub);

    wa_events ev = {NULL, ev_state, ev_qr, ev_paired, NULL, ev_message,
                    ev_receipt, ev_chat_name};
    CHECK(wa_client_init(&g_client, &cfg, &ev) == 0);
    CHECK(wa_client_connect(&g_client) == 0);

    uint64_t deadline = plat_now_ms() + 30000;
    int sent = 0, group_sent = 0;
    while (plat_now_ms() < deadline && !(g_obs.group_delivered && g_obs.group_msg)) {
        struct pollfd p = {wa_client_fd(&g_client), POLLIN, 0};
        int t = wa_client_next_timeout(&g_client);
        if (t < 0 || t > 200)
            t = 200;
        if (p.fd >= 0)
            poll(&p, 1, t);
        else
            poll(NULL, 0, t);
        if (p.fd >= 0 && (p.revents & (POLLIN | POLLHUP | POLLERR)))
            wa_client_on_readable(&g_client);
        wa_client_tick(&g_client);
        if (g_obs.got_message && !sent) {
            wa_jid to;
            jid_parse(&to, MARIA_JID);
            CHECK(wa_send_text(&g_client, &to, REPLY_TEXT, g_obs.sent_id,
                               sizeof g_obs.sent_id) == 0);
            sent = 1;
        }
        if (g_obs.delivered && !group_sent) {
            wa_jid g;
            jid_parse(&g, GROUP_JID);
            CHECK(wa_send_text(&g_client, &g, GROUP_TEXT, g_obs.group_id,
                               sizeof g_obs.group_id) == 0);
            group_sent = 1;
        }
    }
    CHECK(g_obs.qr_count >= 1);
    CHECK(g_obs.paired);
    CHECK(g_client.dev.paired);
    CHECK(g_obs.logged_in_count == 1);
    CHECK(g_obs.got_message == 1);
    CHECK_STR(g_obs.msg_text, MARIA_TEXT);
    CHECK_STR(g_obs.msg_from, MARIA_JID);
    CHECK_STR(g_obs.push, "Maria");
    CHECK(g_obs.sent_acked);
    CHECK(g_obs.delivered);
    CHECK(prekeys_count() > 0);
    CHECK(g_obs.group_delivered);
    CHECK(g_obs.group_msg == 1);
    CHECK_STR(g_obs.group_text, GROUP_IN_TEXT);
    CHECK_STR(g_obs.group_sender, MARIA_JID);
    CHECK_STR(g_obs.chat_name, "Familia");

    /* credentials persisted: a fresh load sees the pairing */
    wa_device d;
    CHECK(credentials_load(&d) == 0);
    CHECK(d.paired && d.jid.device == CLIENT_DEVICE);
    CHECK(d.account_len > 0);
    CHECK_STR(d.jid.user, PHONE_USER);
    CHECK_STR(d.lid.user, "777");

    wa_client_free(&g_client);
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    char cmd[700];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0)
        fprintf(stderr, "  (could not remove %s)\n", g_dir);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    RUN(test_end_to_end);
    return test_done("test_integration");
}
