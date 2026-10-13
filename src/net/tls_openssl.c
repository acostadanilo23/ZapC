/*
 * ZapC - TLS backend using OpenSSL (development / desktop builds).
 */
#include "zapc/tls.h"
#include "zapc/log.h"
#include "zapc/memory.h"
#include "zapc/platform.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string.h>

struct zc_tls {
    SSL_CTX *ctx;
    SSL *ssl;
    int fd;
};

zc_tls *tls_new(void)
{
    zc_tls *t = zap_calloc(1, sizeof *t);
    if (t != NULL)
        t->fd = -1;
    return t;
}

static void log_ssl_errors(const char *what)
{
    unsigned long e;
    char buf[200];
    int any = 0;
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof buf);
        LOGE("tls", "%s: %s", what, buf);
        any = 1;
    }
    if (!any)
        LOGE("tls", "%s failed", what);
}

void tls_close(zc_tls *t)
{
    if (t == NULL || t->ssl == NULL)
        return;
    (void)SSL_shutdown(t->ssl);
    SSL_free(t->ssl);
    t->ssl = NULL;
    t->fd = -1;
}

void tls_free(zc_tls *t)
{
    if (t == NULL)
        return;
    tls_close(t);
    if (t->ctx != NULL)
        SSL_CTX_free(t->ctx);
    zap_free(t);
}

int tls_connect(zc_tls *t, int fd, const char *host, const char *ca_file,
                int timeout_ms)
{
    tls_close(t);
    if (t->ctx == NULL) {
        t->ctx = SSL_CTX_new(TLS_client_method());
        if (t->ctx == NULL) {
            log_ssl_errors("SSL_CTX_new");
            return -1;
        }
        SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, NULL);
        /* Keep OpenSSL's own buffers small. */
        SSL_CTX_set_mode(t->ctx, SSL_MODE_RELEASE_BUFFERS);
        if (SSL_CTX_set_default_verify_paths(t->ctx) != 1)
            LOGW("tls", "could not load default CA paths");
        if (ca_file != NULL && ca_file[0] != '\0' &&
            SSL_CTX_load_verify_locations(t->ctx, ca_file, NULL) != 1) {
            log_ssl_errors("load CA file");
            return -1;
        }
    }
    t->ssl = SSL_new(t->ctx);
    if (t->ssl == NULL) {
        log_ssl_errors("SSL_new");
        return -1;
    }
    t->fd = fd;
    SSL_set_fd(t->ssl, fd);
    SSL_set_tlsext_host_name(t->ssl, host); /* SNI */
    if (SSL_set1_host(t->ssl, host) != 1) { /* hostname verification */
        log_ssl_errors("SSL_set1_host");
        return -1;
    }

    uint64_t deadline = plat_now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        int r = SSL_connect(t->ssl);
        if (r == 1)
            break;
        int err = SSL_get_error(t->ssl, r);
        uint64_t now = plat_now_ms();
        if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
            now < deadline) {
            if (tcp_wait(fd, err == SSL_ERROR_WANT_READ ? 1 : 2,
                         (int)(deadline - now)) == 1)
                continue;
        }
        long vr = SSL_get_verify_result(t->ssl);
        if (vr != X509_V_OK)
            LOGE("tls", "certificate verification failed: %s",
                 X509_verify_cert_error_string(vr));
        log_ssl_errors("TLS handshake");
        tls_close(t);
        return -1;
    }
    LOGI("tls", "%s %s", SSL_get_version(t->ssl), SSL_get_cipher(t->ssl));
    return 0;
}

long tls_read(zc_tls *t, void *buf, size_t len)
{
    if (t->ssl == NULL)
        return ZC_IO_ERROR;
    if (len > INT32_MAX)
        len = INT32_MAX;
    int r = SSL_read(t->ssl, buf, (int)len);
    if (r > 0)
        return r;
    int err = SSL_get_error(t->ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return ZC_IO_AGAIN;
    if (err == SSL_ERROR_ZERO_RETURN)
        return 0;
    log_ssl_errors("SSL_read");
    return ZC_IO_ERROR;
}

long tls_write(zc_tls *t, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t left = len;
    if (t->ssl == NULL)
        return ZC_IO_ERROR;
    while (left > 0) {
        int chunk = left > 16384 ? 16384 : (int)left;
        int r = SSL_write(t->ssl, p, chunk);
        if (r > 0) {
            p += r;
            left -= (size_t)r;
            continue;
        }
        int err = SSL_get_error(t->ssl, r);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            if (tcp_wait(t->fd, err == SSL_ERROR_WANT_READ ? 1 : 2, 30000) != 1)
                return ZC_IO_ERROR;
            continue;
        }
        log_ssl_errors("SSL_write");
        return ZC_IO_ERROR;
    }
    return (long)len;
}

size_t tls_pending(zc_tls *t)
{
    if (t->ssl == NULL)
        return 0;
    int p = SSL_pending(t->ssl);
    return p > 0 ? (size_t)p : 0;
}

const char *tls_version(zc_tls *t)
{
    return t->ssl != NULL ? SSL_get_version(t->ssl) : "-";
}

const char *tls_cipher(zc_tls *t)
{
    return t->ssl != NULL ? SSL_get_cipher(t->ssl) : "-";
}

static long rd(void *ctx, void *buf, size_t len) { return tls_read(ctx, buf, len); }
static long wr(void *ctx, const void *buf, size_t len)
{
    return tls_write(ctx, buf, len);
}
static size_t pend(void *ctx) { return tls_pending(ctx); }

zc_stream tls_stream(zc_tls *t)
{
    zc_stream s;
    s.ctx = t;
    s.fd = t->fd;
    s.read = rd;
    s.write = wr;
    s.pending = pend;
    return s;
}
