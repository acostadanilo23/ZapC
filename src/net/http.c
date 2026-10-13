#include "zapc/http.h"
#include "zapc/build_config.h"
#include "zapc/log.h"
#include "zapc/platform.h"
#include "zapc/tls.h"
#include "zapc/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
    zc_tls *tls;
    int fd;
    uint64_t deadline;
    uint8_t buf[ZAPC_NET_RX_SIZE];
    size_t len;
    size_t pos;
    int eof;
} http_conn;

static int fill(http_conn *h)
{
    if (h->pos < h->len)
        return 0;
    if (h->eof)
        return -1;
    for (;;) {
        long r = tls_read(h->tls, h->buf, sizeof h->buf);
        if (r > 0) {
            h->len = (size_t)r;
            h->pos = 0;
            return 0;
        }
        if (r == 0) {
            h->eof = 1;
            return -1;
        }
        if (r != ZC_IO_AGAIN)
            return -1;
        uint64_t now = plat_now_ms();
        if (now >= h->deadline || tcp_wait(h->fd, 1, (int)(h->deadline - now)) != 1)
            return -1;
    }
}

/* Read one CRLF-terminated line (without the CRLF). */
static int read_line(http_conn *h, char *out, size_t cap)
{
    size_t n = 0;
    for (;;) {
        if (fill(h) != 0)
            return -1;
        char c = (char)h->buf[h->pos++];
        if (c == '\n') {
            if (n > 0 && out[n - 1] == '\r')
                n--;
            out[n] = '\0';
            return 0;
        }
        if (n + 1 >= cap)
            return -1; /* line too long */
        out[n++] = c;
    }
}

/* Stream exactly `len` bytes (or until EOF when len == UINT64_MAX). */
static int stream_body(http_conn *h, uint64_t len, uint64_t *total,
                       uint64_t max_body, http_body_fn cb, void *user)
{
    while (len > 0) {
        if (fill(h) != 0)
            return len == UINT64_MAX ? 0 : -1;
        size_t avail = h->len - h->pos;
        size_t take = (uint64_t)avail < len ? avail : (size_t)len;
        *total += take;
        if (max_body != 0 && *total > max_body) {
            LOGW("http", "response larger than %llu bytes",
                 (unsigned long long)max_body);
            return -1;
        }
        if (cb(user, h->buf + h->pos, take) != 0)
            return -1;
        h->pos += take;
        if (len != UINT64_MAX)
            len -= take;
    }
    return 0;
}

int http_get(const char *host, uint16_t port, const char *path,
             const char *ca_file, uint64_t max_body, http_body_fn cb,
             void *user, int timeout_ms)
{
    static http_conn conn;
    http_conn *h = &conn;
    char line[1024];
    int status = -1;

    memset(h, 0, offsetof(http_conn, buf));
    h->deadline = plat_now_ms() + (uint64_t)timeout_ms;
    h->fd = tcp_connect(host, port, timeout_ms);
    if (h->fd < 0)
        return -1;
    h->tls = tls_new();
    if (h->tls == NULL ||
        tls_connect(h->tls, h->fd, host, ca_file, timeout_ms) != 0)
        goto out;

    char req[2048];
    int n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: ZapC\r\n"
                     "Accept: */*\r\n"
                     "Origin: https://web.whatsapp.com\r\n"
                     "Connection: close\r\n\r\n",
                     path, host);
    if (n < 0 || (size_t)n >= sizeof req ||
        tls_write(h->tls, req, (size_t)n) != n)
        goto out;

    if (read_line(h, line, sizeof line) != 0 ||
        sscanf(line, "HTTP/1.%*d %d", &status) != 1) {
        status = -1;
        goto out;
    }
    uint64_t content_length = UINT64_MAX;
    int chunked = 0;
    for (;;) {
        if (read_line(h, line, sizeof line) != 0) {
            status = -1;
            goto out;
        }
        if (line[0] == '\0')
            break;
        if (strncasecmp(line, "Content-Length:", 15) == 0)
            content_length = strtoull(line + 15, NULL, 10);
        else if (strncasecmp(line, "Transfer-Encoding:", 18) == 0 &&
                 strstr(line + 18, "chunked") != NULL)
            chunked = 1;
    }
    if (status != 200) {
        LOGW("http", "GET %s: HTTP %d", host, status);
        goto out;
    }
    uint64_t total = 0;
    if (chunked) {
        for (;;) {
            if (read_line(h, line, sizeof line) != 0) {
                status = -1;
                goto out;
            }
            uint64_t sz = strtoull(line, NULL, 16);
            if (sz == 0)
                break;
            if (stream_body(h, sz, &total, max_body, cb, user) != 0 ||
                read_line(h, line, sizeof line) != 0) {
                status = -1;
                goto out;
            }
        }
    } else if (stream_body(h, content_length, &total, max_body, cb, user) != 0) {
        status = -1;
    }
out:
    if (h->tls != NULL) {
        tls_close(h->tls);
        tls_free(h->tls);
    }
    tcp_close(h->fd);
    return status;
}
