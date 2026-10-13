#include "zapc/websocket.h"
#include "zapc/log.h"
#include "zapc/platform.h"
#include "zapc/util.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

void ws_init(ws_client *ws, zc_stream io, ws_message_fn fn, void *user)
{
    memset(ws, 0, offsetof(ws_client, rx));
    ws->io = io;
    ws->on_message = fn;
    ws->user = user;
    ws->state = WS_RX_HEADER;
    ws->hdr_need = 2;
    ws->rx_len = 0;
}

int ws_accept_key(const char *key, char out[32])
{
    char buf[128];
    uint8_t digest[20];
    int n = snprintf(buf, sizeof buf, "%s%s", key, WS_GUID);
    if (n < 0 || (size_t)n >= sizeof buf)
        return -1;
    if (crypto_sha1(buf, (size_t)n, digest) != 0)
        return -1;
    return base64_encode(digest, 20, out, 32) > 0 ? 0 : -1;
}

/* Find header `name` in an HTTP response; copies its trimmed value. */
static int http_header(const char *resp, const char *name, char *out,
                       size_t cap)
{
    size_t nlen = strlen(name);
    const char *p = strstr(resp, "\r\n");
    while (p != NULL) {
        p += 2;
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            const char *v = p + nlen + 1;
            while (*v == ' ' || *v == '\t')
                v++;
            const char *e = strstr(v, "\r\n");
            if (e == NULL)
                return -1;
            while (e > v && (e[-1] == ' ' || e[-1] == '\t'))
                e--;
            zstrlcpyn(out, v, (size_t)(e - v), cap);
            return 0;
        }
        p = strstr(p, "\r\n");
    }
    return -1;
}

int ws_handshake(ws_client *ws, const char *host, const char *path,
                 const char *origin, int timeout_ms)
{
    uint8_t nonce[16];
    char key[32], expect[32], got[64];
    char req[768];

    if (plat_random(nonce, sizeof nonce) != 0)
        return -1;
    base64_encode(nonce, sizeof nonce, key, sizeof key);
    if (ws_accept_key(key, expect) != 0)
        return -1;

    int n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "%s%s%s"
                     "User-Agent: ZapC\r\n"
                     "\r\n",
                     path, host, key, origin ? "Origin: " : "",
                     origin ? origin : "", origin ? "\r\n" : "");
    if (n < 0 || (size_t)n >= sizeof req)
        return -1;
    if (ws->io.write(ws->io.ctx, req, (size_t)n) != n)
        return -1;

    /* Read the response headers into rx; keep anything after them. */
    char *resp = (char *)ws->rx;
    size_t have = 0;
    const size_t cap = sizeof ws->rx < ZAPC_WS_HANDSHAKE_SIZE
                           ? sizeof ws->rx
                           : ZAPC_WS_HANDSHAKE_SIZE;
    uint64_t deadline = plat_now_ms() + (uint64_t)timeout_ms;
    char *end = NULL;
    while (end == NULL) {
        if (have + 1 >= cap) {
            LOGE("ws", "handshake response too large");
            return -1;
        }
        long r = ws->io.read(ws->io.ctx, ws->rx + have, cap - 1 - have);
        if (r == ZC_IO_AGAIN) {
            uint64_t now = plat_now_ms();
            if (now >= deadline || ws->io.fd < 0 ||
                tcp_wait(ws->io.fd, 1, (int)(deadline - now)) != 1) {
                LOGE("ws", "handshake timeout");
                return -1;
            }
            continue;
        }
        if (r <= 0) {
            LOGE("ws", "connection closed during handshake");
            return -1;
        }
        have += (size_t)r;
        resp[have] = '\0';
        end = strstr(resp, "\r\n\r\n");
    }
    size_t hdr_len = (size_t)(end - resp) + 4;

    int status = 0;
    if (sscanf(resp, "HTTP/1.1 %d", &status) != 1 || status != 101) {
        char line[96];
        const char *eol = strstr(resp, "\r\n");
        zstrlcpyn(line, resp, eol ? (size_t)(eol - resp) : 0, sizeof line);
        LOGE("ws", "upgrade rejected: %s", line);
        return -1;
    }
    end[2] = '\0'; /* terminate after the last header line's CRLF */
    if (http_header(resp, "Sec-WebSocket-Accept", got, sizeof got) != 0 ||
        strcmp(got, expect) != 0) {
        LOGE("ws", "invalid Sec-WebSocket-Accept");
        return -1;
    }
    if (http_header(resp, "Upgrade", got, sizeof got) != 0 ||
        strcasecmp(got, "websocket") != 0) {
        LOGE("ws", "missing Upgrade: websocket");
        return -1;
    }

    /* Bytes after the headers are the beginning of the frame stream. */
    ws->rx_len = have - hdr_len;
    if (ws->rx_len > 0)
        memmove(ws->rx, ws->rx + hdr_len, ws->rx_len);
    ws->open = 1;
    ws->last_rx_ms = plat_now_ms();
    LOGD("ws", "upgraded %s%s", host, path);
    return 0;
}

size_t ws_build_header(uint8_t *hdr, int opcode, int fin, uint64_t len,
                       const uint8_t mask[4])
{
    size_t h = 0;
    hdr[h++] = (uint8_t)((fin ? 0x80 : 0) | (opcode & 0x0F));
    if (len < 126) {
        hdr[h++] = (uint8_t)(0x80 | len);
    } else if (len <= 0xFFFF) {
        hdr[h++] = 0x80 | 126;
        hdr[h++] = (uint8_t)(len >> 8);
        hdr[h++] = (uint8_t)len;
    } else {
        hdr[h++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--)
            hdr[h++] = (uint8_t)(len >> (8 * i));
    }
    memcpy(hdr + h, mask, 4);
    return h + 4;
}

int ws_send_v(ws_client *ws, int opcode, const zc_iov *parts, size_t n)
{
    uint64_t total = 0;
    uint8_t mask[4];
    for (size_t i = 0; i < n; i++)
        total += parts[i].len;
    if (plat_random(mask, sizeof mask) != 0)
        return -1;

    size_t used = ws_build_header(ws->tx, opcode, 1, total, mask);
    uint64_t mpos = 0;
    for (size_t i = 0; i < n; i++) {
        const uint8_t *p = parts[i].data;
        size_t left = parts[i].len;
        while (left > 0) {
            size_t room = sizeof ws->tx - used;
            size_t take = left < room ? left : room;
            for (size_t k = 0; k < take; k++)
                ws->tx[used + k] = (uint8_t)(p[k] ^ mask[(mpos + k) & 3]);
            used += take;
            mpos += take;
            p += take;
            left -= take;
            if (used == sizeof ws->tx) {
                if (ws->io.write(ws->io.ctx, ws->tx, used) != (long)used)
                    return -1;
                used = 0;
            }
        }
    }
    if (used > 0 && ws->io.write(ws->io.ctx, ws->tx, used) != (long)used)
        return -1;
    return 0;
}

int ws_send(ws_client *ws, int opcode, const void *data, size_t len)
{
    zc_iov v = {data, len};
    return ws_send_v(ws, opcode, &v, 1);
}

int ws_ping(ws_client *ws) { return ws_send(ws, WS_OP_PING, "zapc", 4); }

int ws_close(ws_client *ws, uint16_t code)
{
    if (ws->close_sent)
        return 0;
    uint8_t b[2] = {(uint8_t)(code >> 8), (uint8_t)code};
    ws->close_sent = 1;
    return ws_send(ws, WS_OP_CLOSE, b, 2);
}

static int handle_control(ws_client *ws)
{
    switch (ws->opcode) {
    case WS_OP_PING:
        LOGT("ws", "ping (%zu bytes)", ws->ctrl_len);
        return ws_send(ws, WS_OP_PONG, ws->ctrl, ws->ctrl_len);
    case WS_OP_PONG:
        return 0;
    case WS_OP_CLOSE:
        ws->close_received = 1;
        ws->close_code = ws->ctrl_len >= 2 ? rd_be16(ws->ctrl) : 1005;
        LOGI("ws", "server closed connection (code %u)",
             (unsigned)ws->close_code);
        if (!ws->close_sent)
            (void)ws_close(ws, ws->close_code == 1005 ? 1000 : ws->close_code);
        ws->open = 0;
        return -1;
    default:
        return -1;
    }
}

/* Validate a complete header and set up payload parsing. */
static int begin_frame(ws_client *ws)
{
    uint8_t b0 = ws->hdr[0], b1 = ws->hdr[1];
    if (b0 & 0x70) {
        LOGW("ws", "reserved bits set");
        return -1;
    }
    if (b1 & 0x80) {
        LOGW("ws", "server sent a masked frame");
        return -1;
    }
    ws->fin = (b0 & 0x80) != 0;
    ws->opcode = b0 & 0x0F;
    uint64_t len = b1 & 0x7F;
    if (len == 126) {
        len = rd_be16(ws->hdr + 2);
    } else if (len == 127) {
        len = 0;
        for (int i = 0; i < 8; i++)
            len = (len << 8) | ws->hdr[2 + i];
        if (len >> 63)
            return -1;
    }
    ws->payload_left = len;

    if (ws->opcode >= 0x8) {
        if (!ws->fin || len > 125) {
            LOGW("ws", "invalid control frame");
            return -1;
        }
        ws->ctrl_len = 0;
    } else if (ws->opcode == WS_OP_CONT) {
        if (!ws->in_message) {
            LOGW("ws", "unexpected continuation frame");
            return -1;
        }
    } else if (ws->opcode == WS_OP_TEXT || ws->opcode == WS_OP_BINARY) {
        if (ws->in_message) {
            LOGW("ws", "new message inside fragmented message");
            return -1;
        }
        ws->in_message = 1;
        ws->msg_opcode = ws->opcode;
        ws->msg_first = 1;
        ws->msg_size = 0;
    } else {
        LOGW("ws", "unknown opcode %d", ws->opcode);
        return -1;
    }
    if (ws->opcode < 0x8) {
        if (len > ZAPC_WS_MAX_MESSAGE ||
            ws->msg_size + len > ZAPC_WS_MAX_MESSAGE) {
            LOGW("ws", "message exceeds limit");
            return -1;
        }
        /* Empty final frame still has to terminate the message. */
        if (len == 0 && ws->fin) {
            int r = ws->on_message(ws->user, ws->msg_opcode, NULL, 0,
                                   ws->msg_first, 1);
            ws->in_message = 0;
            if (r != 0)
                return -1;
        }
    } else if (len == 0) {
        return handle_control(ws);
    }
    if (len > 0)
        ws->state = WS_RX_PAYLOAD;
    return 0;
}

int ws_feed(ws_client *ws, const uint8_t *data, size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        if (ws->state == WS_RX_HEADER) {
            ws->hdr[ws->hdr_len++] = data[pos++];
            if (ws->hdr_len == 2) {
                uint8_t l = ws->hdr[1] & 0x7F;
                ws->hdr_need = 2 + (l == 126 ? 2u : l == 127 ? 8u : 0u);
            }
            if (ws->hdr_len >= 2 && ws->hdr_len == ws->hdr_need) {
                ws->hdr_len = 0;
                ws->hdr_need = 2;
                if (begin_frame(ws) != 0)
                    return -1;
            }
            continue;
        }

        size_t avail = len - pos;
        size_t take = ws->payload_left < avail ? (size_t)ws->payload_left
                                               : avail;
        if (ws->opcode >= 0x8) {
            memcpy(ws->ctrl + ws->ctrl_len, data + pos, take);
            ws->ctrl_len += take;
            ws->payload_left -= take;
            pos += take;
            if (ws->payload_left == 0) {
                ws->state = WS_RX_HEADER;
                if (handle_control(ws) != 0)
                    return -1;
            }
            continue;
        }

        ws->payload_left -= take;
        ws->msg_size += take;
        int last = ws->payload_left == 0 && ws->fin;
        int r = ws->on_message(ws->user, ws->msg_opcode, data + pos, take,
                               ws->msg_first, last);
        ws->msg_first = 0;
        pos += take;
        if (ws->payload_left == 0) {
            ws->state = WS_RX_HEADER;
            if (ws->fin)
                ws->in_message = 0;
        }
        if (r != 0)
            return -1;
    }
    return 0;
}

int ws_pump(ws_client *ws)
{
    /* Leftover bytes received together with the handshake response. */
    if (ws->rx_len > 0) {
        size_t n = ws->rx_len;
        ws->rx_len = 0;
        if (ws_feed(ws, ws->rx, n) != 0)
            return -1;
    }
    for (;;) {
        long r = ws->io.read(ws->io.ctx, ws->rx, sizeof ws->rx);
        if (r == ZC_IO_AGAIN)
            return 0;
        if (r == 0) {
            LOGI("ws", "connection closed by peer");
            ws->open = 0;
            return -1;
        }
        if (r < 0) {
            ws->open = 0;
            return -1;
        }
        ws->last_rx_ms = plat_now_ms();
        if (ws_feed(ws, ws->rx, (size_t)r) != 0)
            return -1;
        if (!ws->open)
            return -1;
    }
}
