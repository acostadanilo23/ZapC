#include "test.h"

#include "zapc/websocket.h"

typedef struct {
    uint8_t out[70000];
    size_t out_len;
} mock_io;

static long mock_read(void *ctx, void *buf, size_t len)
{
    (void)ctx;
    (void)buf;
    (void)len;
    return ZC_IO_AGAIN;
}

static long mock_write(void *ctx, const void *buf, size_t len)
{
    mock_io *m = ctx;
    if (len > sizeof m->out - m->out_len)
        return ZC_IO_ERROR;
    memcpy(m->out + m->out_len, buf, len);
    m->out_len += len;
    return (long)len;
}

static size_t mock_pending(void *ctx)
{
    (void)ctx;
    return 0;
}

typedef struct {
    uint8_t data[70000];
    size_t len;
    int messages;
    int chunks;
    int opcode;
} sink;

static int on_msg(void *user, int opcode, const uint8_t *data, size_t len,
                  int first, int last)
{
    sink *s = user;
    if (first)
        s->len = 0;
    if (len > 0) {
        memcpy(s->data + s->len, data, len);
        s->len += len;
    }
    s->chunks++;
    s->opcode = opcode;
    if (last)
        s->messages++;
    return 0;
}

static mock_io g_io;
static sink g_sink;
static ws_client g_ws;

static void setup(void)
{
    memset(&g_io, 0, sizeof g_io);
    memset(&g_sink, 0, sizeof g_sink);
    zc_stream s = {&g_io, -1, mock_read, mock_write, mock_pending};
    ws_init(&g_ws, s, on_msg, &g_sink);
    g_ws.open = 1;
}

/* Decode one client frame from the mock output (checks masking). */
static size_t parse_client_frame(const uint8_t *p, size_t n, int *opcode,
                                 uint8_t *payload, size_t *plen)
{
    if (n < 6)
        return 0;
    *opcode = p[0] & 0x0F;
    if (!(p[1] & 0x80))
        return 0; /* must be masked */
    uint64_t len = p[1] & 0x7F;
    size_t h = 2;
    if (len == 126) {
        len = ((uint64_t)p[2] << 8) | p[3];
        h = 4;
    } else if (len == 127) {
        len = 0;
        for (int i = 0; i < 8; i++)
            len = (len << 8) | p[2 + i];
        h = 10;
    }
    const uint8_t *mask = p + h;
    h += 4;
    for (uint64_t i = 0; i < len; i++)
        payload[i] = (uint8_t)(p[h + i] ^ mask[i & 3]);
    *plen = (size_t)len;
    return h + (size_t)len;
}

static void test_accept_key(void)
{
    char out[32];
    CHECK(ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", out) == 0);
    CHECK_STR(out, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

static void test_header_sizes(void)
{
    uint8_t h[14];
    const uint8_t m[4] = {1, 2, 3, 4};
    CHECK(ws_build_header(h, WS_OP_BINARY, 1, 125, m) == 6);
    CHECK(h[0] == 0x82 && h[1] == (0x80 | 125));
    CHECK(ws_build_header(h, WS_OP_BINARY, 1, 126, m) == 8);
    CHECK(h[1] == (0x80 | 126) && h[2] == 0 && h[3] == 126);
    CHECK(ws_build_header(h, WS_OP_BINARY, 1, 65536, m) == 14);
    CHECK(h[1] == (0x80 | 127) && h[7] == 1 && h[8] == 0);
}

static void test_receive_simple(void)
{
    setup();
    const uint8_t f[] = {0x82, 3, 'a', 'b', 'c'};
    CHECK(ws_feed(&g_ws, f, sizeof f) == 0);
    CHECK(g_sink.messages == 1 && g_sink.len == 3);
    CHECK(memcmp(g_sink.data, "abc", 3) == 0);
    CHECK(g_sink.opcode == WS_OP_BINARY);
}

static void test_receive_bytewise_fragmented(void)
{
    setup();
    /* text "Hel" (not fin) + ping inside + continuation "lo" (fin) */
    const uint8_t f[] = {0x01, 3, 'H', 'e', 'l', 0x89, 2, 'p', 'q',
                         0x80, 2, 'l', 'o'};
    for (size_t i = 0; i < sizeof f; i++)
        CHECK(ws_feed(&g_ws, f + i, 1) == 0);
    CHECK(g_sink.messages == 1);
    CHECK(g_sink.len == 5 && memcmp(g_sink.data, "Hello", 5) == 0);
    CHECK(g_sink.opcode == WS_OP_TEXT);
    /* a pong with the ping payload must have been sent */
    int op;
    uint8_t pl[16];
    size_t plen;
    CHECK(parse_client_frame(g_io.out, g_io.out_len, &op, pl, &plen) > 0);
    CHECK(op == WS_OP_PONG && plen == 2 && pl[0] == 'p' && pl[1] == 'q');
}

static void test_receive_extended_length(void)
{
    setup();
    static uint8_t f[4 + 300];
    f[0] = 0x82;
    f[1] = 126;
    f[2] = 300 >> 8;
    f[3] = 300 & 0xff;
    for (int i = 0; i < 300; i++)
        f[4 + i] = (uint8_t)i;
    CHECK(ws_feed(&g_ws, f, sizeof f) == 0);
    CHECK(g_sink.messages == 1 && g_sink.len == 300);
    CHECK(g_sink.data[299] == (uint8_t)299);
}

static void test_receive_errors(void)
{
    setup();
    const uint8_t masked[] = {0x82, 0x81, 0, 0, 0, 0, 'x'};
    CHECK(ws_feed(&g_ws, masked, sizeof masked) != 0);
    setup();
    const uint8_t cont[] = {0x80, 1, 'x'};
    CHECK(ws_feed(&g_ws, cont, sizeof cont) != 0);
    setup();
    const uint8_t rsv[] = {0xC2, 1, 'x'};
    CHECK(ws_feed(&g_ws, rsv, sizeof rsv) != 0);
    setup();
    const uint8_t bigctl[] = {0x89, 126, 0, 200};
    CHECK(ws_feed(&g_ws, bigctl, sizeof bigctl) != 0);
    setup();
    const uint8_t fragctl[] = {0x09, 0};
    CHECK(ws_feed(&g_ws, fragctl, sizeof fragctl) != 0);
}

static void test_close(void)
{
    setup();
    const uint8_t f[] = {0x88, 2, 0x03, 0xE8};
    CHECK(ws_feed(&g_ws, f, sizeof f) != 0);
    CHECK(g_ws.close_received && g_ws.close_code == 1000);
    int op;
    uint8_t pl[16];
    size_t plen;
    CHECK(parse_client_frame(g_io.out, g_io.out_len, &op, pl, &plen) > 0);
    CHECK(op == WS_OP_CLOSE && plen == 2 && pl[0] == 0x03 && pl[1] == 0xE8);
}

static void test_send_large(void)
{
    setup();
    static uint8_t data[40000];
    static uint8_t back[40000];
    for (size_t i = 0; i < sizeof data; i++)
        data[i] = (uint8_t)(i * 31);
    zc_iov parts[2] = {{data, 10}, {data + 10, sizeof data - 10}};
    CHECK(ws_send_v(&g_ws, WS_OP_BINARY, parts, 2) == 0);
    int op;
    size_t plen;
    CHECK(parse_client_frame(g_io.out, g_io.out_len, &op, back, &plen) ==
          g_io.out_len);
    CHECK(op == WS_OP_BINARY && plen == sizeof data);
    CHECK(memcmp(back, data, sizeof data) == 0);
}

int main(void)
{
    RUN(test_accept_key);
    RUN(test_header_sizes);
    RUN(test_receive_simple);
    RUN(test_receive_bytewise_fragmented);
    RUN(test_receive_extended_length);
    RUN(test_receive_errors);
    RUN(test_close);
    RUN(test_send_large);
    return test_done("test_websocket");
}
