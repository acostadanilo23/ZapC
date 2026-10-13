/*
 * libFuzzer harnesses for the network-facing parsers.
 *
 *   make fuzz                      (needs clang with -fsanitize=fuzzer)
 *   ./build/fuzz/fuzz_node corpus/
 *
 * Select the target with -DFUZZ_TARGET=1..5 (see below).
 */
#include "zapc/binary_node.h"
#include "zapc/history_sync.h"
#include "zapc/inflate.h"
#include "zapc/jid.h"
#include "zapc/protobuf.h"
#include "zapc/websocket.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#if FUZZ_TARGET == 2
static int ws_sink(void *u, int op, const uint8_t *d, size_t n, int f, int l)
{
    (void)u; (void)op; (void)d; (void)n; (void)f; (void)l;
    return 0;
}
static long r0(void *c, void *b, size_t n) { (void)c; (void)b; (void)n; return ZC_IO_AGAIN; }
static long w0(void *c, const void *b, size_t n) { (void)c; (void)b; return (long)n; }
static size_t p0(void *c) { (void)c; return 0; }
#endif

#if FUZZ_TARGET == 5
static long mem_read(void *u, uint8_t *buf, size_t cap)
{
    const uint8_t **pp = u;
    size_t *left = (size_t *)(pp + 1);
    size_t n = *left < cap ? *left : cap;
    memcpy(buf, *pp, n);
    *pp += n;
    *left -= n;
    return (long)n;
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#if FUZZ_TARGET == 1 /* binary nodes */
    static uint8_t arena_mem[65536];
    zap_arena a;
    wa_node *n;
    zap_arena_init(&a, arena_mem, sizeof arena_mem);
    if (wa_node_decode(data, size, &a, &n) == 0) {
        static uint8_t out[131072];
        zbuf b;
        zbuf_init(&b, out, sizeof out);
        (void)wa_node_encode(n, &b);
    }
#elif FUZZ_TARGET == 2 /* WebSocket frames */
    static ws_client ws;
    zc_stream st = {NULL, -1, r0, w0, p0};
    ws_init(&ws, st, ws_sink, NULL);
    ws.open = 1;
    (void)ws_feed(&ws, data, size);
#elif FUZZ_TARGET == 3 /* protobuf + message text extraction */
    pb_reader r;
    pb_field f;
    char text[1024];
    pb_reader_init(&r, data, size);
    while (pb_next(&r, &f) == 1) {
    }
    (void)wa_extract_text(data, size, text, sizeof text);
#elif FUZZ_TARGET == 4 /* JID parser */
    char s[256];
    wa_jid j;
    size_t n = size < sizeof s - 1 ? size : sizeof s - 1;
    memcpy(s, data, n);
    s[n] = '\0';
    if (jid_parse(&j, s) == 0) {
        char out[WA_JID_STR_MAX];
        (void)jid_format(&j, out, sizeof out);
    }
#elif FUZZ_TARGET == 5 /* zlib + history sync */
    struct { const uint8_t *p; size_t left; } src = {data, size};
    wa_hist_sink sink;
    wa_hist_stats st;
    memset(&sink, 0, sizeof sink);
    (void)wa_history_process(mem_read, &src, &sink, &st);
#else
#error "define FUZZ_TARGET"
#endif
    return 0;
}
