/*
 * ZapC - WhatsApp frame layer.
 *
 * Inside the WebSocket stream WhatsApp sends frames prefixed with a 3-byte
 * big-endian length.  Frames may span WebSocket messages and one message
 * may carry several frames.  The very first frame sent by the client is
 * preceded by a 4-byte connection header ("WA", magic, dict version).
 *
 * The framer reassembles frames into a fixed buffer.  Frames larger than the
 * buffer are drained and dropped instead of allocating memory.
 */
#ifndef ZAPC_FRAME_H
#define ZAPC_FRAME_H

#include <stddef.h>
#include <stdint.h>

#define WA_FRAME_LEN_SIZE 3
#define WA_FRAME_MAX_WIRE (1u << 24)

/* Called with a complete frame; the buffer may be modified in place. */
typedef int (*wa_frame_fn)(void *user, uint8_t *frame, size_t len);

typedef struct {
    uint8_t len_buf[WA_FRAME_LEN_SIZE];
    size_t len_have;
    size_t frame_len;
    size_t frame_have;
    int dropping;
    uint8_t *buf;
    size_t cap;
    wa_frame_fn cb;
    void *user;
    unsigned long dropped;
} wa_framer;

void wa_framer_init(wa_framer *f, uint8_t *buf, size_t cap, wa_frame_fn cb,
                    void *user);
void wa_framer_reset(wa_framer *f);
int wa_framer_feed(wa_framer *f, const uint8_t *data, size_t len);

#endif
