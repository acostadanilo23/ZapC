/*
 * ZapC - minimal RFC 6455 WebSocket client.
 *
 * - HTTP/1.1 Upgrade with Sec-WebSocket-Accept verification
 * - masked client frames, binary and text
 * - ping/pong/close handled internally
 * - fragmented messages
 * - streaming receive: payload is delivered in chunks as it arrives, so a
 *   message never has to fit in memory at once
 */
#ifndef ZAPC_WEBSOCKET_H
#define ZAPC_WEBSOCKET_H

#include "zapc/build_config.h"
#include "zapc/crypto.h"
#include "zapc/transport.h"

#include <stddef.h>
#include <stdint.h>

enum {
    WS_OP_CONT = 0x0,
    WS_OP_TEXT = 0x1,
    WS_OP_BINARY = 0x2,
    WS_OP_CLOSE = 0x8,
    WS_OP_PING = 0x9,
    WS_OP_PONG = 0xA
};

/*
 * Message payload callback.  For each message it is called one or more
 * times; `first` is set on the first chunk and `last` on the final one.
 * Returning non-zero aborts the connection.
 */
typedef int (*ws_message_fn)(void *user, int opcode, const uint8_t *data,
                             size_t len, int first, int last);

typedef enum {
    WS_RX_HEADER,
    WS_RX_PAYLOAD
} ws_rx_state;

typedef struct {
    zc_stream io;
    ws_message_fn on_message;
    void *user;

    /* receive parser */
    ws_rx_state state;
    uint8_t hdr[14];
    size_t hdr_len;
    size_t hdr_need;
    uint64_t payload_left;
    int opcode;          /* opcode of the frame being parsed            */
    int fin;
    int msg_opcode;      /* opcode of the message (for continuations)   */
    int in_message;      /* inside a fragmented data message            */
    int msg_first;       /* next delivered chunk is the first one       */
    uint64_t msg_size;   /* bytes delivered for the current message     */
    uint8_t ctrl[125];
    size_t ctrl_len;

    /* status */
    int open;
    int close_sent;
    int close_received;
    uint16_t close_code;
    uint64_t last_rx_ms;

    uint8_t rx[ZAPC_NET_RX_SIZE];
    size_t rx_len; /* bytes in rx not yet parsed (after handshake) */
    uint8_t tx[ZAPC_NET_TX_SIZE];
} ws_client;

void ws_init(ws_client *ws, zc_stream io, ws_message_fn fn, void *user);

/* Blocking HTTP upgrade. Extra headers (e.g. Origin) may be NULL. */
int ws_handshake(ws_client *ws, const char *host, const char *path,
                 const char *origin, int timeout_ms);

/* Feed raw bytes into the frame parser (used by ws_pump and tests). */
int ws_feed(ws_client *ws, const uint8_t *data, size_t len);

/*
 * Read whatever is available from the stream and dispatch it.
 * Returns 0 when everything available was consumed, -1 on error or close.
 */
int ws_pump(ws_client *ws);

/* Send one message built from several buffers (no concatenation copy). */
int ws_send_v(ws_client *ws, int opcode, const zc_iov *parts, size_t n);
int ws_send(ws_client *ws, int opcode, const void *data, size_t len);
int ws_ping(ws_client *ws);
int ws_close(ws_client *ws, uint16_t code);

/* Compute Sec-WebSocket-Accept for a key (exposed for tests). */
int ws_accept_key(const char *key, char out[32]);

/*
 * Build a client frame header for `len` payload bytes with the given mask.
 * Returns the header length (2..14). Exposed for tests.
 */
size_t ws_build_header(uint8_t *hdr, int opcode, int fin, uint64_t len,
                       const uint8_t mask[4]);

#endif
