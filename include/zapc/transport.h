/*
 * ZapC - byte stream abstraction and TCP.
 *
 * A zc_stream is anything that can read and write bytes: a plain TCP socket,
 * a TLS session, or an in-memory pipe in tests.  The WebSocket layer only
 * talks to a zc_stream and therefore does not know about TLS.
 */
#ifndef ZAPC_TRANSPORT_H
#define ZAPC_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#define ZC_IO_AGAIN (-2L) /* no data available right now (non-blocking) */
#define ZC_IO_ERROR (-1L)

typedef struct {
    void *ctx;
    int fd; /* for poll(); -1 when not applicable */
    /* Returns >0 bytes read, 0 on orderly EOF, ZC_IO_AGAIN or ZC_IO_ERROR. */
    long (*read)(void *ctx, void *buf, size_t len);
    /* Writes everything (waiting as needed). Returns len or ZC_IO_ERROR. */
    long (*write)(void *ctx, const void *buf, size_t len);
    /* Bytes already buffered inside the stream (e.g. decrypted TLS). */
    size_t (*pending)(void *ctx);
} zc_stream;

/*
 * Resolve host and connect with a timeout.  Returns a non-blocking socket fd
 * or -1 on failure.
 */
int tcp_connect(const char *host, uint16_t port, int timeout_ms);
void tcp_close(int fd);

/* Wait until fd is readable (events=1) or writable (events=2). 1=ready, 0=timeout, -1=error. */
int tcp_wait(int fd, int events, int timeout_ms);

/* Stream over a plain non-blocking TCP socket. ctx points to an int fd. */
zc_stream tcp_stream(int *fd);

#endif
