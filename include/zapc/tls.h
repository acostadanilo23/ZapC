/*
 * ZapC - TLS client interface.
 *
 * The implementation lives in src/net/tls_<backend>.c (OpenSSL for now;
 * mbedTLS, wolfSSL or BearSSL can be added for small targets).
 *
 * Certificate and hostname verification are always enabled; there is no
 * option to disable them.
 */
#ifndef ZAPC_TLS_H
#define ZAPC_TLS_H

#include "zapc/transport.h"

typedef struct zc_tls zc_tls;

zc_tls *tls_new(void);
void tls_free(zc_tls *t);

/*
 * Perform the TLS handshake over a connected (non-blocking) socket.
 * host is used for SNI and certificate hostname verification.
 * ca_file may be NULL/empty to use the system trust store.
 * Returns 0 on success.
 */
int tls_connect(zc_tls *t, int fd, const char *host, const char *ca_file,
                int timeout_ms);

long tls_read(zc_tls *t, void *buf, size_t len);         /* ZC_IO_AGAIN */
long tls_write(zc_tls *t, const void *buf, size_t len);  /* full write  */
size_t tls_pending(zc_tls *t);
void tls_close(zc_tls *t); /* sends close_notify, does not close fd */

/* Negotiated protocol and cipher, for /status. */
const char *tls_version(zc_tls *t);
const char *tls_cipher(zc_tls *t);

zc_stream tls_stream(zc_tls *t);

#endif
