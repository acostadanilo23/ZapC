/*
 * ZapC - minimal HTTPS GET client (for media / history downloads).
 *
 * The response body is streamed to a callback in chunks; nothing is
 * buffered beyond one network read.  Blocking with a timeout.
 */
#ifndef ZAPC_HTTP_H
#define ZAPC_HTTP_H

#include <stddef.h>
#include <stdint.h>

/* Return 0 to continue, non-zero to abort the download. */
typedef int (*http_body_fn)(void *user, const uint8_t *data, size_t len);

/*
 * GET https://host:port/path.  Returns the HTTP status code (200 on
 * success, the body was streamed), or -1 on connection/protocol errors.
 * max_body > 0 aborts responses larger than that.
 */
int http_get(const char *host, uint16_t port, const char *path,
             const char *ca_file, uint64_t max_body, http_body_fn cb,
             void *user, int timeout_ms);

#endif
