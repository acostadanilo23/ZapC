/*
 * ZapC - small DEFLATE / zlib decoder with a fixed output buffer.
 */
#ifndef ZAPC_INFLATE_H
#define ZAPC_INFLATE_H

#include <stddef.h>
#include <stdint.h>

/* Raw DEFLATE. Returns output length or -1 (also when out is too small). */
long zc_inflate_raw(const uint8_t *in, size_t inlen, size_t *consumed,
                    uint8_t *out, size_t outcap);
/* zlib stream (header + deflate + adler32). */
long zc_inflate_zlib(const uint8_t *in, size_t inlen, uint8_t *out,
                     size_t outcap);

#endif
