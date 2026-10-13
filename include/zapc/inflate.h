/*
 * ZapC - small DEFLATE / zlib decoder.
 *
 * The streaming interface keeps only a 32 KiB window plus a 4 KiB input
 * buffer, regardless of the size of the data.  It is not reentrant (one
 * shared decoder state).
 */
#ifndef ZAPC_INFLATE_H
#define ZAPC_INFLATE_H

#include <stddef.h>
#include <stdint.h>

/* Return bytes read (0 = end of input) or -1. */
typedef long (*inf_read_fn)(void *user, uint8_t *buf, size_t cap);
/* Return 0 to continue, non-zero to abort. */
typedef int (*inf_write_fn)(void *user, const uint8_t *data, size_t len);

/*
 * Decompress a zlib (zlib=1) or raw DEFLATE (zlib=0) stream.  limit > 0
 * aborts once more than `limit` bytes would be produced.  Returns the number
 * of bytes produced (saturated at INT32_MAX) or -1.
 */
long zc_inflate_stream(int zlib, inf_read_fn rd, void *ru, inf_write_fn wr,
                       void *wu, uint64_t limit);

/* Buffer helpers. Return output length or -1 (also when out is too small). */
long zc_inflate_raw(const uint8_t *in, size_t inlen, size_t *consumed,
                    uint8_t *out, size_t outcap);
long zc_inflate_zlib(const uint8_t *in, size_t inlen, uint8_t *out,
                     size_t outcap);

#endif
