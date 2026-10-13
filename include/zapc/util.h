/*
 * ZapC - small utilities: base64, byte buffers, big-endian helpers.
 */
#ifndef ZAPC_UTIL_H
#define ZAPC_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* ---- base64 (RFC 4648, standard alphabet, padded) ---------------------- */
size_t base64_encoded_len(size_t n);
/* Writes a NUL-terminated string. Returns length (excluding NUL) or 0. */
size_t base64_encode(const void *in, size_t n, char *out, size_t out_cap);
/* Returns decoded length or -1 on invalid input / overflow. */
long base64_decode(const char *in, size_t n, void *out, size_t out_cap);

/* ---- bounded writer ---------------------------------------------------- */
typedef struct {
    uint8_t *data;
    size_t cap;
    size_t len;
    int overflow; /* sticky: set once any write did not fit */
} zbuf;

void zbuf_init(zbuf *b, void *mem, size_t cap);
void zbuf_put(zbuf *b, const void *p, size_t n);
void zbuf_put_u8(zbuf *b, uint8_t v);
void zbuf_put_be16(zbuf *b, uint16_t v);
void zbuf_put_be24(zbuf *b, uint32_t v);
void zbuf_put_be32(zbuf *b, uint32_t v);
void zbuf_put_str(zbuf *b, const char *s);

/* ---- endian helpers ---------------------------------------------------- */
static inline uint32_t rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)(((unsigned)p[0] << 8) | (unsigned)p[1]);
}
static inline void wr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Copy at most cap-1 bytes and always NUL-terminate. */
void zstrlcpy(char *dst, const char *src, size_t cap);
void zstrlcpyn(char *dst, const char *src, size_t n, size_t cap);

/* Format bytes as lowercase hex. out needs 2*n+1 bytes. */
void hex_encode(const void *in, size_t n, char *out);

#endif
