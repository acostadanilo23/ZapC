#include "zapc/util.h"

#include <string.h>

void zbuf_init(zbuf *b, void *mem, size_t cap)
{
    b->data = mem;
    b->cap = cap;
    b->len = 0;
    b->overflow = 0;
}

void zbuf_put(zbuf *b, const void *p, size_t n)
{
    if (b->overflow || n > b->cap - b->len) {
        b->overflow = 1;
        return;
    }
    if (n > 0)
        memcpy(b->data + b->len, p, n);
    b->len += n;
}

void zbuf_put_u8(zbuf *b, uint8_t v) { zbuf_put(b, &v, 1); }

void zbuf_put_be16(zbuf *b, uint16_t v)
{
    uint8_t t[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    zbuf_put(b, t, 2);
}

void zbuf_put_be24(zbuf *b, uint32_t v)
{
    uint8_t t[3] = {(uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    zbuf_put(b, t, 3);
}

void zbuf_put_be32(zbuf *b, uint32_t v)
{
    uint8_t t[4];
    wr_be32(t, v);
    zbuf_put(b, t, 4);
}

void zbuf_put_str(zbuf *b, const char *s) { zbuf_put(b, s, strlen(s)); }

void zstrlcpy(char *dst, const char *src, size_t cap)
{
    if (cap == 0)
        return;
    size_t n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void zstrlcpyn(char *dst, const char *src, size_t n, size_t cap)
{
    if (cap == 0)
        return;
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void hex_encode(const void *in, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    const uint8_t *p = in;
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[p[i] >> 4];
        out[2 * i + 1] = hx[p[i] & 15];
    }
    out[2 * n] = '\0';
}
