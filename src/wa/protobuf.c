#include "zapc/protobuf.h"

#include <string.h>

void pb_reader_init(pb_reader *r, const void *data, size_t len)
{
    r->p = data;
    r->end = r->p + len;
}

static int read_varint(pb_reader *r, uint64_t *v)
{
    uint64_t res = 0;
    for (unsigned shift = 0; shift < 64; shift += 7) {
        if (r->p >= r->end)
            return -1;
        uint8_t b = *r->p++;
        if (shift == 63 && (b & 0x7E))
            return -1; /* overflows 64 bits */
        res |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            *v = res;
            return 0;
        }
    }
    return -1; /* more than 10 bytes */
}

int pb_next(pb_reader *r, pb_field *f)
{
    uint64_t key;
    if (r->p >= r->end)
        return 0;
    if (read_varint(r, &key) != 0)
        return -1;
    uint64_t num = key >> 3;
    if (num == 0 || num > 0x1FFFFFFF)
        return -1;
    memset(f, 0, sizeof *f);
    f->num = (uint32_t)num;
    f->wire = (uint8_t)(key & 7);
    size_t left;
    switch (f->wire) {
    case PB_VARINT:
        return read_varint(r, &f->u64) == 0 ? 1 : -1;
    case PB_FIXED64:
        if (r->end - r->p < 8)
            return -1;
        for (int i = 7; i >= 0; i--)
            f->u64 = (f->u64 << 8) | r->p[i];
        r->p += 8;
        return 1;
    case PB_FIXED32:
        if (r->end - r->p < 4)
            return -1;
        for (int i = 3; i >= 0; i--)
            f->u64 = (f->u64 << 8) | r->p[i];
        r->p += 4;
        return 1;
    case PB_LEN: {
        uint64_t len;
        if (read_varint(r, &len) != 0)
            return -1;
        left = (size_t)(r->end - r->p);
        if (len > left)
            return -1;
        f->data = r->p;
        f->len = (size_t)len;
        r->p += len;
        return 1;
    }
    default:
        return -1; /* groups (3/4) are not supported */
    }
}

int pb_find_bytes(const void *msg, size_t len, uint32_t num,
                  const uint8_t **data, size_t *dlen)
{
    pb_reader r;
    pb_field f;
    int rc;
    pb_reader_init(&r, msg, len);
    while ((rc = pb_next(&r, &f)) == 1) {
        if (f.num == num && f.wire == PB_LEN) {
            *data = f.data;
            *dlen = f.len;
            return 1;
        }
    }
    return rc;
}

int pb_find_varint(const void *msg, size_t len, uint32_t num, uint64_t *v)
{
    pb_reader r;
    pb_field f;
    int rc;
    pb_reader_init(&r, msg, len);
    while ((rc = pb_next(&r, &f)) == 1) {
        if (f.num == num && f.wire == PB_VARINT) {
            *v = f.u64;
            return 1;
        }
    }
    return rc;
}

void pb_put_varint_raw(zbuf *b, uint64_t v)
{
    uint8_t t[10];
    size_t n = 0;
    do {
        uint8_t byte = (uint8_t)(v & 0x7F);
        v >>= 7;
        if (v)
            byte |= 0x80;
        t[n++] = byte;
    } while (v);
    zbuf_put(b, t, n);
}

static void put_key(zbuf *b, uint32_t num, unsigned wire)
{
    pb_put_varint_raw(b, ((uint64_t)num << 3) | wire);
}

void pb_put_uint(zbuf *b, uint32_t num, uint64_t v)
{
    put_key(b, num, PB_VARINT);
    pb_put_varint_raw(b, v);
}

void pb_put_bool(zbuf *b, uint32_t num, int v)
{
    pb_put_uint(b, num, v ? 1u : 0u);
}

void pb_put_bytes(zbuf *b, uint32_t num, const void *data, size_t len)
{
    put_key(b, num, PB_LEN);
    pb_put_varint_raw(b, len);
    zbuf_put(b, data, len);
}

void pb_put_string(zbuf *b, uint32_t num, const char *s)
{
    pb_put_bytes(b, num, s, strlen(s));
}

void pb_put_fixed32(zbuf *b, uint32_t num, uint32_t v)
{
    uint8_t t[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16),
                    (uint8_t)(v >> 24)};
    put_key(b, num, PB_FIXED32);
    zbuf_put(b, t, 4);
}

void pb_put_fixed64(zbuf *b, uint32_t num, uint64_t v)
{
    uint8_t t[8];
    for (int i = 0; i < 8; i++)
        t[i] = (uint8_t)(v >> (8 * i));
    put_key(b, num, PB_FIXED64);
    zbuf_put(b, t, 8);
}

size_t pb_begin(zbuf *b, uint32_t num)
{
    put_key(b, num, PB_LEN);
    zbuf_put_u8(b, 0); /* placeholder for a 1-byte length */
    return b->len;
}

void pb_end(zbuf *b, size_t mark)
{
    if (b->overflow)
        return;
    size_t body = b->len - mark;
    uint8_t t[10];
    size_t n = 0;
    uint64_t v = body;
    do {
        uint8_t byte = (uint8_t)(v & 0x7F);
        v >>= 7;
        if (v)
            byte |= 0x80;
        t[n++] = byte;
    } while (v);
    size_t extra = n - 1;
    if (extra > 0) {
        if (extra > b->cap - b->len) {
            b->overflow = 1;
            return;
        }
        memmove(b->data + mark + extra, b->data + mark, body);
        b->len += extra;
    }
    memcpy(b->data + mark - 1, t, n);
}
