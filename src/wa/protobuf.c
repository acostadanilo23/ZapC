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

/* ======================================================================== */
/* streaming walker                                                         */
/* ======================================================================== */

enum { W_KEY = 0, W_VARINT, W_FIXED, W_LEN, W_SKIP, W_BUF };

void pbw_init(pb_walker *w, uint8_t *buf, size_t cap)
{
    pbw_action (*on_len)(pb_walker *, uint32_t, uint64_t) = w->on_len;
    void (*on_varint)(pb_walker *, uint32_t, uint64_t) = w->on_varint;
    void (*on_bytes)(pb_walker *, uint32_t, const uint8_t *, size_t) = w->on_bytes;
    void (*on_end)(pb_walker *, uint32_t) = w->on_end;
    void *user = w->user;
    memset(w, 0, sizeof *w);
    w->on_len = on_len;
    w->on_varint = on_varint;
    w->on_bytes = on_bytes;
    w->on_end = on_end;
    w->user = user;
    w->buf = buf;
    w->buf_cap = cap;
    w->end[0] = UINT64_MAX;
}

/* After a field completed: close every sub-message that ends here. */
static int field_done(pb_walker *w)
{
    w->state = W_KEY;
    w->acc = 0;
    w->shift = 0;
    while (w->depth > 0 && w->pos >= w->end[w->depth]) {
        if (w->pos > w->end[w->depth])
            return -1;
        uint32_t f = w->path[w->depth];
        w->depth--;
        if (w->on_end != NULL)
            w->on_end(w, f);
    }
    return 0;
}

static int varint_byte(pb_walker *w, uint8_t b, int *done)
{
    if (w->shift >= 64 || (w->shift == 63 && (b & 0x7E)))
        return -1;
    w->acc |= (uint64_t)(b & 0x7F) << w->shift;
    w->shift += 7;
    *done = !(b & 0x80);
    return 0;
}

static int start_len(pb_walker *w, uint64_t len)
{
    if (len > w->end[w->depth] - w->pos)
        return -1;
    pbw_action a = w->on_len != NULL ? w->on_len(w, w->field, len) : PBW_SKIP;
    if (a == PBW_DESCEND) {
        if (w->depth >= PBW_MAX_DEPTH)
            return -1;
        w->depth++;
        w->path[w->depth] = w->field;
        w->end[w->depth] = w->pos + len;
        return field_done(w);
    }
    if (a == PBW_BUFFER && len <= w->buf_cap) {
        w->buf_len = 0;
        w->need = len;
        w->state = W_BUF;
        if (len == 0) {
            if (w->on_bytes != NULL)
                w->on_bytes(w, w->field, w->buf, 0);
            return field_done(w);
        }
        return 0;
    }
    w->need = len;
    w->state = W_SKIP;
    return len == 0 ? field_done(w) : 0;
}

int pbw_feed(pb_walker *w, const uint8_t *data, size_t len)
{
    size_t i = 0;
    if (w->error)
        return -1;
    while (i < len) {
        int done = 0;
        switch (w->state) {
        case W_KEY:
            if (varint_byte(w, data[i++], &done) != 0)
                goto bad;
            w->pos++;
            if (!done)
                break;
            if ((w->acc >> 3) == 0 || (w->acc >> 3) > 0x1FFFFFFF)
                goto bad;
            w->field = (uint32_t)(w->acc >> 3);
            w->wire = (int)(w->acc & 7);
            w->acc = 0;
            w->shift = 0;
            if (w->wire == PB_VARINT)
                w->state = W_VARINT;
            else if (w->wire == PB_LEN)
                w->state = W_LEN;
            else if (w->wire == PB_FIXED64 || w->wire == PB_FIXED32) {
                w->state = W_FIXED;
                w->need = w->wire == PB_FIXED64 ? 8 : 4;
            } else {
                goto bad;
            }
            break;
        case W_VARINT:
            if (varint_byte(w, data[i++], &done) != 0)
                goto bad;
            w->pos++;
            if (done) {
                if (w->on_varint != NULL)
                    w->on_varint(w, w->field, w->acc);
                if (field_done(w) != 0)
                    goto bad;
            }
            break;
        case W_FIXED:
            w->acc |= (uint64_t)data[i++] << w->shift;
            w->shift += 8;
            w->pos++;
            if (--w->need == 0) {
                if (w->on_varint != NULL)
                    w->on_varint(w, w->field, w->acc);
                if (field_done(w) != 0)
                    goto bad;
            }
            break;
        case W_LEN:
            if (varint_byte(w, data[i++], &done) != 0)
                goto bad;
            w->pos++;
            if (done) {
                uint64_t l = w->acc;
                w->acc = 0;
                w->shift = 0;
                if (start_len(w, l) != 0)
                    goto bad;
            }
            break;
        case W_SKIP:
        case W_BUF: {
            size_t take = len - i;
            if ((uint64_t)take > w->need)
                take = (size_t)w->need;
            if (w->state == W_BUF) {
                memcpy(w->buf + w->buf_len, data + i, take);
                w->buf_len += take;
            }
            i += take;
            w->pos += take;
            w->need -= take;
            if (w->need == 0) {
                if (w->state == W_BUF && w->on_bytes != NULL)
                    w->on_bytes(w, w->field, w->buf, w->buf_len);
                if (field_done(w) != 0)
                    goto bad;
            }
            break;
        }
        default:
            goto bad;
        }
    }
    return 0;
bad:
    w->error = 1;
    return -1;
}

int pbw_finish(pb_walker *w)
{
    return (!w->error && w->state == W_KEY && w->shift == 0 && w->depth == 0)
               ? 0
               : -1;
}
