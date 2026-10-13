/*
 * ZapC - small zlib/DEFLATE decoder (RFC 1950/1951).
 *
 * Streaming: input is pulled through a read callback into a 4 KiB buffer and
 * output is kept in a 32 KiB circular window (the maximum DEFLATE distance)
 * that is flushed to a write callback.  A multi-megabyte history blob can
 * therefore be decompressed with ~37 KiB of memory.
 *
 * Huffman decoding uses canonical codes by length (the method used by Mark
 * Adler's "puff"), which needs very little memory.
 */
#include "zapc/inflate.h"

#include <string.h>

#define MAXBITS 15
#define MAXLCODES 286
#define MAXDCODES 30
#define FIXLCODES 288
#define WSIZE 32768u
#define INBUF 4096u

typedef struct {
    inf_read_fn rd;
    void *ru;
    inf_write_fn wr;
    void *wu;
    uint8_t in[INBUF];
    size_t in_len;
    size_t in_pos;
    int in_eof;
    uint32_t bitbuf;
    unsigned bitcnt;
    uint8_t window[WSIZE];
    uint64_t out_total;   /* bytes produced so far */
    uint64_t flushed;     /* bytes handed to wr     */
    uint64_t out_limit;   /* 0 = unlimited          */
    int err;
} inf_state;

typedef struct {
    uint16_t count[MAXBITS + 1];
    uint16_t symbol[FIXLCODES];
} huffman;

static int next_byte(inf_state *s, unsigned *b)
{
    if (s->in_pos == s->in_len) {
        if (s->in_eof)
            return -1;
        long n = s->rd(s->ru, s->in, sizeof s->in);
        if (n <= 0) {
            s->in_eof = 1;
            return -1;
        }
        s->in_len = (size_t)n;
        s->in_pos = 0;
    }
    *b = s->in[s->in_pos++];
    return 0;
}

static unsigned getbits(inf_state *s, unsigned need)
{
    uint32_t val = s->bitbuf;
    while (s->bitcnt < need) {
        unsigned b;
        if (next_byte(s, &b) != 0) {
            s->err = 1;
            return 0;
        }
        val |= (uint32_t)b << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = need < 32 ? val >> need : 0;
    s->bitcnt -= need;
    return (unsigned)(val & ((1u << need) - 1u));
}

static int flush_window(inf_state *s)
{
    while (s->flushed < s->out_total) {
        size_t start = (size_t)(s->flushed % WSIZE);
        size_t n = (size_t)(s->out_total - s->flushed);
        if (n > WSIZE - start)
            n = WSIZE - start;
        if (s->wr(s->wu, s->window + start, n) != 0)
            return -1;
        s->flushed += n;
    }
    return 0;
}

static int put_byte(inf_state *s, uint8_t b)
{
    if (s->out_limit != 0 && s->out_total >= s->out_limit)
        return -1;
    if (s->out_total - s->flushed == WSIZE && flush_window(s) != 0)
        return -1;
    s->window[s->out_total % WSIZE] = b;
    s->out_total++;
    return 0;
}

static int stored(inf_state *s)
{
    unsigned b[4];
    s->bitbuf = 0;
    s->bitcnt = 0;
    for (int i = 0; i < 4; i++)
        if (next_byte(s, &b[i]) != 0)
            return -1;
    unsigned len = b[0] | (b[1] << 8);
    unsigned nlen = b[2] | (b[3] << 8);
    if (len != (~nlen & 0xffffu))
        return -1;
    while (len--) {
        unsigned c;
        if (next_byte(s, &c) != 0 || put_byte(s, (uint8_t)c) != 0)
            return -1;
    }
    return 0;
}

static int decode(inf_state *s, const huffman *h)
{
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= MAXBITS; len++) {
        code |= (int)getbits(s, 1);
        if (s->err)
            return -1;
        int count = h->count[len];
        if (code - count < first)
            return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

/* Returns 0 for a complete code, >0 incomplete, <0 over-subscribed. */
static int construct(huffman *h, const uint16_t *length, int n)
{
    uint16_t offs[MAXBITS + 1];
    for (int len = 0; len <= MAXBITS; len++)
        h->count[len] = 0;
    for (int sym = 0; sym < n; sym++)
        h->count[length[sym]]++;
    if (h->count[0] == n)
        return 0;
    int left = 1;
    for (int len = 1; len <= MAXBITS; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0)
            return left;
    }
    offs[1] = 0;
    for (int len = 1; len < MAXBITS; len++)
        offs[len + 1] = (uint16_t)(offs[len] + h->count[len]);
    for (int sym = 0; sym < n; sym++)
        if (length[sym] != 0)
            h->symbol[offs[length[sym]]++] = (uint16_t)sym;
    return left;
}

static const uint16_t lbase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11, 13,
                                   15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
                                   67, 83, 99, 115, 131, 163, 195, 227, 258};
static const uint8_t lext[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t dbase[30] = {
    1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
    33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t dext[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,
                                 4, 4, 5, 5, 6, 6, 7, 7,  8,  8,
                                 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

static int codes(inf_state *s, const huffman *lencode, const huffman *distcode)
{
    for (;;) {
        int sym = decode(s, lencode);
        if (sym < 0)
            return -1;
        if (sym < 256) {
            if (put_byte(s, (uint8_t)sym) != 0)
                return -1;
        } else if (sym == 256) {
            return 0;
        } else {
            sym -= 257;
            if (sym >= 29)
                return -1;
            size_t len = lbase[sym] + getbits(s, lext[sym]);
            int dsym = decode(s, distcode);
            if (dsym < 0 || dsym >= 30)
                return -1;
            size_t dist = dbase[dsym] + getbits(s, dext[dsym]);
            if (s->err || dist > s->out_total || dist > WSIZE)
                return -1;
            while (len--) {
                uint8_t b = s->window[(s->out_total - dist) % WSIZE];
                if (put_byte(s, b) != 0)
                    return -1;
            }
        }
    }
}

static int fixed(inf_state *s)
{
    static huffman lencode, distcode;
    static int built;
    if (!built) {
        uint16_t lengths[FIXLCODES];
        int sym;
        for (sym = 0; sym < 144; sym++)
            lengths[sym] = 8;
        for (; sym < 256; sym++)
            lengths[sym] = 9;
        for (; sym < 280; sym++)
            lengths[sym] = 7;
        for (; sym < FIXLCODES; sym++)
            lengths[sym] = 8;
        construct(&lencode, lengths, FIXLCODES);
        for (sym = 0; sym < MAXDCODES; sym++)
            lengths[sym] = 5;
        construct(&distcode, lengths, MAXDCODES);
        built = 1;
    }
    return codes(s, &lencode, &distcode);
}

static int dynamic(inf_state *s)
{
    static const uint8_t order[19] = {16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                      11, 4,  12, 3, 13, 2, 14, 1, 15};
    uint16_t lengths[MAXLCODES + MAXDCODES];
    huffman lencode, distcode;

    int nlen = (int)getbits(s, 5) + 257;
    int ndist = (int)getbits(s, 5) + 1;
    int ncode = (int)getbits(s, 4) + 4;
    if (s->err || nlen > MAXLCODES || ndist > MAXDCODES)
        return -1;
    int index;
    for (index = 0; index < ncode; index++)
        lengths[order[index]] = (uint16_t)getbits(s, 3);
    for (; index < 19; index++)
        lengths[order[index]] = 0;
    if (s->err || construct(&lencode, lengths, 19) != 0)
        return -1;

    index = 0;
    while (index < nlen + ndist) {
        int sym = decode(s, &lencode);
        if (sym < 0)
            return -1;
        if (sym < 16) {
            lengths[index++] = (uint16_t)sym;
            continue;
        }
        uint16_t len = 0;
        unsigned rep;
        if (sym == 16) {
            if (index == 0)
                return -1;
            len = lengths[index - 1];
            rep = 3 + getbits(s, 2);
        } else if (sym == 17) {
            rep = 3 + getbits(s, 3);
        } else {
            rep = 11 + getbits(s, 7);
        }
        if (s->err || index + (int)rep > nlen + ndist)
            return -1;
        while (rep--)
            lengths[index++] = len;
    }
    if (lengths[256] == 0)
        return -1;
    int err = construct(&lencode, lengths, nlen);
    if (err < 0 || (err > 0 && nlen - lencode.count[0] != 1))
        return -1;
    err = construct(&distcode, lengths + nlen, ndist);
    if (err < 0 || (err > 0 && ndist - distcode.count[0] != 1))
        return -1;
    return codes(s, &lencode, &distcode);
}

/* One decoder state (window + input buffer) shared by all callers. */
static inf_state g_state;

static int run_blocks(inf_state *s)
{
    int last;
    do {
        last = (int)getbits(s, 1);
        unsigned type = getbits(s, 2);
        if (s->err)
            return -1;
        int r;
        if (type == 0)
            r = stored(s);
        else if (type == 1)
            r = fixed(s);
        else if (type == 2)
            r = dynamic(s);
        else
            r = -1;
        if (r != 0 || s->err)
            return -1;
    } while (!last);
    return flush_window(s);
}

typedef struct {
    inf_write_fn wr;
    void *wu;
    uint32_t a, b;
} adler_sink;

static int adler_write(void *user, const uint8_t *data, size_t len)
{
    adler_sink *as = user;
    const uint8_t *p = data;
    size_t n = len;
    while (n > 0) {
        size_t chunk = n < 3800 ? n : 3800;
        n -= chunk;
        while (chunk--) {
            as->a += *p++;
            as->b += as->a;
        }
        as->a %= 65521u;
        as->b %= 65521u;
    }
    return as->wr(as->wu, data, len);
}

long zc_inflate_stream(int zlib, inf_read_fn rd, void *ru, inf_write_fn wr,
                       void *wu, uint64_t limit)
{
    inf_state *s = &g_state;
    adler_sink as = {wr, wu, 1, 0};
    memset(s, 0, offsetof(inf_state, window));
    s->rd = rd;
    s->ru = ru;
    s->wr = zlib ? adler_write : wr;
    s->wu = zlib ? (void *)&as : wu;
    s->out_limit = limit;
    if (zlib) {
        unsigned cmf, flg;
        if (next_byte(s, &cmf) != 0 || next_byte(s, &flg) != 0 ||
            (cmf & 15) != 8 || (cmf >> 4) > 7 || ((cmf << 8) | flg) % 31 != 0 ||
            (flg & 0x20))
            return -1;
    }
    if (run_blocks(s) != 0)
        return -1;
    if (zlib) {
        /* the adler32 trailer starts at the next byte boundary */
        s->bitbuf = 0;
        s->bitcnt = 0;
        unsigned b[4];
        for (int i = 0; i < 4; i++)
            if (next_byte(s, &b[i]) != 0)
                return -1;
        uint32_t want = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
                        ((uint32_t)b[2] << 8) | b[3];
        if (((as.b << 16) | as.a) != want)
            return -1;
    }
    return s->out_total > (uint64_t)INT32_MAX ? INT32_MAX : (long)s->out_total;
}

/* ---- buffer API on top of the stream API -------------------------------- */

typedef struct {
    const uint8_t *p;
    size_t left;
    size_t consumed;
} mem_reader;

static long mem_read(void *user, uint8_t *buf, size_t cap)
{
    mem_reader *m = user;
    size_t n = m->left < cap ? m->left : cap;
    memcpy(buf, m->p, n);
    m->p += n;
    m->left -= n;
    m->consumed += n;
    return (long)n;
}

typedef struct {
    uint8_t *out;
    size_t cap;
    size_t len;
} mem_writer;

static int mem_write(void *user, const uint8_t *data, size_t len)
{
    mem_writer *w = user;
    if (len > w->cap - w->len)
        return -1;
    memcpy(w->out + w->len, data, len);
    w->len += len;
    return 0;
}

long zc_inflate_zlib(const uint8_t *in, size_t inlen, uint8_t *out,
                     size_t outcap)
{
    mem_reader r = {in, inlen, 0};
    mem_writer w = {out, outcap, 0};
    long n = zc_inflate_stream(1, mem_read, &r, mem_write, &w, outcap);
    return n < 0 ? -1 : (long)w.len;
}

long zc_inflate_raw(const uint8_t *in, size_t inlen, size_t *consumed,
                    uint8_t *out, size_t outcap)
{
    mem_reader r = {in, inlen, 0};
    mem_writer w = {out, outcap, 0};
    long n = zc_inflate_stream(0, mem_read, &r, mem_write, &w, outcap);
    if (consumed != NULL) /* bytes consumed, minus what is still buffered */
        *consumed = r.consumed - (g_state.in_len - g_state.in_pos);
    return n < 0 ? -1 : (long)w.len;
}
