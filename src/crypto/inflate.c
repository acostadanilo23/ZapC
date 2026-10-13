/*
 * ZapC - small zlib/DEFLATE decoder (RFC 1950/1951).
 *
 * Output goes into a fixed caller buffer; input larger than the buffer is
 * rejected.  Uses canonical Huffman decoding by code length (the method used
 * by Mark Adler's "puff"), which needs very little memory.
 */
#include "zapc/inflate.h"

#include <string.h>

#define MAXBITS 15
#define MAXLCODES 286
#define MAXDCODES 30
#define FIXLCODES 288

typedef struct {
    const uint8_t *in;
    size_t inlen;
    size_t inpos;
    uint32_t bitbuf;
    unsigned bitcnt;
    uint8_t *out;
    size_t outcap;
    size_t outpos;
    int err;
} inf_state;

typedef struct {
    uint16_t count[MAXBITS + 1];
    uint16_t symbol[FIXLCODES];
} huffman;

static unsigned getbits(inf_state *s, unsigned need)
{
    uint32_t val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->inpos >= s->inlen) {
            s->err = 1;
            return 0;
        }
        val |= (uint32_t)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = need < 32 ? val >> need : 0;
    s->bitcnt -= need;
    return (unsigned)(val & ((1u << need) - 1u));
}

static int stored(inf_state *s)
{
    s->bitbuf = 0;
    s->bitcnt = 0;
    if (s->inpos + 4 > s->inlen)
        return -1;
    unsigned len = s->in[s->inpos] | ((unsigned)s->in[s->inpos + 1] << 8);
    unsigned nlen = s->in[s->inpos + 2] | ((unsigned)s->in[s->inpos + 3] << 8);
    s->inpos += 4;
    if (len != (~nlen & 0xffffu))
        return -1;
    if (len > s->inlen - s->inpos || len > s->outcap - s->outpos)
        return -1;
    memcpy(s->out + s->outpos, s->in + s->inpos, len);
    s->inpos += len;
    s->outpos += len;
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
            if (s->outpos >= s->outcap)
                return -1;
            s->out[s->outpos++] = (uint8_t)sym;
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
            if (s->err || dist > s->outpos || len > s->outcap - s->outpos)
                return -1;
            for (size_t i = 0; i < len; i++, s->outpos++)
                s->out[s->outpos] = s->out[s->outpos - dist];
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

long zc_inflate_raw(const uint8_t *in, size_t inlen, size_t *consumed,
                    uint8_t *out, size_t outcap)
{
    inf_state s;
    memset(&s, 0, sizeof s);
    s.in = in;
    s.inlen = inlen;
    s.out = out;
    s.outcap = outcap;
    int last;
    do {
        last = (int)getbits(&s, 1);
        unsigned type = getbits(&s, 2);
        if (s.err)
            return -1;
        int r;
        if (type == 0)
            r = stored(&s);
        else if (type == 1)
            r = fixed(&s);
        else if (type == 2)
            r = dynamic(&s);
        else
            r = -1;
        if (r != 0 || s.err)
            return -1;
    } while (!last);
    if (consumed != NULL)
        *consumed = s.inpos;
    return (long)s.outpos;
}

static uint32_t adler32(const uint8_t *p, size_t n)
{
    uint32_t a = 1, b = 0;
    while (n > 0) {
        size_t chunk = n < 3800 ? n : 3800;
        n -= chunk;
        while (chunk--) {
            a += *p++;
            b += a;
        }
        a %= 65521u;
        b %= 65521u;
    }
    return (b << 16) | a;
}

long zc_inflate_zlib(const uint8_t *in, size_t inlen, uint8_t *out,
                     size_t outcap)
{
    if (inlen < 6)
        return -1;
    unsigned cmf = in[0], flg = in[1];
    if ((cmf & 15) != 8 || (cmf >> 4) > 7 || ((cmf << 8) | flg) % 31 != 0 ||
        (flg & 0x20))
        return -1;
    size_t used = 0;
    long n = zc_inflate_raw(in + 2, inlen - 2, &used, out, outcap);
    if (n < 0)
        return -1;
    size_t pos = 2 + used;
    if (pos + 4 > inlen)
        return -1;
    uint32_t want = ((uint32_t)in[pos] << 24) | ((uint32_t)in[pos + 1] << 16) |
                    ((uint32_t)in[pos + 2] << 8) | in[pos + 3];
    if (adler32(out, (size_t)n) != want)
        return -1;
    return n;
}
