/*
 * ZapC - QR code encoder following ISO/IEC 18004 (byte mode only).
 */
#include "zapc/qr.h"

#include <string.h>

static const int8_t ECC_PER_BLOCK[4][41] = {
    {-1, 7,  10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30,
     22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30,
     30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
    {-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24,
     24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28,
     28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
    {-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20,
     30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30,
     30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
    {-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24,
     24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30,
     30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
};

static const int8_t NUM_BLOCKS[4][41] = {
    {-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
     8,  9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
    {-1, 1,  1,  1,  2,  2,  4,  4,  4,  5,  5,  5,  8,  9,
     9,  10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25,
     26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
    {-1, 1,  1,  2,  2,  4,  4,  6,  6,  8,  8,  8,  10, 12,
     16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34,
     35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
    {-1, 1,  1,  2,  4,  4,  4,  5,  6,  8,  8,  11, 11, 16,
     16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40,
     42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
};

/* Format information bits for each ECC level (L, M, Q, H). */
static const int ECL_FORMAT_BITS[4] = {1, 0, 3, 2};

static int num_raw_modules(int ver)
{
    int result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
        int num_align = ver / 7 + 2;
        result -= (25 * num_align - 10) * num_align - 55;
        if (ver >= 7)
            result -= 36;
    }
    return result;
}

static int num_data_codewords(int ver, int ecl)
{
    return num_raw_modules(ver) / 8 -
           ECC_PER_BLOCK[ecl][ver] * NUM_BLOCKS[ecl][ver];
}

/* ---- GF(256) Reed-Solomon ---------------------------------------------- */

static uint8_t gf_mul(uint8_t x, uint8_t y)
{
    unsigned z = 0;
    for (int i = 7; i >= 0; i--) {
        z = (z << 1) ^ ((z >> 7) * 0x11Du);
        z ^= ((unsigned)(y >> i) & 1u) * x;
    }
    return (uint8_t)z;
}

static void rs_divisor(int degree, uint8_t *result)
{
    memset(result, 0, (size_t)degree);
    result[degree - 1] = 1;
    uint8_t root = 1;
    for (int i = 0; i < degree; i++) {
        for (int j = 0; j < degree; j++) {
            result[j] = gf_mul(result[j], root);
            if (j + 1 < degree)
                result[j] ^= result[j + 1];
        }
        root = gf_mul(root, 0x02);
    }
}

static void rs_remainder(const uint8_t *data, int len, const uint8_t *div,
                         int degree, uint8_t *result)
{
    memset(result, 0, (size_t)degree);
    for (int i = 0; i < len; i++) {
        uint8_t factor = data[i] ^ result[0];
        memmove(result, result + 1, (size_t)(degree - 1));
        result[degree - 1] = 0;
        for (int j = 0; j < degree; j++)
            result[j] ^= gf_mul(div[j], factor);
    }
}

/* ---- module helpers ------------------------------------------------------ */

static void set_fn(qr_code *qr, int x, int y, int dark)
{
    qr->modules[y * qr->size + x] = (uint8_t)(dark != 0);
    qr->function[y * qr->size + x] = 1;
}

static void draw_finder(qr_code *qr, int x, int y)
{
    for (int dy = -4; dy <= 4; dy++) {
        for (int dx = -4; dx <= 4; dx++) {
            int adx = dx < 0 ? -dx : dx, ady = dy < 0 ? -dy : dy;
            int dist = adx > ady ? adx : ady;
            int xx = x + dx, yy = y + dy;
            if (xx >= 0 && xx < qr->size && yy >= 0 && yy < qr->size)
                set_fn(qr, xx, yy, dist != 2 && dist != 4);
        }
    }
}

static void draw_alignment(qr_code *qr, int x, int y)
{
    for (int dy = -2; dy <= 2; dy++)
        for (int dx = -2; dx <= 2; dx++) {
            int adx = dx < 0 ? -dx : dx, ady = dy < 0 ? -dy : dy;
            set_fn(qr, x + dx, y + dy, (adx > ady ? adx : ady) != 1);
        }
}

static int alignment_positions(int ver, int size, int *pos)
{
    if (ver == 1)
        return 0;
    int num = ver / 7 + 2;
    int step = (ver == 32) ? 26 : (ver * 4 + num * 2 + 1) / (num * 2 - 2) * 2;
    pos[0] = 6;
    for (int i = num - 1, p = size - 7; i >= 1; i--, p -= step)
        pos[i] = p;
    return num;
}

static void draw_format(qr_code *qr, int ecl, int mask)
{
    int data = ECL_FORMAT_BITS[ecl] << 3 | mask;
    int rem = data;
    for (int i = 0; i < 10; i++)
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    int bits = (data << 10 | rem) ^ 0x5412;
    int s = qr->size;
    for (int i = 0; i <= 5; i++)
        set_fn(qr, 8, i, (bits >> i) & 1);
    set_fn(qr, 8, 7, (bits >> 6) & 1);
    set_fn(qr, 8, 8, (bits >> 7) & 1);
    set_fn(qr, 7, 8, (bits >> 8) & 1);
    for (int i = 9; i < 15; i++)
        set_fn(qr, 14 - i, 8, (bits >> i) & 1);
    for (int i = 0; i < 8; i++)
        set_fn(qr, s - 1 - i, 8, (bits >> i) & 1);
    for (int i = 8; i < 15; i++)
        set_fn(qr, 8, s - 15 + i, (bits >> i) & 1);
    set_fn(qr, 8, s - 8, 1);
}

static void draw_version(qr_code *qr)
{
    if (qr->version < 7)
        return;
    int rem = qr->version;
    for (int i = 0; i < 12; i++)
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    long bits = (long)qr->version << 12 | rem;
    for (int i = 0; i < 18; i++) {
        int bit = (int)((bits >> i) & 1);
        int a = qr->size - 11 + i % 3, b = i / 3;
        set_fn(qr, a, b, bit);
        set_fn(qr, b, a, bit);
    }
}

static void draw_function_patterns(qr_code *qr, int ecl)
{
    int s = qr->size;
    for (int i = 0; i < s; i++) {
        set_fn(qr, 6, i, i % 2 == 0);
        set_fn(qr, i, 6, i % 2 == 0);
    }
    draw_finder(qr, 3, 3);
    draw_finder(qr, s - 4, 3);
    draw_finder(qr, 3, s - 4);
    int pos[8];
    int n = alignment_positions(qr->version, s, pos);
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            if (!((i == 0 && j == 0) || (i == 0 && j == n - 1) ||
                  (i == n - 1 && j == 0)))
                draw_alignment(qr, pos[i], pos[j]);
    draw_format(qr, ecl, 0); /* placeholder, redrawn after masking */
    draw_version(qr);
}

static void draw_codewords(qr_code *qr, const uint8_t *data, int len)
{
    int s = qr->size;
    long i = 0;
    long total = (long)len * 8;
    for (int right = s - 1; right >= 1; right -= 2) {
        if (right == 6)
            right = 5;
        for (int vert = 0; vert < s; vert++) {
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                int upward = ((right + 1) & 2) == 0;
                int y = upward ? s - 1 - vert : vert;
                if (!qr->function[y * s + x] && i < total) {
                    qr->modules[y * s + x] =
                        (uint8_t)((data[i >> 3] >> (7 - (i & 7))) & 1);
                    i++;
                }
            }
        }
    }
}

static int mask_bit(int mask, int x, int y)
{
    switch (mask) {
    case 0: return (x + y) % 2 == 0;
    case 1: return y % 2 == 0;
    case 2: return x % 3 == 0;
    case 3: return (x + y) % 3 == 0;
    case 4: return (x / 3 + y / 2) % 2 == 0;
    case 5: return x * y % 2 + x * y % 3 == 0;
    case 6: return (x * y % 2 + x * y % 3) % 2 == 0;
    default: return ((x + y) % 2 + x * y % 3) % 2 == 0;
    }
}

static void apply_mask(qr_code *qr, int mask)
{
    int s = qr->size;
    for (int y = 0; y < s; y++)
        for (int x = 0; x < s; x++)
            if (!qr->function[y * s + x] && mask_bit(mask, x, y))
                qr->modules[y * s + x] ^= 1;
}

/* Simplified penalty score (rules 1, 2, 3 and 4 of the standard). */
static long penalty(const qr_code *qr)
{
    int s = qr->size;
    long score = 0;
    for (int pass = 0; pass < 2; pass++) {
        for (int a = 0; a < s; a++) {
            int run = 0, prev = -1;
            for (int b = 0; b < s; b++) {
                int c = pass == 0 ? qr_module(qr, b, a) : qr_module(qr, a, b);
                if (c == prev) {
                    run++;
                    if (run == 5)
                        score += 3;
                    else if (run > 5)
                        score++;
                } else {
                    prev = c;
                    run = 1;
                }
            }
            /* finder-like 1:1:3:1:1 with 4 light modules on one side */
            for (int b = 0; b + 10 < s; b++) {
                static const uint8_t p1[11] = {1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0};
                static const uint8_t p2[11] = {0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1};
                int m1 = 1, m2 = 1;
                for (int k = 0; k < 11; k++) {
                    int c = pass == 0 ? qr_module(qr, b + k, a)
                                      : qr_module(qr, a, b + k);
                    if (c != p1[k])
                        m1 = 0;
                    if (c != p2[k])
                        m2 = 0;
                }
                score += 40 * (m1 + m2);
            }
        }
    }
    for (int y = 0; y + 1 < s; y++)
        for (int x = 0; x + 1 < s; x++) {
            int c = qr_module(qr, x, y);
            if (c == qr_module(qr, x + 1, y) && c == qr_module(qr, x, y + 1) &&
                c == qr_module(qr, x + 1, y + 1))
                score += 3;
        }
    long dark = 0;
    for (int i = 0; i < s * s; i++)
        dark += qr->modules[i];
    long total = (long)s * s;
    long k = ((dark * 20 - total * 10) < 0 ? -(dark * 20 - total * 10)
                                           : (dark * 20 - total * 10)) /
             total;
    score += k * 10;
    return score;
}

int qr_encode(qr_code *qr, const uint8_t *data, size_t len, int ecl,
              int min_version, int mask)
{
    static uint8_t codewords[2048];
    static uint8_t interleaved[2048];
    static uint8_t ecc[32];
    static uint8_t divisor[32];

    if (ecl < 0 || ecl > 3)
        return -1;
    int ver;
    for (ver = min_version < 1 ? 1 : min_version; ver <= QR_MAX_VERSION; ver++) {
        size_t cap_bits = (size_t)num_data_codewords(ver, ecl) * 8;
        size_t need = 4 + (ver < 10 ? 8u : 16u) + len * 8;
        if (need <= cap_bits)
            break;
    }
    if (ver > QR_MAX_VERSION)
        return -1;

    /* --- data bit stream --- */
    int data_cw = num_data_codewords(ver, ecl);
    memset(codewords, 0, sizeof codewords);
    size_t bit = 0;
#define PUT_BITS(val, n)                                                    \
    do {                                                                    \
        for (int b_ = (n) - 1; b_ >= 0; b_--, bit++)                        \
            if (((unsigned long)(val) >> b_) & 1u)                          \
                codewords[bit >> 3] |= (uint8_t)(0x80u >> (bit & 7));       \
    } while (0)
    PUT_BITS(4, 4); /* byte mode */
    PUT_BITS(len, ver < 10 ? 8 : 16);
    for (size_t i = 0; i < len; i++)
        PUT_BITS(data[i], 8);
    size_t cap = (size_t)data_cw * 8;
    size_t term = cap - bit < 4 ? cap - bit : 4;
    bit += term;
    bit = (bit + 7) & ~(size_t)7;
    for (uint8_t pad = 0xEC; bit < cap; pad ^= 0xEC ^ 0x11) {
        PUT_BITS(pad, 8);
    }
#undef PUT_BITS

    /* --- error correction and interleaving --- */
    int num_blocks = NUM_BLOCKS[ecl][ver];
    int block_ecc = ECC_PER_BLOCK[ecl][ver];
    int raw_cw = num_raw_modules(ver) / 8;
    int num_short = num_blocks - raw_cw % num_blocks;
    int short_len = raw_cw / num_blocks;
    rs_divisor(block_ecc, divisor);

    /* blocks are laid out with stride short_len+1 inside a temp area */
    static uint8_t blocks[2048 + 128];
    int k = 0;
    for (int i = 0; i < num_blocks; i++) {
        int dlen = short_len - block_ecc + (i < num_short ? 0 : 1);
        uint8_t *blk = blocks + i * (short_len + 1);
        memset(blk, 0, (size_t)short_len + 1);
        memcpy(blk, codewords + k, (size_t)dlen);
        k += dlen;
        rs_remainder(blk, dlen, divisor, block_ecc, ecc);
        /* short blocks get a dummy byte so all blocks align */
        int ecc_at = short_len + 1 - block_ecc;
        memcpy(blk + ecc_at, ecc, (size_t)block_ecc);
    }
    int out = 0;
    for (int i = 0; i < short_len + 1; i++)
        for (int j = 0; j < num_blocks; j++)
            if (i != short_len - block_ecc || j >= num_short)
                interleaved[out++] = blocks[j * (short_len + 1) + i];

    /* --- modules --- */
    qr->version = ver;
    qr->size = ver * 4 + 17;
    size_t area = (size_t)qr->size * (size_t)qr->size;
    memset(qr->modules, 0, area);
    memset(qr->function, 0, area);
    draw_function_patterns(qr, ecl);
    draw_codewords(qr, interleaved, out);

    if (mask < 0) {
        long best = -1;
        int best_mask = 0;
        for (int m = 0; m < 8; m++) {
            apply_mask(qr, m);
            draw_format(qr, ecl, m);
            long p = penalty(qr);
            if (best < 0 || p < best) {
                best = p;
                best_mask = m;
            }
            apply_mask(qr, m); /* undo (XOR) */
        }
        mask = best_mask;
    }
    apply_mask(qr, mask);
    draw_format(qr, ecl, mask);
    qr->mask = mask;
    return 0;
}

void qr_render(const qr_code *qr, int unicode, int invert, int quiet,
               void (*emit)(void *user, const char *line), void *user)
{
    char line[QR_MAX_SIZE * 8 + 64];
    int lo = -quiet, hi = qr->size + quiet;
    if (unicode) {
        for (int y = lo; y < hi; y += 2) {
            size_t n = 0;
            for (int x = lo; x < hi; x++) {
                /* "on" = draw a block for this half */
                int top = qr_module(qr, x, y) ^ !invert;
                int bot = (y + 1 < hi) ? (qr_module(qr, x, y + 1) ^ !invert)
                                       : 0;
                const char *g = top && bot ? "\xe2\x96\x88"      /* █ */
                                : top      ? "\xe2\x96\x80"      /* ▀ */
                                : bot      ? "\xe2\x96\x84"      /* ▄ */
                                           : " ";
                size_t gl = strlen(g);
                memcpy(line + n, g, gl);
                n += gl;
            }
            line[n] = '\0';
            emit(user, line);
        }
    } else {
        for (int y = lo; y < hi; y++) {
            size_t n = 0;
            for (int x = lo; x < hi; x++) {
                int on = qr_module(qr, x, y) ^ !invert;
                line[n++] = on ? '#' : ' ';
                line[n++] = on ? '#' : ' ';
            }
            line[n] = '\0';
            emit(user, line);
        }
    }
}
