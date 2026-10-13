/*
 * ZapC - portable Curve25519: X25519 and XEdDSA (libsignal compatible).
 *
 * The field and group arithmetic follows TweetNaCl (Bernstein, van Gastel,
 * Janssen, Lange, Schwabe, Smetsers - public domain).  It is small and
 * endian/alignment independent, which matters for the MIPS R5900 port.  It is
 * not the fastest implementation; a faster one can be swapped in behind the
 * same API if profiling on the PS2 requires it.
 *
 * Signatures implement libsignal's curve25519_sign()/curve25519_verify():
 * an Ed25519 signature computed directly with the X25519 private scalar,
 * with the sign bit of the Edwards public key stored in the top bit of S.
 */
#include "zapc/crypto.h"
#include "zapc/memory.h"
#include "zapc/platform.h"

#include <string.h>

typedef int64_t gf[16];

static const gf gf0;
static const gf gf1 = {1};
static const gf c121665 = {0xDB41, 1};
static const gf D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141,
                     0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
                     0xfe73, 0x2b6f, 0x6cee, 0x5203};
static const gf D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283,
                      0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
                      0xfce7, 0x56df, 0xd9dc, 0x2406};
static const gf X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525,
                     0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
                     0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const gf Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666};
static const gf I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f,
                     0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
                     0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static void set25519(gf r, const gf a)
{
    for (int i = 0; i < 16; i++)
        r[i] = a[i];
}

/*
 * Note: relies on arithmetic right shift of negative values, which every
 * compiler/target we care about (GCC/Clang, x86, MIPS) implements.
 */
static void car25519(gf o)
{
    for (int i = 0; i < 16; i++) {
        o[i] += (int64_t)1 << 16;
        int64_t c = o[i] >> 16;
        if (i < 15)
            o[i + 1] += c - 1;
        else
            o[0] += 38 * (c - 1);
        o[i] -= c * 65536;
    }
}

static void sel25519(gf p, gf q, int b)
{
    int64_t c = ~((int64_t)b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n)
{
    gf m, t;
    set25519(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xff);
    }
}

static int verify32(const uint8_t *x, const uint8_t *y)
{
    return zap_ct_memcmp(x, y, 32) ? -1 : 0;
}

static int neq25519(const gf a, const gf b)
{
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return verify32(c, d);
}

static uint8_t par25519(const gf a)
{
    uint8_t d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static void unpack25519(gf o, const uint8_t *n)
{
    for (int i = 0; i < 16; i++)
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void fA(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++)
        o[i] = a[i] + b[i];
}

static void fZ(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++)
        o[i] = a[i] - b[i];
}

static void fM(gf o, const gf a, const gf b)
{
    int64_t t[31];
    for (int i = 0; i < 31; i++)
        t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++)
        t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++)
        o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void fS(gf o, const gf a) { fM(o, a, a); }

static void inv25519(gf o, const gf in)
{
    gf c;
    set25519(c, in);
    for (int a = 253; a >= 0; a--) {
        fS(c, c);
        if (a != 2 && a != 4)
            fM(c, c, in);
    }
    set25519(o, c);
}

static void pow2523(gf o, const gf in)
{
    gf c;
    set25519(c, in);
    for (int a = 250; a >= 0; a--) {
        fS(c, c);
        if (a != 1)
            fM(c, c, in);
    }
    set25519(o, c);
}

/* ---- X25519 ------------------------------------------------------------- */

static void x25519(uint8_t *q, const uint8_t *n, const uint8_t *p)
{
    uint8_t z[32];
    gf x, a, b, c, d, e, f;
    for (int i = 0; i < 31; i++)
        z[i] = n[i];
    z[31] = (uint8_t)((n[31] & 127) | 64);
    z[0] &= 248;
    unpack25519(x, p);
    for (int i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        fA(e, a, c);
        fZ(a, a, c);
        fA(c, b, d);
        fZ(b, b, d);
        fS(d, e);
        fS(f, a);
        fM(a, c, a);
        fM(c, b, e);
        fA(e, a, c);
        fZ(a, a, c);
        fS(b, a);
        fZ(c, d, f);
        fM(a, c, c121665);
        fA(a, a, d);
        fM(c, c, a);
        fM(a, d, f);
        fM(d, b, x);
        fS(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    fM(a, a, c);
    pack25519(q, a);
    zap_secure_zero(z, sizeof z);
}

void curve25519_clamp(uint8_t priv[32])
{
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
}

void curve25519_public(uint8_t pub[32], const uint8_t priv[32])
{
    static const uint8_t base[32] = {9};
    x25519(pub, priv, base);
}

int curve25519_keypair(uint8_t priv[32], uint8_t pub[32])
{
    if (plat_random(priv, 32) != 0)
        return -1;
    curve25519_clamp(priv);
    curve25519_public(pub, priv);
    return 0;
}

int curve25519_shared(uint8_t out[32], const uint8_t priv[32],
                      const uint8_t pub[32])
{
    static const uint8_t zero[32];
    x25519(out, priv, pub);
    return zap_ct_memcmp(out, zero, 32) ? 0 : -1;
}

/* ---- Edwards group ------------------------------------------------------ */

static void ge_add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;
    fZ(a, p[1], p[0]);
    fZ(t, q[1], q[0]);
    fM(a, a, t);
    fA(b, p[0], p[1]);
    fA(t, q[0], q[1]);
    fM(b, b, t);
    fM(c, p[3], q[3]);
    fM(c, c, D2);
    fM(d, p[2], q[2]);
    fA(d, d, d);
    fZ(e, b, a);
    fZ(f, d, c);
    fA(g, d, c);
    fA(h, b, a);
    fM(p[0], e, f);
    fM(p[1], h, g);
    fM(p[2], g, f);
    fM(p[3], e, h);
}

static void ge_cswap(gf p[4], gf q[4], int b)
{
    for (int i = 0; i < 4; i++)
        sel25519(p[i], q[i], b);
}

static void ge_pack(uint8_t *r, gf p[4])
{
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    fM(tx, p[0], zi);
    fM(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= (uint8_t)(par25519(tx) << 7);
}

static void ge_scalarmult(gf p[4], gf q[4], const uint8_t *s)
{
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (int i = 255; i >= 0; --i) {
        int b = (s[i / 8] >> (i & 7)) & 1;
        ge_cswap(p, q, b);
        ge_add(q, p);
        ge_add(p, p);
        ge_cswap(p, q, b);
    }
}

static void ge_scalarbase(gf p[4], const uint8_t *s)
{
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    fM(q[3], X, Y);
    ge_scalarmult(p, q, s);
}

static int ge_unpackneg(gf r[4], const uint8_t p[32])
{
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    fS(num, r[1]);
    fM(den, num, D);
    fZ(num, num, r[2]);
    fA(den, r[2], den);
    fS(den2, den);
    fS(den4, den2);
    fM(den6, den4, den2);
    fM(t, den6, num);
    fM(t, t, den);
    pow2523(t, t);
    fM(t, t, num);
    fM(t, t, den);
    fM(t, t, den);
    fM(r[0], t, den);
    fS(chk, r[0]);
    fM(chk, chk, den);
    if (neq25519(chk, num))
        fM(r[0], r[0], I);
    fS(chk, r[0]);
    fM(chk, chk, den);
    if (neq25519(chk, num))
        return -1;
    if (par25519(r[0]) == (p[31] >> 7))
        fZ(r[0], gf0, r[0]);
    fM(r[3], r[0], r[1]);
    return 0;
}

/* ---- scalars mod L ------------------------------------------------------ */

static const int64_t L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                              0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                              0,    0,    0,    0,    0,    0,    0,    0,
                              0,    0,    0,    0,    0,    0,    0,    0x10};

static void modL(uint8_t *r, int64_t x[64])
{
    int64_t carry;
    int i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++)
        x[j] -= carry * L[j];
    for (i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void reduce64(uint8_t r[64])
{
    int64_t x[64];
    for (int i = 0; i < 64; i++)
        x[i] = r[i];
    memset(r, 0, 64);
    modL(r, x);
}

/* ---- XEdDSA (libsignal curve25519_sign) --------------------------------- */

void curve25519_mont_to_ed(uint8_t ed[32], const uint8_t mont[32])
{
    gf u, a, b, y;
    unpack25519(u, mont);
    fZ(a, u, gf1);
    fA(b, u, gf1);
    inv25519(b, b);
    fM(y, a, b);
    pack25519(ed, y);
}

#define MAX_SIGN_PARTS 8

int xeddsa_sign_v(uint8_t sig[64], const uint8_t priv[32], const zc_iov *parts,
                  size_t n)
{
    uint8_t ed_pub[32];
    uint8_t rnd[64];
    uint8_t prefix[32];
    uint8_t nonce[64];
    uint8_t hram[64];
    uint8_t a[32];
    gf p[4];
    zc_iov v[MAX_SIGN_PARTS + 3];

    if (n > MAX_SIGN_PARTS)
        return -1;
    if (plat_random(rnd, sizeof rnd) != 0)
        return -1;

    memcpy(a, priv, 32);
    curve25519_clamp(a);

    ge_scalarbase(p, a);
    ge_pack(ed_pub, p);
    uint8_t sign_bit = ed_pub[31] & 0x80;

    /* nonce = SHA512(0xFE || 0xFF*31 || a || msg || random) mod L */
    prefix[0] = 0xFE;
    memset(prefix + 1, 0xFF, 31);
    v[0].data = prefix;
    v[0].len = 32;
    v[1].data = a;
    v[1].len = 32;
    for (size_t i = 0; i < n; i++)
        v[2 + i] = parts[i];
    v[2 + n].data = rnd;
    v[2 + n].len = 64;
    if (crypto_sha512_v(v, n + 3, nonce) != 0)
        return -1;
    reduce64(nonce);

    /* R = nonce * B */
    ge_scalarbase(p, nonce);
    ge_pack(sig, p);

    /* h = SHA512(R || A || msg) mod L */
    v[0].data = sig;
    v[0].len = 32;
    v[1].data = ed_pub;
    v[1].len = 32;
    for (size_t i = 0; i < n; i++)
        v[2 + i] = parts[i];
    if (crypto_sha512_v(v, n + 2, hram) != 0)
        return -1;
    reduce64(hram);

    /* S = h * a + nonce mod L */
    int64_t x[64];
    for (int i = 0; i < 64; i++)
        x[i] = 0;
    for (int i = 0; i < 32; i++)
        x[i] = nonce[i];
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            x[i + j] += (int64_t)hram[i] * (int64_t)a[j];
    modL(sig + 32, x);

    sig[63] &= 0x7F;
    sig[63] |= sign_bit;

    zap_secure_zero(a, sizeof a);
    zap_secure_zero(nonce, sizeof nonce);
    zap_secure_zero(rnd, sizeof rnd);
    zap_secure_zero(x, sizeof x);
    return 0;
}

int xeddsa_sign(uint8_t sig[64], const uint8_t priv[32], const void *msg,
                size_t len)
{
    zc_iov v = {msg, len};
    return xeddsa_sign_v(sig, priv, &v, 1);
}

int xeddsa_verify_v(const uint8_t pub[32], const zc_iov *parts, size_t n,
                    const uint8_t sig[64])
{
    uint8_t ed_pub[32];
    uint8_t s[32];
    uint8_t h[64];
    uint8_t t[32];
    gf p[4], q[4];
    zc_iov v[MAX_SIGN_PARTS + 2];

    if (n > MAX_SIGN_PARTS)
        return -1;

    curve25519_mont_to_ed(ed_pub, pub);
    ed_pub[31] &= 0x7F;
    ed_pub[31] |= (uint8_t)(sig[63] & 0x80);

    memcpy(s, sig + 32, 32);
    s[31] &= 0x7F;
    if (s[31] & 0x60) /* S must be < 2^253 (ref10 check) */
        return -1;

    if (ge_unpackneg(q, ed_pub) != 0)
        return -1;

    v[0].data = sig;
    v[0].len = 32;
    v[1].data = ed_pub;
    v[1].len = 32;
    for (size_t i = 0; i < n; i++)
        v[2 + i] = parts[i];
    if (crypto_sha512_v(v, n + 2, h) != 0)
        return -1;
    reduce64(h);

    ge_scalarmult(p, q, h);
    ge_scalarbase(q, s);
    ge_add(p, q);
    ge_pack(t, p);
    return verify32(sig, t);
}

int xeddsa_verify(const uint8_t pub[32], const void *msg, size_t len,
                  const uint8_t sig[64])
{
    zc_iov v = {msg, len};
    return xeddsa_verify_v(pub, &v, 1, sig);
}
