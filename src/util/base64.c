#include "zapc/util.h"

static const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encoded_len(size_t n) { return ((n + 2) / 3) * 4; }

size_t base64_encode(const void *in, size_t n, char *out, size_t out_cap)
{
    const uint8_t *p = in;
    size_t need = base64_encoded_len(n);
    if (out_cap < need + 1)
        return 0;
    size_t o = 0;
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8) |
                     (uint32_t)p[i + 2];
        out[o++] = b64_alphabet[(v >> 18) & 63];
        out[o++] = b64_alphabet[(v >> 12) & 63];
        out[o++] = b64_alphabet[(v >> 6) & 63];
        out[o++] = b64_alphabet[v & 63];
    }
    if (i < n) {
        uint32_t v = (uint32_t)p[i] << 16;
        if (i + 1 < n)
            v |= (uint32_t)p[i + 1] << 8;
        out[o++] = b64_alphabet[(v >> 18) & 63];
        out[o++] = b64_alphabet[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? b64_alphabet[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+' || c == '-')
        return 62;
    if (c == '/' || c == '_')
        return 63;
    return -1;
}

long base64_decode(const char *in, size_t n, void *out, size_t out_cap)
{
    uint8_t *o = out;
    size_t olen = 0;
    uint32_t acc = 0;
    int bits = 0;
    size_t pad = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c == '=') {
            pad++;
            continue;
        }
        if (pad > 0)
            return -1; /* data after padding */
        int v = b64_value(c);
        if (v < 0)
            return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (olen >= out_cap)
                return -1;
            o[olen++] = (uint8_t)(acc >> bits);
        }
    }
    if (pad > 2 || bits >= 6)
        return -1;
    return (long)olen;
}
