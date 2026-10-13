/*
 * ZapC - QR code encoder (byte mode, versions 1..QR_MAX_VERSION).
 */
#ifndef ZAPC_QR_H
#define ZAPC_QR_H

#include <stddef.h>
#include <stdint.h>

#define QR_MAX_VERSION 20
#define QR_MAX_SIZE (QR_MAX_VERSION * 4 + 17)

enum { QR_ECC_LOW = 0, QR_ECC_MEDIUM, QR_ECC_QUARTILE, QR_ECC_HIGH };

typedef struct {
    int version;
    int size;
    int mask;
    uint8_t modules[QR_MAX_SIZE * QR_MAX_SIZE];  /* 1 = dark */
    uint8_t function[QR_MAX_SIZE * QR_MAX_SIZE]; /* scratch */
} qr_code;

/*
 * Encode data choosing the smallest version that fits.  mask = -1 picks the
 * best mask automatically.  Returns 0 on success, -1 if the data is too long.
 */
int qr_encode(qr_code *qr, const uint8_t *data, size_t len, int ecl,
              int min_version, int mask);

static inline int qr_module(const qr_code *qr, int x, int y)
{
    if (x < 0 || y < 0 || x >= qr->size || y >= qr->size)
        return 0;
    return qr->modules[y * qr->size + x];
}

/*
 * Render for a terminal.  unicode=1 uses half blocks (2 modules per line),
 * otherwise "##" pairs.  invert=0 assumes a dark terminal background (light
 * modules are drawn).  Calls emit() once per output line (without newline).
 */
void qr_render(const qr_code *qr, int unicode, int invert, int quiet,
               void (*emit)(void *user, const char *line), void *user);

#endif
