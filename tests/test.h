/*
 * ZapC - minimal unit test helpers (no external framework).
 */
#ifndef ZAPC_TEST_H
#define ZAPC_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int t_failures;
static int t_checks;

#define CHECK(cond)                                                          \
    do {                                                                     \
        t_checks++;                                                          \
        if (!(cond)) {                                                       \
            t_failures++;                                                    \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                    \
    } while (0)

#define CHECK_MEM(a, b, n) CHECK(memcmp((a), (b), (n)) == 0)
#define CHECK_STR(a, b) CHECK(strcmp((a), (b)) == 0)

#define RUN(fn)                                                              \
    do {                                                                     \
        int before_ = t_failures;                                            \
        fn();                                                                \
        fprintf(stderr, "  %s %s\n", t_failures == before_ ? "ok  " : "FAIL", \
                #fn);                                                        \
    } while (0)

static inline int test_done(const char *name)
{
    fprintf(stderr, "%s: %d checks, %d failures\n", name, t_checks,
            t_failures);
    return t_failures == 0 ? 0 : 1;
}

/* Decode a hex string into buf; returns length. */
static inline size_t unhex(const char *hex, unsigned char *buf, size_t cap)
{
    size_t n = 0;
    while (hex[0] && hex[1] && n < cap) {
        unsigned v;
        if (sscanf(hex, "%2x", &v) != 1)
            break;
        buf[n++] = (unsigned char)v;
        hex += 2;
    }
    return n;
}

#endif
