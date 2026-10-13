#include "zapc/memory.h"

#include <stdlib.h>
#include <string.h>

#if defined(ZAPC_MEM_DEBUG) && ZAPC_MEM_DEBUG

/*
 * Each block is prefixed with a header carrying its size.  The header is
 * padded to max_align_t so the returned pointer keeps malloc's alignment.
 */
typedef union {
    size_t size;
    max_align_t align;
} mem_hdr;

static zap_mem_counters g_mem = {0, 0, 0, 0, 1};

static void account_add(size_t n)
{
    g_mem.live_allocs++;
    g_mem.total_allocs++;
    g_mem.live_bytes += n;
    if (g_mem.live_bytes > g_mem.peak_bytes)
        g_mem.peak_bytes = g_mem.live_bytes;
}

void *zap_malloc(size_t n)
{
    if (n > SIZE_MAX - sizeof(mem_hdr))
        return NULL;
    mem_hdr *h = malloc(sizeof(mem_hdr) + n);
    if (h == NULL)
        return NULL;
    h->size = n;
    account_add(n);
    return h + 1;
}

void *zap_calloc(size_t count, size_t n)
{
    if (n != 0 && count > SIZE_MAX / n)
        return NULL;
    void *p = zap_malloc(count * n);
    if (p != NULL)
        memset(p, 0, count * n);
    return p;
}

void zap_free(void *p)
{
    if (p == NULL)
        return;
    mem_hdr *h = (mem_hdr *)p - 1;
    g_mem.live_allocs--;
    g_mem.live_bytes -= h->size;
    free(h);
}

void *zap_realloc(void *p, size_t n)
{
    if (p == NULL)
        return zap_malloc(n);
    if (n > SIZE_MAX - sizeof(mem_hdr))
        return NULL;
    mem_hdr *h = (mem_hdr *)p - 1;
    size_t old = h->size;
    mem_hdr *nh = realloc(h, sizeof(mem_hdr) + n);
    if (nh == NULL)
        return NULL;
    nh->size = n;
    g_mem.live_bytes = g_mem.live_bytes - old + n;
    g_mem.total_allocs++;
    if (g_mem.live_bytes > g_mem.peak_bytes)
        g_mem.peak_bytes = g_mem.live_bytes;
    return nh + 1;
}

void zap_mem_counters_get(zap_mem_counters *out) { *out = g_mem; }

#else

void *zap_malloc(size_t n) { return malloc(n); }
void *zap_calloc(size_t count, size_t n) { return calloc(count, n); }
void *zap_realloc(void *p, size_t n) { return realloc(p, n); }
void zap_free(void *p) { free(p); }

void zap_mem_counters_get(zap_mem_counters *out)
{
    memset(out, 0, sizeof *out);
}

#endif

void zap_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--)
        *v++ = 0;
}

int zap_ct_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= (uint8_t)(x[i] ^ y[i]);
    return d != 0;
}

void zap_arena_init(zap_arena *a, void *buf, size_t cap)
{
    a->base = buf;
    a->cap = cap;
    a->used = 0;
    a->peak = 0;
}

void *zap_arena_alloc(zap_arena *a, size_t n)
{
    const size_t align = sizeof(void *);
    size_t start = (a->used + align - 1) & ~(align - 1);
    if (start > a->cap || n > a->cap - start)
        return NULL;
    a->used = start + n;
    if (a->used > a->peak)
        a->peak = a->used;
    return a->base + start;
}

char *zap_arena_strndup(zap_arena *a, const char *s, size_t n)
{
    char *d = zap_arena_alloc(a, n + 1);
    if (d == NULL)
        return NULL;
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

void zap_arena_reset(zap_arena *a) { a->used = 0; }
