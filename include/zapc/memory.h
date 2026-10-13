/*
 * ZapC - memory helpers.
 *
 * zap_malloc() & friends are thin wrappers around the libc allocator.  When
 * built with ZAPC_MEM_DEBUG they keep counters of live allocations, live bytes
 * and peak bytes.  The main path of the client should mostly avoid the heap
 * and use fixed buffers or the arena below.
 */
#ifndef ZAPC_MEMORY_H
#define ZAPC_MEMORY_H

#include <stddef.h>
#include <stdint.h>

void *zap_malloc(size_t n);
void *zap_calloc(size_t count, size_t n);
void *zap_realloc(void *p, size_t n);
void zap_free(void *p);

typedef struct {
    size_t live_allocs;
    size_t live_bytes;
    size_t peak_bytes;
    size_t total_allocs;
    int enabled;
} zap_mem_counters;

void zap_mem_counters_get(zap_mem_counters *out);

/* Wipe sensitive memory in a way the compiler will not optimise away. */
void zap_secure_zero(void *p, size_t n);

/* Constant-time comparison. Returns 0 when equal. */
int zap_ct_memcmp(const void *a, const void *b, size_t n);

/*
 * Bump allocator over a caller-provided buffer.  Reset it to free
 * everything at once (e.g. after each processed network frame).
 */
typedef struct {
    uint8_t *base;
    size_t cap;
    size_t used;
    size_t peak;
} zap_arena;

void zap_arena_init(zap_arena *a, void *buf, size_t cap);
void *zap_arena_alloc(zap_arena *a, size_t n);
char *zap_arena_strndup(zap_arena *a, const char *s, size_t n);
void zap_arena_reset(zap_arena *a);

#endif
