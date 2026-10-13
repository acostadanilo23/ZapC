/*
 * ZapC - token dictionary lookups.
 */
#include "zapc/binary_node.h"

#include <string.h>

#include "tokens_table.h"

/*
 * Reverse lookup table: open addressing over FNV-1a hashes.  Each slot holds
 * (code + 1) where code < 256 is a single-byte token and code >= 256 encodes
 * 256 + dict*256 + index.  4 KiB of static memory.
 */
#define TOKEN_HASH_SIZE 2048u

static uint16_t g_hash[TOKEN_HASH_SIZE];
static int g_hash_ready;

static uint32_t fnv1a(const char *s, size_t n)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

static const char *code_str(unsigned code)
{
    if (code < 256)
        return wa_single_tokens[code];
    code -= 256;
    return wa_double_tokens[code >> 8][code & 255];
}

static void insert(unsigned code)
{
    const char *s = code_str(code);
    uint32_t h = fnv1a(s, strlen(s)) & (TOKEN_HASH_SIZE - 1);
    while (g_hash[h] != 0) {
        /* keep the first (lowest) code for duplicate strings */
        if (strcmp(code_str((unsigned)g_hash[h] - 1), s) == 0)
            return;
        h = (h + 1) & (TOKEN_HASH_SIZE - 1);
    }
    g_hash[h] = (uint16_t)(code + 1);
}

static void build_hash(void)
{
    for (unsigned i = 1; i < WA_SINGLE_TOKEN_COUNT; i++)
        insert(i);
    for (unsigned d = 0; d < WA_DOUBLE_DICT_COUNT; d++)
        for (unsigned i = 0; i < 256; i++)
            insert(256 + d * 256 + i);
    g_hash_ready = 1;
}

const char *wa_token_single(unsigned index)
{
    if (index == 0 || index >= WA_SINGLE_TOKEN_COUNT)
        return NULL;
    return wa_single_tokens[index];
}

const char *wa_token_double(unsigned dict, unsigned index)
{
    if (dict >= WA_DOUBLE_DICT_COUNT || index >= 256)
        return NULL;
    return wa_double_tokens[dict][index];
}

int wa_token_lookup(const char *s, size_t len, unsigned *dict, unsigned *idx)
{
    if (!g_hash_ready)
        build_hash();
    if (len == 0)
        return 0;
    uint32_t h = fnv1a(s, len) & (TOKEN_HASH_SIZE - 1);
    while (g_hash[h] != 0) {
        unsigned code = (unsigned)g_hash[h] - 1;
        const char *t = code_str(code);
        if (strlen(t) == len && memcmp(t, s, len) == 0) {
            if (code < 256) {
                *idx = code;
                return 1;
            }
            code -= 256;
            *dict = code >> 8;
            *idx = code & 255;
            return 2;
        }
        h = (h + 1) & (TOKEN_HASH_SIZE - 1);
    }
    return 0;
}
