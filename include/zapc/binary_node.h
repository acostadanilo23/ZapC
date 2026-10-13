/*
 * ZapC - WhatsApp binary XML nodes ("binary nodes").
 *
 * Decoded nodes live in a caller-provided arena.  Binary content is not
 * copied: `data` points into the decoded frame, which must stay alive while
 * the node is used.  Attribute values are always NUL-terminated strings;
 * values that were JIDs on the wire are formatted as text and flagged.
 */
#ifndef ZAPC_BINARY_NODE_H
#define ZAPC_BINARY_NODE_H

#include "zapc/memory.h"
#include "zapc/util.h"

#include <stddef.h>
#include <stdint.h>

/* Wire tags. */
enum {
    WA_TAG_LIST_EMPTY = 0,
    WA_TAG_DICT0 = 236,
    WA_TAG_DICT1 = 237,
    WA_TAG_DICT2 = 238,
    WA_TAG_DICT3 = 239,
    WA_TAG_INTEROP_JID = 245,
    WA_TAG_FB_JID = 246,
    WA_TAG_AD_JID = 247,
    WA_TAG_LIST8 = 248,
    WA_TAG_LIST16 = 249,
    WA_TAG_JID_PAIR = 250,
    WA_TAG_HEX8 = 251,
    WA_TAG_BINARY8 = 252,
    WA_TAG_BINARY20 = 253,
    WA_TAG_BINARY32 = 254,
    WA_TAG_NIBBLE8 = 255
};

#define WA_DICT_VERSION 3
#define WA_PACKED_MAX 127

typedef struct {
    const char *key;
    const char *value;
    uint8_t is_jid; /* encode/was decoded as a JID */
} wa_attr;

typedef enum {
    WA_CONTENT_NONE = 0,
    WA_CONTENT_BYTES = 1,
    WA_CONTENT_CHILDREN = 2
} wa_content_type;

typedef struct wa_node {
    const char *tag;
    const wa_attr *attrs;
    size_t attr_count;
    const struct wa_node *children;
    size_t child_count;
    const uint8_t *data;
    size_t data_len;
    wa_content_type content;
} wa_node;

/* ---- tokens ------------------------------------------------------------- */
const char *wa_token_single(unsigned index);
const char *wa_token_double(unsigned dict, unsigned index);
/* Lookup: returns 1 for single (idx set), 2 for double (dict,idx), 0 none. */
int wa_token_lookup(const char *s, size_t len, unsigned *dict, unsigned *idx);

/* ---- decode ------------------------------------------------------------- */
/*
 * Decode one node from `data` (without the leading frame flags byte).
 * Returns 0 on success; on failure the arena content is undefined.
 */
int wa_node_decode(const uint8_t *data, size_t len, zap_arena *arena,
                   wa_node **out);

/* ---- encode ------------------------------------------------------------- */
/* Encode a node tree (without flags byte). Returns 0 unless out overflows. */
int wa_node_encode(const wa_node *n, zbuf *out);

/* ---- helpers ------------------------------------------------------------ */
const char *wa_node_attr(const wa_node *n, const char *key);
const wa_node *wa_node_child(const wa_node *n, const char *tag);
/* Path lookup, e.g. wa_node_path(n, "pair-success", "device", NULL). */
const wa_node *wa_node_path(const wa_node *n, ...);
int wa_node_has_tag(const wa_node *n, const char *tag);

/* Human readable XML-ish rendering for debugging (binary shown as length). */
size_t wa_node_to_text(const wa_node *n, char *out, size_t cap);

/* Convenience initialisers for outgoing nodes. */
#define WA_ATTR(k, v) {(k), (v), 0}
#define WA_ATTR_JID(k, v) {(k), (v), 1}
#define WA_COUNT(a) (sizeof(a) / sizeof((a)[0]))

#endif
