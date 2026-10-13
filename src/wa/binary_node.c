/*
 * ZapC - WhatsApp binary node encoder/decoder.
 *
 * All input is untrusted: every length is checked against the remaining
 * input, nesting depth is limited, and all allocations come from a bounded
 * arena.
 */
#include "zapc/binary_node.h"
#include "zapc/build_config.h"
#include "zapc/jid.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ======================================================================== */
/* decoder                                                                  */
/* ======================================================================== */

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
    zap_arena *arena;
    int depth;
} decoder;

static int rd_u8(decoder *d, unsigned *v)
{
    if (d->pos >= d->len)
        return -1;
    *v = d->data[d->pos++];
    return 0;
}

static int rd_uint(decoder *d, size_t n, size_t *v)
{
    if (n > d->len - d->pos)
        return -1;
    size_t r = 0;
    for (size_t i = 0; i < n; i++)
        r = (r << 8) | d->data[d->pos + i];
    d->pos += n;
    *v = r;
    return 0;
}

static int rd_int20(decoder *d, size_t *v)
{
    if (3 > d->len - d->pos)
        return -1;
    const uint8_t *p = d->data + d->pos;
    *v = ((size_t)(p[0] & 15) << 16) | ((size_t)p[1] << 8) | p[2];
    d->pos += 3;
    return 0;
}

static int rd_raw(decoder *d, size_t n, const uint8_t **out)
{
    if (n > d->len - d->pos)
        return -1;
    *out = d->data + d->pos;
    d->pos += n;
    return 0;
}

static int list_size(decoder *d, unsigned tag, size_t *size)
{
    switch (tag) {
    case WA_TAG_LIST_EMPTY:
        *size = 0;
        return 0;
    case WA_TAG_LIST8:
        return rd_uint(d, 1, size);
    case WA_TAG_LIST16:
        return rd_uint(d, 2, size);
    default:
        return -1;
    }
}

static int unpack_nibble(unsigned v, char *c)
{
    if (v < 10)
        *c = (char)('0' + v);
    else if (v == 10)
        *c = '-';
    else if (v == 11)
        *c = '.';
    else if (v == 15)
        *c = '\0';
    else
        return -1;
    return 0;
}

static int unpack_hex(unsigned v, char *c)
{
    if (v < 10)
        *c = (char)('0' + v);
    else if (v < 16)
        *c = (char)('A' + v - 10);
    else
        return -1;
    return 0;
}

static int read_packed(decoder *d, unsigned tag, const char **out, size_t *olen)
{
    unsigned start;
    if (rd_u8(d, &start) != 0)
        return -1;
    size_t n = start & 127;
    const uint8_t *p;
    if (rd_raw(d, n, &p) != 0)
        return -1;
    char *s = zap_arena_alloc(d->arena, 2 * n + 1);
    if (s == NULL)
        return -1;
    for (size_t i = 0; i < n; i++) {
        int (*fn)(unsigned, char *) =
            tag == WA_TAG_NIBBLE8 ? unpack_nibble : unpack_hex;
        if (fn((unsigned)(p[i] >> 4), &s[2 * i]) != 0 ||
            fn((unsigned)(p[i] & 15), &s[2 * i + 1]) != 0)
            return -1;
    }
    size_t len = 2 * n;
    if ((start & 128) && len > 0)
        len--;
    s[len] = '\0';
    *out = s;
    *olen = len;
    return 0;
}

/*
 * A decoded scalar value: string (NUL-terminated), raw bytes or a list of
 * child nodes.
 */
typedef enum { V_NONE, V_STRING, V_BYTES, V_LIST } vtype;

typedef struct {
    vtype type;
    const char *str;      /* V_STRING (NUL-terminated)            */
    const uint8_t *bytes; /* V_BYTES (view into input)            */
    size_t len;
    wa_node *list;        /* V_LIST                               */
    int is_jid;
} value;

static int read_value(decoder *d, int as_string, value *v);
static int read_node(decoder *d, wa_node *out);

static int read_string_value(decoder *d, const char **s, int *is_jid)
{
    value v;
    if (read_value(d, 1, &v) != 0)
        return -1;
    if (v.type == V_NONE) {
        *s = NULL;
    } else if (v.type == V_STRING) {
        *s = v.str;
    } else {
        return -1;
    }
    if (is_jid != NULL)
        *is_jid = v.is_jid;
    return 0;
}

static int jid_to_value(decoder *d, const wa_jid *j, value *v)
{
    char buf[WA_JID_STR_MAX];
    int n = jid_format(j, buf, sizeof buf);
    if (n < 0)
        return -1;
    v->type = V_STRING;
    v->str = zap_arena_strndup(d->arena, buf, (size_t)n);
    v->len = (size_t)n;
    v->is_jid = 1;
    return v->str != NULL ? 0 : -1;
}

static int read_jid_pair(decoder *d, value *v)
{
    const char *user, *server;
    wa_jid j;
    if (read_string_value(d, &user, NULL) != 0 ||
        read_string_value(d, &server, NULL) != 0 || server == NULL)
        return -1;
    if (jid_make(&j, user != NULL ? user : "", server) != 0)
        return -1;
    return jid_to_value(d, &j, v);
}

static int read_ad_jid(decoder *d, value *v)
{
    unsigned agent, device;
    const char *user;
    wa_jid j;
    if (rd_u8(d, &agent) != 0 || rd_u8(d, &device) != 0 ||
        read_string_value(d, &user, NULL) != 0 || user == NULL)
        return -1;
    if (jid_make(&j, user, jid_server_for_domain((uint8_t)agent)) != 0)
        return -1;
    /* Domain types are not agents (see whatsmeow NewADJID). */
    if (agent != WA_DOMAIN_LID && agent != WA_DOMAIN_HOSTED &&
        agent != WA_DOMAIN_HOSTED_LID)
        j.agent = (uint8_t)agent;
    j.device = (uint16_t)device;
    return jid_to_value(d, &j, v);
}

static int read_fb_jid(decoder *d, value *v, int interop)
{
    const char *user, *server;
    size_t device, integrator = 0;
    wa_jid j;
    if (read_string_value(d, &user, NULL) != 0 || user == NULL ||
        rd_uint(d, 2, &device) != 0)
        return -1;
    if (interop && rd_uint(d, 2, &integrator) != 0)
        return -1;
    if (read_string_value(d, &server, NULL) != 0 || server == NULL)
        return -1;
    if (strcmp(server, interop ? WA_SERVER_INTEROP : WA_SERVER_MESSENGER) != 0)
        return -1;
    if (jid_make(&j, user, server) != 0)
        return -1;
    j.device = (uint16_t)device;
    j.integrator = (uint16_t)integrator;
    return jid_to_value(d, &j, v);
}

static int read_list(decoder *d, unsigned tag, value *v)
{
    size_t n;
    if (list_size(d, tag, &n) != 0)
        return -1;
    if (++d->depth > ZAPC_NODE_MAX_DEPTH)
        return -1;
    /* Each node needs at least 2 bytes of input: reject absurd counts early. */
    if (n > (d->len - d->pos) / 2 + 1)
        return -1;
    wa_node *nodes = NULL;
    if (n > 0) {
        nodes = zap_arena_alloc(d->arena, n * sizeof *nodes);
        if (nodes == NULL)
            return -1;
    }
    for (size_t i = 0; i < n; i++)
        if (read_node(d, &nodes[i]) != 0)
            return -1;
    d->depth--;
    v->type = V_LIST;
    v->list = nodes;
    v->len = n;
    return 0;
}

static int read_bytes(decoder *d, size_t n, int as_string, value *v)
{
    const uint8_t *p;
    if (rd_raw(d, n, &p) != 0)
        return -1;
    if (as_string) {
        v->type = V_STRING;
        v->str = zap_arena_strndup(d->arena, (const char *)p, n);
        v->len = n;
        return v->str != NULL ? 0 : -1;
    }
    v->type = V_BYTES;
    v->bytes = p;
    v->len = n;
    return 0;
}

static int read_value(decoder *d, int as_string, value *v)
{
    unsigned tag;
    size_t n;
    memset(v, 0, sizeof *v);
    if (rd_u8(d, &tag) != 0)
        return -1;
    switch (tag) {
    case WA_TAG_LIST_EMPTY:
        v->type = V_NONE;
        return 0;
    case WA_TAG_LIST8:
    case WA_TAG_LIST16:
        return read_list(d, tag, v);
    case WA_TAG_BINARY8:
        return rd_uint(d, 1, &n) != 0 ? -1 : read_bytes(d, n, as_string, v);
    case WA_TAG_BINARY20:
        return rd_int20(d, &n) != 0 ? -1 : read_bytes(d, n, as_string, v);
    case WA_TAG_BINARY32:
        return rd_uint(d, 4, &n) != 0 ? -1 : read_bytes(d, n, as_string, v);
    case WA_TAG_DICT0:
    case WA_TAG_DICT1:
    case WA_TAG_DICT2:
    case WA_TAG_DICT3: {
        unsigned idx;
        if (rd_u8(d, &idx) != 0)
            return -1;
        const char *s = wa_token_double(tag - WA_TAG_DICT0, idx);
        if (s == NULL)
            return -1;
        v->type = V_STRING;
        v->str = s;
        v->len = strlen(s);
        return 0;
    }
    case WA_TAG_JID_PAIR:
        return read_jid_pair(d, v);
    case WA_TAG_AD_JID:
        return read_ad_jid(d, v);
    case WA_TAG_FB_JID:
        return read_fb_jid(d, v, 0);
    case WA_TAG_INTEROP_JID:
        return read_fb_jid(d, v, 1);
    case WA_TAG_NIBBLE8:
    case WA_TAG_HEX8:
        v->type = V_STRING;
        return read_packed(d, tag, &v->str, &v->len);
    default: {
        const char *s = wa_token_single(tag);
        if (s == NULL)
            return -1;
        v->type = V_STRING;
        v->str = s;
        v->len = strlen(s);
        return 0;
    }
    }
}

static int read_node(decoder *d, wa_node *out)
{
    unsigned tag;
    size_t size;
    memset(out, 0, sizeof *out);
    if (rd_u8(d, &tag) != 0 || list_size(d, tag, &size) != 0 || size == 0)
        return -1;
    const char *t;
    if (read_string_value(d, &t, NULL) != 0 || t == NULL || t[0] == '\0')
        return -1;
    out->tag = t;

    size_t nattr = (size - 1) >> 1;
    if (nattr > 0) {
        if (nattr > (d->len - d->pos) / 2)
            return -1;
        wa_attr *attrs = zap_arena_alloc(d->arena, nattr * sizeof *attrs);
        if (attrs == NULL)
            return -1;
        for (size_t i = 0; i < nattr; i++) {
            int is_jid = 0;
            const char *k, *val;
            if (read_string_value(d, &k, NULL) != 0 || k == NULL ||
                read_string_value(d, &val, &is_jid) != 0)
                return -1;
            attrs[i].key = k;
            attrs[i].value = val != NULL ? val : "";
            attrs[i].is_jid = (uint8_t)is_jid;
        }
        out->attrs = attrs;
        out->attr_count = nattr;
    }

    if (size % 2 == 1)
        return 0;

    value v;
    if (read_value(d, 0, &v) != 0)
        return -1;
    switch (v.type) {
    case V_NONE:
        break;
    case V_LIST:
        out->content = WA_CONTENT_CHILDREN;
        out->children = v.list;
        out->child_count = v.len;
        break;
    case V_BYTES:
        out->content = WA_CONTENT_BYTES;
        out->data = v.bytes;
        out->data_len = v.len;
        break;
    case V_STRING:
        out->content = WA_CONTENT_BYTES;
        out->data = (const uint8_t *)v.str;
        out->data_len = v.len;
        break;
    }
    return 0;
}

int wa_node_decode(const uint8_t *data, size_t len, zap_arena *arena,
                   wa_node **out)
{
    decoder d = {data, len, 0, arena, 0};
    wa_node *n = zap_arena_alloc(arena, sizeof *n);
    if (n == NULL)
        return -1;
    if (read_node(&d, n) != 0)
        return -1;
    *out = n;
    return 0;
}

/* ======================================================================== */
/* encoder                                                                  */
/* ======================================================================== */

static void put_list_start(zbuf *b, size_t n)
{
    if (n == 0) {
        zbuf_put_u8(b, WA_TAG_LIST_EMPTY);
    } else if (n < 256) {
        zbuf_put_u8(b, WA_TAG_LIST8);
        zbuf_put_u8(b, (uint8_t)n);
    } else if (n < 65536) {
        zbuf_put_u8(b, WA_TAG_LIST16);
        zbuf_put_be16(b, (uint16_t)n);
    } else {
        b->overflow = 1;
    }
}

static void put_byte_length(zbuf *b, size_t n)
{
    if (n < 256) {
        zbuf_put_u8(b, WA_TAG_BINARY8);
        zbuf_put_u8(b, (uint8_t)n);
    } else if (n < (1u << 20)) {
        zbuf_put_u8(b, WA_TAG_BINARY20);
        zbuf_put_be24(b, (uint32_t)n);
    } else if (n < 0x7FFFFFFFu) {
        zbuf_put_u8(b, WA_TAG_BINARY32);
        zbuf_put_be32(b, (uint32_t)n);
    } else {
        b->overflow = 1;
    }
}

static int nibble_ok(const char *s, size_t n)
{
    if (n == 0 || n > WA_PACKED_MAX)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || s[i] == '-' || s[i] == '.'))
            return 0;
    return 1;
}

static int hex_ok(const char *s, size_t n)
{
    if (n == 0 || n > WA_PACKED_MAX)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'A' && s[i] <= 'F')))
            return 0;
    return 1;
}

static uint8_t pack_char(unsigned tag, char c)
{
    if (c == '\0')
        return 15;
    if (c >= '0' && c <= '9')
        return (uint8_t)(c - '0');
    if (tag == WA_TAG_NIBBLE8)
        return c == '-' ? 10 : 11;
    return (uint8_t)(10 + c - 'A');
}

static void put_packed(zbuf *b, const char *s, size_t n, unsigned tag)
{
    zbuf_put_u8(b, (uint8_t)tag);
    uint8_t rounded = (uint8_t)((n + 1) / 2);
    if (n % 2)
        rounded |= 128;
    zbuf_put_u8(b, rounded);
    for (size_t i = 0; i + 1 < n; i += 2)
        zbuf_put_u8(b, (uint8_t)((pack_char(tag, s[i]) << 4) |
                                 pack_char(tag, s[i + 1])));
    if (n % 2)
        zbuf_put_u8(b, (uint8_t)((pack_char(tag, s[n - 1]) << 4) |
                                 pack_char(tag, '\0')));
}

static void put_string(zbuf *b, const char *s, size_t n)
{
    unsigned dict = 0, idx = 0;
    int t = wa_token_lookup(s, n, &dict, &idx);
    if (t == 1) {
        zbuf_put_u8(b, (uint8_t)idx);
    } else if (t == 2) {
        zbuf_put_u8(b, (uint8_t)(WA_TAG_DICT0 + dict));
        zbuf_put_u8(b, (uint8_t)idx);
    } else if (nibble_ok(s, n)) {
        put_packed(b, s, n, WA_TAG_NIBBLE8);
    } else if (hex_ok(s, n)) {
        put_packed(b, s, n, WA_TAG_HEX8);
    } else {
        put_byte_length(b, n);
        zbuf_put(b, s, n);
    }
}

static void put_cstring(zbuf *b, const char *s) { put_string(b, s, strlen(s)); }

static void put_jid(zbuf *b, const char *s)
{
    wa_jid j;
    if (jid_parse(&j, s) != 0) {
        b->overflow = 1; /* treat invalid JIDs as an encoding error */
        return;
    }
    int user_server = strcmp(j.server, WA_SERVER_USER) == 0 ||
                      strcmp(j.server, WA_SERVER_LID) == 0;
    if ((user_server && j.device > 0) ||
        strcmp(j.server, WA_SERVER_HOSTED) == 0 ||
        strcmp(j.server, WA_SERVER_HOSTED_LID) == 0) {
        zbuf_put_u8(b, WA_TAG_AD_JID);
        zbuf_put_u8(b, jid_domain(&j));
        zbuf_put_u8(b, (uint8_t)j.device);
        put_cstring(b, j.user);
    } else if (strcmp(j.server, WA_SERVER_MESSENGER) == 0) {
        zbuf_put_u8(b, WA_TAG_FB_JID);
        put_cstring(b, j.user);
        zbuf_put_be16(b, j.device);
        put_cstring(b, j.server);
    } else if (strcmp(j.server, WA_SERVER_INTEROP) == 0) {
        zbuf_put_u8(b, WA_TAG_INTEROP_JID);
        put_cstring(b, j.user);
        zbuf_put_be16(b, j.device);
        zbuf_put_be16(b, j.integrator);
        put_cstring(b, j.server);
    } else {
        zbuf_put_u8(b, WA_TAG_JID_PAIR);
        if (j.user[0] == '\0')
            zbuf_put_u8(b, WA_TAG_LIST_EMPTY);
        else
            put_cstring(b, j.user);
        put_cstring(b, j.server);
    }
}

static void put_node(zbuf *b, const wa_node *n, int depth)
{
    if (depth > ZAPC_NODE_MAX_DEPTH) {
        b->overflow = 1;
        return;
    }
    size_t nattr = 0;
    for (size_t i = 0; i < n->attr_count; i++)
        if (n->attrs[i].value != NULL && n->attrs[i].value[0] != '\0')
            nattr++;
    int has_content = n->content != WA_CONTENT_NONE;
    put_list_start(b, 2 * nattr + 1 + (has_content ? 1u : 0u));
    put_cstring(b, n->tag);
    for (size_t i = 0; i < n->attr_count; i++) {
        const wa_attr *a = &n->attrs[i];
        if (a->value == NULL || a->value[0] == '\0')
            continue;
        put_cstring(b, a->key);
        if (a->is_jid)
            put_jid(b, a->value);
        else
            put_cstring(b, a->value);
    }
    if (n->content == WA_CONTENT_BYTES) {
        put_byte_length(b, n->data_len);
        zbuf_put(b, n->data, n->data_len);
    } else if (n->content == WA_CONTENT_CHILDREN) {
        put_list_start(b, n->child_count);
        for (size_t i = 0; i < n->child_count; i++)
            put_node(b, &n->children[i], depth + 1);
    }
}

int wa_node_encode(const wa_node *n, zbuf *out)
{
    put_node(out, n, 0);
    return out->overflow ? -1 : 0;
}

/* ======================================================================== */
/* helpers                                                                  */
/* ======================================================================== */

const char *wa_node_attr(const wa_node *n, const char *key)
{
    if (n == NULL)
        return NULL;
    for (size_t i = 0; i < n->attr_count; i++)
        if (strcmp(n->attrs[i].key, key) == 0)
            return n->attrs[i].value;
    return NULL;
}

const wa_node *wa_node_child(const wa_node *n, const char *tag)
{
    if (n == NULL || n->content != WA_CONTENT_CHILDREN)
        return NULL;
    for (size_t i = 0; i < n->child_count; i++)
        if (strcmp(n->children[i].tag, tag) == 0)
            return &n->children[i];
    return NULL;
}

const wa_node *wa_node_path(const wa_node *n, ...)
{
    va_list ap;
    va_start(ap, n);
    const char *tag;
    while (n != NULL && (tag = va_arg(ap, const char *)) != NULL)
        n = wa_node_child(n, tag);
    va_end(ap);
    return n;
}

int wa_node_has_tag(const wa_node *n, const char *tag)
{
    return n != NULL && strcmp(n->tag, tag) == 0;
}

typedef struct {
    char *out;
    size_t cap;
    size_t len;
} textbuf;

static void tb_put(textbuf *t, const char *s)
{
    size_t n = strlen(s);
    if (t->cap == 0)
        return;
    if (t->len + n >= t->cap)
        n = t->cap - 1 - t->len;
    memcpy(t->out + t->len, s, n);
    t->len += n;
    t->out[t->len] = '\0';
}

static void to_text(textbuf *t, const wa_node *n, int depth)
{
    char tmp[48];
    tb_put(t, "<");
    tb_put(t, n->tag);
    for (size_t i = 0; i < n->attr_count; i++) {
        tb_put(t, " ");
        tb_put(t, n->attrs[i].key);
        tb_put(t, "=\"");
        tb_put(t, n->attrs[i].value);
        tb_put(t, "\"");
    }
    if (n->content == WA_CONTENT_NONE) {
        tb_put(t, "/>");
    } else if (n->content == WA_CONTENT_BYTES) {
        snprintf(tmp, sizeof tmp, "><!-- %zu bytes --></", n->data_len);
        tb_put(t, tmp);
        tb_put(t, n->tag);
        tb_put(t, ">");
    } else {
        tb_put(t, ">");
        if (depth < 6)
            for (size_t i = 0; i < n->child_count; i++)
                to_text(t, &n->children[i], depth + 1);
        else
            tb_put(t, "...");
        tb_put(t, "</");
        tb_put(t, n->tag);
        tb_put(t, ">");
    }
}

size_t wa_node_to_text(const wa_node *n, char *out, size_t cap)
{
    textbuf t = {out, cap, 0};
    if (cap > 0)
        out[0] = '\0';
    to_text(&t, n, 0);
    return t.len;
}
