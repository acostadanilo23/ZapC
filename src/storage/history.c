#include "zapc/history.h"
#include "zapc/log.h"
#include "zapc/platform.h"
#include "zapc/storage.h"
#include "zapc/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ======================================================================== */
/* chats                                                                    */
/* ======================================================================== */

#define CHATS_MAGIC "ZCH1"
#define CONTACTS_MAGIC "ZCT1"

static void put_str(zbuf *b, const char *s)
{
    size_t n = strlen(s);
    if (n > 255)
        n = 255;
    zbuf_put_u8(b, (uint8_t)n);
    zbuf_put(b, s, n);
}

typedef struct {
    const uint8_t *p;
    size_t left;
    int err;
} rdr;

static void get_str(rdr *r, char *out, size_t cap)
{
    if (r->err || r->left < 1) {
        r->err = 1;
        return;
    }
    size_t n = *r->p++;
    r->left--;
    if (n > r->left) {
        r->err = 1;
        return;
    }
    zstrlcpyn(out, (const char *)r->p, n, cap);
    r->p += n;
    r->left -= n;
}

static uint32_t get_u32(rdr *r)
{
    if (r->err || r->left < 4) {
        r->err = 1;
        return 0;
    }
    uint32_t v = rd_be32(r->p);
    r->p += 4;
    r->left -= 4;
    return v;
}

static int64_t get_i64(rdr *r)
{
    uint64_t hi = get_u32(r), lo = get_u32(r);
    return (int64_t)((hi << 32) | lo);
}

static void put_i64(zbuf *b, int64_t v)
{
    zbuf_put_be32(b, (uint32_t)((uint64_t)v >> 32));
    zbuf_put_be32(b, (uint32_t)v);
}

void chats_load(chat_list *cl)
{
    static uint8_t buf[ZAPC_MAX_CHATS * 256 + 16];
    char path[ZAPC_PATH_MAX];
    memset(cl, 0, sizeof *cl);
    if (storage_path(path, sizeof path, "chats.bin") != 0)
        return;
    long n = plat_read_file(path, buf, sizeof buf);
    if (n < 4 || memcmp(buf, CHATS_MAGIC, 4) != 0)
        return;
    rdr r = {buf + 4, (size_t)n - 4, 0};
    while (!r.err && r.left > 0 && cl->count < ZAPC_MAX_CHATS) {
        chat_entry *e = &cl->chats[cl->count];
        char jid[WA_JID_STR_MAX];
        get_str(&r, jid, sizeof jid);
        get_str(&r, e->name, sizeof e->name);
        e->last_ts = get_i64(&r);
        e->unread = get_u32(&r);
        get_str(&r, e->preview, sizeof e->preview);
        if (r.err || jid_parse(&e->jid, jid) != 0)
            break;
        cl->count++;
    }
}

int chats_save(chat_list *cl)
{
    static uint8_t buf[ZAPC_MAX_CHATS * 256 + 16];
    char path[ZAPC_PATH_MAX];
    zbuf b;
    zbuf_init(&b, buf, sizeof buf);
    zbuf_put(&b, CHATS_MAGIC, 4);
    for (size_t i = 0; i < cl->count; i++) {
        const chat_entry *e = &cl->chats[i];
        char jid[WA_JID_STR_MAX];
        jid_format(&e->jid, jid, sizeof jid);
        put_str(&b, jid);
        put_str(&b, e->name);
        put_i64(&b, e->last_ts);
        zbuf_put_be32(&b, e->unread);
        put_str(&b, e->preview);
    }
    if (b.overflow || storage_path(path, sizeof path, "chats.bin") != 0)
        return -1;
    cl->dirty = 0;
    return plat_write_file_atomic(path, buf, b.len, 0600);
}

chat_entry *chats_find(chat_list *cl, const wa_jid *jid)
{
    for (size_t i = 0; i < cl->count; i++)
        if (jid_same_user(&cl->chats[i].jid, jid))
            return &cl->chats[i];
    return NULL;
}

chat_entry *chats_touch(chat_list *cl, const wa_jid *jid)
{
    chat_entry *e = chats_find(cl, jid);
    if (e != NULL)
        return e;
    if (cl->count < ZAPC_MAX_CHATS) {
        e = &cl->chats[cl->count++];
    } else {
        /* evict the least recently active chat */
        e = &cl->chats[0];
        for (size_t i = 1; i < cl->count; i++)
            if (cl->chats[i].last_ts < e->last_ts)
                e = &cl->chats[i];
    }
    memset(e, 0, sizeof *e);
    jid_to_non_ad(&e->jid, jid);
    cl->dirty = 1;
    return e;
}

static int cmp_chat(const void *a, const void *b)
{
    const chat_entry *x = a, *y = b;
    return (y->last_ts > x->last_ts) - (y->last_ts < x->last_ts);
}

void chats_sort(chat_list *cl)
{
    qsort(cl->chats, cl->count, sizeof cl->chats[0], cmp_chat);
}

/* ======================================================================== */
/* contacts                                                                 */
/* ======================================================================== */

void contacts_load(contact_list *ct)
{
    static uint8_t buf[ZAPC_MAX_CONTACTS * 160 + 16];
    char path[ZAPC_PATH_MAX];
    memset(ct, 0, sizeof *ct);
    if (storage_path(path, sizeof path, "contacts.bin") != 0)
        return;
    long n = plat_read_file(path, buf, sizeof buf);
    if (n < 4 || memcmp(buf, CONTACTS_MAGIC, 4) != 0)
        return;
    rdr r = {buf + 4, (size_t)n - 4, 0};
    while (!r.err && r.left > 0 && ct->count < ZAPC_MAX_CONTACTS) {
        contact_entry *e = &ct->items[ct->count];
        get_str(&r, e->user, sizeof e->user);
        get_str(&r, e->server, sizeof e->server);
        get_str(&r, e->name, sizeof e->name);
        if (r.err)
            break;
        ct->count++;
    }
}

int contacts_save(contact_list *ct)
{
    static uint8_t buf[ZAPC_MAX_CONTACTS * 160 + 16];
    char path[ZAPC_PATH_MAX];
    zbuf b;
    zbuf_init(&b, buf, sizeof buf);
    zbuf_put(&b, CONTACTS_MAGIC, 4);
    for (size_t i = 0; i < ct->count; i++) {
        put_str(&b, ct->items[i].user);
        put_str(&b, ct->items[i].server);
        put_str(&b, ct->items[i].name);
    }
    if (b.overflow || storage_path(path, sizeof path, "contacts.bin") != 0)
        return -1;
    ct->dirty = 0;
    return plat_write_file_atomic(path, buf, b.len, 0600);
}

void contacts_set(contact_list *ct, const wa_jid *jid, const char *name)
{
    if (name == NULL || name[0] == '\0')
        return;
    for (size_t i = 0; i < ct->count; i++) {
        contact_entry *e = &ct->items[i];
        if (strcmp(e->user, jid->user) == 0 && strcmp(e->server, jid->server) == 0) {
            if (strcmp(e->name, name) != 0) {
                zstrlcpy(e->name, name, sizeof e->name);
                ct->dirty = 1;
            }
            return;
        }
    }
    contact_entry *e;
    if (ct->count < ZAPC_MAX_CONTACTS) {
        e = &ct->items[ct->count++];
    } else {
        e = &ct->items[ct->next_evict];
        ct->next_evict = (ct->next_evict + 1) % ZAPC_MAX_CONTACTS;
    }
    zstrlcpy(e->user, jid->user, sizeof e->user);
    zstrlcpy(e->server, jid->server, sizeof e->server);
    zstrlcpy(e->name, name, sizeof e->name);
    ct->dirty = 1;
}

const char *contacts_get(const contact_list *ct, const wa_jid *jid)
{
    for (size_t i = 0; i < ct->count; i++)
        if (strcmp(ct->items[i].user, jid->user) == 0 &&
            strcmp(ct->items[i].server, jid->server) == 0)
            return ct->items[i].name;
    return NULL;
}

/* ======================================================================== */
/* message log                                                              */
/*                                                                          */
/* Record: u16 total length, u8 flags (bit0 = from_me), i64 timestamp,      */
/*         then strings (u8 len + bytes): id, sender, push name, and text   */
/*         (u16 len + bytes).                                               */
/* ======================================================================== */

static int log_path(const wa_jid *chat, char *out, size_t cap)
{
    wa_jid c;
    char jid[WA_JID_STR_MAX], rel[WA_JID_STR_MAX + 16];
    jid_to_non_ad(&c, chat);
    if (jid_format(&c, jid, sizeof jid) < 0)
        return -1;
    for (char *p = jid; *p; p++)
        if (*p == '/')
            *p = '_';
    snprintf(rel, sizeof rel, "messages/%s.log", jid);
    return storage_path(out, cap, rel);
}

int history_append(const wa_message *m)
{
    uint8_t rec[ZAPC_MSG_TEXT_MAX + 512];
    char path[ZAPC_PATH_MAX], sender[WA_JID_STR_MAX];
    zbuf b;
    if (log_path(&m->chat, path, sizeof path) != 0)
        return -1;
    jid_format(&m->sender, sender, sizeof sender);
    zbuf_init(&b, rec, sizeof rec);
    zbuf_put_be16(&b, 0); /* patched below */
    zbuf_put_u8(&b, (uint8_t)(m->from_me ? 1 : 0));
    put_i64(&b, m->timestamp);
    put_str(&b, m->id);
    put_str(&b, sender);
    put_str(&b, m->push_name);
    size_t tl = strlen(m->text);
    zbuf_put_be16(&b, (uint16_t)tl);
    zbuf_put(&b, m->text, tl);
    if (b.overflow || b.len > 0xFFFF)
        return -1;
    rec[0] = (uint8_t)(b.len >> 8);
    rec[1] = (uint8_t)b.len;
    FILE *f = fopen(path, "ab");
    if (f == NULL)
        return -1;
    (void)chmod(path, 0600);
    int ok = fwrite(rec, 1, b.len, f) == b.len;
    ok = (fclose(f) == 0) && ok;
    return ok ? 0 : -1;
}

static int parse_record(const uint8_t *rec, size_t len, wa_message *m)
{
    rdr r = {rec + 2, len - 2, 0};
    char sender[WA_JID_STR_MAX];
    memset(m, 0, sizeof *m);
    if (r.left < 1)
        return -1;
    m->from_me = (*r.p & 1) != 0;
    r.p++;
    r.left--;
    m->timestamp = get_i64(&r);
    get_str(&r, m->id, sizeof m->id);
    get_str(&r, sender, sizeof sender);
    get_str(&r, m->push_name, sizeof m->push_name);
    if (r.err || r.left < 2)
        return -1;
    size_t tl = rd_be16(r.p);
    r.p += 2;
    r.left -= 2;
    if (tl > r.left)
        return -1;
    zstrlcpyn(m->text, (const char *)r.p, tl, sizeof m->text);
    if (jid_parse(&m->sender, sender) != 0)
        jid_clear(&m->sender);
    return 0;
}

long history_count(const wa_jid *chat)
{
    char path[ZAPC_PATH_MAX];
    uint8_t hdr[2];
    if (log_path(chat, path, sizeof path) != 0)
        return 0;
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return 0;
    long count = 0;
    while (fread(hdr, 1, 2, f) == 2) {
        size_t len = rd_be16(hdr);
        if (len < 2 || fseek(f, (long)len - 2, SEEK_CUR) != 0)
            break;
        count++;
    }
    fclose(f);
    return count;
}

int history_load(const wa_jid *chat, long end, wa_message *out, int max,
                 long *first_index)
{
    static uint8_t rec[ZAPC_MSG_TEXT_MAX + 512];
    char path[ZAPC_PATH_MAX];
    *first_index = 0;
    if (max <= 0 || log_path(chat, path, sizeof path) != 0)
        return 0;
    long total = history_count(chat);
    if (end < 0 || end > total)
        end = total;
    long start = end - max;
    if (start < 0)
        start = 0;
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return 0;
    long idx = 0;
    int n = 0;
    while (idx < end && fread(rec, 1, 2, f) == 2) {
        size_t len = rd_be16(rec);
        if (len < 2 || len > sizeof rec)
            break;
        if (idx < start) {
            if (fseek(f, (long)len - 2, SEEK_CUR) != 0)
                break;
        } else {
            if (fread(rec + 2, 1, len - 2, f) != len - 2)
                break;
            if (parse_record(rec, len, &out[n]) == 0)
                n++;
        }
        idx++;
    }
    fclose(f);
    *first_index = start;
    return n;
}
