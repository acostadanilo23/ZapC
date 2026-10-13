/*
 * ZapC - chats, contacts and message history.
 *
 * The chat list and contact names are small fixed-size caches kept in RAM
 * and saved to disk.  Messages are appended to one log file per chat and
 * read back in blocks; only the visible window is held in memory.
 */
#ifndef ZAPC_HISTORY_H
#define ZAPC_HISTORY_H

#include "zapc/build_config.h"
#include "zapc/jid.h"
#include "zapc/wa.h"

#include <stddef.h>
#include <stdint.h>

#define CHAT_PREVIEW_MAX 48

typedef struct {
    wa_jid jid;
    char name[ZAPC_NAME_MAX];
    int64_t last_ts;
    unsigned unread;
    char preview[CHAT_PREVIEW_MAX];
    uint8_t name_requested; /* RAM only: group subject query sent */
} chat_entry;

typedef struct {
    chat_entry chats[ZAPC_MAX_CHATS];
    size_t count;
    int dirty;
} chat_list;

typedef struct {
    char user[64];
    char server[24];
    char name[ZAPC_NAME_MAX];
} contact_entry;

typedef struct {
    contact_entry items[ZAPC_MAX_CONTACTS];
    size_t count;
    size_t next_evict;
    int dirty;
} contact_list;

/* ---- chats --------------------------------------------------------------- */
void chats_load(chat_list *cl);
int chats_save(chat_list *cl);
/* Find or create (evicting the oldest chat when full). */
chat_entry *chats_touch(chat_list *cl, const wa_jid *jid);
chat_entry *chats_find(chat_list *cl, const wa_jid *jid);
/* Sort by most recent activity. */
void chats_sort(chat_list *cl);

/* ---- contacts ------------------------------------------------------------ */
void contacts_load(contact_list *ct);
int contacts_save(contact_list *ct);
void contacts_set(contact_list *ct, const wa_jid *jid, const char *name);
const char *contacts_get(const contact_list *ct, const wa_jid *jid);

/* ---- message log --------------------------------------------------------- */
int history_append(const wa_message *m);
/* Total number of stored messages for a chat. */
long history_count(const wa_jid *chat);
/*
 * Load up to `max` messages ending before message index `end` (exclusive;
 * -1 = newest).  Returns the number loaded into out[0..n) in chronological
 * order; *first_index receives the index of out[0].
 */
int history_load(const wa_jid *chat, long end, wa_message *out, int max,
                 long *first_index);

#endif
