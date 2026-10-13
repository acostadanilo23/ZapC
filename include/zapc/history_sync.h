/*
 * ZapC - streaming history sync processing.
 *
 * A HistorySync blob (zlib-compressed protobuf, possibly many megabytes) is
 * processed in one pass: inflate -> streaming protobuf walker -> per chat
 * only the newest ZAPC_HISTORY_PER_CHAT messages are kept in a fixed ring.
 */
#ifndef ZAPC_HISTORY_SYNC_H
#define ZAPC_HISTORY_SYNC_H

#include "zapc/inflate.h"
#include "zapc/wa.h"

typedef struct {
    void *user;
    /* msgs are sorted oldest first; the array is reused afterwards */
    void (*on_chat)(void *user, const wa_jid *chat, const char *name,
                    int64_t last_ts, unsigned unread, const wa_message *msgs,
                    int nmsgs);
    void (*on_push_name)(void *user, const wa_jid *jid, const char *name);
    wa_jid self;     /* own phone-number JID */
    wa_jid self_lid; /* own LID (may be empty) */
} wa_hist_sink;

typedef struct {
    unsigned sync_type;
    unsigned chats;
    unsigned messages;
    unsigned push_names;
} wa_hist_stats;

/* Process a zlib-compressed HistorySync read through `rd`. */
int wa_history_process(inf_read_fn rd, void *ru, const wa_hist_sink *sink,
                       wa_hist_stats *stats);

/* Extract display text from a serialized Message (see message.c). */
int wa_extract_text(const uint8_t *msg, size_t len, char *out, size_t cap);

#endif
