/*
 * ZapC - streaming history sync.
 *
 * HistorySync { syncType=1, conversations=2, pushnames=7, ... }
 *   Conversation { id=1, messages=2 (HistorySyncMsg), lastMsgTimestamp=5,
 *                  unreadCount=6, conversationTimestamp=12, name=13,
 *                  displayName=38 }
 *   HistorySyncMsg { message=1 (WebMessageInfo), msgOrderId=2 }
 *   WebMessageInfo { key=1 {remoteJid=1, fromMe=2, id=3, participant=4},
 *                    message=2, messageTimestamp=3, participant=5,
 *                    pushName=19 }
 *   Pushname { id=1, pushname=2 }
 */
#include "zapc/history_sync.h"
#include "zapc/log.h"
#include "zapc/memory.h"
#include "zapc/protobuf.h"
#include "zapc/util.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    pb_walker w;
    const wa_hist_sink *sink;
    wa_hist_stats *stats;
    int error;

    /* current conversation */
    int in_conv;
    wa_jid jid;
    int have_jid;
    char name[ZAPC_NAME_MAX];
    int64_t ts;
    unsigned unread;
    wa_message msgs[ZAPC_HISTORY_PER_CHAT];
    int nmsgs;

    uint8_t buf[ZAPC_HISTORY_MSG_MAX];
} hs_state;

static hs_state g_hs;

static void str_field(const uint8_t *msg, size_t len, uint32_t field,
                      char *out, size_t cap)
{
    const uint8_t *s;
    size_t n;
    out[0] = '\0';
    if (pb_find_bytes(msg, len, field, &s, &n) == 1)
        zstrlcpyn(out, (const char *)s, n, cap);
}

static int is_self(const hs_state *h, const wa_jid *j)
{
    return jid_same_user(j, &h->sink->self) ||
           (!jid_is_empty(&h->sink->self_lid) && jid_same_user(j, &h->sink->self_lid));
}

static void add_message(hs_state *h, const uint8_t *wmi, size_t len)
{
    const uint8_t *key, *msg;
    size_t key_len, msg_len;
    if (pb_find_bytes(wmi, len, 1, &key, &key_len) != 1 ||
        pb_find_bytes(wmi, len, 2, &msg, &msg_len) != 1)
        return;
    static wa_message m;
    memset(&m, 0, sizeof m);
    if (wa_extract_text(msg, msg_len, m.text, sizeof m.text) <= 0)
        return; /* nothing displayable (protocol/system message) */

    char remote[WA_JID_STR_MAX], participant[WA_JID_STR_MAX];
    uint64_t from_me = 0, ts = 0;
    str_field(key, key_len, 1, remote, sizeof remote);
    str_field(key, key_len, 3, m.id, sizeof m.id);
    str_field(key, key_len, 4, participant, sizeof participant);
    if (participant[0] == '\0')
        str_field(wmi, len, 5, participant, sizeof participant);
    str_field(wmi, len, 19, m.push_name, sizeof m.push_name);
    pb_find_varint(key, key_len, 2, &from_me);
    pb_find_varint(wmi, len, 3, &ts);

    if (h->have_jid)
        m.chat = h->jid;
    else if (jid_parse(&m.chat, remote) != 0)
        return;
    jid_to_non_ad(&m.chat, &m.chat);
    m.timestamp = (int64_t)ts;
    m.from_me = from_me != 0;
    if (m.from_me) {
        jid_to_non_ad(&m.sender, &h->sink->self);
    } else if (jid_is_group(&m.chat)) {
        if (jid_parse(&m.sender, participant) != 0)
            return;
        jid_to_non_ad(&m.sender, &m.sender);
        if (is_self(h, &m.sender))
            m.from_me = 1;
    } else {
        m.sender = m.chat;
    }

    /* keep the newest messages */
    if (h->nmsgs < ZAPC_HISTORY_PER_CHAT) {
        h->msgs[h->nmsgs++] = m;
    } else {
        int oldest = 0;
        for (int i = 1; i < h->nmsgs; i++)
            if (h->msgs[i].timestamp < h->msgs[oldest].timestamp)
                oldest = i;
        if (m.timestamp > h->msgs[oldest].timestamp)
            h->msgs[oldest] = m;
    }
    h->stats->messages++;
}

static int cmp_msg(const void *a, const void *b)
{
    const wa_message *x = a, *y = b;
    return (x->timestamp > y->timestamp) - (x->timestamp < y->timestamp);
}

static void end_conversation(hs_state *h)
{
    if (h->have_jid && h->sink->on_chat != NULL) {
        qsort(h->msgs, (size_t)h->nmsgs, sizeof h->msgs[0], cmp_msg);
        int64_t ts = h->ts;
        if (h->nmsgs > 0 && h->msgs[h->nmsgs - 1].timestamp > ts)
            ts = h->msgs[h->nmsgs - 1].timestamp;
        h->sink->on_chat(h->sink->user, &h->jid, h->name, ts, h->unread,
                         h->msgs, h->nmsgs);
        h->stats->chats++;
    }
    h->in_conv = 0;
}

static pbw_action on_len(pb_walker *w, uint32_t field, uint64_t len)
{
    hs_state *h = w->user;
    (void)len;
    if (w->depth == 0) {
        if (field == 2) {
            h->in_conv = 1;
            h->have_jid = 0;
            h->name[0] = '\0';
            h->ts = 0;
            h->unread = 0;
            h->nmsgs = 0;
            return PBW_DESCEND;
        }
        return field == 7 ? PBW_BUFFER : PBW_SKIP;
    }
    if (w->depth == 1 && w->path[1] == 2) {
        switch (field) {
        case 1:  /* id */
        case 2:  /* HistorySyncMsg */
        case 13: /* name */
        case 38: /* displayName */
            return PBW_BUFFER;
        default:
            return PBW_SKIP;
        }
    }
    return PBW_SKIP;
}

static void on_varint(pb_walker *w, uint32_t field, uint64_t v)
{
    hs_state *h = w->user;
    if (w->depth == 0 && field == 1) {
        h->stats->sync_type = (unsigned)v;
    } else if (w->depth == 1 && w->path[1] == 2) {
        if (field == 6)
            h->unread = (unsigned)v;
        else if ((field == 12 || field == 5) && (int64_t)v > h->ts)
            h->ts = (int64_t)v;
    }
}

static void on_bytes(pb_walker *w, uint32_t field, const uint8_t *data,
                     size_t len)
{
    hs_state *h = w->user;
    char tmp[WA_JID_STR_MAX];
    if (w->depth == 0 && field == 7) {
        char name[ZAPC_NAME_MAX];
        wa_jid j;
        str_field(data, len, 1, tmp, sizeof tmp);
        str_field(data, len, 2, name, sizeof name);
        if (name[0] != '\0' && jid_parse(&j, tmp) == 0 &&
            h->sink->on_push_name != NULL) {
            h->sink->on_push_name(h->sink->user, &j, name);
            h->stats->push_names++;
        }
        return;
    }
    if (w->depth != 1)
        return;
    switch (field) {
    case 1:
        zstrlcpyn(tmp, (const char *)data, len, sizeof tmp);
        h->have_jid = jid_parse(&h->jid, tmp) == 0;
        break;
    case 13:
        zstrlcpyn(h->name, (const char *)data, len, sizeof h->name);
        break;
    case 38:
        if (h->name[0] == '\0')
            zstrlcpyn(h->name, (const char *)data, len, sizeof h->name);
        break;
    case 2: {
        const uint8_t *wmi;
        size_t wl;
        if (pb_find_bytes(data, len, 1, &wmi, &wl) == 1)
            add_message(h, wmi, wl);
        break;
    }
    default:
        break;
    }
}

static void on_end(pb_walker *w, uint32_t field)
{
    hs_state *h = w->user;
    if (w->depth == 0 && field == 2)
        end_conversation(h);
}

static int feed(void *user, const uint8_t *data, size_t len)
{
    hs_state *h = user;
    return pbw_feed(&h->w, data, len);
}

int wa_history_process(inf_read_fn rd, void *ru, const wa_hist_sink *sink,
                       wa_hist_stats *stats)
{
    hs_state *h = &g_hs;
    memset(stats, 0, sizeof *stats);
    h->sink = sink;
    h->stats = stats;
    h->in_conv = 0;
    h->w.on_len = on_len;
    h->w.on_varint = on_varint;
    h->w.on_bytes = on_bytes;
    h->w.on_end = on_end;
    h->w.user = h;
    pbw_init(&h->w, h->buf, sizeof h->buf);
    long n = zc_inflate_stream(1, rd, ru, feed, h, ZAPC_HISTORY_BLOB_MAX);
    if (n < 0 || pbw_finish(&h->w) != 0) {
        LOGW("history", "history sync blob is malformed");
        return -1;
    }
    LOGI("history", "history sync type %u: %u chats, %u messages, %u names",
         stats->sync_type, stats->chats, stats->messages, stats->push_names);
    return 0;
}

/* ======================================================================== */
/* running queued jobs                                                      */
/* ======================================================================== */

#include "zapc/media.h"
#include "zapc/storage.h"

#include <stdio.h>
#include <unistd.h>

static long file_read(void *user, uint8_t *buf, size_t cap)
{
    FILE *f = user;
    size_t n = fread(buf, 1, cap, f);
    if (n == 0 && ferror(f))
        return -1;
    return (long)n;
}

void wa_history_run_pending(wa_client *c)
{
    if (c->hist_count <= 0)
        return;
    wa_hist_job job = c->hist_jobs[0];
    memmove(&c->hist_jobs[0], &c->hist_jobs[1],
            (size_t)(c->hist_count - 1) * sizeof c->hist_jobs[0]);
    c->hist_count--;

    wa_hist_sink sink;
    memset(&sink, 0, sizeof sink);
    sink.user = c->ev.user;
    sink.on_chat = c->ev.on_history_chat;
    sink.on_push_name = c->ev.on_push_name;
    sink.self = c->dev.jid;
    sink.self_lid = c->dev.lid;
    wa_hist_stats st;
    int rc = -1;

    if (job.inline_path[0] != '\0') {
        FILE *f = fopen(job.inline_path, "rb");
        if (f != NULL) {
            rc = wa_history_process(file_read, f, &sink, &st);
            fclose(f);
        }
        unlink(job.inline_path);
    } else {
        static char hosts[WA_MEDIA_HOSTS + 1][64];
        int nh = 0;
        if (c->cfg->media_host[0] != '\0') {
            zstrlcpy(hosts[nh++], c->cfg->media_host, sizeof hosts[0]);
        } else {
            for (int i = 0; i < c->n_media_hosts; i++)
                zstrlcpy(hosts[nh++], c->media_hosts[i], sizeof hosts[0]);
            if (nh == 0)
                zstrlcpy(hosts[nh++], "mmg.whatsapp.net", sizeof hosts[0]);
        }
        char tmp[ZAPC_PATH_MAX];
        wa_media_keys keys;
        LOGI("history", "downloading history sync from %s...", hosts[0]);
        wa_media_ref ref = {job.direct_path,
                            job.has_enc_sha256 ? job.enc_sha256 : NULL,
                            WA_MEDIA_HISTORY_MMS, ZAPC_HISTORY_BLOB_MAX};
        if (storage_path(tmp, sizeof tmp, "hist-download.enc") == 0 &&
            wa_media_keys_derive(job.media_key, WA_MEDIA_HISTORY_INFO, &keys) == 0 &&
            wa_media_download(&ref, &keys, (const char(*)[64])hosts, nh,
                              c->cfg->media_port, c->cfg->ca_file, tmp) == 0) {
            static wa_media_reader rdr;
            if (wa_media_reader_open(&rdr, tmp, &keys) == 0) {
                rc = wa_history_process(wa_media_reader_read, &rdr, &sink, &st);
                wa_media_reader_close(&rdr);
            }
            unlink(tmp);
        }
        zap_secure_zero(&keys, sizeof keys);
    }
    zap_secure_zero(job.media_key, sizeof job.media_key);
    if (rc != 0) {
        LOGW("history", "history sync failed");
        return;
    }
    if (c->ev.on_history_done != NULL)
        c->ev.on_history_done(c->ev.user, st.chats, st.messages);
}
