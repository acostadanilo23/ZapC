/*
 * ZapC - messages: receive/decrypt, receipts, prekey upload and the send
 * pipeline (device list -> prekey bundles -> encrypt -> send).
 */
#include "zapc/crypto.h"
#include "zapc/history_sync.h"
#include "zapc/log.h"
#include "zapc/platform.h"
#include "zapc/protobuf.h"
#include "zapc/signal.h"
#include "zapc/storage.h"
#include "zapc/util.h"
#include "zapc/wa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SEND_DEVICES 128 /* devices per outgoing message */
#define MAX_GROUP_USERS 96   /* group members resolved per send */
#define CT_ARENA_SIZE (96u * 1024u)

/* ======================================================================== */
/* Message protobuf -> display text                                         */
/* ======================================================================== */

typedef struct {
    char *out;
    size_t cap;
    const uint8_t *skdm;     /* senderKeyDistributionMessage payload */
    size_t skdm_len;
    char dsm_dest[WA_JID_STR_MAX]; /* deviceSentMessage.destinationJid */
    int found;
    const uint8_t *hist;     /* protocolMessage.historySyncNotification */
    size_t hist_len;
} msg_extract;

static void copy_text(msg_extract *x, const char *prefix, const uint8_t *s,
                      size_t n, const char *suffix)
{
    size_t pl = strlen(prefix), sl = strlen(suffix);
    if (x->cap == 0)
        return;
    size_t room = x->cap - 1;
    size_t o = 0;
    size_t t = pl < room ? pl : room;
    memcpy(x->out, prefix, t);
    o = t;
    t = n < room - o ? n : room - o;
    memcpy(x->out + o, s, t);
    o += t;
    t = sl < room - o ? sl : room - o;
    memcpy(x->out + o, suffix, t);
    o += t;
    x->out[o] = '\0';
    /* replace control characters (but keep newlines) */
    for (size_t i = 0; i < o; i++)
        if ((unsigned char)x->out[i] < 0x20 && x->out[i] != '\n')
            x->out[i] = ' ';
    x->found = 1;
}

static int sub_string(const uint8_t *msg, size_t len, uint32_t field,
                      const uint8_t **s, size_t *n)
{
    return pb_find_bytes(msg, len, field, s, n) == 1;
}

static void media_text(msg_extract *x, const char *kind, const uint8_t *m,
                       size_t n, uint32_t caption_field, uint32_t name_field)
{
    const uint8_t *s;
    size_t sl;
    char prefix[64];
    if (name_field && sub_string(m, n, name_field, &s, &sl) && sl > 0) {
        snprintf(prefix, sizeof prefix, "[%s: ", kind);
        copy_text(x, prefix, s, sl, "]");
    } else if (caption_field && sub_string(m, n, caption_field, &s, &sl) &&
               sl > 0) {
        snprintf(prefix, sizeof prefix, "[%s] ", kind);
        copy_text(x, prefix, s, sl, "");
    } else {
        snprintf(prefix, sizeof prefix, "[%s]", kind);
        copy_text(x, prefix, (const uint8_t *)"", 0, "");
    }
}

static void extract(msg_extract *x, const uint8_t *msg, size_t len, int depth)
{
    pb_reader r;
    pb_field f;
    if (depth > 4)
        return;
    pb_reader_init(&r, msg, len);
    while (pb_next(&r, &f) == 1) {
        if (f.wire != PB_LEN)
            continue;
        const uint8_t *s;
        size_t sl;
        switch (f.num) {
        case 1: /* conversation */
            if (!x->found)
                copy_text(x, "", f.data, f.len, "");
            break;
        case 2: /* senderKeyDistributionMessage */
            if (sub_string(f.data, f.len, 2, &s, &sl)) {
                x->skdm = s;
                x->skdm_len = sl;
            }
            break;
        case 3: media_text(x, "Imagem", f.data, f.len, 3, 0); break;
        case 4:
            if (sub_string(f.data, f.len, 1, &s, &sl))
                copy_text(x, "[Contato: ", s, sl, "]");
            break;
        case 5:
            if (sub_string(f.data, f.len, 3, &s, &sl) && sl > 0)
                copy_text(x, "[Localiza\xc3\xa7\xc3\xa3o: ", s, sl, "]");
            else
                copy_text(x, "[Localiza\xc3\xa7\xc3\xa3o]", (const uint8_t *)"",
                          0, "");
            break;
        case 6: /* extendedTextMessage */
            if (sub_string(f.data, f.len, 1, &s, &sl))
                copy_text(x, "", s, sl, "");
            break;
        case 7: media_text(x, "Documento", f.data, f.len, 3, 8); break;
        case 8: media_text(x, "\xc3\x81udio", f.data, f.len, 0, 0); break;
        case 9: media_text(x, "V\xc3\xad" "deo", f.data, f.len, 7, 0); break;
        case 12: { /* protocolMessage */
            uint64_t type = 99;
            pb_find_varint(f.data, f.len, 2, &type);
            if (sub_string(f.data, f.len, 6, &s, &sl)) {
                x->hist = s;
                x->hist_len = sl;
            }
            if (type == 0)
                copy_text(x, "[mensagem apagada]", (const uint8_t *)"", 0, "");
            else if (type == 14 && sub_string(f.data, f.len, 14, &s, &sl)) {
                char tmp[ZAPC_MSG_TEXT_MAX];
                msg_extract y;
                memset(&y, 0, sizeof y);
                y.out = tmp;
                y.cap = sizeof tmp;
                tmp[0] = '\0';
                extract(&y, s, sl, depth + 1);
                if (y.found)
                    copy_text(x, "[editada] ", (const uint8_t *)tmp,
                              strlen(tmp), "");
            }
            break;
        }
        case 26: copy_text(x, "[Figurinha]", (const uint8_t *)"", 0, ""); break;
        case 31: /* deviceSentMessage */
            if (sub_string(f.data, f.len, 1, &s, &sl) &&
                sl < sizeof x->dsm_dest) {
                memcpy(x->dsm_dest, s, sl);
                x->dsm_dest[sl] = '\0';
            }
            if (sub_string(f.data, f.len, 2, &s, &sl))
                extract(x, s, sl, depth + 1);
            break;
        case 37: case 40: case 53: case 55: case 58: case 59: case 62:
            /* FutureProofMessage wrappers */
            if (sub_string(f.data, f.len, 1, &s, &sl))
                extract(x, s, sl, depth + 1);
            break;
        case 46:
            if (sub_string(f.data, f.len, 2, &s, &sl) && sl > 0)
                copy_text(x, "[Rea\xc3\xa7\xc3\xa3o: ", s, sl, "]");
            break;
        case 49: case 60: case 64:
            if (sub_string(f.data, f.len, 2, &s, &sl))
                copy_text(x, "[Enquete: ", s, sl, "]");
            break;
        case 66: copy_text(x, "[V\xc3\xad" "deo]", (const uint8_t *)"", 0, ""); break;
        default:
            break;
        }
    }
}

int wa_extract_text(const uint8_t *msg, size_t len, char *out, size_t cap)
{
    msg_extract x;
    memset(&x, 0, sizeof x);
    x.out = out;
    x.cap = cap;
    if (cap > 0)
        out[0] = '\0';
    extract(&x, msg, len, 0);
    return x.found ? (int)strlen(out) : 0;
}

/* ======================================================================== */
/* receiving                                                                */
/* ======================================================================== */

static int own_user(const wa_client *c, const wa_jid *j)
{
    return (strcmp(j->user, c->dev.jid.user) == 0 &&
            strcmp(j->server, c->dev.jid.server) == 0) ||
           (!jid_is_empty(&c->dev.lid) && strcmp(j->user, c->dev.lid.user) == 0 &&
            strcmp(j->server, c->dev.lid.server) == 0);
}

static void send_receipt(wa_client *c, const wa_node *node, const char *type)
{
    wa_attr a[5];
    size_t n = 0;
    const char *v;
    a[n++] = (wa_attr)WA_ATTR("id", wa_node_attr(node, "id"));
    a[n++] = (wa_attr)WA_ATTR_JID("to", wa_node_attr(node, "from"));
    if ((v = wa_node_attr(node, "recipient")) != NULL)
        a[n++] = (wa_attr)WA_ATTR_JID("recipient", v);
    if ((v = wa_node_attr(node, "participant")) != NULL)
        a[n++] = (wa_attr)WA_ATTR_JID("participant", v);
    if (type != NULL)
        a[n++] = (wa_attr)WA_ATTR("type", type);
    wa_node r = {"receipt", a, n, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    (void)wa_send_node(c, &r);
}

/* Queue a HistorySyncNotification for processing outside the receive path. */
static int queue_history(wa_client *c, const uint8_t *n, size_t len)
{
    const uint8_t *p;
    size_t pl;
    uint64_t type = 0;
    if (!c->cfg->history_sync || c->hist_count >= WA_MAX_HIST_JOBS) {
        LOGW("msg", "skipping history sync notification");
        return -1;
    }
    wa_hist_job *job = &c->hist_jobs[c->hist_count];
    memset(job, 0, sizeof *job);
    pb_find_varint(n, len, 6, &type);
    job->sync_type = (unsigned)type;
    if (pb_find_bytes(n, len, 11, &p, &pl) == 1 && pl > 0) {
        char rel[64];
        snprintf(rel, sizeof rel, "hist-inline-%u.z", c->hist_seq++);
        if (storage_path(job->inline_path, sizeof job->inline_path, rel) != 0 ||
            plat_write_file_atomic(job->inline_path, p, pl, 0600) != 0)
            return -1;
    } else {
        if (pb_find_bytes(n, len, 5, &p, &pl) != 1 || pl == 0 ||
            pl >= sizeof job->direct_path)
            return -1;
        memcpy(job->direct_path, p, pl);
        job->direct_path[pl] = '\0';
        if (pb_find_bytes(n, len, 3, &p, &pl) != 1 || pl != 32)
            return -1;
        memcpy(job->media_key, p, 32);
        if (pb_find_bytes(n, len, 4, &p, &pl) == 1 && pl == 32) {
            memcpy(job->enc_sha256, p, 32);
            job->has_enc_sha256 = 1;
        }
    }
    c->hist_count++;
    LOGI("msg", "history sync (type %u) queued", job->sync_type);
    return 0;
}

static void send_retry_receipt(wa_client *c, const wa_node *node)
{
    uint8_t reg[4];
    wr_be32(reg, c->dev.registration_id);
    const char *id = wa_node_attr(node, "id");
    const char *t = wa_node_attr(node, "t");
    wa_attr ra[] = {WA_ATTR("count", "1"), WA_ATTR("id", id),
                    WA_ATTR("t", t ? t : ""), WA_ATTR("v", "1")};
    wa_node kids[2] = {
        {"retry", ra, WA_COUNT(ra), NULL, 0, NULL, 0, WA_CONTENT_NONE},
        {"registration", NULL, 0, NULL, 0, reg, 4, WA_CONTENT_BYTES},
    };
    wa_attr a[5];
    size_t n = 0;
    const char *v;
    a[n++] = (wa_attr)WA_ATTR("id", id);
    a[n++] = (wa_attr)WA_ATTR("type", "retry");
    a[n++] = (wa_attr)WA_ATTR_JID("to", wa_node_attr(node, "from"));
    if ((v = wa_node_attr(node, "recipient")) != NULL)
        a[n++] = (wa_attr)WA_ATTR_JID("recipient", v);
    if ((v = wa_node_attr(node, "participant")) != NULL)
        a[n++] = (wa_attr)WA_ATTR_JID("participant", v);
    wa_node r = {"receipt", a, n, kids, 2, NULL, 0, WA_CONTENT_CHILDREN};
    (void)wa_send_node(c, &r);
}

void wa_handle_message(wa_client *c, const wa_node *node)
{
    static uint8_t plain[ZAPC_MSG_PLAIN_MAX + 64];
    const char *from_s = wa_node_attr(node, "from");
    const char *id = wa_node_attr(node, "id");
    const char *participant_s = wa_node_attr(node, "participant");
    const char *recipient_s = wa_node_attr(node, "recipient");
    const char *t = wa_node_attr(node, "t");
    const char *notify = wa_node_attr(node, "notify");
    wa_jid from, sender;
    char addr[96];

    if (from_s == NULL || id == NULL || jid_parse(&from, from_s) != 0) {
        wa_send_ack(c, node, NULL);
        return;
    }
    int is_group = jid_is_group(&from) ||
                   strcmp(from.server, WA_SERVER_BROADCAST) == 0;
    if (is_group) {
        if (participant_s == NULL || jid_parse(&sender, participant_s) != 0) {
            wa_send_ack(c, node, NULL);
            return;
        }
    } else {
        sender = from;
    }

    wa_message m;
    memset(&m, 0, sizeof m);
    zstrlcpy(m.id, id, sizeof m.id);
    m.timestamp = t != NULL ? strtoll(t, NULL, 10) : plat_time_unix();
    if (notify != NULL)
        zstrlcpy(m.push_name, notify, sizeof m.push_name);
    m.from_me = own_user(c, &sender);
    jid_to_non_ad(&m.sender, &sender);
    if (is_group) {
        m.chat = from;
    } else if (m.from_me && recipient_s != NULL) {
        jid_parse(&m.chat, recipient_s);
        jid_to_non_ad(&m.chat, &m.chat);
    } else {
        jid_to_non_ad(&m.chat, &from);
    }

    if (jid_signal_address(&sender, addr, sizeof addr) < 0) {
        wa_send_ack(c, node, NULL);
        return;
    }

    int decrypted_any = 0, failed = 0, hist_queued = 0;
    for (size_t i = 0; node->content == WA_CONTENT_CHILDREN && i < node->child_count;
         i++) {
        const wa_node *enc = &node->children[i];
        if (strcmp(enc->tag, "enc") != 0 || enc->content != WA_CONTENT_BYTES)
            continue;
        const char *type = wa_node_attr(enc, "type");
        const char *ver = wa_node_attr(enc, "v");
        long n = -1;
        if (type == NULL)
            continue;
        if (strcmp(type, "pkmsg") == 0 || strcmp(type, "msg") == 0) {
            n = signal_decrypt(&c->dev, addr, type[0] == 'p', enc->data,
                               enc->data_len, plain, sizeof plain);
        } else if (strcmp(type, "skmsg") == 0) {
            n = senderkey_decrypt(from_s, addr, enc->data, enc->data_len,
                                  plain, sizeof plain);
        } else {
            LOGD("msg", "unsupported enc type %s", type);
            continue;
        }
        if (n < 0) {
            LOGW("msg", "failed to decrypt %s message %s", type, id);
            failed = 1;
            continue;
        }
        if (ver == NULL || strcmp(ver, "3") != 0) {
            n = wa_unpad_message(plain, (size_t)n);
            if (n < 0) {
                failed = 1;
                continue;
            }
        }
        decrypted_any = 1;
        msg_extract x;
        memset(&x, 0, sizeof x);
        x.out = m.text;
        x.cap = sizeof m.text;
        x.found = m.text[0] != '\0';
        extract(&x, plain, (size_t)n, 0);
        if (x.skdm != NULL && is_group &&
            senderkey_process(from_s, addr, x.skdm, x.skdm_len) != 0)
            LOGW("msg", "invalid sender key distribution message");
        if (x.hist != NULL && m.from_me && queue_history(c, x.hist, x.hist_len) == 0)
            hist_queued = 1;
        if (x.dsm_dest[0] != '\0' && m.from_me) {
            wa_jid dest;
            if (jid_parse(&dest, x.dsm_dest) == 0)
                jid_to_non_ad(&m.chat, &dest);
        }
    }
    zap_secure_zero(plain, sizeof plain);

    if (hist_queued) {
        /* <receipt id=.. type="hist_sync" to=own-jid/> */
        char own[WA_JID_STR_MAX];
        wa_jid me;
        jid_to_non_ad(&me, &c->dev.jid);
        jid_format(&me, own, sizeof own);
        wa_attr ha[] = {WA_ATTR("id", id), WA_ATTR("type", "hist_sync"),
                        WA_ATTR_JID("to", own)};
        wa_node hr = {"receipt", ha, 3, NULL, 0, NULL, 0, WA_CONTENT_NONE};
        (void)wa_send_node(c, &hr);
    }
    if (decrypted_any) {
        send_receipt(c, node, m.from_me ? "sender" : "inactive");
        if (m.text[0] != '\0' && c->ev.on_message != NULL)
            c->ev.on_message(c->ev.user, &m);
    } else if (failed) {
        send_retry_receipt(c, node);
    }
    wa_send_ack(c, node, NULL);
}

void wa_handle_receipt(wa_client *c, const wa_node *node)
{
    const char *type = wa_node_attr(node, "type");
    const char *from = wa_node_attr(node, "from");
    const char *id = wa_node_attr(node, "id");
    wa_send_ack(c, node, NULL);
    if (from == NULL || id == NULL || c->ev.on_receipt == NULL)
        return;
    if (type != NULL && strcmp(type, "retry") == 0) {
        LOGI("msg", "recipient asked for a retry of %s (not supported yet)", id);
        return;
    }
    wa_jid chat;
    if (jid_parse(&chat, from) != 0)
        return;
    jid_to_non_ad(&chat, &chat);
    const char *kind = type == NULL ? "delivered" : type;
    if (strcmp(kind, "read") == 0 || strcmp(kind, "read-self") == 0)
        kind = "read";
    else if (strcmp(kind, "played") == 0 || strcmp(kind, "played-self") == 0)
        kind = "played";
    else if (strcmp(kind, "delivered") != 0)
        return;
    c->ev.on_receipt(c->ev.user, &chat, id, kind);
    /* <list><item id=..></list> carries further ids */
    const wa_node *list = wa_node_child(node, "list");
    for (size_t i = 0; list != NULL && list->content == WA_CONTENT_CHILDREN &&
                       i < list->child_count;
         i++) {
        const char *iid = wa_node_attr(&list->children[i], "id");
        if (iid != NULL)
            c->ev.on_receipt(c->ev.user, &chat, iid, kind);
    }
}

int wa_mark_read(wa_client *c, const wa_jid *chat, const wa_jid *sender,
                 const char *msg_id)
{
    char chat_s[WA_JID_STR_MAX], sender_s[WA_JID_STR_MAX], ts[24];
    if (c->state != WA_ST_LOGGED_IN)
        return -1;
    jid_format(chat, chat_s, sizeof chat_s);
    snprintf(ts, sizeof ts, "%lld",
             (long long)(plat_time_unix() + c->server_time_offset));
    wa_attr a[5];
    size_t n = 0;
    a[n++] = (wa_attr)WA_ATTR("id", msg_id);
    a[n++] = (wa_attr)WA_ATTR("type", "read");
    a[n++] = (wa_attr)WA_ATTR_JID("to", chat_s);
    a[n++] = (wa_attr)WA_ATTR("t", ts);
    if (jid_is_group(chat) && sender != NULL) {
        jid_format(sender, sender_s, sizeof sender_s);
        a[n++] = (wa_attr)WA_ATTR_JID("participant", sender_s);
    }
    wa_node r = {"receipt", a, n, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    return wa_send_node(c, &r);
}

/* ======================================================================== */
/* prekeys                                                                  */
/* ======================================================================== */

void wa_upload_prekeys(wa_client *c, unsigned count)
{
    /* Each <key> node: <key><id>3 bytes</id><value>32 bytes</value></key> */
    enum { MAXK = ZAPC_PREKEY_BATCH };
    static uint8_t ids[MAXK][3];
    static uint8_t pubs[MAXK][32];
    static wa_node idn[MAXK][2];
    static wa_node keys[MAXK];
    if (count > MAXK)
        count = MAXK;
    for (unsigned i = 0; i < count; i++) {
        wa_keypair kp;
        uint32_t id = c->dev.next_prekey_id++;
        if (c->dev.next_prekey_id > 0xFFFFFF)
            c->dev.next_prekey_id = 1;
        if (wa_keypair_generate(&kp) != 0 || prekeys_append(id, kp.priv) != 0) {
            LOGE("msg", "cannot generate prekeys");
            return;
        }
        ids[i][0] = (uint8_t)(id >> 16);
        ids[i][1] = (uint8_t)(id >> 8);
        ids[i][2] = (uint8_t)id;
        memcpy(pubs[i], kp.pub, 32);
        zap_secure_zero(&kp, sizeof kp);
        idn[i][0] = (wa_node){"id", NULL, 0, NULL, 0, ids[i], 3, WA_CONTENT_BYTES};
        idn[i][1] = (wa_node){"value", NULL, 0, NULL, 0, pubs[i], 32,
                              WA_CONTENT_BYTES};
        keys[i] = (wa_node){"key", NULL, 0, idn[i], 2, NULL, 0,
                            WA_CONTENT_CHILDREN};
    }
    credentials_save(&c->dev);

    uint8_t reg[4], skid[3];
    uint8_t type = WA_KEY_TYPE_DJB;
    wr_be32(reg, c->dev.registration_id);
    skid[0] = (uint8_t)(c->dev.signed_prekey_id >> 16);
    skid[1] = (uint8_t)(c->dev.signed_prekey_id >> 8);
    skid[2] = (uint8_t)c->dev.signed_prekey_id;
    wa_node skey_kids[3] = {
        {"id", NULL, 0, NULL, 0, skid, 3, WA_CONTENT_BYTES},
        {"value", NULL, 0, NULL, 0, c->dev.signed_prekey.pub, 32,
         WA_CONTENT_BYTES},
        {"signature", NULL, 0, NULL, 0, c->dev.signed_prekey_sig, 64,
         WA_CONTENT_BYTES},
    };
    wa_node content[5] = {
        {"registration", NULL, 0, NULL, 0, reg, 4, WA_CONTENT_BYTES},
        {"type", NULL, 0, NULL, 0, &type, 1, WA_CONTENT_BYTES},
        {"identity", NULL, 0, NULL, 0, c->dev.identity_key.pub, 32,
         WA_CONTENT_BYTES},
        {"list", NULL, 0, keys, count, NULL, 0, WA_CONTENT_CHILDREN},
        {"skey", NULL, 0, skey_kids, 3, NULL, 0, WA_CONTENT_CHILDREN},
    };
    wa_attr a[] = {WA_ATTR("id", ""), WA_ATTR("xmlns", "encrypt"),
                   WA_ATTR("type", "set"), WA_ATTR_JID("to", WA_SERVER_USER)};
    wa_node iq = {"iq", a, WA_COUNT(a), content, 5, NULL, 0,
                  WA_CONTENT_CHILDREN};
    LOGI("msg", "uploading %u prekeys", count);
    (void)wa_send_iq(c, &iq, IQ_PREKEY_UPLOAD, -1, NULL, 0);
}

/* ======================================================================== */
/* sending                                                                  */
/* ======================================================================== */

typedef enum { JOB_GROUP_INFO, JOB_DEVICES, JOB_PREKEYS } job_stage;

typedef struct wa_send_job {
    job_stage stage;
    char id[32];
    wa_jid to;
    int is_group;
    int lid_addressing;
    char text[ZAPC_MSG_TEXT_MAX];
    wa_jid users[MAX_GROUP_USERS];
    int nusers;
    wa_jid devices[MAX_SEND_DEVICES];
    int ndevices;
} wa_send_job;

static wa_send_job g_job;

void wa_message_job_abort(wa_client *c, const char *why)
{
    if (c->send_job == NULL)
        return;
    LOGW("msg", "message %s not sent: %s", c->send_job->id, why);
    if (c->ev.on_receipt != NULL)
        c->ev.on_receipt(c->ev.user, &c->send_job->to, c->send_job->id, "error");
    c->send_job = NULL;
}

void wa_message_job_timeout(wa_client *c) { wa_message_job_abort(c, "timeout"); }

static size_t build_message_proto(const char *text, uint8_t *out, size_t cap)
{
    zbuf b;
    zbuf_init(&b, out, cap);
    pb_put_string(&b, 1, text); /* conversation */
    return b.overflow ? 0 : b.len;
}

static size_t build_dsm_proto(const wa_jid *to, const uint8_t *msg,
                              size_t mlen, uint8_t *out, size_t cap)
{
    char dest[WA_JID_STR_MAX];
    zbuf b;
    jid_format(to, dest, sizeof dest);
    zbuf_init(&b, out, cap);
    size_t m = pb_begin(&b, 31);
    pb_put_string(&b, 1, dest);
    pb_put_bytes(&b, 2, msg, mlen);
    pb_end(&b, m);
    return b.overflow ? 0 : b.len;
}

/* Message{senderKeyDistributionMessage{groupId, axolotlSKDM}} */
static size_t build_skdm_proto(const wa_jid *group, const uint8_t *skdm,
                               size_t len, uint8_t *out, size_t cap)
{
    char gid[WA_JID_STR_MAX];
    zbuf b;
    jid_format(group, gid, sizeof gid);
    zbuf_init(&b, out, cap);
    size_t m = pb_begin(&b, 2);
    pb_put_string(&b, 1, gid);
    pb_put_bytes(&b, 2, skdm, len);
    pb_end(&b, m);
    return b.overflow ? 0 : b.len;
}

/* Our own identity in the addressing domain used for this message. */
static void own_identity(const wa_client *c, int lid, wa_jid *out)
{
    if (lid && !jid_is_empty(&c->dev.lid))
        *out = c->dev.lid;
    else
        *out = c->dev.jid;
}

static void request_devices(wa_client *c, wa_send_job *job)
{
    static char jids[MAX_GROUP_USERS + 2][WA_JID_STR_MAX];
    static wa_attr ua[MAX_GROUP_USERS + 2][1];
    static wa_node users[MAX_GROUP_USERS + 2];
    char sid[24];
    size_t n = 0;
    wa_jid me;
    own_identity(c, job->lid_addressing, &me);
    jid_to_non_ad(&me, &me);

    if (!job->is_group) {
        jid_to_non_ad(&job->users[0], &job->to);
        job->nusers = 1;
    }
    int have_me = 0;
    for (int i = 0; i < job->nusers; i++) {
        if (jid_same_user(&job->users[i], &me))
            have_me = 1;
        jid_format(&job->users[i], jids[n], sizeof jids[n]);
        ua[n][0] = (wa_attr)WA_ATTR_JID("jid", jids[n]);
        users[n] = (wa_node){"user", ua[n], 1, NULL, 0, NULL, 0, WA_CONTENT_NONE};
        n++;
    }
    if (!have_me) {
        jid_format(&me, jids[n], sizeof jids[n]);
        ua[n][0] = (wa_attr)WA_ATTR_JID("jid", jids[n]);
        users[n] = (wa_node){"user", ua[n], 1, NULL, 0, NULL, 0, WA_CONTENT_NONE};
        n++;
    }
    wa_new_request_id(c, sid, sizeof sid);
    wa_attr da[] = {WA_ATTR("version", "2")};
    wa_node devices = {"devices", da, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    wa_node qkids[2] = {
        {"query", NULL, 0, &devices, 1, NULL, 0, WA_CONTENT_CHILDREN},
        {"list", NULL, 0, users, n, NULL, 0, WA_CONTENT_CHILDREN},
    };
    wa_attr usa[] = {WA_ATTR("sid", sid), WA_ATTR("mode", "query"),
                     WA_ATTR("last", "true"), WA_ATTR("index", "0"),
                     WA_ATTR("context", "message")};
    wa_node usync = {"usync", usa, WA_COUNT(usa), qkids, 2, NULL, 0,
                     WA_CONTENT_CHILDREN};
    wa_attr a[] = {WA_ATTR("id", ""), WA_ATTR("xmlns", "usync"),
                   WA_ATTR("type", "get"), WA_ATTR_JID("to", WA_SERVER_USER)};
    wa_node iq = {"iq", a, WA_COUNT(a), &usync, 1, NULL, 0,
                  WA_CONTENT_CHILDREN};
    job->stage = JOB_DEVICES;
    if (wa_send_iq(c, &iq, IQ_USYNC_DEVICES, 0, NULL, 0) != 0)
        wa_message_job_abort(c, "cannot query devices");
}

static int send_group_info_query(wa_client *c, const wa_jid *group, int slot)
{
    char g[WA_JID_STR_MAX];
    jid_format(group, g, sizeof g);
    wa_attr qa[] = {WA_ATTR("request", "interactive")};
    wa_node q = {"query", qa, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    wa_attr a[] = {WA_ATTR("id", ""), WA_ATTR("xmlns", "w:g2"),
                   WA_ATTR("type", "get"), WA_ATTR_JID("to", g)};
    wa_node iq = {"iq", a, WA_COUNT(a), &q, 1, NULL, 0, WA_CONTENT_CHILDREN};
    return wa_send_iq(c, &iq, IQ_GROUP_INFO, slot, NULL, 0);
}

int wa_request_group_info(wa_client *c, const wa_jid *group)
{
    if (c->state != WA_ST_LOGGED_IN || !jid_is_group(group))
        return -1;
    return send_group_info_query(c, group, -1);
}

int wa_send_text(wa_client *c, const wa_jid *to, const char *text,
                 char *id_out, size_t id_cap)
{
    if (c->state != WA_ST_LOGGED_IN)
        return -1;
    if (c->send_job != NULL)
        return -2; /* busy */
    wa_send_job *job = &g_job;
    memset(job, 0, sizeof *job);
    wa_new_message_id(c, job->id, sizeof job->id);
    jid_to_non_ad(&job->to, to);
    job->is_group = jid_is_group(to);
    job->lid_addressing = strcmp(to->server, WA_SERVER_LID) == 0;
    zstrlcpy(job->text, text, sizeof job->text);
    c->send_job = job;
    if (id_out != NULL)
        zstrlcpy(id_out, job->id, id_cap);
    if (job->is_group) {
        job->stage = JOB_GROUP_INFO;
        if (send_group_info_query(c, &job->to, 0) != 0)
            wa_message_job_abort(c, "cannot query group");
    } else {
        request_devices(c, job);
    }
    return c->send_job != NULL ? 0 : -1;
}

static void handle_group_info(wa_client *c, const wa_node *iq,
                              const wa_pending_iq *req)
{
    const wa_node *g = wa_node_child(iq, "group");
    if (g == NULL)
        return;
    const char *subject = wa_node_attr(g, "subject");
    const char *gid = wa_node_attr(g, "id");
    const char *from = wa_node_attr(iq, "from");
    wa_jid gj;
    int have_jid = 0;
    if (from != NULL && jid_parse(&gj, from) == 0 && jid_is_group(&gj))
        have_jid = 1;
    else if (gid != NULL && jid_make(&gj, gid, WA_SERVER_GROUP) == 0)
        have_jid = 1;
    if (have_jid && subject != NULL && c->ev.on_chat_name != NULL)
        c->ev.on_chat_name(c->ev.user, &gj, subject);

    wa_send_job *job = c->send_job;
    if (req->slot < 0 || job == NULL || job->stage != JOB_GROUP_INFO)
        return;
    const char *mode = wa_node_attr(g, "addressing_mode");
    job->lid_addressing = mode != NULL && strcmp(mode, "lid") == 0;
    job->nusers = 0;
    for (size_t i = 0; g->content == WA_CONTENT_CHILDREN && i < g->child_count; i++) {
        const wa_node *p = &g->children[i];
        const char *js = wa_node_attr(p, "jid");
        wa_jid pj;
        if (strcmp(p->tag, "participant") != 0 || js == NULL ||
            jid_parse(&pj, js) != 0)
            continue;
        if (job->nusers >= MAX_GROUP_USERS) {
            wa_message_job_abort(c, "group too large for this build");
            return;
        }
        jid_to_non_ad(&job->users[job->nusers++], &pj);
    }
    if (job->nusers == 0) {
        wa_message_job_abort(c, "group has no participants");
        return;
    }
    request_devices(c, job);
}

static int add_device(wa_send_job *job, const wa_jid *user, unsigned dev)
{
    wa_jid d = *user;
    d.device = (uint16_t)dev;
    d.agent = 0;
    for (int i = 0; i < job->ndevices; i++)
        if (jid_equal(&job->devices[i], &d))
            return 0;
    if (job->ndevices >= MAX_SEND_DEVICES)
        return -1;
    job->devices[job->ndevices++] = d;
    return 0;
}

static void finish_send(wa_client *c, wa_send_job *job);

static void request_prekeys(wa_client *c, wa_send_job *job)
{
    static char jids[MAX_SEND_DEVICES][WA_JID_STR_MAX];
    static wa_attr ua[MAX_SEND_DEVICES][2];
    static wa_node users[MAX_SEND_DEVICES];
    size_t n = 0;
    char addr[96];
    for (int i = 0; i < job->ndevices; i++) {
        if (jid_signal_address(&job->devices[i], addr, sizeof addr) < 0 ||
            signal_has_session(addr))
            continue;
        jid_format(&job->devices[i], jids[n], sizeof jids[n]);
        ua[n][0] = (wa_attr)WA_ATTR_JID("jid", jids[n]);
        ua[n][1] = (wa_attr)WA_ATTR("reason", "identity");
        users[n] = (wa_node){"user", ua[n], 2, NULL, 0, NULL, 0, WA_CONTENT_NONE};
        n++;
    }
    if (n == 0) {
        finish_send(c, job);
        return;
    }
    wa_node key = {"key", NULL, 0, users, n, NULL, 0, WA_CONTENT_CHILDREN};
    wa_attr a[] = {WA_ATTR("id", ""), WA_ATTR("xmlns", "encrypt"),
                   WA_ATTR("type", "get"), WA_ATTR_JID("to", WA_SERVER_USER)};
    wa_node iq = {"iq", a, WA_COUNT(a), &key, 1, NULL, 0, WA_CONTENT_CHILDREN};
    job->stage = JOB_PREKEYS;
    if (wa_send_iq(c, &iq, IQ_PREKEY_FETCH, 0, NULL, 0) != 0)
        wa_message_job_abort(c, "cannot fetch prekeys");
}

static void handle_usync_result(wa_client *c, const wa_node *iq)
{
    wa_send_job *job = c->send_job;
    if (job == NULL || job->stage != JOB_DEVICES)
        return;
    const wa_node *list = wa_node_path(iq, "usync", "list", NULL);
    for (size_t i = 0; list != NULL && list->content == WA_CONTENT_CHILDREN &&
                       i < list->child_count;
         i++) {
        const wa_node *user = &list->children[i];
        const char *js = wa_node_attr(user, "jid");
        wa_jid uj;
        if (strcmp(user->tag, "user") != 0 || js == NULL || jid_parse(&uj, js) != 0)
            continue;
        jid_to_non_ad(&uj, &uj);
        int is_me = own_user(c, &uj);
        const wa_node *dl = wa_node_path(user, "devices", "device-list", NULL);
        for (size_t k = 0; dl != NULL && dl->content == WA_CONTENT_CHILDREN &&
                           k < dl->child_count;
             k++) {
            const wa_node *d = &dl->children[k];
            const char *ids = wa_node_attr(d, "id");
            const char *hosted = wa_node_attr(d, "is_hosted");
            if (strcmp(d->tag, "device") != 0 || ids == NULL)
                continue;
            if (hosted != NULL && strcmp(hosted, "true") == 0)
                continue;
            unsigned long dev = strtoul(ids, NULL, 10);
            if (dev > 0xFFFF)
                continue;
            if (is_me && dev == c->dev.jid.device)
                continue; /* ourselves */
            if (add_device(job, &uj, (unsigned)dev) != 0) {
                wa_message_job_abort(c, "too many devices for this build");
                return;
            }
        }
    }
    if (job->ndevices == 0 && !job->is_group)
        add_device(job, &job->to, 0); /* fall back to the main device */
    LOGD("msg", "sending to %d devices", job->ndevices);
    request_prekeys(c, job);
}

static int parse_key_node(const wa_node *n, uint32_t *id, uint8_t pub[32],
                          uint8_t *sig)
{
    const wa_node *idn = wa_node_child(n, "id");
    const wa_node *val = wa_node_child(n, "value");
    const wa_node *sg = wa_node_child(n, "signature");
    if (idn == NULL || idn->content != WA_CONTENT_BYTES || idn->data_len != 3 ||
        val == NULL || val->content != WA_CONTENT_BYTES || val->data_len != 32)
        return -1;
    *id = ((uint32_t)idn->data[0] << 16) | ((uint32_t)idn->data[1] << 8) |
          idn->data[2];
    memcpy(pub, val->data, 32);
    if (sig != NULL) {
        if (sg == NULL || sg->content != WA_CONTENT_BYTES || sg->data_len != 64)
            return -1;
        memcpy(sig, sg->data, 64);
    }
    return 0;
}

static void handle_prekey_result(wa_client *c, const wa_node *iq)
{
    wa_send_job *job = c->send_job;
    if (job == NULL || job->stage != JOB_PREKEYS)
        return;
    const wa_node *list = wa_node_child(iq, "list");
    for (size_t i = 0; list != NULL && list->content == WA_CONTENT_CHILDREN &&
                       i < list->child_count;
         i++) {
        const wa_node *u = &list->children[i];
        const char *js = wa_node_attr(u, "jid");
        wa_jid dj;
        char addr[96];
        if (js == NULL || jid_parse(&dj, js) != 0 ||
            wa_node_child(u, "error") != NULL)
            continue;
        sig_bundle b;
        memset(&b, 0, sizeof b);
        const wa_node *reg = wa_node_child(u, "registration");
        const wa_node *keys = wa_node_child(u, "keys");
        if (keys == NULL)
            keys = u;
        const wa_node *ident = wa_node_child(keys, "identity");
        if (reg == NULL || reg->content != WA_CONTENT_BYTES || reg->data_len != 4 ||
            ident == NULL || ident->content != WA_CONTENT_BYTES ||
            ident->data_len != 32)
            continue;
        b.registration_id = rd_be32(reg->data);
        memcpy(b.identity, ident->data, 32);
        if (parse_key_node(wa_node_child(keys, "skey"), &b.signed_prekey_id,
                           b.signed_prekey, b.signed_prekey_sig) != 0)
            continue;
        const wa_node *k = wa_node_child(keys, "key");
        if (k == NULL || parse_key_node(k, &b.prekey_id, b.prekey, NULL) != 0)
            b.prekey_id = SIG_NO_PREKEY;
        if (jid_signal_address(&dj, addr, sizeof addr) > 0 &&
            signal_session_from_bundle(&c->dev, addr, &b) != 0)
            LOGW("msg", "could not build session with %s", js);
    }
    finish_send(c, job);
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* phash = "2:" + base64(sha256(sorted "user.agent:device@server")[:6]) */
static void participant_hash(const wa_send_job *job, const wa_jid *self,
                             char *out, size_t cap)
{
    static char list[MAX_SEND_DEVICES + 1][WA_JID_STR_MAX];
    int n = 0;
    for (int i = 0; i < job->ndevices; i++, n++)
        snprintf(list[n], sizeof list[n], "%s.%u:%u@%s", job->devices[i].user,
                 (unsigned)job->devices[i].agent, (unsigned)job->devices[i].device,
                 job->devices[i].server);
    snprintf(list[n], sizeof list[n], "%s.0:%u@%s", self->user,
             (unsigned)self->device, self->server);
    n++;
    qsort(list, (size_t)n, sizeof list[0], cmp_str);
    zc_iov parts[MAX_SEND_DEVICES + 1];
    for (int i = 0; i < n; i++) {
        parts[i].data = list[i];
        parts[i].len = strlen(list[i]);
    }
    uint8_t hash[32];
    char b64[16];
    crypto_sha256_v(parts, (size_t)n, hash);
    base64_encode(hash, 6, b64, sizeof b64); /* 6 bytes: no padding */
    snprintf(out, cap, "2:%s", b64);
}

static void finish_send(wa_client *c, wa_send_job *job)
{
    static uint8_t msg[ZAPC_MSG_TEXT_MAX + 64];
    static uint8_t dsm[ZAPC_MSG_TEXT_MAX + 256];
    static uint8_t skdm_msg[512];
    static uint8_t pad[ZAPC_MSG_TEXT_MAX + 256 + 16];
    static uint8_t ct_mem[CT_ARENA_SIZE];
    static uint8_t skmsg[ZAPC_MSG_TEXT_MAX + 256];
    static char jids[MAX_SEND_DEVICES][WA_JID_STR_MAX];
    static wa_attr enc_attrs[MAX_SEND_DEVICES][2];
    static wa_attr to_attrs[MAX_SEND_DEVICES][1];
    static wa_node encs[MAX_SEND_DEVICES];
    static wa_node tos[MAX_SEND_DEVICES];
    zap_arena cta;
    zap_arena_init(&cta, ct_mem, sizeof ct_mem);

    wa_jid self;
    own_identity(c, job->lid_addressing, &self);
    char own_addr[96];
    jid_signal_address(&self, own_addr, sizeof own_addr);
    char group_s[WA_JID_STR_MAX];
    jid_format(&job->to, group_s, sizeof group_s);

    size_t mlen = build_message_proto(job->text, msg, sizeof msg);
    size_t dlen = 0, slen = 0;
    long sklen = 0;
    if (mlen == 0) {
        wa_message_job_abort(c, "message too long");
        return;
    }
    if (job->is_group) {
        uint8_t dist[256];
        long dl = senderkey_distribution(group_s, own_addr, dist, sizeof dist);
        slen = dl > 0 ? build_skdm_proto(&job->to, dist, (size_t)dl, skdm_msg,
                                         sizeof skdm_msg)
                      : 0;
        memcpy(pad, msg, mlen);
        size_t padded = wa_pad_message(pad, mlen, sizeof pad);
        sklen = padded ? senderkey_encrypt(group_s, own_addr, pad, padded,
                                           skmsg, sizeof skmsg)
                       : -1;
        if (slen == 0 || sklen < 0) {
            wa_message_job_abort(c, "sender key encryption failed");
            return;
        }
    } else {
        dlen = build_dsm_proto(&job->to, msg, mlen, dsm, sizeof dsm);
        if (dlen == 0) {
            wa_message_job_abort(c, "message too long");
            return;
        }
    }

    size_t n = 0;
    int include_identity = 0, reached_other = 0;
    for (int i = 0; i < job->ndevices; i++) {
        const wa_jid *d = &job->devices[i];
        char addr[96];
        int is_own = own_user(c, d);
        const uint8_t *pt = job->is_group ? skdm_msg : is_own ? dsm : msg;
        size_t plen = job->is_group ? slen : is_own ? dlen : mlen;
        memcpy(pad, pt, plen);
        size_t padded = wa_pad_message(pad, plen, sizeof pad);
        int pkmsg = 0;
        if (padded == 0 || jid_signal_address(d, addr, sizeof addr) < 0)
            continue;
        size_t room = cta.cap - cta.used;
        if (room < padded + 512) {
            LOGW("msg", "ciphertext buffer full, skipping remaining devices");
            break;
        }
        uint8_t *ct = zap_arena_alloc(&cta, padded + 512);
        long ctl = ct != NULL ? signal_encrypt(&c->dev, addr, pad, padded, ct,
                                               padded + 512, &pkmsg)
                              : -1;
        if (ctl < 0) {
            LOGD("msg", "no session with %s, skipping device", addr);
            continue;
        }
        include_identity |= pkmsg;
        if (!is_own)
            reached_other = 1;
        jid_format(d, jids[n], sizeof jids[n]);
        enc_attrs[n][0] = (wa_attr)WA_ATTR("v", "2");
        enc_attrs[n][1] = (wa_attr)WA_ATTR("type", pkmsg ? "pkmsg" : "msg");
        encs[n] = (wa_node){"enc", enc_attrs[n], 2, NULL, 0, ct, (size_t)ctl,
                            WA_CONTENT_BYTES};
        to_attrs[n][0] = (wa_attr)WA_ATTR_JID("jid", jids[n]);
        tos[n] = (wa_node){"to", to_attrs[n], 1, &encs[n], 1, NULL, 0,
                           WA_CONTENT_CHILDREN};
        n++;
    }
    zap_secure_zero(pad, sizeof pad);
    if (!reached_other && !job->is_group) {
        wa_message_job_abort(c, "no session with recipient");
        return;
    }

    wa_node content[3];
    size_t nc = 0;
    content[nc++] = (wa_node){"participants", NULL, 0, tos, n, NULL, 0,
                              WA_CONTENT_CHILDREN};
    wa_attr ska[] = {WA_ATTR("v", "2"), WA_ATTR("type", "skmsg")};
    if (job->is_group)
        content[nc++] = (wa_node){"enc", ska, 2, NULL, 0, skmsg, (size_t)sklen,
                                  WA_CONTENT_BYTES};
    if (include_identity)
        content[nc++] = (wa_node){"device-identity", NULL, 0, NULL, 0,
                                  c->dev.account, c->dev.account_len,
                                  WA_CONTENT_BYTES};
    char phash[32] = "";
    if (job->is_group)
        participant_hash(job, &self, phash, sizeof phash);
    wa_attr a[] = {WA_ATTR("id", job->id), WA_ATTR("type", "text"),
                   WA_ATTR_JID("to", group_s), WA_ATTR("phash", phash),
                   WA_ATTR("addressing_mode", job->lid_addressing && job->is_group
                                                  ? "lid"
                                                  : "")};
    wa_node m = {"message", a, WA_COUNT(a), content, nc, NULL, 0,
                 WA_CONTENT_CHILDREN};
    if (wa_send_node(c, &m) != 0) {
        wa_message_job_abort(c, "send failed");
        return;
    }
    LOGI("msg", "message %s sent (%zu device envelopes)", job->id, n);
    c->send_job = NULL;
}

void wa_handle_iq_result(wa_client *c, const wa_node *node,
                         const wa_pending_iq *req)
{
    const char *type = wa_node_attr(node, "type");
    int is_error = type != NULL && strcmp(type, "error") == 0;
    if (is_error) {
        const wa_node *err = wa_node_child(node, "error");
        LOGW("wa", "request %s failed: %s %s", req->id,
             wa_node_attr(err, "code") ? wa_node_attr(err, "code") : "?",
             wa_node_attr(err, "text") ? wa_node_attr(err, "text") : "");
        if (req->slot >= 0)
            wa_message_job_abort(c, "server error");
        return;
    }
    switch (req->kind) {
    case IQ_PREKEY_COUNT: {
        const char *v = wa_node_attr(wa_node_child(node, "count"), "value");
        int count = v != NULL ? atoi(v) : 0;
        LOGD("wa", "server has %d prekeys", count);
        if (count < 5)
            wa_upload_prekeys(c, ZAPC_PREKEY_BATCH);
        break;
    }
    case IQ_PREKEY_UPLOAD:
        c->dev.uploaded_prekey_id = c->dev.next_prekey_id;
        credentials_save(&c->dev);
        LOGI("wa", "prekeys uploaded");
        break;
    case IQ_GROUP_INFO:
        handle_group_info(c, node, req);
        break;
    case IQ_MEDIA_CONN: {
        const wa_node *mc = wa_node_child(node, "media_conn");
        c->n_media_hosts = 0;
        for (size_t i = 0; mc != NULL && mc->content == WA_CONTENT_CHILDREN &&
                           i < mc->child_count && c->n_media_hosts < WA_MEDIA_HOSTS;
             i++) {
            const char *h = wa_node_attr(&mc->children[i], "hostname");
            if (strcmp(mc->children[i].tag, "host") == 0 && h != NULL &&
                strlen(h) < sizeof c->media_hosts[0])
                zstrlcpy(c->media_hosts[c->n_media_hosts++], h,
                         sizeof c->media_hosts[0]);
        }
        LOGD("wa", "%d media hosts", c->n_media_hosts);
        break;
    }
    case IQ_USYNC_DEVICES:
        handle_usync_result(c, node);
        break;
    case IQ_PREKEY_FETCH:
        handle_prekey_result(c, node);
        break;
    default:
        break;
    }
}
