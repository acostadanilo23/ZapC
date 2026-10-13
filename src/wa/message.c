/*
 * ZapC - messages: receive/decrypt, receipts, prekey upload and the send
 * pipeline (device list -> prekey bundles -> encrypt -> send).
 */
#include "zapc/crypto.h"
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

#define MAX_SEND_DEVICES 24

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
            if (type == 0)
                copy_text(x, "[mensagem apagada]", (const uint8_t *)"", 0, "");
            else if (type == 14 && sub_string(f.data, f.len, 14, &s, &sl)) {
                char tmp[ZAPC_MSG_TEXT_MAX];
                msg_extract y = {tmp, sizeof tmp, NULL, 0, "", 0};
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

    int decrypted_any = 0, failed = 0;
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
        msg_extract x = {m.text, sizeof m.text, NULL, 0, "", m.text[0] != '\0'};
        extract(&x, plain, (size_t)n, 0);
        if (x.skdm != NULL && is_group &&
            senderkey_process(from_s, addr, x.skdm, x.skdm_len) != 0)
            LOGW("msg", "invalid sender key distribution message");
        if (x.dsm_dest[0] != '\0' && m.from_me) {
            wa_jid dest;
            if (jid_parse(&dest, x.dsm_dest) == 0)
                jid_to_non_ad(&m.chat, &dest);
        }
    }
    zap_secure_zero(plain, sizeof plain);

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

typedef enum { JOB_DEVICES, JOB_PREKEYS } job_stage;

typedef struct wa_send_job {
    job_stage stage;
    char id[32];
    wa_jid to;
    char text[ZAPC_MSG_TEXT_MAX];
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

static void request_devices(wa_client *c, wa_send_job *job)
{
    char to_s[WA_JID_STR_MAX], me_s[WA_JID_STR_MAX], sid[24];
    wa_jid to_user, me_user;
    jid_to_non_ad(&to_user, &job->to);
    /* use the same addressing (PN or LID) for our own devices */
    if (strcmp(job->to.server, WA_SERVER_LID) == 0 && !jid_is_empty(&c->dev.lid))
        jid_to_non_ad(&me_user, &c->dev.lid);
    else
        jid_to_non_ad(&me_user, &c->dev.jid);
    jid_format(&to_user, to_s, sizeof to_s);
    jid_format(&me_user, me_s, sizeof me_s);
    wa_new_request_id(c, sid, sizeof sid);

    wa_attr ua[2][1] = {{WA_ATTR_JID("jid", to_s)}, {WA_ATTR_JID("jid", me_s)}};
    wa_node users[2] = {
        {"user", ua[0], 1, NULL, 0, NULL, 0, WA_CONTENT_NONE},
        {"user", ua[1], 1, NULL, 0, NULL, 0, WA_CONTENT_NONE},
    };
    wa_attr da[] = {WA_ATTR("version", "2")};
    wa_node devices = {"devices", da, 1, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    wa_node qkids[2] = {
        {"query", NULL, 0, &devices, 1, NULL, 0, WA_CONTENT_CHILDREN},
        {"list", NULL, 0, users, jid_same_user(&to_user, &me_user) ? 1u : 2u,
         NULL, 0, WA_CONTENT_CHILDREN},
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

int wa_send_text(wa_client *c, const wa_jid *to, const char *text,
                 char *id_out, size_t id_cap)
{
    if (c->state != WA_ST_LOGGED_IN)
        return -1;
    if (c->send_job != NULL)
        return -2; /* busy */
    if (jid_is_group(to)) {
        LOGW("msg", "sending to groups is not implemented yet");
        return -3;
    }
    wa_send_job *job = &g_job;
    memset(job, 0, sizeof *job);
    wa_new_message_id(c, job->id, sizeof job->id);
    jid_to_non_ad(&job->to, to);
    zstrlcpy(job->text, text, sizeof job->text);
    c->send_job = job;
    if (id_out != NULL)
        zstrlcpy(id_out, job->id, id_cap);
    request_devices(c, job);
    return c->send_job != NULL ? 0 : -1;
}

static void add_device(wa_send_job *job, const wa_jid *user, unsigned dev)
{
    if (job->ndevices >= MAX_SEND_DEVICES)
        return;
    wa_jid d = *user;
    d.device = (uint16_t)dev;
    d.agent = 0;
    for (int i = 0; i < job->ndevices; i++)
        if (jid_equal(&job->devices[i], &d))
            return;
    job->devices[job->ndevices++] = d;
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
    if (job == NULL)
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
            unsigned dev = (unsigned)strtoul(ids, NULL, 10);
            if (dev > 0xFFFF)
                continue;
            /* skip ourselves */
            if (is_me && dev == c->dev.jid.device)
                continue;
            add_device(job, &uj, dev);
        }
    }
    if (job->ndevices == 0) {
        /* no device list: fall back to the main device */
        add_device(job, &job->to, 0);
    }
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
    if (job == NULL)
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

static void finish_send(wa_client *c, wa_send_job *job)
{
    static uint8_t msg[ZAPC_MSG_TEXT_MAX + 64];
    static uint8_t dsm[ZAPC_MSG_TEXT_MAX + 256];
    static uint8_t pad[ZAPC_MSG_TEXT_MAX + 256 + 16];
    static uint8_t cts[MAX_SEND_DEVICES][ZAPC_MSG_TEXT_MAX + 512];
    static char jids[MAX_SEND_DEVICES][WA_JID_STR_MAX];
    static wa_attr enc_attrs[MAX_SEND_DEVICES][2];
    static wa_attr to_attrs[MAX_SEND_DEVICES][1];
    static wa_node encs[MAX_SEND_DEVICES];
    static wa_node tos[MAX_SEND_DEVICES];

    size_t mlen = build_message_proto(job->text, msg, sizeof msg);
    size_t dlen = build_dsm_proto(&job->to, msg, mlen, dsm, sizeof dsm);
    if (mlen == 0 || dlen == 0) {
        wa_message_job_abort(c, "message too long");
        return;
    }
    size_t n = 0;
    int include_identity = 0;
    for (int i = 0; i < job->ndevices; i++) {
        const wa_jid *d = &job->devices[i];
        char addr[96];
        int is_own = own_user(c, d);
        const uint8_t *pt = is_own ? dsm : msg;
        size_t plen = is_own ? dlen : mlen;
        memcpy(pad, pt, plen);
        size_t padded = wa_pad_message(pad, plen, sizeof pad);
        int pkmsg = 0;
        if (padded == 0 || jid_signal_address(d, addr, sizeof addr) < 0)
            continue;
        long ct = signal_encrypt(&c->dev, addr, pad, padded, cts[n],
                                 sizeof cts[n], &pkmsg);
        if (ct < 0) {
            LOGD("msg", "no session with %s, skipping device", addr);
            continue;
        }
        include_identity |= pkmsg;
        jid_format(d, jids[n], sizeof jids[n]);
        enc_attrs[n][0] = (wa_attr)WA_ATTR("v", "2");
        enc_attrs[n][1] = (wa_attr)WA_ATTR("type", pkmsg ? "pkmsg" : "msg");
        encs[n] = (wa_node){"enc", enc_attrs[n], 2, NULL, 0, cts[n], (size_t)ct,
                            WA_CONTENT_BYTES};
        to_attrs[n][0] = (wa_attr)WA_ATTR_JID("jid", jids[n]);
        tos[n] = (wa_node){"to", to_attrs[n], 1, &encs[n], 1, NULL, 0,
                           WA_CONTENT_CHILDREN};
        n++;
    }
    zap_secure_zero(pad, sizeof pad);
    int to_ok = 0;
    for (size_t i = 0; i < n; i++)
        if (!own_user(c, &job->devices[i]))
            to_ok = 1;
    if (!to_ok) {
        wa_message_job_abort(c, "no session with recipient");
        return;
    }
    char to_s[WA_JID_STR_MAX];
    jid_format(&job->to, to_s, sizeof to_s);
    wa_node content[2] = {
        {"participants", NULL, 0, tos, n, NULL, 0, WA_CONTENT_CHILDREN},
        {"device-identity", NULL, 0, NULL, 0, c->dev.account,
         c->dev.account_len, WA_CONTENT_BYTES},
    };
    wa_attr a[] = {WA_ATTR("id", job->id), WA_ATTR("type", "text"),
                   WA_ATTR_JID("to", to_s)};
    wa_node m = {"message", a, WA_COUNT(a), content,
                 include_identity ? 2u : 1u, NULL, 0, WA_CONTENT_CHILDREN};
    if (wa_send_node(c, &m) != 0) {
        wa_message_job_abort(c, "send failed");
        return;
    }
    LOGI("msg", "message %s sent to %zu devices", job->id, n);
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
