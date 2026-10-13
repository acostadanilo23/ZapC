/*
 * ZapC - WhatsApp JIDs ("user.agent:device@server").
 */
#ifndef ZAPC_JID_H
#define ZAPC_JID_H

#include <stddef.h>
#include <stdint.h>

#define WA_SERVER_USER "s.whatsapp.net"
#define WA_SERVER_GROUP "g.us"
#define WA_SERVER_LEGACY "c.us"
#define WA_SERVER_BROADCAST "broadcast"
#define WA_SERVER_LID "lid"
#define WA_SERVER_MESSENGER "msgr"
#define WA_SERVER_INTEROP "interop"
#define WA_SERVER_NEWSLETTER "newsletter"
#define WA_SERVER_HOSTED "hosted"
#define WA_SERVER_HOSTED_LID "hosted.lid"
#define WA_SERVER_BOT "bot"

/* Domain types used in AD-JID encoding. */
#define WA_DOMAIN_WHATSAPP 0
#define WA_DOMAIN_LID 1
#define WA_DOMAIN_HOSTED 128
#define WA_DOMAIN_HOSTED_LID 129

#define WA_JID_STR_MAX 112

typedef struct {
    char user[64];
    char server[24];
    uint8_t agent;      /* raw agent (0 for normal users) */
    uint16_t device;    /* 0 = main device                */
    uint16_t integrator;
} wa_jid;

void jid_clear(wa_jid *j);
int jid_is_empty(const wa_jid *j);

/* Parse "user[.agent][:device]@server" or "server". 0 on success. */
int jid_parse(wa_jid *j, const char *s);
/* Format into out. Returns length or -1 when it does not fit. */
int jid_format(const wa_jid *j, char *out, size_t cap);

/* Build a JID from parts. */
int jid_make(wa_jid *j, const char *user, const char *server);

/* The domain type for AD-JID encoding (see whatsmeow ActualAgent). */
uint8_t jid_domain(const wa_jid *j);
/* Server name for an AD-JID domain type. */
const char *jid_server_for_domain(uint8_t domain);

/* Same user and server, ignoring device/agent. */
int jid_same_user(const wa_jid *a, const wa_jid *b);
int jid_equal(const wa_jid *a, const wa_jid *b);
/* Copy without device ("non-AD" JID). */
void jid_to_non_ad(wa_jid *dst, const wa_jid *src);
int jid_is_group(const wa_jid *j);
/* Phone number / user as integer (for ClientPayload.username). */
int jid_user_u64(const wa_jid *j, uint64_t *out);

/*
 * Signal protocol address string for this JID, e.g. "123456:2" or
 * "123456_1:2" for LID users (whatsmeow's SignalAddress()).
 */
int jid_signal_address(const wa_jid *j, char *out, size_t cap);

#endif
