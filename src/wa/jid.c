#include "zapc/jid.h"
#include "zapc/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void jid_clear(wa_jid *j) { memset(j, 0, sizeof *j); }

int jid_is_empty(const wa_jid *j) { return j->server[0] == '\0'; }

static int parse_uint(const char *s, size_t n, unsigned long max,
                      unsigned long *out)
{
    if (n == 0 || n > 10)
        return -1;
    unsigned long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (unsigned long)(s[i] - '0');
    }
    if (v > max)
        return -1;
    *out = v;
    return 0;
}

int jid_parse(wa_jid *j, const char *s)
{
    jid_clear(j);
    const char *at = strchr(s, '@');
    if (at == NULL) {
        if (strlen(s) >= sizeof j->server)
            return -1;
        zstrlcpy(j->server, s, sizeof j->server);
        return 0;
    }
    if (strchr(at + 1, '@') != NULL)
        return -1;
    size_t slen = strlen(at + 1);
    if (slen == 0 || slen >= sizeof j->server)
        return -1;
    memcpy(j->server, at + 1, slen + 1);

    size_t ulen = (size_t)(at - s);
    const char *dot = memchr(s, '.', ulen);
    const char *colon = memchr(s, ':', ulen);
    size_t user_end = ulen;
    unsigned long v;
    if (dot != NULL) {
        user_end = (size_t)(dot - s);
        const char *ad = dot + 1;
        size_t adlen = ulen - user_end - 1;
        const char *c2 = memchr(ad, ':', adlen);
        size_t agent_len = c2 ? (size_t)(c2 - ad) : adlen;
        if (memchr(ad, '.', adlen) != NULL)
            return -1;
        if (parse_uint(ad, agent_len, 255, &v) != 0)
            return -1;
        j->agent = (uint8_t)v;
        if (c2 != NULL) {
            if (parse_uint(c2 + 1, adlen - agent_len - 1, 65535, &v) != 0)
                return -1;
            j->device = (uint16_t)v;
        }
    } else if (colon != NULL) {
        user_end = (size_t)(colon - s);
        if (parse_uint(colon + 1, ulen - user_end - 1, 65535, &v) != 0)
            return -1;
        j->device = (uint16_t)v;
    }
    if (user_end >= sizeof j->user)
        return -1;
    memcpy(j->user, s, user_end);
    j->user[user_end] = '\0';
    return 0;
}

int jid_format(const wa_jid *j, char *out, size_t cap)
{
    int n;
    if (j->server[0] == '\0') {
        n = snprintf(out, cap, "%s", "");
    } else if (j->agent > 0) {
        n = snprintf(out, cap, "%s.%u:%u@%s", j->user, (unsigned)j->agent,
                     (unsigned)j->device, j->server);
    } else if (j->device > 0) {
        n = snprintf(out, cap, "%s:%u@%s", j->user, (unsigned)j->device,
                     j->server);
    } else if (j->user[0] != '\0') {
        n = snprintf(out, cap, "%s@%s", j->user, j->server);
    } else {
        n = snprintf(out, cap, "%s", j->server);
    }
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return n;
}

int jid_make(wa_jid *j, const char *user, const char *server)
{
    jid_clear(j);
    if (strlen(user) >= sizeof j->user || strlen(server) >= sizeof j->server)
        return -1;
    zstrlcpy(j->user, user, sizeof j->user);
    zstrlcpy(j->server, server, sizeof j->server);
    return 0;
}

uint8_t jid_domain(const wa_jid *j)
{
    if (strcmp(j->server, WA_SERVER_USER) == 0)
        return WA_DOMAIN_WHATSAPP;
    if (strcmp(j->server, WA_SERVER_LID) == 0)
        return WA_DOMAIN_LID;
    if (strcmp(j->server, WA_SERVER_HOSTED) == 0)
        return WA_DOMAIN_HOSTED;
    if (strcmp(j->server, WA_SERVER_HOSTED_LID) == 0)
        return WA_DOMAIN_HOSTED_LID;
    return j->agent;
}

const char *jid_server_for_domain(uint8_t domain)
{
    switch (domain) {
    case WA_DOMAIN_LID:
        return WA_SERVER_LID;
    case WA_DOMAIN_HOSTED:
        return WA_SERVER_HOSTED;
    case WA_DOMAIN_HOSTED_LID:
        return WA_SERVER_HOSTED_LID;
    default:
        return WA_SERVER_USER;
    }
}

int jid_same_user(const wa_jid *a, const wa_jid *b)
{
    return strcmp(a->user, b->user) == 0 && strcmp(a->server, b->server) == 0;
}

int jid_equal(const wa_jid *a, const wa_jid *b)
{
    return jid_same_user(a, b) && a->device == b->device &&
           a->agent == b->agent;
}

void jid_to_non_ad(wa_jid *dst, const wa_jid *src)
{
    wa_jid t = *src;
    t.device = 0;
    t.agent = 0;
    *dst = t;
}

int jid_is_group(const wa_jid *j)
{
    return strcmp(j->server, WA_SERVER_GROUP) == 0;
}

int jid_user_u64(const wa_jid *j, uint64_t *out)
{
    if (j->user[0] == '\0' || strlen(j->user) > 19)
        return -1;
    uint64_t v = 0;
    for (const char *p = j->user; *p; p++) {
        if (*p < '0' || *p > '9')
            return -1;
        v = v * 10 + (uint64_t)(*p - '0');
    }
    *out = v;
    return 0;
}

int jid_signal_address(const wa_jid *j, char *out, size_t cap)
{
    uint8_t agent = jid_domain(j);
    int n;
    if (agent != 0)
        n = snprintf(out, cap, "%s_%u:%u", j->user, (unsigned)agent,
                     (unsigned)j->device);
    else
        n = snprintf(out, cap, "%s:%u", j->user, (unsigned)j->device);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}
