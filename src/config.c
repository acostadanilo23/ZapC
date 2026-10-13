#include "zapc/config.h"
#include "zapc/platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void config_defaults(zapc_config *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->log_level = LOG_INFO;
    cfg->history_cache = ZAPC_VISIBLE_MESSAGES;
    cfg->ascii = 0;
    cfg->color = 1;
    snprintf(cfg->wa_host, sizeof cfg->wa_host, "web.whatsapp.com");
    cfg->wa_port = 443;
    cfg->media_port = 443;
    cfg->history_sync = 1;
    snprintf(cfg->wa_path, sizeof cfg->wa_path, "/ws/chat");
    cfg->wa_version[0] = 2;
    cfg->wa_version[1] = 3000;
    cfg->wa_version[2] = 1049558099;
    snprintf(cfg->device_name, sizeof cfg->device_name, "ZapC");
    cfg->auto_connect = 1;
    cfg->keepalive_s = 25;
    if (plat_state_dir(cfg->state_dir, sizeof cfg->state_dir) != 0)
        snprintf(cfg->state_dir, sizeof cfg->state_dir, "/tmp/zapc");
    const char *home = getenv("HOME");
    snprintf(cfg->download_dir, sizeof cfg->download_dir, "%s/Downloads",
             home != NULL ? home : "/tmp");
}

static int parse_bool(const char *v)
{
    return strcasecmp(v, "1") == 0 || strcasecmp(v, "true") == 0 ||
           strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0;
}

static int parse_uint(const char *v, unsigned long max, unsigned long *out)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(v, &end, 10);
    if (errno != 0 || end == v || *end != '\0' || n > max)
        return -1;
    *out = n;
    return 0;
}

static int copy_str(char *dst, size_t cap, const char *v)
{
    size_t n = strlen(v);
    if (n >= cap)
        return -1;
    memcpy(dst, v, n + 1);
    return 0;
}

int config_set(zapc_config *cfg, const char *key, const char *value)
{
    unsigned long n;
    if (strcmp(key, "log_level") == 0)
        return log_level_parse(value, &cfg->log_level);
    if (strcmp(key, "log_file") == 0)
        return copy_str(cfg->log_file, sizeof cfg->log_file, value);
    if (strcmp(key, "download_dir") == 0)
        return copy_str(cfg->download_dir, sizeof cfg->download_dir, value);
    if (strcmp(key, "state_dir") == 0)
        return copy_str(cfg->state_dir, sizeof cfg->state_dir, value);
    if (strcmp(key, "history_cache") == 0) {
        if (parse_uint(value, ZAPC_VISIBLE_MESSAGES, &n) != 0 || n == 0)
            return -1;
        cfg->history_cache = (unsigned)n;
        return 0;
    }
    if (strcmp(key, "ascii") == 0) {
        cfg->ascii = parse_bool(value);
        return 0;
    }
    if (strcmp(key, "color") == 0) {
        cfg->color = parse_bool(value);
        return 0;
    }
    if (strcmp(key, "wa_host") == 0)
        return copy_str(cfg->wa_host, sizeof cfg->wa_host, value);
    if (strcmp(key, "wa_path") == 0)
        return copy_str(cfg->wa_path, sizeof cfg->wa_path, value);
    if (strcmp(key, "wa_port") == 0) {
        if (parse_uint(value, 65535, &n) != 0 || n == 0)
            return -1;
        cfg->wa_port = (uint16_t)n;
        return 0;
    }
    if (strcmp(key, "media_host") == 0)
        return copy_str(cfg->media_host, sizeof cfg->media_host, value);
    if (strcmp(key, "media_port") == 0) {
        if (parse_uint(value, 65535, &n) != 0 || n == 0)
            return -1;
        cfg->media_port = (uint16_t)n;
        return 0;
    }
    if (strcmp(key, "history_sync") == 0) {
        cfg->history_sync = parse_bool(value);
        return 0;
    }
    if (strcmp(key, "ca_file") == 0)
        return copy_str(cfg->ca_file, sizeof cfg->ca_file, value);
    if (strcmp(key, "wa_version") == 0) {
        unsigned long a, b, c;
        char extra;
        if (sscanf(value, "%lu.%lu.%lu%c", &a, &b, &c, &extra) != 3 ||
            a > UINT32_MAX || b > UINT32_MAX || c > UINT32_MAX)
            return -1;
        cfg->wa_version[0] = (uint32_t)a;
        cfg->wa_version[1] = (uint32_t)b;
        cfg->wa_version[2] = (uint32_t)c;
        return 0;
    }
    if (strcmp(key, "device_name") == 0)
        return copy_str(cfg->device_name, sizeof cfg->device_name, value);
    if (strcmp(key, "push_name") == 0)
        return copy_str(cfg->push_name, sizeof cfg->push_name, value);
    if (strcmp(key, "auto_connect") == 0) {
        cfg->auto_connect = parse_bool(value);
        return 0;
    }
    if (strcmp(key, "keepalive") == 0) {
        if (parse_uint(value, 600, &n) != 0 || n < 5)
            return -1;
        cfg->keepalive_s = (unsigned)n;
        return 0;
    }
    return -1;
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                     s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = '\0';
    return s;
}

int config_load(zapc_config *cfg, const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return errno == ENOENT ? 1 : -1;
    char line[ZAPC_PATH_MAX + 64];
    unsigned lineno = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        lineno++;
        char *s = trim(line);
        if (*s == '\0' || *s == '#')
            continue;
        char *eq = strchr(s, '=');
        if (eq == NULL) {
            LOGW("config", "%s:%u: missing '='", path, lineno);
            continue;
        }
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);
        if (config_set(cfg, key, val) != 0)
            LOGW("config", "%s:%u: invalid setting '%s'", path, lineno, key);
    }
    fclose(f);
    return 0;
}
