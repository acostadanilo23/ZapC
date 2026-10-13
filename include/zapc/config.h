/*
 * ZapC - runtime configuration (~/.config/zapc/config).
 *
 * Format: one `key=value` per line, `#` starts a comment.
 */
#ifndef ZAPC_CONFIG_H
#define ZAPC_CONFIG_H

#include "zapc/build_config.h"
#include "zapc/log.h"

#include <stdint.h>

typedef struct {
    log_level log_level;
    char log_file[ZAPC_PATH_MAX];     /* empty = <state>/zapc.log         */
    char download_dir[ZAPC_PATH_MAX];
    char state_dir[ZAPC_PATH_MAX];
    unsigned history_cache;           /* messages kept per open chat      */
    int ascii;                        /* 1 = no Unicode box drawing       */
    int color;                        /* 1 = ANSI colors                  */

    /* connection */
    char wa_host[128];
    uint16_t wa_port;
    char wa_path[128];
    char ca_file[ZAPC_PATH_MAX];      /* optional extra CA bundle         */
    char media_host[128];             /* override media server (testing)  */
    uint16_t media_port;
    int history_sync;                 /* process history sync blobs       */
    uint32_t wa_version[3];           /* WhatsApp Web version to announce */
    char device_name[32];             /* shown in "Linked devices"        */
    char push_name[ZAPC_NAME_MAX];
    int auto_connect;
    unsigned keepalive_s;
} zapc_config;

void config_defaults(zapc_config *cfg);

/* Apply one `key=value` pair. Returns 0 if the key was recognised. */
int config_set(zapc_config *cfg, const char *key, const char *value);

/*
 * Load a config file.  A missing file is not an error (returns 1).
 * Returns 0 on success, -1 on read error.
 */
int config_load(zapc_config *cfg, const char *path);

#endif
