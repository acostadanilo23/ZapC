/*
 * ZapC - application: event loop, commands and the text UI.
 */
#ifndef ZAPC_APP_H
#define ZAPC_APP_H

#include "zapc/config.h"

typedef struct {
    int plain;      /* line mode even on a TTY */
    int no_connect; /* do not connect automatically */
} app_options;

/* Runs until /quit. Returns the process exit code. */
int app_run(const zapc_config *cfg, const app_options *opt);

#endif
