/*
 * ZapC - unofficial WhatsApp client for the terminal.
 */
#include "zapc/app.h"
#include "zapc/config.h"
#include "zapc/log.h"
#include "zapc/platform.h"

#include <stdio.h>
#include <string.h>

#define ZAPC_VERSION "0.1.0"

static void usage(void)
{
    printf("uso: zapc [op\xc3\xa7\xc3\xb5" "es]\n"
           "  --plain            modo linha (sem tela cheia)\n"
           "  --ascii            bordas ASCII (sem Unicode)\n"
           "  --no-connect       n\xc3\xa3o conectar ao iniciar\n"
           "  --config <arq>     arquivo de configura\xc3\xa7\xc3\xa3o\n"
           "  --state-dir <dir>  diret\xc3\xb3rio de estado\n"
           "  --log-level <n>    error|warn|info|debug|trace\n"
           "  --set chave=valor  sobrescrever uma configura\xc3\xa7\xc3\xa3o\n"
           "  --version\n");
}

int main(int argc, char **argv)
{
    zapc_config cfg;
    app_options opt;
    char cfgpath[ZAPC_PATH_MAX + 16] = "";
    memset(&opt, 0, sizeof opt);
    config_defaults(&cfg);

    /* first pass: config file location */
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            snprintf(cfgpath, sizeof cfgpath, "%s", argv[++i]);
    if (cfgpath[0] == '\0') {
        char dir[ZAPC_PATH_MAX];
        if (plat_config_dir(dir, sizeof dir) == 0)
            snprintf(cfgpath, sizeof cfgpath, "%s/config", dir);
    }
    if (cfgpath[0] != '\0' && config_load(&cfg, cfgpath) < 0)
        fprintf(stderr, "zapc: cannot read %s\n", cfgpath);

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--plain") == 0) {
            opt.plain = 1;
        } else if (strcmp(a, "--ascii") == 0) {
            cfg.ascii = 1;
        } else if (strcmp(a, "--no-connect") == 0) {
            opt.no_connect = 1;
        } else if (strcmp(a, "--config") == 0 && i + 1 < argc) {
            i++;
        } else if (strcmp(a, "--state-dir") == 0 && i + 1 < argc) {
            config_set(&cfg, "state_dir", argv[++i]);
        } else if (strcmp(a, "--log-level") == 0 && i + 1 < argc) {
            if (config_set(&cfg, "log_level", argv[++i]) != 0) {
                fprintf(stderr, "zapc: invalid log level\n");
                return 2;
            }
        } else if (strcmp(a, "--set") == 0 && i + 1 < argc) {
            char kv[ZAPC_PATH_MAX + 64];
            snprintf(kv, sizeof kv, "%s", argv[++i]);
            char *eq = strchr(kv, '=');
            if (eq == NULL || (*eq = '\0', config_set(&cfg, kv, eq + 1)) != 0) {
                fprintf(stderr, "zapc: invalid setting %s\n", argv[i]);
                return 2;
            }
        } else if (strcmp(a, "--version") == 0) {
            printf("zapc %s\n", ZAPC_VERSION);
            return 0;
        } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage();
            return 0;
        } else {
            fprintf(stderr, "zapc: unknown option %s\n", a);
            usage();
            return 2;
        }
    }
    log_set_level(cfg.log_level);
    return app_run(&cfg, &opt);
}
