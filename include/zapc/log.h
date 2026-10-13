/*
 * ZapC - logging.
 *
 * Never log passwords, tokens, private keys, Signal keys or decrypted
 * message contents.  Use log_hex() only for public data.
 */
#ifndef ZAPC_LOG_H
#define ZAPC_LOG_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN = 1,
    LOG_INFO = 2,
    LOG_DEBUG = 3,
    LOG_TRACE = 4
} log_level;

/* Called for every emitted line (after level filtering). */
typedef void (*log_sink_fn)(void *user, log_level lvl, const char *line);

void log_set_level(log_level lvl);
log_level log_get_level(void);
int log_level_parse(const char *s, log_level *out);
const char *log_level_name(log_level lvl);

/* Log to a file (append). NULL closes it. Returns 0 on success. */
int log_open_file(const char *path);
void log_close(void);
/* Additionally mirror lines to stderr (useful for non-interactive mode). */
void log_set_stderr(int enabled);
void log_set_sink(log_sink_fn fn, void *user);

#if defined(__GNUC__) || defined(__clang__)
#define ZAPC_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define ZAPC_PRINTF(a, b)
#endif

void log_msg(log_level lvl, const char *module, const char *fmt, ...)
    ZAPC_PRINTF(3, 4);
/* Hex dump of public data at TRACE level. */
void log_hex(const char *module, const char *label, const void *data,
             size_t len);

/* Recent lines ring buffer for /debug. index 0 = oldest. */
size_t log_ring_count(void);
const char *log_ring_get(size_t index);

#define LOGE(mod, ...) log_msg(LOG_ERROR, mod, __VA_ARGS__)
#define LOGW(mod, ...) log_msg(LOG_WARN, mod, __VA_ARGS__)
#define LOGI(mod, ...) log_msg(LOG_INFO, mod, __VA_ARGS__)
#define LOGD(mod, ...) log_msg(LOG_DEBUG, mod, __VA_ARGS__)
#define LOGT(mod, ...) log_msg(LOG_TRACE, mod, __VA_ARGS__)

#endif
