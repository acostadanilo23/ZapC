#include "zapc/log.h"
#include "zapc/build_config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

static log_level g_level = LOG_INFO;
static FILE *g_file;
static int g_stderr;
static log_sink_fn g_sink;
static void *g_sink_user;

#define LOG_LINE_MAX 256
static char g_ring[ZAPC_LOG_RING][LOG_LINE_MAX];
static size_t g_ring_head; /* next slot to write */
static size_t g_ring_count;

static const char *const level_names[] = {"ERROR", "WARN", "INFO", "DEBUG",
                                          "TRACE"};

void log_set_level(log_level lvl) { g_level = lvl; }
log_level log_get_level(void) { return g_level; }

const char *log_level_name(log_level lvl)
{
    if ((unsigned)lvl > LOG_TRACE)
        return "?";
    return level_names[lvl];
}

int log_level_parse(const char *s, log_level *out)
{
    for (unsigned i = 0; i <= LOG_TRACE; i++) {
        if (strcasecmp(s, level_names[i]) == 0) {
            *out = (log_level)i;
            return 0;
        }
    }
    if (strcasecmp(s, "warning") == 0) {
        *out = LOG_WARN;
        return 0;
    }
    return -1;
}

int log_open_file(const char *path)
{
    log_close();
    if (path == NULL)
        return 0;
    g_file = fopen(path, "a");
    if (g_file == NULL)
        return -1;
    (void)chmod(path, 0600); /* logs may contain phone numbers */
    setvbuf(g_file, NULL, _IOLBF, 0);
    return 0;
}

void log_close(void)
{
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
}

void log_set_stderr(int enabled) { g_stderr = enabled; }

void log_set_sink(log_sink_fn fn, void *user)
{
    g_sink = fn;
    g_sink_user = user;
}

void log_msg(log_level lvl, const char *module, const char *fmt, ...)
{
    if (lvl > g_level)
        return;
    char msg[LOG_LINE_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    char line[LOG_LINE_MAX + 32];
    snprintf(line, sizeof line, "%-5s %-8s %s", log_level_name(lvl), module,
             msg);

    memcpy(g_ring[g_ring_head], line, LOG_LINE_MAX - 1);
    g_ring[g_ring_head][LOG_LINE_MAX - 1] = '\0';
    g_ring_head = (g_ring_head + 1) % ZAPC_LOG_RING;
    if (g_ring_count < ZAPC_LOG_RING)
        g_ring_count++;

    if (g_file != NULL) {
        time_t now = time(NULL);
        struct tm tm;
        char ts[32] = "";
        if (localtime_r(&now, &tm) != NULL)
            strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
        fprintf(g_file, "%s %s\n", ts, line);
    }
    if (g_stderr)
        fprintf(stderr, "%s\n", line);
    if (g_sink != NULL)
        g_sink(g_sink_user, lvl, line);
}

void log_hex(const char *module, const char *label, const void *data,
             size_t len)
{
    if (g_level < LOG_TRACE)
        return;
    static const char hx[] = "0123456789abcdef";
    char buf[2 * 64 + 4];
    const uint8_t *p = data;
    size_t n = len > 64 ? 64 : len;
    for (size_t i = 0; i < n; i++) {
        buf[2 * i] = hx[p[i] >> 4];
        buf[2 * i + 1] = hx[p[i] & 15];
    }
    buf[2 * n] = '\0';
    log_msg(LOG_TRACE, module, "%s (%zu bytes): %s%s", label, len, buf,
            len > n ? "..." : "");
}

size_t log_ring_count(void) { return g_ring_count; }

const char *log_ring_get(size_t index)
{
    if (index >= g_ring_count)
        return NULL;
    size_t start = (g_ring_head + ZAPC_LOG_RING - g_ring_count) % ZAPC_LOG_RING;
    return g_ring[(start + index) % ZAPC_LOG_RING];
}
