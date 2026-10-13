/*
 * ZapC - POSIX/Linux portability layer.
 */
#define _DEFAULT_SOURCE 1
#include "zapc/platform.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

uint64_t plat_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

int64_t plat_time_unix(void)
{
    return (int64_t)time(NULL);
}

void plat_format_hhmm(int64_t unix_ts, char *out, size_t out_len)
{
    time_t t = (time_t)unix_ts;
    struct tm tm;
    if (out_len == 0)
        return;
    if (localtime_r(&t, &tm) == NULL) {
        snprintf(out, out_len, "--:--");
        return;
    }
    snprintf(out, out_len, "%02d:%02d", tm.tm_hour, tm.tm_min);
}

int plat_random(void *buf, size_t len)
{
    uint8_t *p = buf;
#if defined(__linux__)
    while (len > 0) {
        ssize_t n = getrandom(p, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break; /* fall back to /dev/urandom */
        }
        p += n;
        len -= (size_t)n;
    }
    if (len == 0)
        return 0;
#endif
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    close(fd);
    return 0;
}

int plat_mkdir_p(const char *path, unsigned mode)
{
    char tmp[512];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof tmp)
        return -1;
    memcpy(tmp, path, len + 1);
    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] == '/' || tmp[i] == '\0') {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (mkdir(tmp, (mode_t)mode) != 0 && errno != EEXIST)
                return -1;
            tmp[i] = saved;
        }
    }
    return 0;
}

static int xdg_dir(const char *env, const char *fallback, char *out,
                   size_t out_len)
{
    const char *base = getenv(env);
    int n;
    if (base != NULL && base[0] == '/') {
        n = snprintf(out, out_len, "%s/zapc", base);
    } else {
        const char *home = getenv("HOME");
        if (home == NULL || home[0] == '\0')
            home = "/tmp";
        n = snprintf(out, out_len, "%s/%s/zapc", home, fallback);
    }
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

int plat_state_dir(char *out, size_t out_len)
{
    const char *override = getenv("ZAPC_STATE_DIR");
    if (override != NULL && override[0] != '\0') {
        int n = snprintf(out, out_len, "%s", override);
        return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
    }
    return xdg_dir("XDG_STATE_HOME", ".local/state", out, out_len);
}

int plat_config_dir(char *out, size_t out_len)
{
    return xdg_dir("XDG_CONFIG_HOME", ".config", out, out_len);
}

int plat_write_file_atomic(const char *path, const void *data, size_t len,
                           unsigned mode)
{
    char tmp[600];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof tmp)
        return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, (mode_t)mode);
    if (fd < 0)
        return -1;
    const uint8_t *p = data;
    size_t left = len;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0) {
            close(fd);
            unlink(tmp);
            return -1;
        }
        p += w;
        left -= (size_t)w;
    }
    if (fsync(fd) != 0 || close(fd) != 0) {
        unlink(tmp);
        return -1;
    }
    (void)chmod(tmp, (mode_t)mode);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

long plat_read_file(const char *path, void *buf, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t total = 0;
    uint8_t *p = buf;
    for (;;) {
        if (total == cap) {
            /* file larger than the buffer: check for EOF */
            uint8_t extra;
            ssize_t r = read(fd, &extra, 1);
            close(fd);
            return r == 0 ? (long)total : -1;
        }
        ssize_t r = read(fd, p + total, cap - total);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            close(fd);
            return -1;
        }
        if (r == 0)
            break;
        total += (size_t)r;
    }
    close(fd);
    return (long)total;
}

static unsigned long status_field(const char *buf, const char *key)
{
    const char *p = strstr(buf, key);
    if (p == NULL)
        return 0;
    p += strlen(key);
    while (*p == ' ' || *p == '\t')
        p++;
    return strtoul(p, NULL, 10);
}

int plat_mem_stats_get(plat_mem_stats *st)
{
    char buf[2048];
    memset(st, 0, sizeof *st);
    long n = plat_read_file("/proc/self/status", buf, sizeof buf - 1);
    if (n <= 0) {
        /* Larger than our buffer is unexpected; try a partial read. */
        FILE *f = fopen("/proc/self/status", "r");
        if (f == NULL)
            return -1;
        n = (long)fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        if (n <= 0)
            return -1;
    }
    buf[n] = '\0';
    st->rss_kb = status_field(buf, "VmRSS:");
    st->vm_kb = status_field(buf, "VmSize:");
    st->peak_rss_kb = status_field(buf, "VmHWM:");
    st->data_kb = status_field(buf, "VmData:");
    st->stack_kb = status_field(buf, "VmStk:");
    return 0;
}
