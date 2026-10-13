/*
 * ZapC - portability layer.
 *
 * Everything the rest of the code needs from the operating system that is
 * not plain ISO C goes through here, so that a port (e.g. PS2 Linux) only
 * needs a new src/platform/<name>.c.
 */
#ifndef ZAPC_PLATFORM_H
#define ZAPC_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* Monotonic clock in milliseconds (arbitrary epoch). */
uint64_t plat_now_ms(void);

/* Wall clock, seconds since the Unix epoch. */
int64_t plat_time_unix(void);

/* Format a unix timestamp as local "HH:MM". out must hold >= 6 bytes. */
void plat_format_hhmm(int64_t unix_ts, char *out, size_t out_len);

/*
 * Fill buf with cryptographically secure random bytes.
 * Returns 0 on success, -1 on failure (callers must treat this as fatal for
 * any key material).
 */
int plat_random(void *buf, size_t len);

/* Create a directory and all parents with the given mode. 0 on success. */
int plat_mkdir_p(const char *path, unsigned mode);

/* Resolve the state and config directories (XDG on Unix). 0 on success. */
int plat_state_dir(char *out, size_t out_len);
int plat_config_dir(char *out, size_t out_len);

/*
 * Write a file atomically (tmp file + rename) with the given permissions.
 * Returns 0 on success.
 */
int plat_write_file_atomic(const char *path, const void *data, size_t len,
                           unsigned mode);

/* Read a whole file into buf. Returns bytes read, or -1 on error/overflow. */
long plat_read_file(const char *path, void *buf, size_t cap);

/* Memory statistics of the current process in KiB (0 when unknown). */
typedef struct {
    unsigned long rss_kb;
    unsigned long vm_kb;
    unsigned long peak_rss_kb;
    unsigned long data_kb;
    unsigned long stack_kb;
} plat_mem_stats;

int plat_mem_stats_get(plat_mem_stats *st);

#endif
