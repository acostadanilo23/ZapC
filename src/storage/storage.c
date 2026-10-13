#include "zapc/storage.h"
#include "zapc/log.h"
#include "zapc/platform.h"
#include "zapc/util.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[ZAPC_PATH_MAX];

int storage_init(const char *state_dir)
{
    zstrlcpy(g_dir, state_dir, sizeof g_dir);
    if (plat_mkdir_p(g_dir, 0700) != 0) {
        LOGE("storage", "cannot create %s: %s", g_dir, strerror(errno));
        return -1;
    }
    (void)chmod(g_dir, 0700);
    static const char *const subdirs[] = {"sessions", "identities",
                                          "senderkeys", "messages"};
    for (size_t i = 0; i < sizeof subdirs / sizeof subdirs[0]; i++) {
        char p[ZAPC_PATH_MAX];
        if (storage_path(p, sizeof p, subdirs[i]) != 0 ||
            plat_mkdir_p(p, 0700) != 0)
            return -1;
    }
    return 0;
}

const char *storage_dir(void) { return g_dir; }

int storage_path(char *out, size_t cap, const char *rel)
{
    int n = snprintf(out, cap, "%s/%s", g_dir, rel);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* Only allow file names made of safe characters. */
static int safe_name(const char *s)
{
    if (s[0] == '\0' || s[0] == '.')
        return 0;
    for (; *s; s++) {
        char c = *s;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' ||
              c == ':' || c == '@'))
            return 0;
    }
    return 1;
}

static int blob_path(char *out, size_t cap, const char *kind, const char *name)
{
    if (!safe_name(kind) || !safe_name(name))
        return -1;
    int n = snprintf(out, cap, "%s/%s/%s", g_dir, kind, name);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

long storage_blob_load(const char *kind, const char *name, void *buf,
                       size_t cap)
{
    char p[ZAPC_PATH_MAX];
    if (blob_path(p, sizeof p, kind, name) != 0)
        return -1;
    return plat_read_file(p, buf, cap);
}

int storage_blob_save(const char *kind, const char *name, const void *data,
                      size_t len)
{
    char p[ZAPC_PATH_MAX];
    if (blob_path(p, sizeof p, kind, name) != 0)
        return -1;
    return plat_write_file_atomic(p, data, len, 0600);
}

int storage_blob_delete(const char *kind, const char *name)
{
    char p[ZAPC_PATH_MAX];
    if (blob_path(p, sizeof p, kind, name) != 0)
        return -1;
    return unlink(p) == 0 || errno == ENOENT ? 0 : -1;
}

static void clear_dir(const char *rel)
{
    char p[ZAPC_PATH_MAX];
    if (storage_path(p, sizeof p, rel) != 0)
        return;
    DIR *d = opendir(p);
    if (d == NULL)
        return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        char f[ZAPC_PATH_MAX + 256];
        snprintf(f, sizeof f, "%s/%s", p, e->d_name);
        (void)unlink(f);
    }
    closedir(d);
}

int credentials_delete(void)
{
    char p[ZAPC_PATH_MAX];
    if (storage_path(p, sizeof p, "credentials.bin") == 0)
        (void)unlink(p);
    if (storage_path(p, sizeof p, "prekeys.bin") == 0)
        (void)unlink(p);
    clear_dir("sessions");
    clear_dir("identities");
    clear_dir("senderkeys");
    return 0;
}

/* ---- prekeys: fixed 36-byte records (id BE32 + private key) ------------- */

#define PREKEY_REC 36

int prekeys_append(uint32_t id, const uint8_t priv[32])
{
    char p[ZAPC_PATH_MAX];
    uint8_t rec[PREKEY_REC];
    if (storage_path(p, sizeof p, "prekeys.bin") != 0)
        return -1;
    FILE *f = fopen(p, "ab");
    if (f == NULL)
        return -1;
    (void)chmod(p, 0600);
    wr_be32(rec, id);
    memcpy(rec + 4, priv, 32);
    int ok = fwrite(rec, 1, sizeof rec, f) == sizeof rec;
    ok = (fclose(f) == 0) && ok;
    memset(rec, 0, sizeof rec);
    return ok ? 0 : -1;
}

int prekeys_find(uint32_t id, uint8_t priv[32])
{
    char p[ZAPC_PATH_MAX];
    uint8_t rec[PREKEY_REC];
    if (storage_path(p, sizeof p, "prekeys.bin") != 0)
        return -1;
    FILE *f = fopen(p, "rb");
    if (f == NULL)
        return -1;
    int found = -1;
    while (fread(rec, 1, sizeof rec, f) == sizeof rec) {
        if (rd_be32(rec) == id) {
            memcpy(priv, rec + 4, 32);
            found = 0;
            break;
        }
    }
    fclose(f);
    memset(rec, 0, sizeof rec);
    return found;
}

int prekeys_remove(uint32_t id)
{
    char p[ZAPC_PATH_MAX], tmp[ZAPC_PATH_MAX + 8];
    uint8_t rec[PREKEY_REC];
    if (storage_path(p, sizeof p, "prekeys.bin") != 0)
        return -1;
    snprintf(tmp, sizeof tmp, "%s.tmp", p);
    FILE *in = fopen(p, "rb");
    if (in == NULL)
        return -1;
    FILE *out = fopen(tmp, "wb");
    if (out == NULL) {
        fclose(in);
        return -1;
    }
    (void)chmod(tmp, 0600);
    int ok = 1;
    while (fread(rec, 1, sizeof rec, in) == sizeof rec)
        if (rd_be32(rec) != id && fwrite(rec, 1, sizeof rec, out) != sizeof rec)
            ok = 0;
    fclose(in);
    ok = (fclose(out) == 0) && ok;
    memset(rec, 0, sizeof rec);
    if (!ok || rename(tmp, p) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

long prekeys_count(void)
{
    char p[ZAPC_PATH_MAX];
    struct stat st;
    if (storage_path(p, sizeof p, "prekeys.bin") != 0)
        return -1;
    if (stat(p, &st) != 0)
        return 0;
    return (long)(st.st_size / PREKEY_REC);
}
