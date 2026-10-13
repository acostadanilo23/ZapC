#include "zapc/media.h"
#include "zapc/http.h"
#include "zapc/log.h"
#include "zapc/memory.h"
#include "zapc/util.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int wa_media_keys_derive(const uint8_t media_key[32], const char *app_info,
                         wa_media_keys *out)
{
    uint8_t exp[112];
    if (crypto_hkdf_sha256(NULL, 0, media_key, 32, app_info, strlen(app_info),
                           exp, sizeof exp) != 0)
        return -1;
    memcpy(out->iv, exp, 16);
    memcpy(out->cipher_key, exp + 16, 32);
    memcpy(out->mac_key, exp + 48, 32);
    zap_secure_zero(exp, sizeof exp);
    return 0;
}

typedef struct {
    FILE *f;
    zc_sha256_ctx sha;
    uint64_t size;
    int error;
} dl_sink;

static int dl_write(void *user, const uint8_t *data, size_t len)
{
    dl_sink *s = user;
    if (fwrite(data, 1, len, s->f) != len || zc_sha256_update(&s->sha, data, len) != 0) {
        s->error = 1;
        return -1;
    }
    s->size += len;
    return 0;
}

/* URL-safe base64 with padding (Go's base64.URLEncoding). */
static void b64url(const uint8_t *in, size_t n, char *out, size_t cap)
{
    base64_encode(in, n, out, cap);
    for (char *p = out; *p; p++) {
        if (*p == '+')
            *p = '-';
        else if (*p == '/')
            *p = '_';
    }
}

static int verify_mac(const char *path, const wa_media_keys *keys, uint64_t size)
{
    static uint8_t buf[16384];
    uint8_t mac[32], tail[WA_MEDIA_MAC_LEN];
    zc_hmac_ctx h;
    if (size < WA_MEDIA_MAC_LEN + 16)
        return -1;
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return -1;
    uint64_t left = size - WA_MEDIA_MAC_LEN;
    int ok = zc_hmac_sha256_init(&h, keys->mac_key, 32) == 0 &&
             zc_hmac_sha256_update(&h, keys->iv, 16) == 0;
    while (ok && left > 0) {
        size_t take = left < sizeof buf ? (size_t)left : sizeof buf;
        ok = fread(buf, 1, take, f) == take && zc_hmac_sha256_update(&h, buf, take) == 0;
        left -= take;
    }
    ok = ok && fread(tail, 1, sizeof tail, f) == sizeof tail;
    ok = ok && zc_hmac_sha256_final(&h, mac) == 0;
    fclose(f);
    return ok && zap_ct_memcmp(mac, tail, WA_MEDIA_MAC_LEN) == 0 ? 0 : -1;
}

int wa_media_download(const wa_media_ref *ref, const wa_media_keys *keys,
                      const char hosts[][64], int nhosts, uint16_t port,
                      const char *ca_file, const char *tmp_path)
{
    char path[1024], hash[64] = "";
    if (ref->direct_path == NULL || ref->direct_path[0] != '/')
        return -1;
    if (ref->enc_sha256 != NULL)
        b64url(ref->enc_sha256, 32, hash, sizeof hash);
    int n = snprintf(path, sizeof path, "%s%chash=%s&mms-type=%s&__wa-mms=",
                     ref->direct_path,
                     strchr(ref->direct_path, '?') != NULL ? '&' : '?', hash,
                     ref->mms_type);
    if (n < 0 || (size_t)n >= sizeof path)
        return -1;

    for (int i = 0; i < nhosts; i++) {
        dl_sink s;
        memset(&s, 0, sizeof s);
        s.f = fopen(tmp_path, "wb");
        if (s.f == NULL)
            return -1;
        (void)chmod(tmp_path, 0600);
        if (zc_sha256_init(&s.sha) != 0) {
            fclose(s.f);
            return -1;
        }
        LOGD("media", "downloading from %s", hosts[i]);
        int status = http_get(hosts[i], port, path, ca_file, ref->max_size,
                              dl_write, &s, 60000);
        uint8_t digest[32];
        zc_sha256_final(&s.sha, digest);
        if (fclose(s.f) != 0)
            s.error = 1;
        if (status != 200 || s.error) {
            LOGW("media", "download from %s failed (%d)", hosts[i], status);
            continue;
        }
        if (ref->enc_sha256 != NULL &&
            zap_ct_memcmp(digest, ref->enc_sha256, 32) != 0) {
            LOGW("media", "encrypted file hash mismatch");
            break;
        }
        if (verify_mac(tmp_path, keys, s.size) != 0) {
            LOGW("media", "media MAC mismatch");
            break;
        }
        return 0;
    }
    unlink(tmp_path);
    return -1;
}

int wa_media_reader_open(wa_media_reader *r, const char *path,
                         const wa_media_keys *keys)
{
    struct stat st;
    memset(r, 0, offsetof(wa_media_reader, in));
    if (stat(path, &st) != 0 || (uint64_t)st.st_size < WA_MEDIA_MAC_LEN + 16)
        return -1;
    r->f = fopen(path, "rb");
    if (r->f == NULL)
        return -1;
    r->ct_left = (uint64_t)st.st_size - WA_MEDIA_MAC_LEN;
    if (zc_cbc_decrypt_init(&r->cbc, keys->cipher_key, keys->iv) != 0) {
        fclose(r->f);
        r->f = NULL;
        return -1;
    }
    return 0;
}

long wa_media_reader_read(void *user, uint8_t *buf, size_t cap)
{
    wa_media_reader *r = user;
    while (r->out_pos == r->out_len) {
        if (r->done || r->error)
            return r->error ? -1 : 0;
        r->out_pos = 0;
        r->out_len = 0;
        if (r->ct_left == 0) {
            long n = zc_cbc_decrypt_final(&r->cbc, r->out);
            if (n < 0) {
                r->error = 1;
                return -1;
            }
            r->out_len = (size_t)n;
            r->done = 1;
            continue;
        }
        size_t take = r->ct_left < sizeof r->in ? (size_t)r->ct_left : sizeof r->in;
        if (fread(r->in, 1, take, r->f) != take) {
            r->error = 1;
            return -1;
        }
        r->ct_left -= take;
        long n = zc_cbc_decrypt_update(&r->cbc, r->in, take, r->out);
        if (n < 0) {
            r->error = 1;
            return -1;
        }
        r->out_len = (size_t)n;
    }
    size_t n = r->out_len - r->out_pos;
    if (n > cap)
        n = cap;
    memcpy(buf, r->out + r->out_pos, n);
    r->out_pos += n;
    return (long)n;
}

void wa_media_reader_close(wa_media_reader *r)
{
    if (r->f != NULL)
        fclose(r->f);
    r->f = NULL;
    zc_cbc_free(&r->cbc);
    zap_secure_zero(r->out, sizeof r->out);
}

long wa_media_encrypt(const wa_media_keys *keys, const uint8_t *in, size_t len,
                      uint8_t *out, size_t cap)
{
    long n = crypto_aes256_cbc_encrypt(keys->cipher_key, keys->iv, in, len,
                                       out, cap);
    if (n < 0 || (size_t)n + WA_MEDIA_MAC_LEN > cap)
        return -1;
    uint8_t mac[32];
    zc_iov v[2] = {{keys->iv, 16}, {out, (size_t)n}};
    if (crypto_hmac_sha256_v(keys->mac_key, 32, v, 2, mac) != 0)
        return -1;
    memcpy(out + n, mac, WA_MEDIA_MAC_LEN);
    return n + WA_MEDIA_MAC_LEN;
}
