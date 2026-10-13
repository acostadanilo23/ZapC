/*
 * ZapC - encrypted media download (used for history sync blobs; the same
 * code path will serve /download later).
 *
 * The encrypted file is streamed to a temporary file while its SHA-256 is
 * computed, then its HMAC is verified, and only then it is decrypted - again
 * streaming - through a reader that plugs into the inflater.  Memory use is
 * independent of the file size.
 */
#ifndef ZAPC_MEDIA_H
#define ZAPC_MEDIA_H

#include "zapc/crypto.h"

#include <stdint.h>
#include <stdio.h>

#define WA_MEDIA_HISTORY_INFO "WhatsApp History Keys"
#define WA_MEDIA_HISTORY_MMS "md-msg-hist"
#define WA_MEDIA_MAC_LEN 10
#define WA_MEDIA_MAX_HOSTS 4

typedef struct {
    uint8_t iv[16];
    uint8_t cipher_key[32];
    uint8_t mac_key[32];
} wa_media_keys;

int wa_media_keys_derive(const uint8_t media_key[32], const char *app_info,
                         wa_media_keys *out);

typedef struct {
    const char *direct_path;
    const uint8_t *enc_sha256; /* may be NULL */
    const char *mms_type;
    uint64_t max_size;
} wa_media_ref;

/*
 * Download and verify into `tmp_path`.  hosts are tried in order; port is
 * normally 443.  Returns 0 when the file is authentic.
 */
int wa_media_download(const wa_media_ref *ref, const wa_media_keys *keys,
                      const char hosts[][64], int nhosts, uint16_t port,
                      const char *ca_file, const char *tmp_path);

/* Streaming decryption of a verified file. */
typedef struct {
    FILE *f;
    uint64_t ct_left;
    zc_cbc_ctx cbc;
    uint8_t in[16384];
    uint8_t out[16384 + 32];
    size_t out_len;
    size_t out_pos;
    int done;
    int error;
} wa_media_reader;

int wa_media_reader_open(wa_media_reader *r, const char *path,
                         const wa_media_keys *keys);
/* inf_read_fn compatible: returns bytes, 0 at the end, -1 on error. */
long wa_media_reader_read(void *r, uint8_t *buf, size_t cap);
void wa_media_reader_close(wa_media_reader *r);

/* Helper for tests and uploads: encrypt plaintext into the media format. */
long wa_media_encrypt(const wa_media_keys *keys, const uint8_t *in, size_t len,
                      uint8_t *out, size_t cap);

#endif
