/*
 * ZapC - OpenSSL crypto backend.
 *
 * Only symmetric primitives and hashes live here; a smaller backend (mbedTLS,
 * BearSSL, ...) only has to provide this file for a port.
 */
#include "zapc/crypto.h"
#include "zapc/memory.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

static int digest_v(const EVP_MD *md, const zc_iov *parts, size_t n,
                    uint8_t *out)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx != NULL && EVP_DigestInit_ex(ctx, md, NULL) == 1;
    for (size_t i = 0; ok && i < n; i++)
        ok = EVP_DigestUpdate(ctx, parts[i].data, parts[i].len) == 1;
    ok = ok && EVP_DigestFinal_ex(ctx, out, NULL) == 1;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

int crypto_sha1(const void *data, size_t len, uint8_t out[20])
{
    zc_iov v = {data, len};
    return digest_v(EVP_sha1(), &v, 1, out);
}

int crypto_md5(const void *data, size_t len, uint8_t out[16])
{
    zc_iov v = {data, len};
    return digest_v(EVP_md5(), &v, 1, out);
}

int crypto_sha256_v(const zc_iov *parts, size_t n, uint8_t out[32])
{
    return digest_v(EVP_sha256(), parts, n, out);
}

int crypto_sha512_v(const zc_iov *parts, size_t n, uint8_t out[64])
{
    return digest_v(EVP_sha512(), parts, n, out);
}

int crypto_sha256(const void *data, size_t len, uint8_t out[32])
{
    zc_iov v = {data, len};
    return digest_v(EVP_sha256(), &v, 1, out);
}

/*
 * HMAC-SHA256 implemented over the digest primitive (RFC 2104) so it only
 * needs SHA-256 from the backend.
 */
int crypto_hmac_sha256_v(const void *key, size_t key_len, const zc_iov *parts,
                         size_t n, uint8_t out[32])
{
    uint8_t k[64];
    uint8_t pad[64];
    uint8_t inner[32];
    memset(k, 0, sizeof k);
    if (key_len > 64) {
        if (crypto_sha256(key, key_len, k) != 0)
            return -1;
    } else if (key_len > 0) {
        memcpy(k, key, key_len);
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return -1;
    for (int i = 0; i < 64; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, pad, 64) == 1;
    for (size_t i = 0; ok && i < n; i++)
        ok = EVP_DigestUpdate(ctx, parts[i].data, parts[i].len) == 1;
    ok = ok && EVP_DigestFinal_ex(ctx, inner, NULL) == 1;
    for (int i = 0; i < 64; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    ok = ok && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
         EVP_DigestUpdate(ctx, pad, 64) == 1 &&
         EVP_DigestUpdate(ctx, inner, 32) == 1 &&
         EVP_DigestFinal_ex(ctx, out, NULL) == 1;
    EVP_MD_CTX_free(ctx);
    zap_secure_zero(k, sizeof k);
    zap_secure_zero(pad, sizeof pad);
    return ok ? 0 : -1;
}

int crypto_hmac_sha256(const void *key, size_t key_len, const void *data,
                       size_t len, uint8_t out[32])
{
    zc_iov v = {data, len};
    return crypto_hmac_sha256_v(key, key_len, &v, 1, out);
}

int crypto_hkdf_sha256(const void *salt, size_t salt_len, const void *ikm,
                       size_t ikm_len, const void *info, size_t info_len,
                       uint8_t *out, size_t out_len)
{
    static const uint8_t zero_salt[32];
    uint8_t prk[32];
    uint8_t t[32];
    if (out_len > 255 * 32)
        return -1;
    if (salt == NULL || salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof zero_salt;
    }
    if (crypto_hmac_sha256(salt, salt_len, ikm, ikm_len, prk) != 0)
        return -1;
    size_t done = 0;
    size_t tlen = 0;
    uint8_t counter = 1;
    while (done < out_len) {
        zc_iov parts[3] = {{t, tlen}, {info, info_len}, {&counter, 1}};
        if (crypto_hmac_sha256_v(prk, 32, parts, 3, t) != 0) {
            zap_secure_zero(prk, sizeof prk);
            return -1;
        }
        tlen = 32;
        size_t take = out_len - done < 32 ? out_len - done : 32;
        memcpy(out + done, t, take);
        done += take;
        counter++;
    }
    zap_secure_zero(prk, sizeof prk);
    zap_secure_zero(t, sizeof t);
    return 0;
}

static int gcm_crypt(int enc, const uint8_t key[32], const uint8_t iv[12],
                     const void *aad, size_t aad_len, const void *in,
                     size_t len, uint8_t *out)
{
    if (len > INT32_MAX || aad_len > INT32_MAX)
        return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;
    int outl = 0;
    int ok = EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL,
                               enc) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc) == 1;
    if (ok && aad_len > 0)
        ok = EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)aad_len) == 1;
    if (enc) {
        ok = ok && EVP_CipherUpdate(ctx, out, &outl, in, (int)len) == 1;
        ok = ok && EVP_CipherFinal_ex(ctx, out + outl, &outl) == 1;
        ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                                       out + len) == 1;
    } else {
        if (len < 16) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        size_t clen = len - 16;
        uint8_t tag[16];
        memcpy(tag, (const uint8_t *)in + clen, 16);
        ok = ok && EVP_CipherUpdate(ctx, out, &outl, in, (int)clen) == 1;
        ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
        ok = ok && EVP_CipherFinal_ex(ctx, out + outl, &outl) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int crypto_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                              const void *aad, size_t aad_len, const void *in,
                              size_t len, uint8_t *out)
{
    return gcm_crypt(1, key, iv, aad, aad_len, in, len, out);
}

int crypto_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                              const void *aad, size_t aad_len, const void *in,
                              size_t len, uint8_t *out)
{
    return gcm_crypt(0, key, iv, aad, aad_len, in, len, out);
}

static long cbc_crypt(int enc, const uint8_t key[32], const uint8_t iv[16],
                      const void *in, size_t len, uint8_t *out, size_t out_cap)
{
    /* OpenSSL may write up to one extra block in either direction. */
    if (len > INT32_MAX - 32 || out_cap < len + 16u)
        return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;
    int l1 = 0, l2 = 0;
    int ok = EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, enc) ==
                 1 &&
             EVP_CipherUpdate(ctx, out, &l1, in, (int)len) == 1 &&
             EVP_CipherFinal_ex(ctx, out + l1, &l2) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok ? (long)l1 + l2 : -1;
}

long crypto_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                               const void *in, size_t len, uint8_t *out,
                               size_t out_cap)
{
    return cbc_crypt(1, key, iv, in, len, out, out_cap);
}

long crypto_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                               const void *in, size_t len, uint8_t *out,
                               size_t out_cap)
{
    return cbc_crypt(0, key, iv, in, len, out, out_cap);
}
