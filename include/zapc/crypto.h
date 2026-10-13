/*
 * ZapC - cryptographic primitives.
 *
 * Symmetric primitives and hashes are provided by a backend
 * (src/crypto/crypto_<backend>.c, OpenSSL by default).  Curve25519 (X25519
 * and XEdDSA signatures as used by Signal/WhatsApp) is implemented in
 * portable C in src/crypto/curve25519.c so that every port gets it for free.
 */
#ifndef ZAPC_CRYPTO_H
#define ZAPC_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const void *data;
    size_t len;
} zc_iov;

/* ---- hashes -------------------------------------------------------------- */
int crypto_sha1(const void *data, size_t len, uint8_t out[20]);
int crypto_md5(const void *data, size_t len, uint8_t out[16]);
int crypto_sha256_v(const zc_iov *parts, size_t n, uint8_t out[32]);
int crypto_sha512_v(const zc_iov *parts, size_t n, uint8_t out[64]);
int crypto_sha256(const void *data, size_t len, uint8_t out[32]);

int crypto_hmac_sha256_v(const void *key, size_t key_len, const zc_iov *parts,
                         size_t n, uint8_t out[32]);
int crypto_hmac_sha256(const void *key, size_t key_len, const void *data,
                       size_t len, uint8_t out[32]);

/* RFC 5869 HKDF-SHA256. out_len <= 255*32. */
int crypto_hkdf_sha256(const void *salt, size_t salt_len, const void *ikm,
                       size_t ikm_len, const void *info, size_t info_len,
                       uint8_t *out, size_t out_len);

/* ---- AES ---------------------------------------------------------------- */
/*
 * AES-256-GCM with a 12-byte IV and 16-byte tag appended to the ciphertext.
 * out must hold len+16 bytes; in-place operation (out == in) is allowed.
 */
int crypto_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                              const void *aad, size_t aad_len, const void *in,
                              size_t len, uint8_t *out);
/* in = ciphertext||tag (len includes the tag). Returns 0 if authentic. */
int crypto_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                              const void *aad, size_t aad_len, const void *in,
                              size_t len, uint8_t *out);

/*
 * AES-256-CBC with PKCS#7 padding.  Encrypt output is at most len+16 bytes.
 * Return output length, or -1 on error/bad padding.
 */
long crypto_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                               const void *in, size_t len, uint8_t *out,
                               size_t out_cap);
long crypto_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                               const void *in, size_t len, uint8_t *out,
                               size_t out_cap);

/* ---- streaming interfaces (for large media / history blobs) ------------ */
typedef struct {
    void *impl;
} zc_sha256_ctx;
int zc_sha256_init(zc_sha256_ctx *c);
int zc_sha256_update(zc_sha256_ctx *c, const void *data, size_t len);
int zc_sha256_final(zc_sha256_ctx *c, uint8_t out[32]); /* also frees */

typedef struct {
    zc_sha256_ctx inner;
    uint8_t opad[64];
} zc_hmac_ctx;
int zc_hmac_sha256_init(zc_hmac_ctx *c, const void *key, size_t key_len);
int zc_hmac_sha256_update(zc_hmac_ctx *c, const void *data, size_t len);
int zc_hmac_sha256_final(zc_hmac_ctx *c, uint8_t out[32]);

typedef struct {
    void *impl;
} zc_cbc_ctx;
/* AES-256-CBC decryption with PKCS#7 padding removed at the end. */
int zc_cbc_decrypt_init(zc_cbc_ctx *c, const uint8_t key[32],
                        const uint8_t iv[16]);
/* out must hold len + 16 bytes. Returns bytes written or -1. */
long zc_cbc_decrypt_update(zc_cbc_ctx *c, const uint8_t *in, size_t len,
                           uint8_t *out);
long zc_cbc_decrypt_final(zc_cbc_ctx *c, uint8_t out[16]); /* also frees */
void zc_cbc_free(zc_cbc_ctx *c);

/* ---- Curve25519 (portable implementation) ------------------------------- */
#define CURVE25519_KEY_LEN 32
#define XEDDSA_SIG_LEN 64

/* Clamp a random 32-byte string into a valid X25519 private key. */
void curve25519_clamp(uint8_t priv[32]);
/* Generate a key pair using plat_random(). Returns 0 on success. */
int curve25519_keypair(uint8_t priv[32], uint8_t pub[32]);
void curve25519_public(uint8_t pub[32], const uint8_t priv[32]);
/* X25519 Diffie-Hellman. Returns -1 when the result is all zero. */
int curve25519_shared(uint8_t out[32], const uint8_t priv[32],
                      const uint8_t pub[32]);

/*
 * XEdDSA-style signatures over Curve25519 keys, compatible with
 * libsignal's curve25519_sign()/curve25519_verify().
 */
int xeddsa_sign(uint8_t sig[64], const uint8_t priv[32], const void *msg,
                size_t len);
/* Returns 0 if the signature is valid. */
int xeddsa_verify(const uint8_t pub[32], const void *msg, size_t len,
                  const uint8_t sig[64]);
/* Same, with the message given as several parts (no concatenation copy). */
int xeddsa_verify_v(const uint8_t pub[32], const zc_iov *parts, size_t n,
                    const uint8_t sig[64]);
int xeddsa_sign_v(uint8_t sig[64], const uint8_t priv[32], const zc_iov *parts,
                  size_t n);

/* Montgomery u -> Edwards y (with sign bit 0). Exposed for tests. */
void curve25519_mont_to_ed(uint8_t ed[32], const uint8_t mont[32]);

#endif
