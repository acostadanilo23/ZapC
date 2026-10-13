#include "zapc/noise.h"
#include "zapc/crypto.h"
#include "zapc/memory.h"

#include <string.h>

static void make_iv(uint8_t iv[12], uint32_t counter)
{
    memset(iv, 0, 8);
    iv[8] = (uint8_t)(counter >> 24);
    iv[9] = (uint8_t)(counter >> 16);
    iv[10] = (uint8_t)(counter >> 8);
    iv[11] = (uint8_t)counter;
}

int noise_hs_start(noise_handshake *hs, const void *pattern, size_t plen,
                   const void *prologue, size_t prologue_len)
{
    memset(hs, 0, sizeof *hs);
    if (plen == 32) {
        memcpy(hs->hash, pattern, 32);
    } else if (crypto_sha256(pattern, plen, hs->hash) != 0) {
        return -1;
    }
    memcpy(hs->salt, hs->hash, 32);
    memcpy(hs->key, hs->hash, 32);
    return noise_hs_authenticate(hs, prologue, prologue_len);
}

int noise_hs_authenticate(noise_handshake *hs, const void *data, size_t len)
{
    zc_iov v[2] = {{hs->hash, 32}, {data, len}};
    return crypto_sha256_v(v, 2, hs->hash);
}

static int extract_and_expand(const uint8_t salt[32], const void *ikm,
                              size_t len, uint8_t write[32], uint8_t read[32])
{
    uint8_t out[64];
    if (crypto_hkdf_sha256(salt, 32, ikm, len, NULL, 0, out, sizeof out) != 0)
        return -1;
    memcpy(write, out, 32);
    memcpy(read, out + 32, 32);
    zap_secure_zero(out, sizeof out);
    return 0;
}

int noise_hs_mix_key(noise_handshake *hs, const void *ikm, size_t len)
{
    uint8_t write[32], read[32];
    hs->counter = 0;
    if (extract_and_expand(hs->salt, ikm, len, write, read) != 0)
        return -1;
    memcpy(hs->salt, write, 32);
    memcpy(hs->key, read, 32);
    zap_secure_zero(write, sizeof write);
    zap_secure_zero(read, sizeof read);
    return 0;
}

int noise_hs_mix_dh(noise_handshake *hs, const uint8_t priv[32],
                    const uint8_t pub[32])
{
    uint8_t shared[32];
    if (curve25519_shared(shared, priv, pub) != 0)
        return -1;
    int r = noise_hs_mix_key(hs, shared, 32);
    zap_secure_zero(shared, sizeof shared);
    return r;
}

int noise_hs_encrypt(noise_handshake *hs, const void *in, size_t len,
                     uint8_t *out)
{
    uint8_t iv[12];
    make_iv(iv, hs->counter++);
    if (crypto_aes256_gcm_encrypt(hs->key, iv, hs->hash, 32, in, len, out) != 0)
        return -1;
    return noise_hs_authenticate(hs, out, len + WA_NOISE_TAG_LEN);
}

int noise_hs_decrypt(noise_handshake *hs, const void *in, size_t len,
                     uint8_t *out)
{
    uint8_t iv[12];
    uint8_t next_hash[32];
    if (len < WA_NOISE_TAG_LEN)
        return -1;
    /* The ciphertext is authenticated; in may alias out, so hash it first. */
    zc_iov v[2] = {{hs->hash, 32}, {in, len}};
    if (crypto_sha256_v(v, 2, next_hash) != 0)
        return -1;
    make_iv(iv, hs->counter++);
    if (crypto_aes256_gcm_decrypt(hs->key, iv, hs->hash, 32, in, len, out) != 0)
        return -1;
    memcpy(hs->hash, next_hash, 32);
    return 0;
}

int noise_hs_finish(noise_handshake *hs, noise_cipher *write_cs,
                    noise_cipher *read_cs)
{
    memset(write_cs, 0, sizeof *write_cs);
    memset(read_cs, 0, sizeof *read_cs);
    return extract_and_expand(hs->salt, NULL, 0, write_cs->key, read_cs->key);
}

int noise_encrypt(noise_cipher *cs, uint8_t *buf, size_t len)
{
    uint8_t iv[12];
    make_iv(iv, cs->counter++);
    return crypto_aes256_gcm_encrypt(cs->key, iv, NULL, 0, buf, len, buf);
}

long noise_decrypt(noise_cipher *cs, uint8_t *buf, size_t len)
{
    uint8_t iv[12];
    if (len < WA_NOISE_TAG_LEN)
        return -1;
    make_iv(iv, cs->counter++);
    if (crypto_aes256_gcm_decrypt(cs->key, iv, NULL, 0, buf, len, buf) != 0)
        return -1;
    return (long)(len - WA_NOISE_TAG_LEN);
}

void noise_hs_wipe(noise_handshake *hs) { zap_secure_zero(hs, sizeof *hs); }
