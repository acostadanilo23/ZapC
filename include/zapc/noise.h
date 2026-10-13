/*
 * ZapC - Noise_XX_25519_AESGCM_SHA256 as used by WhatsApp.
 *
 * Separated into the handshake symmetric state (hash/salt/key mixing) and the
 * transport cipher states that are produced when the handshake finishes.
 */
#ifndef ZAPC_NOISE_H
#define ZAPC_NOISE_H

#include <stddef.h>
#include <stdint.h>

#define WA_NOISE_PATTERN "Noise_XX_25519_AESGCM_SHA256\0\0\0\0"
#define WA_NOISE_PATTERN_LEN 32
#define WA_NOISE_TAG_LEN 16

/* Handshake symmetric state. */
typedef struct {
    uint8_t hash[32];
    uint8_t salt[32];
    uint8_t key[32];
    uint32_t counter;
} noise_handshake;

/* Initialise with the protocol name (exactly 32 bytes or hashed) and prologue. */
int noise_hs_start(noise_handshake *hs, const void *pattern, size_t plen,
                   const void *prologue, size_t prologue_len);
int noise_hs_authenticate(noise_handshake *hs, const void *data, size_t len);
/* HKDF(salt, ikm) -> new salt (write half) and cipher key (read half). */
int noise_hs_mix_key(noise_handshake *hs, const void *ikm, size_t len);
/* X25519(priv, pub) mixed into the key. */
int noise_hs_mix_dh(noise_handshake *hs, const uint8_t priv[32],
                    const uint8_t pub[32]);
/* Encrypt with AAD = hash, then authenticate the ciphertext. out: len+16. */
int noise_hs_encrypt(noise_handshake *hs, const void *in, size_t len,
                     uint8_t *out);
/* Decrypt (len includes tag) with AAD = hash; out: len-16. */
int noise_hs_decrypt(noise_handshake *hs, const void *in, size_t len,
                     uint8_t *out);

/* Transport cipher state for one direction. */
typedef struct {
    uint8_t key[32];
    uint32_t counter;
} noise_cipher;

/* Split into write (client->server) and read (server->client) ciphers. */
int noise_hs_finish(noise_handshake *hs, noise_cipher *write_cs,
                    noise_cipher *read_cs);

/* In-place transport encryption: buf must have len+16 bytes of space. */
int noise_encrypt(noise_cipher *cs, uint8_t *buf, size_t len);
/* In-place decryption; len includes the tag. Returns plaintext length or -1. */
long noise_decrypt(noise_cipher *cs, uint8_t *buf, size_t len);

void noise_hs_wipe(noise_handshake *hs);

#endif
