#include "test.h"

#include "zapc/crypto.h"
#include "zapc/util.h"

#include <openssl/evp.h>

/* RFC 7748 section 5.2 */
static void test_x25519_vectors(void)
{
    unsigned char k[32], u[32], out[32], exp[32];
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
          k, 32);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
          u, 32);
    unhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
          exp, 32);
    CHECK(curve25519_shared(out, k, u) == 0);
    CHECK_MEM(out, exp, 32);

    /* RFC 7748 section 6.1 Diffie-Hellman */
    unsigned char a_priv[32], a_pub[32], b_priv[32], b_pub[32], s1[32], s2[32];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
          a_priv, 32);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
          b_priv, 32);
    curve25519_public(a_pub, a_priv);
    curve25519_public(b_pub, b_priv);
    unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
          exp, 32);
    CHECK_MEM(a_pub, exp, 32);
    unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
          exp, 32);
    CHECK_MEM(b_pub, exp, 32);
    CHECK(curve25519_shared(s1, a_priv, b_pub) == 0);
    CHECK(curve25519_shared(s2, b_priv, a_pub) == 0);
    unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
          exp, 32);
    CHECK_MEM(s1, exp, 32);
    CHECK_MEM(s2, exp, 32);
}

static void test_xeddsa_roundtrip(void)
{
    unsigned char priv[32], pub[32], sig[64];
    const char *msg = "hello zapc";
    for (int i = 0; i < 8; i++) {
        CHECK(curve25519_keypair(priv, pub) == 0);
        CHECK(xeddsa_sign(sig, priv, msg, strlen(msg)) == 0);
        CHECK(xeddsa_verify(pub, msg, strlen(msg), sig) == 0);
        sig[5] ^= 1;
        CHECK(xeddsa_verify(pub, msg, strlen(msg), sig) != 0);
        sig[5] ^= 1;
        CHECK(xeddsa_verify(pub, "hello zapC", 10, sig) != 0);
    }
}

/*
 * An XEdDSA signature is a standard Ed25519 signature for the Edwards key
 * derived from the Montgomery key, so OpenSSL must accept it.
 */
static void test_xeddsa_vs_openssl(void)
{
    for (int i = 0; i < 8; i++) {
        unsigned char priv[32], pub[32], sig[64], ed[32];
        const unsigned char msg[] = {6, 1, 2, 3, 4, 5};
        CHECK(curve25519_keypair(priv, pub) == 0);
        CHECK(xeddsa_sign(sig, priv, msg, sizeof msg) == 0);
        curve25519_mont_to_ed(ed, pub);
        ed[31] = (unsigned char)((ed[31] & 0x7f) | (sig[63] & 0x80));
        sig[63] &= 0x7f;
        EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, ed,
                                                   32);
        CHECK(pk != NULL);
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        CHECK(EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pk) == 1);
        CHECK(EVP_DigestVerify(ctx, sig, 64, msg, sizeof msg) == 1);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pk);
    }
}

/* RFC 5869 test case 1 */
static void test_hkdf(void)
{
    unsigned char ikm[22], salt[13], info[10], okm[42], exp[42];
    memset(ikm, 0x0b, sizeof ikm);
    unhex("000102030405060708090a0b0c", salt, sizeof salt);
    unhex("f0f1f2f3f4f5f6f7f8f9", info, sizeof info);
    unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
          "34007208d5b887185865",
          exp, sizeof exp);
    CHECK(crypto_hkdf_sha256(salt, sizeof salt, ikm, sizeof ikm, info,
                             sizeof info, okm, sizeof okm) == 0);
    CHECK_MEM(okm, exp, sizeof exp);
}

/* RFC 4231 test case 2 */
static void test_hmac(void)
{
    unsigned char out[32], exp[32];
    const char *data = "what do ya want for nothing?";
    unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
          exp, 32);
    CHECK(crypto_hmac_sha256("Jefe", 4, data, strlen(data), out) == 0);
    CHECK_MEM(out, exp, 32);
}

static void test_aes_gcm(void)
{
    unsigned char key[32] = {1, 2, 3}, iv[12] = {9};
    unsigned char buf[64 + 16], orig[64];
    for (int i = 0; i < 64; i++)
        orig[i] = buf[i] = (unsigned char)i;
    CHECK(crypto_aes256_gcm_encrypt(key, iv, "ad", 2, buf, 64, buf) == 0);
    CHECK(memcmp(buf, orig, 64) != 0);
    CHECK(crypto_aes256_gcm_decrypt(key, iv, "ad", 2, buf, 80, buf) == 0);
    CHECK_MEM(buf, orig, 64);
    /* tamper */
    CHECK(crypto_aes256_gcm_encrypt(key, iv, NULL, 0, orig, 64, buf) == 0);
    buf[70] ^= 1;
    CHECK(crypto_aes256_gcm_decrypt(key, iv, NULL, 0, buf, 80, buf) != 0);
}

static void test_aes_cbc(void)
{
    unsigned char key[32] = {7}, iv[16] = {3};
    unsigned char ct[64], pt[64];
    const char *msg = "signal message body";
    long n = crypto_aes256_cbc_encrypt(key, iv, msg, strlen(msg), ct, sizeof ct);
    CHECK(n == 32);
    long m = crypto_aes256_cbc_decrypt(key, iv, ct, (size_t)n, pt, sizeof pt);
    CHECK(m == (long)strlen(msg));
    CHECK_MEM(pt, msg, strlen(msg));
}

static void test_base64(void)
{
    char out[64];
    unsigned char dec[64];
    CHECK(base64_encode("foobar", 6, out, sizeof out) == 8);
    CHECK_STR(out, "Zm9vYmFy");
    CHECK(base64_encode("fooba", 5, out, sizeof out) == 8);
    CHECK_STR(out, "Zm9vYmE=");
    CHECK(base64_encode("f", 1, out, sizeof out) == 4);
    CHECK_STR(out, "Zg==");
    CHECK(base64_decode("Zm9vYmE=", 8, dec, sizeof dec) == 5);
    CHECK_MEM(dec, "fooba", 5);
    CHECK(base64_decode("Zg==", 4, dec, sizeof dec) == 1);
    CHECK(base64_decode("Z!==", 4, dec, sizeof dec) == -1);
    CHECK(base64_decode("Zm9vYmFy", 8, dec, 3) == -1);
}

int main(void)
{
    RUN(test_x25519_vectors);
    RUN(test_xeddsa_roundtrip);
    RUN(test_xeddsa_vs_openssl);
    RUN(test_hkdf);
    RUN(test_hmac);
    RUN(test_aes_gcm);
    RUN(test_aes_cbc);
    RUN(test_base64);
    return test_done("test_crypto");
}
