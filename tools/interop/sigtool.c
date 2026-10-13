/* Interop helper: drive libzapc's Signal code from the command line. */
#include "zapc/crypto.h"
#include "zapc/keys.h"
#include "zapc/signal.h"
#include "zapc/storage.h"
#include "zapc/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t unhex(const char *h, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (h[0] && h[1] && n < cap) { unsigned v; sscanf(h, "%2x", &v); out[n++] = (uint8_t)v; h += 2; }
    return n;
}
static void phex(const uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", p[i]); printf("\n"); }

int main(int argc, char **argv) {
    static uint8_t a[65536], b[65536];
    if (argc < 3) return 2;
    const char *cmd = argv[1];
    storage_init(argv[2]);
    wa_device dev;
    if (strcmp(cmd, "init") == 0) { /* init dir ident_priv spk_priv spk_id regid [otk_priv otk_id] */
        memset(&dev, 0, sizeof dev);
        unhex(argv[3], dev.identity_key.priv, 32); curve25519_public(dev.identity_key.pub, dev.identity_key.priv);
        unhex(argv[4], dev.signed_prekey.priv, 32); curve25519_public(dev.signed_prekey.pub, dev.signed_prekey.priv);
        dev.signed_prekey_id = (uint32_t)atoi(argv[5]);
        dev.registration_id = (uint32_t)atoi(argv[6]);
        wa_sign_prekey(&dev.identity_key, dev.signed_prekey.pub, dev.signed_prekey_sig);
        dev.next_prekey_id = 1; dev.uploaded_prekey_id = 1;
        if (credentials_save(&dev) != 0) return 1;
        if (argc > 8) { uint8_t otk[32]; unhex(argv[7], otk, 32); prekeys_append((uint32_t)atoi(argv[8]), otk); }
        printf("ok\n"); return 0;
    }
    if (credentials_load(&dev) != 0) { printf("ERR creds\n"); return 1; }
    if (strcmp(cmd, "decrypt") == 0) { /* decrypt dir addr pk|msg hex */
        size_t n = unhex(argv[5], a, sizeof a);
        long r = signal_decrypt(&dev, argv[3], strcmp(argv[4], "pk") == 0, a, n, b, sizeof b);
        if (r < 0) { printf("ERR\n"); return 1; }
        phex(b, (size_t)r); return 0;
    }
    if (strcmp(cmd, "encrypt") == 0) { /* encrypt dir addr hex */
        size_t n = unhex(argv[4], a, sizeof a); int pk = 0;
        long r = signal_encrypt(&dev, argv[3], a, n, b, sizeof b, &pk);
        if (r < 0) { printf("ERR\n"); return 1; }
        printf("%s ", pk ? "pk" : "msg"); phex(b, (size_t)r); return 0;
    }
    if (strcmp(cmd, "bundle") == 0) { /* bundle dir addr regid ident spk_id spk spk_sig otk_id otk */
        sig_bundle bd; memset(&bd, 0, sizeof bd);
        bd.registration_id = (uint32_t)atoi(argv[4]);
        unhex(argv[5], bd.identity, 32);
        bd.signed_prekey_id = (uint32_t)atoi(argv[6]);
        unhex(argv[7], bd.signed_prekey, 32);
        unhex(argv[8], bd.signed_prekey_sig, 64);
        bd.prekey_id = (uint32_t)atoi(argv[9]);
        unhex(argv[10], bd.prekey, 32);
        int r = signal_session_from_bundle(&dev, argv[3], &bd);
        printf(r == 0 ? "ok\n" : "ERR\n"); return r == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "skdm_process") == 0) { /* dir group addr hex */
        size_t n = unhex(argv[5], a, sizeof a);
        int r = senderkey_process(argv[3], argv[4], a, n);
        printf(r == 0 ? "ok\n" : "ERR\n"); return r == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "sk_decrypt") == 0) { /* dir group addr hex */
        size_t n = unhex(argv[5], a, sizeof a);
        long r = senderkey_decrypt(argv[3], argv[4], a, n, b, sizeof b);
        if (r < 0) { printf("ERR\n"); return 1; }
        phex(b, (size_t)r); return 0;
    }
    if (strcmp(cmd, "sk_dist") == 0) { /* dir group own_addr */
        long r = senderkey_distribution(argv[3], argv[4], b, sizeof b);
        if (r < 0) { printf("ERR\n"); return 1; }
        phex(b, (size_t)r); return 0;
    }
    if (strcmp(cmd, "sk_encrypt") == 0) { /* dir group own_addr hex */
        size_t n = unhex(argv[5], a, sizeof a);
        long r = senderkey_encrypt(argv[3], argv[4], a, n, b, sizeof b);
        if (r < 0) { printf("ERR\n"); return 1; }
        phex(b, (size_t)r); return 0;
    }
    return 2;
}
