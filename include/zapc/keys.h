/*
 * ZapC - device identity and key material.
 *
 * Private keys in this structure must never be logged.
 */
#ifndef ZAPC_KEYS_H
#define ZAPC_KEYS_H

#include "zapc/build_config.h"
#include "zapc/jid.h"

#include <stddef.h>
#include <stdint.h>

#define WA_KEY_TYPE_DJB 0x05 /* Signal "DjbType" public key prefix */
#define WA_ACCOUNT_MAX 1024  /* serialized ADVSignedDeviceIdentity */

typedef struct {
    uint8_t priv[32];
    uint8_t pub[32];
} wa_keypair;

typedef struct {
    /* generated on first start */
    wa_keypair noise_key;
    wa_keypair identity_key;
    wa_keypair signed_prekey;
    uint32_t signed_prekey_id;
    uint8_t signed_prekey_sig[64];
    uint32_t registration_id;
    uint8_t adv_secret[32];

    /* filled in by pairing */
    int paired;
    wa_jid jid;
    wa_jid lid;
    char platform[32];
    char business_name[ZAPC_NAME_MAX];
    char push_name[ZAPC_NAME_MAX];
    uint8_t account[WA_ACCOUNT_MAX]; /* ADVSignedDeviceIdentity (signed) */
    size_t account_len;

    /* one-time prekeys */
    uint32_t next_prekey_id;     /* next id to generate          */
    uint32_t uploaded_prekey_id; /* ids below this are on server */
} wa_device;

int wa_keypair_generate(wa_keypair *kp);
/* Sign 0x05||pub(key) with the identity key (Signal signed prekey). */
int wa_sign_prekey(const wa_keypair *identity, const uint8_t pub[32],
                   uint8_t sig[64]);

/* Fill a fresh, unpaired device with new keys. */
int wa_device_generate(wa_device *dev);
void wa_device_wipe(wa_device *dev);

#endif
