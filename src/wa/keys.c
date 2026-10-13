#include "zapc/keys.h"
#include "zapc/crypto.h"
#include "zapc/memory.h"
#include "zapc/platform.h"

#include <string.h>

int wa_keypair_generate(wa_keypair *kp)
{
    return curve25519_keypair(kp->priv, kp->pub);
}

int wa_sign_prekey(const wa_keypair *identity, const uint8_t pub[32],
                   uint8_t sig[64])
{
    uint8_t msg[33];
    msg[0] = WA_KEY_TYPE_DJB;
    memcpy(msg + 1, pub, 32);
    return xeddsa_sign(sig, identity->priv, msg, sizeof msg);
}

int wa_device_generate(wa_device *dev)
{
    uint8_t rid[4];
    memset(dev, 0, sizeof *dev);
    if (wa_keypair_generate(&dev->noise_key) != 0 ||
        wa_keypair_generate(&dev->identity_key) != 0 ||
        wa_keypair_generate(&dev->signed_prekey) != 0 ||
        plat_random(dev->adv_secret, sizeof dev->adv_secret) != 0 ||
        plat_random(rid, sizeof rid) != 0)
        return -1;
    dev->signed_prekey_id = 1;
    if (wa_sign_prekey(&dev->identity_key, dev->signed_prekey.pub,
                       dev->signed_prekey_sig) != 0)
        return -1;
    /* Signal registration ids are 14-bit values (1..16380). */
    dev->registration_id = ((((uint32_t)rid[0] << 8) | rid[1]) % 16380u) + 1u;
    dev->next_prekey_id = 1;
    dev->uploaded_prekey_id = 1;
    return 0;
}

void wa_device_wipe(wa_device *dev) { zap_secure_zero(dev, sizeof *dev); }
