/*
 * ZapC - the parts of the Signal protocol WhatsApp needs.
 *
 *   - X3DH session setup (as receiver from a PreKeySignalMessage and as
 *     initiator from a server prekey bundle)
 *   - Double Ratchet message encryption/decryption
 *   - Sender keys for groups
 *
 * Sessions live on disk (see storage.h); only the one being used is held in
 * memory.  The number of receive chains and skipped message keys kept per
 * session is bounded.  Private keys are never logged.
 */
#ifndef ZAPC_SIGNAL_H
#define ZAPC_SIGNAL_H

#include "zapc/keys.h"

#include <stddef.h>
#include <stdint.h>

#define SIG_VERSION 3
#define SIG_MAX_RECV_CHAINS 5
#define SIG_MAX_SKIPPED 32
#define SIG_MAX_FORWARD 2000
#define SIG_NO_PREKEY 0xFFFFFFFFu

/* Remote device prekey bundle (from <iq xmlns="encrypt"><key>). */
typedef struct {
    uint32_t registration_id;
    uint8_t identity[32];
    uint32_t signed_prekey_id;
    uint8_t signed_prekey[32];
    uint8_t signed_prekey_sig[64];
    uint32_t prekey_id; /* SIG_NO_PREKEY when absent */
    uint8_t prekey[32];
} sig_bundle;

/*
 * Decrypt a "pkmsg" (PreKeySignalMessage) or "msg" (SignalMessage) from the
 * device with Signal address `addr` (see jid_signal_address()).
 * Returns plaintext length (still padded) or -1.
 */
long signal_decrypt(wa_device *dev, const char *addr, int prekey_msg,
                    const uint8_t *in, size_t len, uint8_t *out, size_t cap);

/*
 * Encrypt for `addr`.  *prekey_msg is set when the result is a pkmsg.
 * Returns ciphertext length or -1 (e.g. no session).
 */
long signal_encrypt(wa_device *dev, const char *addr, const uint8_t *in,
                    size_t len, uint8_t *out, size_t cap, int *prekey_msg);

int signal_has_session(const char *addr);
/* Build an initiator session from a bundle (X3DH). */
int signal_session_from_bundle(wa_device *dev, const char *addr,
                               const sig_bundle *b);

/* ---- sender keys (groups) ----------------------------------------------- */
/* Store a SenderKeyDistributionMessage from `sender_addr` for `group`. */
int senderkey_process(const char *group, const char *sender_addr,
                      const uint8_t *skdm, size_t len);
long senderkey_decrypt(const char *group, const char *sender_addr,
                       const uint8_t *in, size_t len, uint8_t *out,
                       size_t cap);
/* Encrypt with our own sender key (created on first use). */
long senderkey_encrypt(const char *group, const char *own_addr,
                       const uint8_t *in, size_t len, uint8_t *out,
                       size_t cap);
/* Serialize our current distribution message for `group`. */
long senderkey_distribution(const char *group, const char *own_addr,
                            uint8_t *out, size_t cap);

/* ---- WhatsApp message padding ------------------------------------------- */
size_t wa_pad_message(uint8_t *buf, size_t len, size_t cap);
long wa_unpad_message(const uint8_t *buf, size_t len);

#endif
