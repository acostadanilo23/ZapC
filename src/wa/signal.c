/*
 * ZapC - Signal protocol (X3DH, Double Ratchet, sender keys).
 *
 * Wire formats follow libsignal: messages start with a version byte
 * (0x33), public keys are serialized with a 0x05 type prefix, and
 * SignalMessages carry an 8-byte truncated HMAC-SHA256.
 */
#include "zapc/signal.h"
#include "zapc/crypto.h"
#include "zapc/log.h"
#include "zapc/memory.h"
#include "zapc/platform.h"
#include "zapc/protobuf.h"
#include "zapc/storage.h"
#include "zapc/util.h"

#include <stdio.h>
#include <string.h>

#define VERSION_BYTE ((SIG_VERSION << 4) | SIG_VERSION)
#define MAC_LEN 8

/* ======================================================================== */
/* session state                                                            */
/* ======================================================================== */

typedef struct {
    uint8_t their_ratchet[32];
    uint8_t chain_key[32];
    uint32_t index;
} sig_chain;

typedef struct {
    uint8_t their_ratchet[32];
    uint32_t counter;
    uint8_t cipher_key[32];
    uint8_t mac_key[32];
    uint8_t iv[16];
} sig_skipped;

typedef struct {
    uint8_t valid;
    uint8_t remote_identity[32];
    uint8_t root_key[32];
    wa_keypair sender_ratchet;
    uint8_t sender_chain_key[32];
    uint32_t sender_index;
    uint32_t previous_counter;
    uint8_t recv_count;
    sig_chain recv[SIG_MAX_RECV_CHAINS]; /* [0] = newest */
    uint8_t skipped_count;
    sig_skipped skipped[SIG_MAX_SKIPPED];
    uint8_t has_pending;
    uint32_t pending_prekey_id;
    uint32_t pending_signed_id;
    uint8_t pending_base_key[32];
    uint32_t remote_reg_id;
    uint32_t local_reg_id;
    uint8_t alice_base_key[32];
} sig_state;

typedef struct {
    sig_state cur;
    sig_state prev; /* one archived state for in-flight messages */
} sig_session;

typedef struct {
    uint8_t cipher_key[32];
    uint8_t mac_key[32];
    uint8_t iv[16];
} msg_keys;

/* One session in RAM at a time. */
static sig_session g_sess;
static sig_session g_tmp;

/* ---- serialization ------------------------------------------------------ */

#define SESS_MAGIC "ZSS1"

static void put_state(zbuf *b, const sig_state *s)
{
    zbuf_put_u8(b, s->valid);
    if (!s->valid)
        return;
    zbuf_put(b, s->remote_identity, 32);
    zbuf_put(b, s->root_key, 32);
    zbuf_put(b, s->sender_ratchet.priv, 32);
    zbuf_put(b, s->sender_ratchet.pub, 32);
    zbuf_put(b, s->sender_chain_key, 32);
    zbuf_put_be32(b, s->sender_index);
    zbuf_put_be32(b, s->previous_counter);
    zbuf_put_u8(b, s->recv_count);
    for (unsigned i = 0; i < s->recv_count; i++) {
        zbuf_put(b, s->recv[i].their_ratchet, 32);
        zbuf_put(b, s->recv[i].chain_key, 32);
        zbuf_put_be32(b, s->recv[i].index);
    }
    zbuf_put_u8(b, s->skipped_count);
    for (unsigned i = 0; i < s->skipped_count; i++) {
        const sig_skipped *k = &s->skipped[i];
        zbuf_put(b, k->their_ratchet, 32);
        zbuf_put_be32(b, k->counter);
        zbuf_put(b, k->cipher_key, 32);
        zbuf_put(b, k->mac_key, 32);
        zbuf_put(b, k->iv, 16);
    }
    zbuf_put_u8(b, s->has_pending);
    zbuf_put_be32(b, s->pending_prekey_id);
    zbuf_put_be32(b, s->pending_signed_id);
    zbuf_put(b, s->pending_base_key, 32);
    zbuf_put_be32(b, s->remote_reg_id);
    zbuf_put_be32(b, s->local_reg_id);
    zbuf_put(b, s->alice_base_key, 32);
}

typedef struct {
    const uint8_t *p;
    size_t left;
    int err;
} rdr;

static void rd(rdr *r, void *dst, size_t n)
{
    if (r->err || n > r->left) {
        r->err = 1;
        memset(dst, 0, n);
        return;
    }
    memcpy(dst, r->p, n);
    r->p += n;
    r->left -= n;
}

static uint8_t rd8(rdr *r)
{
    uint8_t v;
    rd(r, &v, 1);
    return v;
}

static uint32_t rd32(rdr *r)
{
    uint8_t t[4];
    rd(r, t, 4);
    return rd_be32(t);
}

static void get_state(rdr *r, sig_state *s)
{
    memset(s, 0, sizeof *s);
    s->valid = rd8(r);
    if (!s->valid)
        return;
    rd(r, s->remote_identity, 32);
    rd(r, s->root_key, 32);
    rd(r, s->sender_ratchet.priv, 32);
    rd(r, s->sender_ratchet.pub, 32);
    rd(r, s->sender_chain_key, 32);
    s->sender_index = rd32(r);
    s->previous_counter = rd32(r);
    s->recv_count = rd8(r);
    if (s->recv_count > SIG_MAX_RECV_CHAINS)
        r->err = 1;
    for (unsigned i = 0; !r->err && i < s->recv_count; i++) {
        rd(r, s->recv[i].their_ratchet, 32);
        rd(r, s->recv[i].chain_key, 32);
        s->recv[i].index = rd32(r);
    }
    s->skipped_count = rd8(r);
    if (s->skipped_count > SIG_MAX_SKIPPED)
        r->err = 1;
    for (unsigned i = 0; !r->err && i < s->skipped_count; i++) {
        sig_skipped *k = &s->skipped[i];
        rd(r, k->their_ratchet, 32);
        k->counter = rd32(r);
        rd(r, k->cipher_key, 32);
        rd(r, k->mac_key, 32);
        rd(r, k->iv, 16);
    }
    s->has_pending = rd8(r);
    s->pending_prekey_id = rd32(r);
    s->pending_signed_id = rd32(r);
    rd(r, s->pending_base_key, 32);
    s->remote_reg_id = rd32(r);
    s->local_reg_id = rd32(r);
    rd(r, s->alice_base_key, 32);
}

static int session_load(const char *addr, sig_session *s)
{
    static uint8_t buf[2 * sizeof(sig_state) + 64];
    memset(s, 0, sizeof *s);
    long n = storage_blob_load("sessions", addr, buf, sizeof buf);
    if (n < 0)
        return 1; /* no session */
    rdr r = {buf, (size_t)n, 0};
    char magic[4];
    rd(&r, magic, 4);
    if (r.err || memcmp(magic, SESS_MAGIC, 4) != 0) {
        LOGW("signal", "corrupt session for %s", addr);
        return -1;
    }
    get_state(&r, &s->cur);
    get_state(&r, &s->prev);
    zap_secure_zero(buf, sizeof buf);
    if (r.err) {
        LOGW("signal", "truncated session for %s", addr);
        memset(s, 0, sizeof *s);
        return -1;
    }
    return 0;
}

static int session_save(const char *addr, const sig_session *s)
{
    static uint8_t buf[2 * sizeof(sig_state) + 64];
    zbuf b;
    zbuf_init(&b, buf, sizeof buf);
    zbuf_put(&b, SESS_MAGIC, 4);
    put_state(&b, &s->cur);
    put_state(&b, &s->prev);
    int r = b.overflow ? -1 : storage_blob_save("sessions", addr, buf, b.len);
    zap_secure_zero(buf, sizeof buf);
    return r;
}

int signal_has_session(const char *addr)
{
    sig_session *s = &g_tmp;
    int r = session_load(addr, s) == 0 && s->cur.valid;
    zap_secure_zero(s, sizeof *s);
    return r;
}

/* ======================================================================== */
/* KDFs                                                                     */
/* ======================================================================== */

static int kdf_root(const uint8_t *master, size_t len, uint8_t root[32],
                    uint8_t chain[32])
{
    uint8_t out[64];
    static const char info[] = "WhisperText";
    if (crypto_hkdf_sha256(NULL, 0, master, len, info, sizeof info - 1, out,
                           64) != 0)
        return -1;
    memcpy(root, out, 32);
    memcpy(chain, out + 32, 32);
    zap_secure_zero(out, sizeof out);
    return 0;
}

/* RootKey.createChain(theirRatchet, ourRatchet) */
static int create_chain(const uint8_t root[32], const uint8_t their[32],
                        const uint8_t our_priv[32], uint8_t new_root[32],
                        uint8_t chain[32])
{
    uint8_t shared[32], out[64];
    static const char info[] = "WhisperRatchet";
    if (curve25519_shared(shared, our_priv, their) != 0)
        return -1;
    int r = crypto_hkdf_sha256(root, 32, shared, 32, info, sizeof info - 1,
                               out, 64);
    if (r == 0) {
        memcpy(new_root, out, 32);
        memcpy(chain, out + 32, 32);
    }
    zap_secure_zero(shared, sizeof shared);
    zap_secure_zero(out, sizeof out);
    return r;
}

static int chain_message_keys(const uint8_t chain[32], msg_keys *k)
{
    static const uint8_t one = 0x01;
    static const char info[] = "WhisperMessageKeys";
    uint8_t seed[32], out[80];
    if (crypto_hmac_sha256(chain, 32, &one, 1, seed) != 0 ||
        crypto_hkdf_sha256(NULL, 0, seed, 32, info, sizeof info - 1, out,
                           80) != 0)
        return -1;
    memcpy(k->cipher_key, out, 32);
    memcpy(k->mac_key, out + 32, 32);
    memcpy(k->iv, out + 64, 16);
    zap_secure_zero(seed, sizeof seed);
    zap_secure_zero(out, sizeof out);
    return 0;
}

static int chain_next(uint8_t chain[32])
{
    static const uint8_t two = 0x02;
    return crypto_hmac_sha256(chain, 32, &two, 1, chain);
}

static void put_key33(uint8_t out[33], const uint8_t key[32])
{
    out[0] = WA_KEY_TYPE_DJB;
    memcpy(out + 1, key, 32);
}

static int get_key33(const uint8_t *p, size_t n, uint8_t out[32])
{
    if (n == 33 && p[0] == WA_KEY_TYPE_DJB) {
        memcpy(out, p + 1, 32);
        return 0;
    }
    if (n == 32) {
        memcpy(out, p, 32);
        return 0;
    }
    return -1;
}

static int compute_mac(const uint8_t mac_key[32], const uint8_t sender[32],
                       const uint8_t receiver[32], const uint8_t *msg,
                       size_t len, uint8_t out[MAC_LEN])
{
    uint8_t s33[33], r33[33], full[32];
    put_key33(s33, sender);
    put_key33(r33, receiver);
    zc_iov v[3] = {{s33, 33}, {r33, 33}, {msg, len}};
    if (crypto_hmac_sha256_v(mac_key, 32, v, 3, full) != 0)
        return -1;
    memcpy(out, full, MAC_LEN);
    return 0;
}

/* ======================================================================== */
/* ratchet                                                                  */
/* ======================================================================== */

static sig_chain *find_recv_chain(sig_state *s, const uint8_t their[32])
{
    for (unsigned i = 0; i < s->recv_count; i++)
        if (memcmp(s->recv[i].their_ratchet, their, 32) == 0)
            return &s->recv[i];
    return NULL;
}

static sig_chain *add_recv_chain(sig_state *s, const uint8_t their[32],
                                 const uint8_t chain[32])
{
    if (s->recv_count == SIG_MAX_RECV_CHAINS)
        s->recv_count--; /* drop the oldest */
    memmove(&s->recv[1], &s->recv[0], s->recv_count * sizeof s->recv[0]);
    s->recv_count++;
    memcpy(s->recv[0].their_ratchet, their, 32);
    memcpy(s->recv[0].chain_key, chain, 32);
    s->recv[0].index = 0;
    return &s->recv[0];
}

static void add_skipped(sig_state *s, const uint8_t their[32], uint32_t counter,
                        const msg_keys *k)
{
    if (s->skipped_count == SIG_MAX_SKIPPED) {
        memmove(&s->skipped[0], &s->skipped[1],
                (SIG_MAX_SKIPPED - 1) * sizeof s->skipped[0]);
        s->skipped_count--;
    }
    sig_skipped *e = &s->skipped[s->skipped_count++];
    memcpy(e->their_ratchet, their, 32);
    e->counter = counter;
    memcpy(e->cipher_key, k->cipher_key, 32);
    memcpy(e->mac_key, k->mac_key, 32);
    memcpy(e->iv, k->iv, 16);
}

static int take_skipped(sig_state *s, const uint8_t their[32], uint32_t counter,
                        msg_keys *k)
{
    for (unsigned i = 0; i < s->skipped_count; i++) {
        sig_skipped *e = &s->skipped[i];
        if (e->counter == counter && memcmp(e->their_ratchet, their, 32) == 0) {
            memcpy(k->cipher_key, e->cipher_key, 32);
            memcpy(k->mac_key, e->mac_key, 32);
            memcpy(k->iv, e->iv, 16);
            memmove(e, e + 1, (s->skipped_count - i - 1) * sizeof *e);
            s->skipped_count--;
            return 0;
        }
    }
    return -1;
}

static sig_chain *get_or_create_chain(sig_state *s, const uint8_t their[32])
{
    sig_chain *ch = find_recv_chain(s, their);
    if (ch != NULL)
        return ch;
    uint8_t root1[32], recv_chain[32], root2[32], send_chain[32];
    wa_keypair next;
    if (create_chain(s->root_key, their, s->sender_ratchet.priv, root1,
                     recv_chain) != 0 ||
        wa_keypair_generate(&next) != 0 ||
        create_chain(root1, their, next.priv, root2, send_chain) != 0)
        return NULL;
    memcpy(s->root_key, root2, 32);
    ch = add_recv_chain(s, their, recv_chain);
    s->previous_counter = s->sender_index > 0 ? s->sender_index - 1 : 0;
    s->sender_ratchet = next;
    memcpy(s->sender_chain_key, send_chain, 32);
    s->sender_index = 0;
    zap_secure_zero(&next, sizeof next);
    return ch;
}

typedef struct {
    uint8_t ratchet[32];
    uint32_t counter;
    uint32_t prev_counter;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    const uint8_t *signed_part; /* version byte + protobuf */
    size_t signed_len;
    const uint8_t *mac;
} sig_msg;

static int parse_signal_message(const uint8_t *in, size_t len, sig_msg *m)
{
    pb_reader r;
    pb_field f;
    int rc, have_key = 0, have_ct = 0;
    memset(m, 0, sizeof *m);
    if (len < 1 + MAC_LEN || (in[0] >> 4) != SIG_VERSION) {
        LOGW("signal", "unsupported message version");
        return -1;
    }
    m->signed_part = in;
    m->signed_len = len - MAC_LEN;
    m->mac = in + len - MAC_LEN;
    pb_reader_init(&r, in + 1, len - 1 - MAC_LEN);
    while ((rc = pb_next(&r, &f)) == 1) {
        if (f.num == 1 && f.wire == PB_LEN)
            have_key = get_key33(f.data, f.len, m->ratchet) == 0;
        else if (f.num == 2 && f.wire == PB_VARINT)
            m->counter = (uint32_t)f.u64;
        else if (f.num == 3 && f.wire == PB_VARINT)
            m->prev_counter = (uint32_t)f.u64;
        else if (f.num == 4 && f.wire == PB_LEN) {
            m->ciphertext = f.data;
            m->ciphertext_len = f.len;
            have_ct = 1;
        }
    }
    return (rc == 0 && have_key && have_ct) ? 0 : -1;
}

/* Decrypt with one state; modifies the state only through *s (a copy). */
static long decrypt_with_state(sig_state *s, const uint8_t local_identity[32],
                               const uint8_t *in, size_t len, uint8_t *out,
                               size_t cap)
{
    sig_msg m;
    msg_keys k;
    if (!s->valid || parse_signal_message(in, len, &m) != 0)
        return -1;
    sig_chain *ch = get_or_create_chain(s, m.ratchet);
    if (ch == NULL)
        return -1;
    if (ch->index > m.counter) {
        if (take_skipped(s, m.ratchet, m.counter, &k) != 0) {
            LOGD("signal", "duplicate or too old message (counter %u)",
                 (unsigned)m.counter);
            return -1;
        }
    } else {
        if (m.counter - ch->index > SIG_MAX_FORWARD)
            return -1;
        while (ch->index < m.counter) {
            msg_keys sk;
            if (chain_message_keys(ch->chain_key, &sk) != 0)
                return -1;
            /* only the most recent skipped keys are kept */
            if (m.counter - ch->index <= SIG_MAX_SKIPPED)
                add_skipped(s, m.ratchet, ch->index, &sk);
            chain_next(ch->chain_key);
            ch->index++;
        }
        if (chain_message_keys(ch->chain_key, &k) != 0)
            return -1;
        chain_next(ch->chain_key);
        ch->index++;
    }
    uint8_t mac[MAC_LEN];
    if (compute_mac(k.mac_key, s->remote_identity, local_identity,
                    m.signed_part, m.signed_len, mac) != 0 ||
        zap_ct_memcmp(mac, m.mac, MAC_LEN) != 0) {
        LOGD("signal", "bad MAC");
        return -1;
    }
    long n = crypto_aes256_cbc_decrypt(k.cipher_key, k.iv, m.ciphertext,
                                       m.ciphertext_len, out, cap);
    zap_secure_zero(&k, sizeof k);
    if (n < 0)
        return -1;
    s->has_pending = 0;
    return n;
}

/* ======================================================================== */
/* X3DH                                                                     */
/* ======================================================================== */

typedef struct {
    uint32_t registration_id;
    uint32_t prekey_id;
    uint32_t signed_prekey_id;
    uint8_t base_key[32];
    uint8_t identity[32];
    const uint8_t *message;
    size_t message_len;
} prekey_msg;

static int parse_prekey_message(const uint8_t *in, size_t len, prekey_msg *m)
{
    pb_reader r;
    pb_field f;
    int rc, have_base = 0, have_id = 0;
    memset(m, 0, sizeof *m);
    m->prekey_id = SIG_NO_PREKEY;
    if (len < 2 || (in[0] >> 4) != SIG_VERSION)
        return -1;
    pb_reader_init(&r, in + 1, len - 1);
    while ((rc = pb_next(&r, &f)) == 1) {
        switch (f.num) {
        case 1: if (f.wire == PB_VARINT) m->prekey_id = (uint32_t)f.u64; break;
        case 2:
            if (f.wire == PB_LEN)
                have_base = get_key33(f.data, f.len, m->base_key) == 0;
            break;
        case 3:
            if (f.wire == PB_LEN)
                have_id = get_key33(f.data, f.len, m->identity) == 0;
            break;
        case 4:
            if (f.wire == PB_LEN) {
                m->message = f.data;
                m->message_len = f.len;
            }
            break;
        case 5: if (f.wire == PB_VARINT) m->registration_id = (uint32_t)f.u64; break;
        case 6: if (f.wire == PB_VARINT) m->signed_prekey_id = (uint32_t)f.u64; break;
        default: break;
        }
    }
    return (rc == 0 && have_base && have_id && m->message != NULL) ? 0 : -1;
}

static const uint8_t DISCONTINUITY[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* Bob: initialise a state from an incoming PreKeySignalMessage. */
static int init_bob(sig_state *s, wa_device *dev, const prekey_msg *m,
                    const uint8_t *otk_priv)
{
    uint8_t master[32 * 5];
    size_t n = 0;
    memcpy(master, DISCONTINUITY, 32);
    n = 32;
    if (curve25519_shared(master + n, dev->signed_prekey.priv, m->identity) != 0)
        return -1;
    n += 32;
    if (curve25519_shared(master + n, dev->identity_key.priv, m->base_key) != 0)
        return -1;
    n += 32;
    if (curve25519_shared(master + n, dev->signed_prekey.priv, m->base_key) != 0)
        return -1;
    n += 32;
    if (otk_priv != NULL) {
        if (curve25519_shared(master + n, otk_priv, m->base_key) != 0)
            return -1;
        n += 32;
    }
    memset(s, 0, sizeof *s);
    int r = kdf_root(master, n, s->root_key, s->sender_chain_key);
    zap_secure_zero(master, sizeof master);
    if (r != 0)
        return -1;
    s->valid = 1;
    memcpy(s->remote_identity, m->identity, 32);
    s->sender_ratchet = dev->signed_prekey;
    s->sender_index = 0;
    s->remote_reg_id = m->registration_id;
    s->local_reg_id = dev->registration_id;
    memcpy(s->alice_base_key, m->base_key, 32);
    s->pending_prekey_id = SIG_NO_PREKEY;
    return 0;
}

static void save_identity(const char *addr, const uint8_t identity[32])
{
    uint8_t old[32];
    long n = storage_blob_load("identities", addr, old, sizeof old);
    if (n == 32 && memcmp(old, identity, 32) == 0)
        return;
    if (n == 32)
        LOGW("signal", "identity key changed for %s", addr);
    storage_blob_save("identities", addr, identity, 32);
}

long signal_decrypt(wa_device *dev, const char *addr, int prekey_msg_flag,
                    const uint8_t *in, size_t len, uint8_t *out, size_t cap)
{
    sig_session *sess = &g_sess;
    int lr = session_load(addr, sess);
    long n = -1;

    if (prekey_msg_flag) {
        prekey_msg m;
        if (parse_prekey_message(in, len, &m) != 0) {
            LOGW("signal", "malformed prekey message from %s", addr);
            goto done;
        }
        /* Already have this session (duplicate pkmsg)? */
        if (lr == 0 && sess->cur.valid &&
            memcmp(sess->cur.alice_base_key, m.base_key, 32) == 0) {
            g_tmp.cur = sess->cur;
            n = decrypt_with_state(&g_tmp.cur, dev->identity_key.pub,
                                   m.message, m.message_len, out, cap);
            if (n >= 0) {
                sess->cur = g_tmp.cur;
                session_save(addr, sess);
            }
            goto done;
        }
        if (m.signed_prekey_id != dev->signed_prekey_id) {
            LOGW("signal", "unknown signed prekey %u", (unsigned)m.signed_prekey_id);
            goto done;
        }
        uint8_t otk[32];
        int have_otk = 0;
        if (m.prekey_id != SIG_NO_PREKEY) {
            if (prekeys_find(m.prekey_id, otk) != 0) {
                LOGW("signal", "unknown one-time prekey %u", (unsigned)m.prekey_id);
                goto done;
            }
            have_otk = 1;
        }
        sig_state ns;
        if (init_bob(&ns, dev, &m, have_otk ? otk : NULL) != 0) {
            zap_secure_zero(otk, sizeof otk);
            goto done;
        }
        zap_secure_zero(otk, sizeof otk);
        n = decrypt_with_state(&ns, dev->identity_key.pub, m.message,
                               m.message_len, out, cap);
        if (n >= 0) {
            if (lr == 0 && sess->cur.valid)
                sess->prev = sess->cur;
            sess->cur = ns;
            session_save(addr, sess);
            save_identity(addr, m.identity);
            if (have_otk)
                prekeys_remove(m.prekey_id);
        }
        zap_secure_zero(&ns, sizeof ns);
        goto done;
    }

    if (lr != 0 || !sess->cur.valid) {
        LOGD("signal", "no session for %s", addr);
        goto done;
    }
    g_tmp.cur = sess->cur;
    n = decrypt_with_state(&g_tmp.cur, dev->identity_key.pub, in, len, out, cap);
    if (n >= 0) {
        sess->cur = g_tmp.cur;
    } else if (sess->prev.valid) {
        g_tmp.cur = sess->prev;
        n = decrypt_with_state(&g_tmp.cur, dev->identity_key.pub, in, len, out,
                               cap);
        if (n >= 0) { /* promote the archived state */
            sess->prev = sess->cur;
            sess->cur = g_tmp.cur;
        }
    }
    if (n >= 0)
        session_save(addr, sess);
done:
    zap_secure_zero(sess, sizeof *sess);
    zap_secure_zero(&g_tmp, sizeof g_tmp);
    return n;
}

int signal_session_from_bundle(wa_device *dev, const char *addr,
                               const sig_bundle *b)
{
    uint8_t spk33[33];
    put_key33(spk33, b->signed_prekey);
    if (xeddsa_verify(b->identity, spk33, 33, b->signed_prekey_sig) != 0) {
        LOGW("signal", "invalid signed prekey signature for %s", addr);
        return -1;
    }
    wa_keypair base, sending;
    if (wa_keypair_generate(&base) != 0 || wa_keypair_generate(&sending) != 0)
        return -1;
    uint8_t master[32 * 5];
    size_t n = 32;
    memcpy(master, DISCONTINUITY, 32);
    int ok = curve25519_shared(master + 32, dev->identity_key.priv,
                               b->signed_prekey) == 0 &&
             curve25519_shared(master + 64, base.priv, b->identity) == 0 &&
             curve25519_shared(master + 96, base.priv, b->signed_prekey) == 0;
    n = 128;
    if (ok && b->prekey_id != SIG_NO_PREKEY) {
        ok = curve25519_shared(master + 128, base.priv, b->prekey) == 0;
        n = 160;
    }
    sig_session *sess = &g_sess;
    int lr = session_load(addr, sess);
    sig_state *s = &g_tmp.cur;
    memset(s, 0, sizeof *s);
    uint8_t root[32], chain[32];
    ok = ok && kdf_root(master, n, root, chain) == 0;
    zap_secure_zero(master, sizeof master);
    uint8_t new_root[32], send_chain[32];
    ok = ok && create_chain(root, b->signed_prekey, sending.priv, new_root,
                            send_chain) == 0;
    if (ok) {
        s->valid = 1;
        memcpy(s->remote_identity, b->identity, 32);
        add_recv_chain(s, b->signed_prekey, chain);
        s->sender_ratchet = sending;
        memcpy(s->sender_chain_key, send_chain, 32);
        memcpy(s->root_key, new_root, 32);
        s->has_pending = 1;
        s->pending_prekey_id = b->prekey_id;
        s->pending_signed_id = b->signed_prekey_id;
        memcpy(s->pending_base_key, base.pub, 32);
        s->local_reg_id = dev->registration_id;
        s->remote_reg_id = b->registration_id;
        memcpy(s->alice_base_key, base.pub, 32);
        if (lr == 0 && sess->cur.valid)
            sess->prev = sess->cur;
        sess->cur = *s;
        ok = session_save(addr, sess) == 0;
        save_identity(addr, b->identity);
    }
    zap_secure_zero(&base, sizeof base);
    zap_secure_zero(&sending, sizeof sending);
    zap_secure_zero(root, sizeof root);
    zap_secure_zero(chain, sizeof chain);
    zap_secure_zero(sess, sizeof *sess);
    zap_secure_zero(&g_tmp, sizeof g_tmp);
    return ok ? 0 : -1;
}

long signal_encrypt(wa_device *dev, const char *addr, const uint8_t *in,
                    size_t len, uint8_t *out, size_t cap, int *prekey_msg_out)
{
    static uint8_t body[ZAPC_PROTOBUF_SCRATCH + 32];
    static uint8_t smsg[ZAPC_PROTOBUF_SCRATCH + 128];
    sig_session *sess = &g_sess;
    long result = -1;
    msg_keys k;

    if (session_load(addr, sess) != 0 || !sess->cur.valid)
        goto done;
    sig_state *s = &sess->cur;
    if (chain_message_keys(s->sender_chain_key, &k) != 0)
        goto done;
    long blen = crypto_aes256_cbc_encrypt(k.cipher_key, k.iv, in, len, body,
                                          sizeof body);
    if (blen < 0)
        goto done;

    /* SignalMessage = version || protobuf || mac */
    zbuf b;
    uint8_t key33[33];
    zbuf_init(&b, smsg, sizeof smsg);
    zbuf_put_u8(&b, VERSION_BYTE);
    put_key33(key33, s->sender_ratchet.pub);
    pb_put_bytes(&b, 1, key33, 33);
    pb_put_uint(&b, 2, s->sender_index);
    pb_put_uint(&b, 3, s->previous_counter);
    pb_put_bytes(&b, 4, body, (size_t)blen);
    if (b.overflow || b.len + MAC_LEN > sizeof smsg)
        goto done;
    uint8_t mac[MAC_LEN];
    if (compute_mac(k.mac_key, dev->identity_key.pub, s->remote_identity, smsg,
                    b.len, mac) != 0)
        goto done;
    zbuf_put(&b, mac, MAC_LEN);
    size_t smsg_len = b.len;

    zbuf o;
    zbuf_init(&o, out, cap);
    if (s->has_pending) {
        zbuf_put_u8(&o, VERSION_BYTE);
        if (s->pending_prekey_id != SIG_NO_PREKEY)
            pb_put_uint(&o, 1, s->pending_prekey_id);
        put_key33(key33, s->pending_base_key);
        pb_put_bytes(&o, 2, key33, 33);
        put_key33(key33, dev->identity_key.pub);
        pb_put_bytes(&o, 3, key33, 33);
        pb_put_bytes(&o, 4, smsg, smsg_len);
        pb_put_uint(&o, 5, dev->registration_id);
        pb_put_uint(&o, 6, s->pending_signed_id);
        *prekey_msg_out = 1;
    } else {
        zbuf_put(&o, smsg, smsg_len);
        *prekey_msg_out = 0;
    }
    if (o.overflow)
        goto done;
    chain_next(s->sender_chain_key);
    s->sender_index++;
    if (session_save(addr, sess) != 0)
        goto done;
    result = (long)o.len;
done:
    zap_secure_zero(&k, sizeof k);
    zap_secure_zero(sess, sizeof *sess);
    zap_secure_zero(body, sizeof body);
    return result;
}

/* ======================================================================== */
/* sender keys                                                              */
/* ======================================================================== */

#define SK_MAX_STATES 2
#define SK_MAX_SKIPPED 16
#define SK_MAGIC "ZSK1"

typedef struct {
    uint32_t iteration;
    uint8_t iv[16];
    uint8_t key[32];
} sk_skipped;

typedef struct {
    uint8_t valid;
    uint32_t key_id;
    uint32_t iteration;
    uint8_t chain_key[32];
    uint8_t signing_pub[32];
    uint8_t has_priv;
    uint8_t signing_priv[32];
    uint8_t skipped_count;
    sk_skipped skipped[SK_MAX_SKIPPED];
} sk_state;

typedef struct {
    sk_state states[SK_MAX_STATES]; /* [0] = newest */
} sk_record;

static sk_record g_sk;

static int sk_name(char *out, size_t cap, const char *group, const char *addr)
{
    int n = snprintf(out, cap, "%s_%s", group, addr);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

static int sk_load(const char *group, const char *addr, sk_record *r)
{
    static uint8_t buf[sizeof(sk_record) + 64];
    char name[200];
    memset(r, 0, sizeof *r);
    if (sk_name(name, sizeof name, group, addr) != 0)
        return -1;
    long n = storage_blob_load("senderkeys", name, buf, sizeof buf);
    if (n < 0)
        return 1;
    rdr d = {buf, (size_t)n, 0};
    char magic[4];
    rd(&d, magic, 4);
    if (memcmp(magic, SK_MAGIC, 4) != 0)
        return -1;
    for (int i = 0; i < SK_MAX_STATES && !d.err; i++) {
        sk_state *s = &r->states[i];
        s->valid = rd8(&d);
        if (!s->valid)
            continue;
        s->key_id = rd32(&d);
        s->iteration = rd32(&d);
        rd(&d, s->chain_key, 32);
        rd(&d, s->signing_pub, 32);
        s->has_priv = rd8(&d);
        if (s->has_priv)
            rd(&d, s->signing_priv, 32);
        s->skipped_count = rd8(&d);
        if (s->skipped_count > SK_MAX_SKIPPED)
            d.err = 1;
        for (unsigned k = 0; !d.err && k < s->skipped_count; k++) {
            s->skipped[k].iteration = rd32(&d);
            rd(&d, s->skipped[k].iv, 16);
            rd(&d, s->skipped[k].key, 32);
        }
    }
    zap_secure_zero(buf, sizeof buf);
    if (d.err) {
        memset(r, 0, sizeof *r);
        return -1;
    }
    return 0;
}

static int sk_save(const char *group, const char *addr, const sk_record *r)
{
    static uint8_t buf[sizeof(sk_record) + 64];
    char name[200];
    zbuf b;
    if (sk_name(name, sizeof name, group, addr) != 0)
        return -1;
    zbuf_init(&b, buf, sizeof buf);
    zbuf_put(&b, SK_MAGIC, 4);
    for (int i = 0; i < SK_MAX_STATES; i++) {
        const sk_state *s = &r->states[i];
        zbuf_put_u8(&b, s->valid);
        if (!s->valid)
            continue;
        zbuf_put_be32(&b, s->key_id);
        zbuf_put_be32(&b, s->iteration);
        zbuf_put(&b, s->chain_key, 32);
        zbuf_put(&b, s->signing_pub, 32);
        zbuf_put_u8(&b, s->has_priv);
        if (s->has_priv)
            zbuf_put(&b, s->signing_priv, 32);
        zbuf_put_u8(&b, s->skipped_count);
        for (unsigned k = 0; k < s->skipped_count; k++) {
            zbuf_put_be32(&b, s->skipped[k].iteration);
            zbuf_put(&b, s->skipped[k].iv, 16);
            zbuf_put(&b, s->skipped[k].key, 32);
        }
    }
    int rc = b.overflow ? -1 : storage_blob_save("senderkeys", name, buf, b.len);
    zap_secure_zero(buf, sizeof buf);
    return rc;
}

static int sk_message_key(const uint8_t chain[32], uint8_t iv[16],
                          uint8_t key[32])
{
    static const uint8_t one = 0x01;
    static const char info[] = "WhisperGroup";
    uint8_t seed[32], out[48];
    if (crypto_hmac_sha256(chain, 32, &one, 1, seed) != 0 ||
        crypto_hkdf_sha256(NULL, 0, seed, 32, info, sizeof info - 1, out,
                           48) != 0)
        return -1;
    memcpy(iv, out, 16);
    memcpy(key, out + 16, 32);
    zap_secure_zero(seed, sizeof seed);
    zap_secure_zero(out, sizeof out);
    return 0;
}

int senderkey_process(const char *group, const char *sender_addr,
                      const uint8_t *skdm, size_t len)
{
    pb_reader r;
    pb_field f;
    int rc;
    sk_state ns;
    int have_chain = 0, have_key = 0;
    if (len < 2 || (skdm[0] >> 4) != SIG_VERSION)
        return -1;
    memset(&ns, 0, sizeof ns);
    pb_reader_init(&r, skdm + 1, len - 1);
    while ((rc = pb_next(&r, &f)) == 1) {
        if (f.num == 1 && f.wire == PB_VARINT)
            ns.key_id = (uint32_t)f.u64;
        else if (f.num == 2 && f.wire == PB_VARINT)
            ns.iteration = (uint32_t)f.u64;
        else if (f.num == 3 && f.wire == PB_LEN && f.len == 32) {
            memcpy(ns.chain_key, f.data, 32);
            have_chain = 1;
        } else if (f.num == 4 && f.wire == PB_LEN)
            have_key = get_key33(f.data, f.len, ns.signing_pub) == 0;
    }
    if (rc != 0 || !have_chain || !have_key)
        return -1;
    ns.valid = 1;
    sk_record *rec = &g_sk;
    if (sk_load(group, sender_addr, rec) < 0)
        memset(rec, 0, sizeof *rec);
    /* replace an existing state with the same id, else push front */
    int idx = -1;
    for (int i = 0; i < SK_MAX_STATES; i++)
        if (rec->states[i].valid && rec->states[i].key_id == ns.key_id)
            idx = i;
    if (idx < 0) {
        memmove(&rec->states[1], &rec->states[0],
                (SK_MAX_STATES - 1) * sizeof rec->states[0]);
        idx = 0;
    }
    rec->states[idx] = ns;
    int ret = sk_save(group, sender_addr, rec);
    zap_secure_zero(rec, sizeof *rec);
    zap_secure_zero(&ns, sizeof ns);
    return ret;
}

long senderkey_decrypt(const char *group, const char *sender_addr,
                       const uint8_t *in, size_t len, uint8_t *out, size_t cap)
{
    pb_reader r;
    pb_field f;
    int rc;
    uint32_t key_id = 0, iteration = 0;
    const uint8_t *ct = NULL;
    size_t ct_len = 0;
    long result = -1;
    if (len < 1 + 64 || (in[0] >> 4) != SIG_VERSION)
        return -1;
    pb_reader_init(&r, in + 1, len - 1 - 64);
    while ((rc = pb_next(&r, &f)) == 1) {
        if (f.num == 1 && f.wire == PB_VARINT)
            key_id = (uint32_t)f.u64;
        else if (f.num == 2 && f.wire == PB_VARINT)
            iteration = (uint32_t)f.u64;
        else if (f.num == 3 && f.wire == PB_LEN) {
            ct = f.data;
            ct_len = f.len;
        }
    }
    if (rc != 0 || ct == NULL)
        return -1;
    sk_record *rec = &g_sk;
    if (sk_load(group, sender_addr, rec) != 0) {
        LOGD("signal", "no sender key for %s in %s", sender_addr, group);
        return -1;
    }
    sk_state *s = NULL;
    for (int i = 0; i < SK_MAX_STATES; i++)
        if (rec->states[i].valid && rec->states[i].key_id == key_id)
            s = &rec->states[i];
    if (s == NULL)
        goto done;
    if (xeddsa_verify(s->signing_pub, in, len - 64, in + len - 64) != 0) {
        LOGW("signal", "bad sender key signature");
        goto done;
    }
    uint8_t iv[16], key[32];
    if (s->iteration > iteration) {
        int found = 0;
        for (unsigned k = 0; k < s->skipped_count; k++) {
            if (s->skipped[k].iteration == iteration) {
                memcpy(iv, s->skipped[k].iv, 16);
                memcpy(key, s->skipped[k].key, 32);
                memmove(&s->skipped[k], &s->skipped[k + 1],
                        (s->skipped_count - k - 1) * sizeof s->skipped[0]);
                s->skipped_count--;
                found = 1;
                break;
            }
        }
        if (!found)
            goto done;
    } else {
        if (iteration - s->iteration > SIG_MAX_FORWARD)
            goto done;
        while (s->iteration < iteration) {
            if (iteration - s->iteration <= SK_MAX_SKIPPED) {
                if (s->skipped_count == SK_MAX_SKIPPED) {
                    memmove(&s->skipped[0], &s->skipped[1],
                            (SK_MAX_SKIPPED - 1) * sizeof s->skipped[0]);
                    s->skipped_count--;
                }
                sk_skipped *e = &s->skipped[s->skipped_count++];
                e->iteration = s->iteration;
                sk_message_key(s->chain_key, e->iv, e->key);
            }
            chain_next(s->chain_key);
            s->iteration++;
        }
        if (sk_message_key(s->chain_key, iv, key) != 0)
            goto done;
        chain_next(s->chain_key);
        s->iteration++;
    }
    result = crypto_aes256_cbc_decrypt(key, iv, ct, ct_len, out, cap);
    zap_secure_zero(key, sizeof key);
    if (result >= 0)
        sk_save(group, sender_addr, rec);
done:
    zap_secure_zero(rec, sizeof *rec);
    return result;
}

static int own_sender_key(const char *group, const char *own_addr,
                          sk_record *rec)
{
    if (sk_load(group, own_addr, rec) == 0 && rec->states[0].valid &&
        rec->states[0].has_priv)
        return 0;
    memset(rec, 0, sizeof *rec);
    sk_state *s = &rec->states[0];
    uint8_t id[4];
    wa_keypair kp;
    if (plat_random(id, 4) != 0 || plat_random(s->chain_key, 32) != 0 ||
        wa_keypair_generate(&kp) != 0)
        return -1;
    s->valid = 1;
    s->key_id = rd_be32(id) & 0x7FFFFFFFu;
    s->iteration = 0;
    memcpy(s->signing_pub, kp.pub, 32);
    memcpy(s->signing_priv, kp.priv, 32);
    s->has_priv = 1;
    zap_secure_zero(&kp, sizeof kp);
    return sk_save(group, own_addr, rec);
}

long senderkey_distribution(const char *group, const char *own_addr,
                            uint8_t *out, size_t cap)
{
    sk_record *rec = &g_sk;
    zbuf b;
    uint8_t key33[33];
    long r = -1;
    if (own_sender_key(group, own_addr, rec) != 0)
        goto done;
    sk_state *s = &rec->states[0];
    zbuf_init(&b, out, cap);
    zbuf_put_u8(&b, VERSION_BYTE);
    pb_put_uint(&b, 1, s->key_id);
    pb_put_uint(&b, 2, s->iteration);
    pb_put_bytes(&b, 3, s->chain_key, 32);
    put_key33(key33, s->signing_pub);
    pb_put_bytes(&b, 4, key33, 33);
    if (!b.overflow)
        r = (long)b.len;
done:
    zap_secure_zero(rec, sizeof *rec);
    return r;
}

long senderkey_encrypt(const char *group, const char *own_addr,
                       const uint8_t *in, size_t len, uint8_t *out, size_t cap)
{
    static uint8_t ct[ZAPC_PROTOBUF_SCRATCH + 32];
    sk_record *rec = &g_sk;
    uint8_t iv[16], key[32];
    long result = -1;
    zbuf b;
    if (own_sender_key(group, own_addr, rec) != 0)
        goto done;
    sk_state *s = &rec->states[0];
    if (sk_message_key(s->chain_key, iv, key) != 0)
        goto done;
    long n = crypto_aes256_cbc_encrypt(key, iv, in, len, ct, sizeof ct);
    if (n < 0)
        goto done;
    zbuf_init(&b, out, cap);
    zbuf_put_u8(&b, VERSION_BYTE);
    pb_put_uint(&b, 1, s->key_id);
    pb_put_uint(&b, 2, s->iteration);
    pb_put_bytes(&b, 3, ct, (size_t)n);
    if (b.overflow || b.len + 64 > cap)
        goto done;
    if (xeddsa_sign(out + b.len, s->signing_priv, out, b.len) != 0)
        goto done;
    result = (long)(b.len + 64);
    chain_next(s->chain_key);
    s->iteration++;
    if (sk_save(group, own_addr, rec) != 0)
        result = -1;
done:
    zap_secure_zero(key, sizeof key);
    zap_secure_zero(rec, sizeof *rec);
    return result;
}

/* ======================================================================== */
/* padding                                                                  */
/* ======================================================================== */

size_t wa_pad_message(uint8_t *buf, size_t len, size_t cap)
{
    uint8_t pad;
    if (plat_random(&pad, 1) != 0)
        pad = 0;
    pad &= 0x0F;
    if (pad == 0)
        pad = 0x0F;
    if (cap - len < pad)
        return 0;
    memset(buf + len, pad, pad);
    return len + pad;
}

long wa_unpad_message(const uint8_t *buf, size_t len)
{
    if (len == 0)
        return -1;
    uint8_t pad = buf[len - 1];
    if (pad == 0 || pad > len)
        return -1;
    return (long)(len - pad);
}
