/*
 * ZapC - credentials file.
 *
 * Format: "ZAPC" magic, u16 version, then TLV records (u8 tag, u16 length,
 * value).  Unknown tags are skipped so newer files stay readable.
 */
#include "zapc/storage.h"
#include "zapc/log.h"
#include "zapc/memory.h"
#include "zapc/platform.h"
#include "zapc/util.h"

#include <string.h>

#define CRED_VERSION 1

enum {
    T_NOISE_PRIV = 1,
    T_NOISE_PUB,
    T_IDENT_PRIV,
    T_IDENT_PUB,
    T_SPK_PRIV,
    T_SPK_PUB,
    T_SPK_ID,
    T_SPK_SIG,
    T_REG_ID,
    T_ADV_SECRET,
    T_JID,
    T_LID,
    T_PLATFORM,
    T_BUSINESS,
    T_PUSHNAME,
    T_ACCOUNT,
    T_NEXT_PREKEY,
    T_UPLOADED_PREKEY
};

static void put_tlv(zbuf *b, uint8_t tag, const void *v, size_t len)
{
    zbuf_put_u8(b, tag);
    zbuf_put_be16(b, (uint16_t)len);
    zbuf_put(b, v, len);
}

static void put_u32(zbuf *b, uint8_t tag, uint32_t v)
{
    uint8_t t[4];
    wr_be32(t, v);
    put_tlv(b, tag, t, 4);
}

static void put_str(zbuf *b, uint8_t tag, const char *s)
{
    put_tlv(b, tag, s, strlen(s));
}

int credentials_save(const wa_device *dev)
{
    uint8_t mem[4096];
    zbuf b;
    char path[ZAPC_PATH_MAX];
    char jid[WA_JID_STR_MAX];

    zbuf_init(&b, mem, sizeof mem);
    zbuf_put(&b, "ZAPC", 4);
    zbuf_put_be16(&b, CRED_VERSION);
    put_tlv(&b, T_NOISE_PRIV, dev->noise_key.priv, 32);
    put_tlv(&b, T_NOISE_PUB, dev->noise_key.pub, 32);
    put_tlv(&b, T_IDENT_PRIV, dev->identity_key.priv, 32);
    put_tlv(&b, T_IDENT_PUB, dev->identity_key.pub, 32);
    put_tlv(&b, T_SPK_PRIV, dev->signed_prekey.priv, 32);
    put_tlv(&b, T_SPK_PUB, dev->signed_prekey.pub, 32);
    put_u32(&b, T_SPK_ID, dev->signed_prekey_id);
    put_tlv(&b, T_SPK_SIG, dev->signed_prekey_sig, 64);
    put_u32(&b, T_REG_ID, dev->registration_id);
    put_tlv(&b, T_ADV_SECRET, dev->adv_secret, 32);
    put_u32(&b, T_NEXT_PREKEY, dev->next_prekey_id);
    put_u32(&b, T_UPLOADED_PREKEY, dev->uploaded_prekey_id);
    if (dev->paired) {
        if (jid_format(&dev->jid, jid, sizeof jid) > 0)
            put_str(&b, T_JID, jid);
        if (!jid_is_empty(&dev->lid) &&
            jid_format(&dev->lid, jid, sizeof jid) > 0)
            put_str(&b, T_LID, jid);
        put_str(&b, T_PLATFORM, dev->platform);
        put_str(&b, T_BUSINESS, dev->business_name);
        put_str(&b, T_PUSHNAME, dev->push_name);
        put_tlv(&b, T_ACCOUNT, dev->account, dev->account_len);
    }
    if (b.overflow || storage_path(path, sizeof path, "credentials.bin") != 0) {
        zap_secure_zero(mem, sizeof mem);
        return -1;
    }
    int r = plat_write_file_atomic(path, mem, b.len, 0600);
    zap_secure_zero(mem, sizeof mem);
    if (r != 0)
        LOGE("storage", "failed to save credentials");
    return r;
}

static int get_fixed(void *dst, size_t want, const uint8_t *v, size_t len)
{
    if (len != want)
        return -1;
    memcpy(dst, v, want);
    return 0;
}

static int get_str(char *dst, size_t cap, const uint8_t *v, size_t len)
{
    if (len >= cap)
        return -1;
    memcpy(dst, v, len);
    dst[len] = '\0';
    return 0;
}

int credentials_load(wa_device *dev)
{
    uint8_t mem[4096];
    char path[ZAPC_PATH_MAX];
    char tmp[WA_JID_STR_MAX];

    memset(dev, 0, sizeof *dev);
    if (storage_path(path, sizeof path, "credentials.bin") != 0)
        return -1;
    long n = plat_read_file(path, mem, sizeof mem);
    if (n < 0)
        return 1;
    if (n < 6 || memcmp(mem, "ZAPC", 4) != 0 ||
        rd_be16(mem + 4) != CRED_VERSION) {
        LOGE("storage", "credentials file is invalid");
        return -1;
    }
    size_t pos = 6, len = (size_t)n;
    unsigned seen = 0;
    int err = 0;
    while (pos + 3 <= len && !err) {
        uint8_t tag = mem[pos];
        size_t l = rd_be16(mem + pos + 1);
        pos += 3;
        if (l > len - pos) {
            err = 1;
            break;
        }
        const uint8_t *v = mem + pos;
        pos += l;
        if (tag < 32)
            seen |= 1u << tag;
        switch (tag) {
        case T_NOISE_PRIV: err = get_fixed(dev->noise_key.priv, 32, v, l); break;
        case T_NOISE_PUB: err = get_fixed(dev->noise_key.pub, 32, v, l); break;
        case T_IDENT_PRIV: err = get_fixed(dev->identity_key.priv, 32, v, l); break;
        case T_IDENT_PUB: err = get_fixed(dev->identity_key.pub, 32, v, l); break;
        case T_SPK_PRIV: err = get_fixed(dev->signed_prekey.priv, 32, v, l); break;
        case T_SPK_PUB: err = get_fixed(dev->signed_prekey.pub, 32, v, l); break;
        case T_SPK_SIG: err = get_fixed(dev->signed_prekey_sig, 64, v, l); break;
        case T_ADV_SECRET: err = get_fixed(dev->adv_secret, 32, v, l); break;
        case T_SPK_ID:
        case T_REG_ID:
        case T_NEXT_PREKEY:
        case T_UPLOADED_PREKEY: {
            if (l != 4) {
                err = 1;
                break;
            }
            uint32_t x = rd_be32(v);
            if (tag == T_SPK_ID)
                dev->signed_prekey_id = x;
            else if (tag == T_REG_ID)
                dev->registration_id = x;
            else if (tag == T_NEXT_PREKEY)
                dev->next_prekey_id = x;
            else
                dev->uploaded_prekey_id = x;
            break;
        }
        case T_JID:
        case T_LID:
            err = get_str(tmp, sizeof tmp, v, l) != 0 ||
                  jid_parse(tag == T_JID ? &dev->jid : &dev->lid, tmp) != 0;
            if (tag == T_JID && !err)
                dev->paired = 1;
            break;
        case T_PLATFORM:
            err = get_str(dev->platform, sizeof dev->platform, v, l);
            break;
        case T_BUSINESS:
            err = get_str(dev->business_name, sizeof dev->business_name, v, l);
            break;
        case T_PUSHNAME:
            err = get_str(dev->push_name, sizeof dev->push_name, v, l);
            break;
        case T_ACCOUNT:
            if (l > sizeof dev->account) {
                err = 1;
                break;
            }
            memcpy(dev->account, v, l);
            dev->account_len = l;
            break;
        default:
            break; /* unknown: skip */
        }
    }
    zap_secure_zero(mem, sizeof mem);
    const unsigned required = (1u << T_NOISE_PRIV) | (1u << T_IDENT_PRIV) |
                              (1u << T_SPK_PRIV) | (1u << T_REG_ID) |
                              (1u << T_ADV_SECRET) | (1u << T_SPK_SIG);
    if (err || (seen & required) != required) {
        LOGE("storage", "credentials file is corrupt");
        wa_device_wipe(dev);
        return -1;
    }
    if (dev->next_prekey_id == 0)
        dev->next_prekey_id = 1;
    if (dev->uploaded_prekey_id == 0)
        dev->uploaded_prekey_id = 1;
    return 0;
}
