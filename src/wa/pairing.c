/*
 * ZapC - companion device pairing (QR code).
 *
 * Flow:
 *   server --> <iq><pair-device><ref>..</ref>...</pair-device></iq>
 *   we show "ref,noise_pub,identity_pub,adv_secret,client_type" as QR codes
 *   phone scans, server --> <iq><pair-success>...</pair-success></iq>
 *   we verify the HMAC and account signature, sign the device identity and
 *   reply with <pair-device-sign>, then the server restarts the stream (515)
 *   and we log in with the new identity.
 */
#include "zapc/crypto.h"
#include "zapc/log.h"
#include "zapc/platform.h"
#include "zapc/protobuf.h"
#include "zapc/storage.h"
#include "zapc/util.h"
#include "zapc/wa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QR_LINK_PREFIX "https://wa.me/settings/linked_devices#"
#define QR_CLIENT_TYPE "9" /* "other web client" */
#define ADV_ENCRYPTION_HOSTED 1

static const uint8_t ADV_ACCOUNT_SIG_PREFIX[2] = {6, 0};
static const uint8_t ADV_DEVICE_SIG_PREFIX[2] = {6, 1};
static const uint8_t ADV_HOSTED_ACCOUNT_SIG_PREFIX[2] = {6, 5};

static void show_qr(wa_client *c)
{
    char noise[64], ident[64], adv[64];
    char payload[WA_QR_REF_MAX + 256];
    if (c->qr_ref_index >= c->qr_ref_count)
        return;
    base64_encode(c->dev.noise_key.pub, 32, noise, sizeof noise);
    base64_encode(c->dev.identity_key.pub, 32, ident, sizeof ident);
    base64_encode(c->dev.adv_secret, 32, adv, sizeof adv);
    snprintf(payload, sizeof payload, "%s%s,%s,%s,%s,%s", QR_LINK_PREFIX,
             c->qr_refs[c->qr_ref_index], noise, ident, adv, QR_CLIENT_TYPE);
    if (c->ev.on_qr != NULL)
        c->ev.on_qr(c->ev.user, payload);
}

void wa_handle_pair_device(wa_client *c, const wa_node *iq)
{
    if (iq == NULL) { /* timer: next code */
        show_qr(c);
        return;
    }
    /* acknowledge */
    wa_attr attrs[] = {WA_ATTR_JID("to", wa_node_attr(iq, "from")),
                       WA_ATTR("id", wa_node_attr(iq, "id")),
                       WA_ATTR("type", "result")};
    wa_node ack = {"iq", attrs, WA_COUNT(attrs), NULL, 0, NULL, 0,
                   WA_CONTENT_NONE};
    if (attrs[1].value != NULL)
        (void)wa_send_node(c, &ack);

    const wa_node *pd = wa_node_child(iq, "pair-device");
    c->qr_ref_count = 0;
    c->qr_ref_index = 0;
    for (size_t i = 0; pd != NULL && pd->content == WA_CONTENT_CHILDREN &&
                       i < pd->child_count && c->qr_ref_count < WA_MAX_QR_REFS;
         i++) {
        const wa_node *ref = &pd->children[i];
        if (strcmp(ref->tag, "ref") != 0 || ref->content != WA_CONTENT_BYTES ||
            ref->data_len == 0 || ref->data_len >= WA_QR_REF_MAX)
            continue;
        /* refs are printable; reject anything that would break the QR text */
        int ok = 1;
        for (size_t k = 0; k < ref->data_len; k++)
            if (ref->data[k] < 0x21 || ref->data[k] > 0x7e || ref->data[k] == ',')
                ok = 0;
        if (!ok)
            continue;
        memcpy(c->qr_refs[c->qr_ref_count], ref->data, ref->data_len);
        c->qr_refs[c->qr_ref_count][ref->data_len] = '\0';
        c->qr_ref_count++;
    }
    if (c->qr_ref_count == 0) {
        LOGW("pair", "pair-device without usable refs");
        return;
    }
    LOGI("pair", "received %d pairing codes", c->qr_ref_count);
    c->qr_next_at = plat_now_ms() + 60000; /* first code lasts 60 s */
    show_qr(c);
}

static void send_pair_error(wa_client *c, const char *id, const char *code,
                            const char *text)
{
    wa_attr ea[] = {WA_ATTR("code", code), WA_ATTR("text", text)};
    wa_node err = {"error", ea, 2, NULL, 0, NULL, 0, WA_CONTENT_NONE};
    wa_attr a[] = {WA_ATTR_JID("to", WA_SERVER_USER), WA_ATTR("type", "error"),
                   WA_ATTR("id", id)};
    wa_node iq = {"iq", a, WA_COUNT(a), &err, 1, NULL, 0, WA_CONTENT_CHILDREN};
    (void)wa_send_node(c, &iq);
}

typedef struct {
    const uint8_t *details;
    size_t details_len;
    const uint8_t *account_sig_key;
    size_t account_sig_key_len;
    const uint8_t *account_sig;
    size_t account_sig_len;
} adv_signed_identity;

static int parse_signed_identity(const uint8_t *p, size_t n,
                                 adv_signed_identity *s)
{
    pb_reader r;
    pb_field f;
    int rc;
    memset(s, 0, sizeof *s);
    pb_reader_init(&r, p, n);
    while ((rc = pb_next(&r, &f)) == 1) {
        if (f.wire != PB_LEN)
            continue;
        if (f.num == 1) {
            s->details = f.data;
            s->details_len = f.len;
        } else if (f.num == 2) {
            s->account_sig_key = f.data;
            s->account_sig_key_len = f.len;
        } else if (f.num == 3) {
            s->account_sig = f.data;
            s->account_sig_len = f.len;
        }
    }
    return rc < 0 || s->details == NULL ? -1 : 0;
}

void wa_handle_pair_success(wa_client *c, const wa_node *iq)
{
    const char *id = wa_node_attr(iq, "id");
    const wa_node *ps = wa_node_child(iq, "pair-success");
    const wa_node *di = wa_node_child(ps, "device-identity");
    const wa_node *dev = wa_node_child(ps, "device");
    const char *platform = wa_node_attr(wa_node_child(ps, "platform"), "name");
    const char *biz = wa_node_attr(wa_node_child(ps, "biz"), "name");
    const char *jid_s = wa_node_attr(dev, "jid");
    const char *lid_s = wa_node_attr(dev, "lid");
    const char *t = wa_node_attr(iq, "t");
    wa_jid jid, lid;

    if (id == NULL)
        return;
    if (t != NULL)
        c->server_time_offset = strtoll(t, NULL, 10) - plat_time_unix();
    if (di == NULL || di->content != WA_CONTENT_BYTES || jid_s == NULL ||
        jid_parse(&jid, jid_s) != 0) {
        send_pair_error(c, id, "500", "internal-error");
        LOGE("pair", "malformed pair-success");
        return;
    }
    if (lid_s == NULL || jid_parse(&lid, lid_s) != 0)
        jid_clear(&lid);

    /* ADVSignedDeviceIdentityHMAC { details=1, hmac=2, accountType=3 } */
    const uint8_t *hdetails = NULL, *hmac = NULL;
    size_t hdetails_len = 0, hmac_len = 0;
    uint64_t account_type = 0;
    if (pb_find_bytes(di->data, di->data_len, 1, &hdetails, &hdetails_len) != 1 ||
        pb_find_bytes(di->data, di->data_len, 2, &hmac, &hmac_len) != 1 ||
        pb_find_varint(di->data, di->data_len, 3, &account_type) < 0) {
        send_pair_error(c, id, "500", "internal-error");
        LOGE("pair", "cannot parse device identity container");
        return;
    }
    int hosted = account_type == ADV_ENCRYPTION_HOSTED;
    uint8_t mac[32];
    zc_iov hv[2] = {{ADV_HOSTED_ACCOUNT_SIG_PREFIX, hosted ? 2u : 0u},
                    {hdetails, hdetails_len}};
    if (crypto_hmac_sha256_v(c->dev.adv_secret, 32, hv, 2, mac) != 0 ||
        hmac_len != 32 || zap_ct_memcmp(mac, hmac, 32) != 0) {
        LOGE("pair", "invalid HMAC in pair-success");
        send_pair_error(c, id, "401", "hmac-mismatch");
        return;
    }

    adv_signed_identity si;
    if (parse_signed_identity(hdetails, hdetails_len, &si) != 0 ||
        si.account_sig_key_len != 32 || si.account_sig_len != 64) {
        send_pair_error(c, id, "500", "internal-error");
        LOGE("pair", "cannot parse signed device identity");
        return;
    }
    /* ADVDeviceIdentity { rawId=1, timestamp=2, keyIndex=3, accountType=4, deviceType=5 } */
    uint64_t key_index = 0, device_type = 0;
    if (pb_find_varint(si.details, si.details_len, 3, &key_index) < 0 ||
        pb_find_varint(si.details, si.details_len, 5, &device_type) < 0) {
        send_pair_error(c, id, "500", "internal-error");
        return;
    }
    int dev_hosted = device_type == ADV_ENCRYPTION_HOSTED;
    zc_iov av[3] = {
        {dev_hosted ? ADV_HOSTED_ACCOUNT_SIG_PREFIX : ADV_ACCOUNT_SIG_PREFIX, 2},
        {si.details, si.details_len},
        {c->dev.identity_key.pub, 32}};
    if (xeddsa_verify_v(si.account_sig_key, av, 3, si.account_sig) != 0) {
        LOGE("pair", "invalid account signature");
        send_pair_error(c, id, "401", "signature-mismatch");
        return;
    }

    uint8_t device_sig[64];
    zc_iov dv[4] = {{ADV_DEVICE_SIG_PREFIX, 2},
                    {si.details, si.details_len},
                    {c->dev.identity_key.pub, 32},
                    {si.account_sig_key, 32}};
    if (xeddsa_sign_v(device_sig, c->dev.identity_key.priv, dv, 4) != 0) {
        send_pair_error(c, id, "500", "internal-error");
        return;
    }

    /* Full identity (kept for outgoing pkmsg device-identity nodes). */
    zbuf b;
    zbuf_init(&b, c->dev.account, sizeof c->dev.account);
    pb_put_bytes(&b, 1, si.details, si.details_len);
    pb_put_bytes(&b, 2, si.account_sig_key, 32);
    pb_put_bytes(&b, 3, si.account_sig, 64);
    pb_put_bytes(&b, 4, device_sig, 64);
    if (b.overflow) {
        send_pair_error(c, id, "500", "internal-error");
        return;
    }
    c->dev.account_len = b.len;

    /* Self-signed identity sent back: without the account signature key. */
    uint8_t reply[WA_ACCOUNT_MAX];
    zbuf_init(&b, reply, sizeof reply);
    pb_put_bytes(&b, 1, si.details, si.details_len);
    pb_put_bytes(&b, 3, si.account_sig, 64);
    pb_put_bytes(&b, 4, device_sig, 64);

    c->dev.paired = 1;
    c->dev.jid = jid;
    c->dev.lid = lid;
    zstrlcpy(c->dev.platform, platform ? platform : "", sizeof c->dev.platform);
    zstrlcpy(c->dev.business_name, biz ? biz : "", sizeof c->dev.business_name);
    if (credentials_save(&c->dev) != 0) {
        send_pair_error(c, id, "500", "internal-error");
        c->dev.paired = 0;
        return;
    }
    /* Trust the primary device's identity key (on its LID address). */
    if (!jid_is_empty(&lid)) {
        wa_jid main = lid;
        char addr[96];
        main.device = 0;
        if (jid_signal_address(&main, addr, sizeof addr) > 0)
            storage_blob_save("identities", addr, si.account_sig_key, 32);
    }

    char kidx[16];
    snprintf(kidx, sizeof kidx, "%llu", (unsigned long long)key_index);
    wa_attr da[] = {WA_ATTR("key-index", kidx)};
    wa_node dinode = {"device-identity", da, 1, NULL, 0, reply, b.len,
                      WA_CONTENT_BYTES};
    wa_node sign = {"pair-device-sign", NULL, 0, &dinode, 1, NULL, 0,
                    WA_CONTENT_CHILDREN};
    wa_attr a[] = {WA_ATTR_JID("to", WA_SERVER_USER), WA_ATTR("type", "result"),
                   WA_ATTR("id", id)};
    wa_node res = {"iq", a, WA_COUNT(a), &sign, 1, NULL, 0, WA_CONTENT_CHILDREN};
    c->expect_disconnect = 1;
    c->qr_next_at = 0;
    if (wa_send_node(c, &res) != 0) {
        LOGE("pair", "failed to send pairing confirmation");
        return;
    }
    LOGI("pair", "paired successfully (platform %s)",
         platform ? platform : "?");
    if (c->ev.on_paired != NULL)
        c->ev.on_paired(c->ev.user, &jid, platform ? platform : "");
}
