/*
 * ZapC - WhatsApp client (multi-device / companion protocol).
 *
 * Single-threaded: the application polls wa_client_fd() and calls
 * wa_client_on_readable() / wa_client_tick().  Results are reported through
 * the callbacks in wa_events.
 */
#ifndef ZAPC_WA_H
#define ZAPC_WA_H

#include "zapc/binary_node.h"
#include "zapc/build_config.h"
#include "zapc/config.h"
#include "zapc/frame.h"
#include "zapc/jid.h"
#include "zapc/keys.h"
#include "zapc/noise.h"
#include "zapc/tls.h"
#include "zapc/websocket.h"

#include <stdint.h>

typedef enum {
    WA_ST_DISCONNECTED = 0,
    WA_ST_CONNECTING,   /* TCP/TLS/WebSocket setup     */
    WA_ST_HANDSHAKE,    /* Noise handshake in progress */
    WA_ST_PAIRING,      /* waiting for QR scan         */
    WA_ST_AUTHENTICATING,
    WA_ST_LOGGED_IN
} wa_state;

const char *wa_state_name(wa_state st);

/* A decrypted, displayable message. */
typedef struct {
    char id[64];
    wa_jid chat;     /* conversation (user or group)          */
    wa_jid sender;   /* author (device stripped)              */
    int from_me;
    int64_t timestamp;
    char push_name[ZAPC_NAME_MAX];
    char text[ZAPC_MSG_TEXT_MAX]; /* text or "[Image: ...]"   */
} wa_message;

typedef struct {
    void *user;
    void (*on_state)(void *user, wa_state st, const char *detail);
    void (*on_qr)(void *user, const char *qr_payload);
    void (*on_paired)(void *user, const wa_jid *jid, const char *platform);
    void (*on_logged_out)(void *user, const char *reason);
    void (*on_message)(void *user, const wa_message *msg);
    /* type: "delivered", "read", "played", "sent" (server ack) */
    void (*on_receipt)(void *user, const wa_jid *chat, const char *msg_id,
                       const char *type);
    void (*on_chat_name)(void *user, const wa_jid *chat, const char *name);
} wa_events;

#define WA_MAX_PENDING_IQ 16
#define WA_MAX_QR_REFS 8
#define WA_QR_REF_MAX 160

typedef enum {
    IQ_NONE = 0,
    IQ_GENERIC,
    IQ_PREKEY_COUNT,
    IQ_PREKEY_UPLOAD,
    IQ_USYNC_DEVICES,
    IQ_PREKEY_FETCH,
    IQ_GROUP_INFO,
    IQ_KEEPALIVE
} wa_iq_kind;

typedef struct {
    char id[24];
    wa_iq_kind kind;
    uint64_t sent_ms;
    int slot; /* outgoing message slot for send pipeline, -1 if none */
} wa_pending_iq;

struct wa_send_job; /* defined in message.c */

typedef struct wa_client {
    const zapc_config *cfg;
    wa_events ev;
    wa_device dev;
    int have_device;

    wa_state state;
    int fd;
    zc_tls *tls;
    ws_client ws;
    wa_framer framer;
    int header_sent;

    noise_handshake hs;
    wa_keypair ephemeral;
    noise_cipher wcs;
    noise_cipher rcs;

    /* request ids */
    char id_prefix[16];
    uint32_t id_counter;
    wa_pending_iq pending[WA_MAX_PENDING_IQ];

    /* timers (monotonic ms, 0 = disabled) */
    uint64_t keepalive_at;
    uint64_t keepalive_sent;
    uint64_t reconnect_at;
    unsigned reconnect_attempts;
    int want_connected;
    int expect_disconnect;
    int64_t server_time_offset;

    /* pairing QR rotation */
    char qr_refs[WA_MAX_QR_REFS][WA_QR_REF_MAX];
    int qr_ref_count;
    int qr_ref_index;
    uint64_t qr_next_at;

    /* statistics */
    unsigned long frames_rx;
    unsigned long frames_tx;
    unsigned long bytes_rx;
    unsigned long bytes_tx;
    size_t arena_peak;

    struct wa_send_job *send_job; /* in-flight outgoing message (or NULL) */

    /* fixed buffers (must stay last: wa_client_init clears up to here) */
    zap_arena arena;
    uint8_t arena_mem[ZAPC_NODE_ARENA_SIZE];
    uint8_t frame_buf[ZAPC_WA_FRAME_MAX];
    uint8_t inflate_buf[ZAPC_INFLATE_MAX];
    uint8_t enc_buf[ZAPC_NODE_ENC_SIZE + WA_NOISE_TAG_LEN + 8];
} wa_client;

/* Initialise (loads or creates the device identity). */
int wa_client_init(wa_client *c, const zapc_config *cfg, const wa_events *ev);
void wa_client_free(wa_client *c);

int wa_client_connect(wa_client *c);
void wa_client_disconnect(wa_client *c);
/* Forget the session (unlink device). */
int wa_client_logout(wa_client *c);

int wa_client_fd(const wa_client *c);
/* Process incoming data. Returns -1 when the connection was lost. */
int wa_client_on_readable(wa_client *c);
/* Timers: keepalive, reconnect, QR rotation. */
void wa_client_tick(wa_client *c);
/* Milliseconds until the next timer (or -1 for none). */
int wa_client_next_timeout(const wa_client *c);

/* ---- sending ------------------------------------------------------------ */
int wa_send_node(wa_client *c, const wa_node *n);
/* Send an iq; id_out receives the generated id. */
int wa_send_iq(wa_client *c, wa_node *iq, wa_iq_kind kind, int slot,
               char *id_out, size_t id_cap);
void wa_new_request_id(wa_client *c, char *out, size_t cap);
void wa_new_message_id(wa_client *c, char *out, size_t cap);

/* Send a text message (async; progress reported via on_receipt "sent"). */
int wa_send_text(wa_client *c, const wa_jid *to, const char *text,
                 char *id_out, size_t id_cap);
/* Mark messages as read. */
int wa_mark_read(wa_client *c, const wa_jid *chat, const wa_jid *sender,
                 const char *msg_id);

/* ---- internal (shared between client.c, pairing.c and message.c) -------- */
void wa_handle_pair_device(wa_client *c, const wa_node *iq);
void wa_handle_pair_success(wa_client *c, const wa_node *iq);
void wa_handle_message(wa_client *c, const wa_node *node);
void wa_handle_receipt(wa_client *c, const wa_node *node);
void wa_handle_iq_result(wa_client *c, const wa_node *node,
                         const wa_pending_iq *req);
void wa_send_ack(wa_client *c, const wa_node *node, const char *error_code);
void wa_upload_prekeys(wa_client *c, unsigned count);
void wa_message_job_abort(wa_client *c, const char *why);
void wa_message_job_timeout(wa_client *c);

#endif
