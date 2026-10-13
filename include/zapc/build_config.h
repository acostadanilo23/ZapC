/*
 * ZapC - compile-time limits.
 *
 * Every buffer and cache in ZapC has an explicit, fixed upper bound that is
 * defined here.  All values can be overridden from the compiler command line,
 * e.g. `make CFLAGS_EXTRA=-DZAPC_NET_RX_SIZE=8192`.
 *
 * The defaults are chosen so that the whole client stays well below 10 MB of
 * RSS on a 32-bit machine with ~32 MB of RAM (the PlayStation 2 target).
 */
#ifndef ZAPC_BUILD_CONFIG_H
#define ZAPC_BUILD_CONFIG_H

/* ---- terminal ---------------------------------------------------------- */
#ifndef ZAPC_INPUT_SIZE
#define ZAPC_INPUT_SIZE 2048            /* line editor buffer               */
#endif
#ifndef ZAPC_TERM_OUT_SIZE
#define ZAPC_TERM_OUT_SIZE 8192         /* batched terminal output          */
#endif

/* ---- network ----------------------------------------------------------- */
#ifndef ZAPC_NET_RX_SIZE
#define ZAPC_NET_RX_SIZE 16384          /* TLS/WebSocket receive chunk      */
#endif
#ifndef ZAPC_NET_TX_SIZE
#define ZAPC_NET_TX_SIZE 16384          /* WebSocket transmit chunk         */
#endif
#ifndef ZAPC_WS_HANDSHAKE_SIZE
#define ZAPC_WS_HANDSHAKE_SIZE 4096     /* HTTP upgrade response            */
#endif
#ifndef ZAPC_WS_MAX_MESSAGE
#define ZAPC_WS_MAX_MESSAGE (1u << 24)  /* sanity limit for one WS message  */
#endif

/* ---- WhatsApp framing -------------------------------------------------- */
/*
 * Largest single noise frame ZapC is willing to hold in memory.  Larger
 * frames are drained from the socket without being stored and are dropped.
 */
#ifndef ZAPC_WA_FRAME_MAX
#define ZAPC_WA_FRAME_MAX (256u * 1024u)
#endif
/* Scratch space for decoded binary-node structures and unpacked strings. */
#ifndef ZAPC_NODE_ARENA_SIZE
#define ZAPC_NODE_ARENA_SIZE (64u * 1024u)
#endif
#ifndef ZAPC_NODE_MAX_DEPTH
#define ZAPC_NODE_MAX_DEPTH 16
#endif
#ifndef ZAPC_NODE_ENC_SIZE
#define ZAPC_NODE_ENC_SIZE (64u * 1024u) /* outgoing encoded node buffer   */
#endif
#ifndef ZAPC_PROTOBUF_SCRATCH
#define ZAPC_PROTOBUF_SCRATCH 16384
#endif
/* Largest decrypted message plaintext (messages may carry thumbnails). */
#ifndef ZAPC_MSG_PLAIN_MAX
#define ZAPC_MSG_PLAIN_MAX (64u * 1024u)
#endif
/* Decompression output limit for zlib-compressed frames. */
#ifndef ZAPC_INFLATE_MAX
#define ZAPC_INFLATE_MAX (256u * 1024u)
#endif

/* ---- application caches ------------------------------------------------ */
#ifndef ZAPC_VISIBLE_MESSAGES
#define ZAPC_VISIBLE_MESSAGES 64
#endif
#ifndef ZAPC_MAX_CONTACTS
#define ZAPC_MAX_CONTACTS 128
#endif
#ifndef ZAPC_MAX_CHATS
#define ZAPC_MAX_CHATS 64
#endif
#ifndef ZAPC_MSG_TEXT_MAX
#define ZAPC_MSG_TEXT_MAX 1024          /* bytes of text kept per message   */
#endif
#ifndef ZAPC_NAME_MAX
#define ZAPC_NAME_MAX 64
#endif
#ifndef ZAPC_LOG_RING
#define ZAPC_LOG_RING 32                /* lines kept for /debug            */
#endif

/* ---- Signal ------------------------------------------------------------ */
#ifndef ZAPC_MAX_SESSIONS
#define ZAPC_MAX_SESSIONS 32            /* Signal sessions cached in RAM    */
#endif
#ifndef ZAPC_MAX_SENDER_KEYS
#define ZAPC_MAX_SENDER_KEYS 16
#endif
#ifndef ZAPC_PREKEY_BATCH
#define ZAPC_PREKEY_BATCH 30            /* one-time prekeys per upload      */
#endif

/* ---- paths ------------------------------------------------------------- */
#ifndef ZAPC_PATH_MAX
#define ZAPC_PATH_MAX 512
#endif

#endif /* ZAPC_BUILD_CONFIG_H */
