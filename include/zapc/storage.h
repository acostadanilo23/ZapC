/*
 * ZapC - persistent storage in simple binary files.
 *
 *   <state>/credentials.bin     device keys + pairing data (0600)
 *   <state>/prekeys.bin         one-time prekeys (0600)
 *   <state>/sessions/<addr>     Signal sessions (0600)
 *   <state>/identities/<addr>   remote identity keys
 *   <state>/senderkeys/<grp>_<addr>
 *   <state>/chats.bin           chat list
 *   <state>/contacts.bin        contact names
 *   <state>/messages/<chat>.log append-only message history
 *
 * The directory is created with mode 0700.  Nothing is kept in RAM by this
 * module: records are read and written on demand.
 */
#ifndef ZAPC_STORAGE_H
#define ZAPC_STORAGE_H

#include "zapc/build_config.h"
#include "zapc/keys.h"

#include <stddef.h>
#include <stdint.h>

int storage_init(const char *state_dir);
const char *storage_dir(void);
/* Build "<state>/<rel>" into out. */
int storage_path(char *out, size_t cap, const char *rel);

/* ---- credentials -------------------------------------------------------- */
/* 0 = loaded, 1 = no credentials yet, -1 = error/corrupt. */
int credentials_load(wa_device *dev);
int credentials_save(const wa_device *dev);
/* Remove credentials and all Signal state (logout). */
int credentials_delete(void);

/* ---- generic small blobs keyed by name (Signal sessions etc.) ----------- */
/* kind is a subdirectory ("sessions", "identities", "senderkeys"). */
long storage_blob_load(const char *kind, const char *name, void *buf,
                       size_t cap);
int storage_blob_save(const char *kind, const char *name, const void *data,
                      size_t len);
int storage_blob_delete(const char *kind, const char *name);

/* ---- one-time prekeys --------------------------------------------------- */
int prekeys_append(uint32_t id, const uint8_t priv[32]);
/* Find (and optionally delete) a prekey's private key. 0 = found. */
int prekeys_find(uint32_t id, uint8_t priv[32]);
int prekeys_remove(uint32_t id);
long prekeys_count(void);

#endif
