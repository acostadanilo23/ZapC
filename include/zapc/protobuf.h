/*
 * ZapC - minimal protobuf wire-format reader and writer.
 *
 * No schema compiler: callers iterate over fields and pick what they need.
 * Fields are returned as views into the input buffer (no copies), and all
 * varints and lengths are validated.
 */
#ifndef ZAPC_PROTOBUF_H
#define ZAPC_PROTOBUF_H

#include "zapc/util.h"

#include <stddef.h>
#include <stdint.h>

enum {
    PB_VARINT = 0,
    PB_FIXED64 = 1,
    PB_LEN = 2,
    PB_FIXED32 = 5
};

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} pb_reader;

typedef struct {
    uint32_t num;
    uint8_t wire;
    uint64_t u64;        /* VARINT, FIXED32, FIXED64 */
    const uint8_t *data; /* LEN                       */
    size_t len;
} pb_field;

void pb_reader_init(pb_reader *r, const void *data, size_t len);
/* Returns 1 when a field was read, 0 at the end, -1 on malformed input. */
int pb_next(pb_reader *r, pb_field *f);

/*
 * Find the first field `num` with wire type LEN.  Returns 1 when found,
 * 0 when absent, -1 on malformed input.
 */
int pb_find_bytes(const void *msg, size_t len, uint32_t num,
                  const uint8_t **data, size_t *dlen);
int pb_find_varint(const void *msg, size_t len, uint32_t num, uint64_t *v);

/* ---- writer (into a zbuf) ---------------------------------------------- */
void pb_put_varint_raw(zbuf *b, uint64_t v);
void pb_put_uint(zbuf *b, uint32_t num, uint64_t v);
void pb_put_bool(zbuf *b, uint32_t num, int v);
void pb_put_bytes(zbuf *b, uint32_t num, const void *data, size_t len);
void pb_put_string(zbuf *b, uint32_t num, const char *s);
void pb_put_fixed32(zbuf *b, uint32_t num, uint32_t v);
void pb_put_fixed64(zbuf *b, uint32_t num, uint64_t v);

/*
 * Nested messages: pb_begin() writes the tag and reserves one length byte,
 * pb_end() patches the length (shifting the body if it needs more bytes).
 */
size_t pb_begin(zbuf *b, uint32_t num);
void pb_end(zbuf *b, size_t mark);

/* ---- streaming walker ---------------------------------------------------- */
/*
 * Parses a protobuf stream fed in arbitrary chunks without holding it in
 * memory.  For every length-delimited field the callback decides whether to
 * skip it, descend into it as a sub-message, or buffer it whole (up to the
 * walker's buffer size; larger fields are skipped).
 */
#define PBW_MAX_DEPTH 8

typedef enum { PBW_SKIP = 0, PBW_DESCEND, PBW_BUFFER } pbw_action;

typedef struct pb_walker pb_walker;

struct pb_walker {
    /* callbacks */
    pbw_action (*on_len)(pb_walker *w, uint32_t field, uint64_t len);
    void (*on_varint)(pb_walker *w, uint32_t field, uint64_t value);
    void (*on_bytes)(pb_walker *w, uint32_t field, const uint8_t *data,
                     size_t len);
    void (*on_end)(pb_walker *w, uint32_t field); /* end of descended msg */
    void *user;

    /* current position */
    int depth;                          /* 0 = top level            */
    uint32_t path[PBW_MAX_DEPTH + 1];   /* field numbers of levels  */
    uint64_t end[PBW_MAX_DEPTH + 1];    /* absolute end offsets     */
    uint64_t pos;

    /* field parser */
    int state;
    uint64_t acc;
    unsigned shift;
    uint32_t field;
    int wire;
    uint64_t need;
    int error;

    uint8_t *buf;
    size_t buf_cap;
    size_t buf_len;
};

void pbw_init(pb_walker *w, uint8_t *buf, size_t cap);
/* Returns 0, or -1 once the stream is malformed. */
int pbw_feed(pb_walker *w, const uint8_t *data, size_t len);
/* Returns 0 if the stream ended on a field boundary at the top level. */
int pbw_finish(pb_walker *w);

#endif
