#include "zapc/frame.h"
#include "zapc/log.h"

#include <string.h>

void wa_framer_init(wa_framer *f, uint8_t *buf, size_t cap, wa_frame_fn cb,
                    void *user)
{
    memset(f, 0, sizeof *f);
    f->buf = buf;
    f->cap = cap;
    f->cb = cb;
    f->user = user;
}

void wa_framer_reset(wa_framer *f)
{
    f->len_have = 0;
    f->frame_len = 0;
    f->frame_have = 0;
    f->dropping = 0;
}

int wa_framer_feed(wa_framer *f, const uint8_t *data, size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        if (f->len_have < WA_FRAME_LEN_SIZE) {
            f->len_buf[f->len_have++] = data[pos++];
            if (f->len_have == WA_FRAME_LEN_SIZE) {
                f->frame_len = ((size_t)f->len_buf[0] << 16) |
                               ((size_t)f->len_buf[1] << 8) | f->len_buf[2];
                f->frame_have = 0;
                f->dropping = f->frame_len > f->cap;
                if (f->dropping) {
                    LOGW("frame", "dropping %zu-byte frame (limit %zu)",
                         f->frame_len, f->cap);
                    f->dropped++;
                }
                if (f->frame_len == 0) {
                    f->len_have = 0;
                    if (f->cb(f->user, f->buf, 0) != 0)
                        return -1;
                }
            }
            continue;
        }
        size_t need = f->frame_len - f->frame_have;
        size_t take = len - pos < need ? len - pos : need;
        if (!f->dropping)
            memcpy(f->buf + f->frame_have, data + pos, take);
        f->frame_have += take;
        pos += take;
        if (f->frame_have == f->frame_len) {
            int dropped = f->dropping;
            size_t flen = f->frame_len;
            wa_framer_reset(f);
            /*
             * A dropped frame still consumed a noise counter on the sender
             * side; report it with a NULL buffer so the caller can keep its
             * counters in sync.
             */
            if (f->cb(f->user, dropped ? NULL : f->buf, flen) != 0)
                return -1;
        }
    }
    return 0;
}
