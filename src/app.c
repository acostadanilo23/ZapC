/*
 * ZapC - application layer.
 *
 * Single-threaded event loop over poll(): terminal input, the WhatsApp
 * socket and timers.  The UI is redrawn only when something changed.
 */
#include "zapc/app.h"
#include "zapc/history.h"
#include "zapc/log.h"
#include "zapc/memory.h"
#include "zapc/platform.h"
#include "zapc/qr.h"
#include "zapc/storage.h"
#include "zapc/terminal.h"
#include "zapc/util.h"
#include "zapc/wa.h"

#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONSOLE_LINES 160
#define CONSOLE_LINE_MAX 256
#define MAX_DISPLAY_LINES 2048

typedef enum { MS_NONE = 0, MS_PENDING, MS_SENT, MS_DELIVERED, MS_READ, MS_ERROR } msg_status;

typedef struct {
    zapc_config cfg;
    app_options opt;
    int quit;
    int dirty;

    chat_list chats;
    contact_list contacts;

    /* open chat */
    int chat_open;
    wa_jid chat;
    wa_message msgs[ZAPC_VISIBLE_MESSAGES];
    msg_status status[ZAPC_VISIBLE_MESSAGES];
    int msg_count;
    long msg_first; /* history index of msgs[0] */
    long msg_total;
    int scroll;     /* display lines scrolled up from the bottom */

    /* console view */
    char console[CONSOLE_LINES][CONSOLE_LINE_MAX];
    int console_head;
    int console_count;

    int show_qr;
    char status_line[160];
    char notice[200];
    uint64_t notice_until;

    term_line input;
    uint64_t last_save;
} app_state;

static app_state g_app;
static wa_client g_wa;
static qr_code g_qr;

static void app_printf(const char *fmt, ...) ZAPC_PRINTF(1, 2);

/* ======================================================================== */
/* console                                                                  */
/* ======================================================================== */

static void console_add(const char *s)
{
    app_state *a = &g_app;
    if (!term_is_interactive()) {
        term_puts(s);
        term_puts("\n");
        term_flush();
        return;
    }
    char *dst = a->console[a->console_head];
    zstrlcpy(dst, s, CONSOLE_LINE_MAX);
    a->console_head = (a->console_head + 1) % CONSOLE_LINES;
    if (a->console_count < CONSOLE_LINES)
        a->console_count++;
    a->dirty = 1;
}

static void app_printf(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    /* split on newlines */
    char *p = buf;
    for (;;) {
        char *nl = strchr(p, '\n');
        if (nl != NULL)
            *nl = '\0';
        console_add(p);
        if (nl == NULL)
            break;
        p = nl + 1;
    }
}

static void notice(const char *fmt, ...) ZAPC_PRINTF(1, 2);
static void notice(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_app.notice, sizeof g_app.notice, fmt, ap);
    va_end(ap);
    g_app.notice_until = plat_now_ms() + 6000;
    g_app.dirty = 1;
    if (!term_is_interactive())
        app_printf("* %s", g_app.notice);
}

static void log_sink(void *user, log_level lvl, const char *line)
{
    (void)user;
    if (lvl <= LOG_WARN && term_is_interactive()) {
        /* skip the "LEVEL module " prefix */
        const char *msg = line;
        for (int sp = 0; sp < 2 && msg != NULL; sp++) {
            msg = strchr(msg, ' ');
            while (msg != NULL && *msg == ' ')
                msg++;
        }
        snprintf(g_app.notice, sizeof g_app.notice, "%s: %s",
                 lvl == LOG_ERROR ? "erro" : "aviso", msg ? msg : line);
        g_app.notice_until = plat_now_ms() + 8000;
        g_app.dirty = 1;
    }
}

/* ======================================================================== */
/* names                                                                    */
/* ======================================================================== */

static const char *display_name(const wa_jid *jid, char *buf, size_t cap)
{
    chat_entry *ce = chats_find(&g_app.chats, jid);
    if (ce != NULL && ce->name[0] != '\0')
        return ce->name;
    const char *n = contacts_get(&g_app.contacts, jid);
    if (n != NULL && n[0] != '\0')
        return n;
    if (jid->user[0] != '\0') {
        if (strcmp(jid->server, WA_SERVER_USER) == 0)
            snprintf(buf, cap, "+%s", jid->user);
        else
            snprintf(buf, cap, "%s", jid->user);
    } else {
        snprintf(buf, cap, "%s", jid->server);
    }
    return buf;
}

static const char *sender_name(const wa_message *m, char *buf, size_t cap)
{
    if (m->from_me)
        return "Voc\xc3\xaa";
    const char *n = contacts_get(&g_app.contacts, &m->sender);
    if (n != NULL)
        return n;
    if (m->push_name[0] != '\0')
        return m->push_name;
    return display_name(&m->sender, buf, cap);
}

/* ======================================================================== */
/* rendering                                                                */
/* ======================================================================== */

typedef struct {
    int msg;       /* -1 for blank */
    int header;    /* 1 = "HH:MM Name" line */
    size_t off;
    size_t len;
} disp_line;

static disp_line g_lines[MAX_DISPLAY_LINES];

static const char *status_mark(msg_status s)
{
    int ascii = g_app.cfg.ascii;
    switch (s) {
    case MS_PENDING: return ascii ? " ..." : " \xe2\x80\xa6";
    case MS_SENT: return ascii ? " *" : " \xe2\x9c\x93";
    case MS_DELIVERED: return ascii ? " **" : " \xe2\x9c\x93\xe2\x9c\x93";
    case MS_READ: return ascii ? " R" : " \xe2\x9c\x93\xe2\x9c\x93";
    case MS_ERROR: return " !";
    default: return "";
    }
}

/* Wrap message texts into display lines for a given width. */
static int layout_messages(int width)
{
    app_state *a = &g_app;
    int n = 0;
    for (int i = 0; i < a->msg_count && n < MAX_DISPLAY_LINES - 2; i++) {
        const char *t = a->msgs[i].text;
        size_t len = strlen(t);
        g_lines[n++] = (disp_line){i, 1, 0, 0};
        size_t pos = 0;
        while (pos < len && n < MAX_DISPLAY_LINES - 1) {
            const char *nl = memchr(t + pos, '\n', len - pos);
            size_t seg_end = nl ? (size_t)(nl - t) : len;
            size_t seg = seg_end - pos;
            size_t fit = utf8_fit(t + pos, seg, (size_t)width);
            if (fit == 0 && seg > 0)
                fit = utf8_seq_len((unsigned char)t[pos]);
            if (fit < seg) {
                /* break at the last space inside the fitting part */
                size_t sp = fit;
                while (sp > 0 && t[pos + sp - 1] != ' ')
                    sp--;
                if (sp > 0)
                    fit = sp;
            }
            g_lines[n++] = (disp_line){i, 0, pos, fit};
            pos += fit;
            if (pos == seg_end && nl != NULL)
                pos++; /* skip newline */
            else
                while (pos < len && t[pos] == ' ' && pos < seg_end)
                    pos++;
        }
        if (len == 0)
            g_lines[n++] = (disp_line){i, 0, 0, 0};
        g_lines[n++] = (disp_line){-1, 0, 0, 0};
    }
    return n;
}

static void draw_hline(int row, int cols, const char *l, const char *m,
                       const char *r)
{
    term_move(row, 1);
    term_puts(l);
    for (int i = 0; i < cols - 2; i++)
        term_puts(m);
    term_puts(r);
}

/* Print text clipped/padded to exactly `width` columns. */
static void put_cell(const char *s, size_t n, int width)
{
    size_t fit = utf8_fit(s, n, (size_t)width);
    term_write(s, fit);
    size_t w = utf8_width(s, fit);
    for (size_t i = w; i < (size_t)width; i++)
        term_write(" ", 1);
}

static void render(void)
{
    app_state *a = &g_app;
    int cols, rows;
    term_size(&cols, &rows);
    if (cols < 20 || rows < 8) {
        term_clear();
        term_puts("terminal muito pequeno");
        term_flush();
        return;
    }
    const char *V = a->cfg.ascii ? "|" : "\xe2\x94\x82";
    const char *H = a->cfg.ascii ? "-" : "\xe2\x94\x80";
    int inner = cols - 4; /* "│ " + text + " │" */

    term_cursor(0);
    /* top border and title */
    draw_hline(1, cols, a->cfg.ascii ? "+" : "\xe2\x94\x8c", H,
               a->cfg.ascii ? "+" : "\xe2\x94\x90");
    term_move(2, 1);
    term_puts(V);
    term_puts(" ");
    char title[256];
    const char *st = wa_state_name(g_wa.state);
    if (a->notice[0] != '\0' && plat_now_ms() < a->notice_until)
        snprintf(title, sizeof title, "ZapC  %.200s", a->notice);
    else
        snprintf(title, sizeof title, "ZapC  [%s]", st);
    term_attr_set(ATTR_BOLD);
    put_cell(title, strlen(title), inner);
    term_attr_set(ATTR_RESET);
    term_puts(" ");
    term_puts(V);
    draw_hline(3, cols, a->cfg.ascii ? "+" : "\xe2\x94\x9c", H,
               a->cfg.ascii ? "+" : "\xe2\x94\xa4");

    int top = 4;
    int bottom = rows - 3; /* last content row */
    int height = bottom - top + 1;

    if (a->chat_open) {
        char nb[80];
        const char *name = display_name(&a->chat, nb, sizeof nb);
        term_move(top, 1);
        term_puts(V);
        term_puts(" ");
        term_attr_set(ATTR_CYAN);
        put_cell(name, strlen(name), inner);
        term_attr_set(ATTR_RESET);
        term_puts(" ");
        term_puts(V);
        top++;
        height--;
        int nl = layout_messages(inner);
        int max_scroll = nl > height ? nl - height : 0;
        if (a->scroll > max_scroll)
            a->scroll = max_scroll;
        int first = nl - height - a->scroll;
        for (int r = 0; r < height; r++) {
            int li = first + r;
            term_move(top + r, 1);
            term_puts(V);
            term_puts(" ");
            if (li < 0 || li >= nl || g_lines[li].msg < 0) {
                put_cell("", 0, inner);
            } else {
                const disp_line *d = &g_lines[li];
                const wa_message *m = &a->msgs[d->msg];
                if (d->header) {
                    char hh[8], nb2[80], hdr[200];
                    plat_format_hhmm(m->timestamp, hh, sizeof hh);
                    snprintf(hdr, sizeof hdr, "%s %s%s", hh,
                             sender_name(m, nb2, sizeof nb2),
                             m->from_me ? status_mark(a->status[d->msg]) : "");
                    term_attr_set(m->from_me ? ATTR_GREEN : ATTR_BOLD);
                    put_cell(hdr, strlen(hdr), inner);
                    term_attr_set(ATTR_RESET);
                } else {
                    put_cell(m->text + d->off, d->len, inner);
                }
            }
            term_puts(" ");
            term_puts(V);
        }
    } else if (a->show_qr) {
        int qrows = (g_qr.size + 4 + 1) / 2;
        int y0 = top + (height > qrows ? (height - qrows) / 2 : 0);
        for (int r = top; r <= bottom; r++) {
            term_move(r, 1);
            term_puts(V);
            term_move(r, cols);
            term_puts(V);
            if (r < y0) {
                term_move(r, 3);
                put_cell("", 0, inner);
            }
        }
        /* render QR rows directly */
        int row = y0;
        int lo = -2, hi = g_qr.size + 2;
        int qcols = hi - lo;
        int x0 = 3 + (inner > qcols ? (inner - qcols) / 2 : 0);
        for (int y = lo; y < hi && row <= bottom; y += 2, row++) {
            term_move(row, 3);
            put_cell("", 0, inner);
            term_move(row, x0);
            for (int x = lo; x < hi && x - lo < inner; x++) {
                int t1 = !qr_module(&g_qr, x, y);
                int t2 = (y + 1 < hi) ? !qr_module(&g_qr, x, y + 1) : 0;
                term_puts(t1 && t2 ? "\xe2\x96\x88"
                          : t1     ? "\xe2\x96\x80"
                          : t2     ? "\xe2\x96\x84"
                                   : " ");
            }
        }
        for (; row <= bottom; row++) {
            term_move(row, 3);
            put_cell("", 0, inner);
        }
    } else {
        int n = a->console_count;
        int first = n > height ? n - height : 0;
        for (int r = 0; r < height; r++) {
            term_move(top + r, 1);
            term_puts(V);
            term_puts(" ");
            int li = first + r;
            if (li < n) {
                int idx = (a->console_head - n + li + CONSOLE_LINES) % CONSOLE_LINES;
                put_cell(a->console[idx], strlen(a->console[idx]), inner);
            } else {
                put_cell("", 0, inner);
            }
            term_puts(" ");
            term_puts(V);
        }
    }

    /* input */
    draw_hline(rows - 2, cols, a->cfg.ascii ? "+" : "\xe2\x94\x9c", H,
               a->cfg.ascii ? "+" : "\xe2\x94\xa4");
    term_move(rows - 1, 1);
    term_puts(V);
    term_puts(" > ");
    int iw = inner - 2;
    /* keep the cursor visible: show the tail when the line is long */
    size_t cw = utf8_width(a->input.buf, a->input.cursor);
    size_t start = 0;
    while (cw - utf8_width(a->input.buf, start) >= (size_t)iw && start < a->input.cursor)
        start += utf8_seq_len((unsigned char)a->input.buf[start]);
    put_cell(a->input.buf + start, a->input.len - start, iw);
    term_puts(" ");
    term_puts(V);
    draw_hline(rows, cols, a->cfg.ascii ? "+" : "\xe2\x94\x94", H,
               a->cfg.ascii ? "+" : "\xe2\x94\x98");
    int ccol = 5 + (int)(cw - utf8_width(a->input.buf, start));
    term_move(rows - 1, ccol);
    term_cursor(1);
    term_flush();
    a->dirty = 0;
}

/* ======================================================================== */
/* chat window                                                              */
/* ======================================================================== */

static void send_read_receipts(void)
{
    app_state *a = &g_app;
    chat_entry *ce = chats_find(&a->chats, &a->chat);
    if (ce == NULL || ce->unread == 0)
        return;
    int n = (int)ce->unread;
    for (int i = a->msg_count - 1; i >= 0 && n > 0; i--, n--) {
        const wa_message *m = &a->msgs[i];
        if (!m->from_me && g_wa.state == WA_ST_LOGGED_IN)
            wa_mark_read(&g_wa, &a->chat, &m->sender, m->id);
    }
    ce->unread = 0;
    a->chats.dirty = 1;
}

static void load_window(long end)
{
    app_state *a = &g_app;
    int max = (int)a->cfg.history_cache;
    if (max > ZAPC_VISIBLE_MESSAGES)
        max = ZAPC_VISIBLE_MESSAGES;
    a->msg_total = history_count(&a->chat);
    a->msg_count = history_load(&a->chat, end, a->msgs, max, &a->msg_first);
    for (int i = 0; i < a->msg_count; i++)
        a->status[i] = a->msgs[i].from_me ? MS_SENT : MS_NONE;
}

static void open_chat(const wa_jid *jid)
{
    app_state *a = &g_app;
    jid_to_non_ad(&a->chat, jid);
    a->chat_open = 1;
    a->scroll = 0;
    a->show_qr = 0;
    load_window(-1);
    send_read_receipts();
    a->dirty = 1;
}

static void close_chat(void)
{
    g_app.chat_open = 0;
    g_app.msg_count = 0;
    g_app.dirty = 1;
}

static void scroll_by(int delta)
{
    app_state *a = &g_app;
    if (!a->chat_open)
        return;
    int cols, rows;
    term_size(&cols, &rows);
    int height = rows - 7;
    int nl = layout_messages(cols - 4);
    int max_scroll = nl > height ? nl - height : 0;
    a->scroll += delta;
    long end = a->msg_first + a->msg_count;
    if (a->scroll > max_scroll && a->msg_first > 0) {
        /* load the previous block, dropping the newest half */
        long new_end = end - a->msg_count / 2;
        if (new_end < 1)
            new_end = 1;
        load_window(new_end);
        a->scroll = 0;
        nl = layout_messages(cols - 4);
        a->scroll = nl > height ? nl - height : 0;
    } else if (a->scroll < 0) {
        if (end < a->msg_total) {
            load_window(end + a->msg_count / 2);
            nl = layout_messages(cols - 4);
            a->scroll = nl / 3;
        } else {
            a->scroll = 0;
        }
    }
    a->dirty = 1;
}

static int visible_append(const wa_message *m, msg_status st)
{
    app_state *a = &g_app;
    long end = a->msg_first + a->msg_count;
    a->msg_total++;
    if (end + 1 < a->msg_total)
        return -1; /* viewing older history */
    if (a->msg_count == ZAPC_VISIBLE_MESSAGES) {
        memmove(&a->msgs[0], &a->msgs[1], (ZAPC_VISIBLE_MESSAGES - 1) * sizeof a->msgs[0]);
        memmove(&a->status[0], &a->status[1],
                (ZAPC_VISIBLE_MESSAGES - 1) * sizeof a->status[0]);
        a->msg_count--;
        a->msg_first++;
    }
    a->msgs[a->msg_count] = *m;
    a->status[a->msg_count] = st;
    a->msg_count++;
    a->dirty = 1;
    return a->msg_count - 1;
}

static void record_message(const wa_message *m, msg_status st)
{
    app_state *a = &g_app;
    history_append(m);
    chat_entry *ce = chats_touch(&a->chats, &m->chat);
    ce->last_ts = m->timestamp;
    zstrlcpyn(ce->preview, m->text, utf8_fit(m->text, strlen(m->text), 40),
              sizeof ce->preview);
    for (char *p = ce->preview; *p; p++)
        if (*p == '\n')
            *p = ' ';
    if (jid_is_group(&m->chat) && ce->name[0] == '\0' && !ce->name_requested &&
        g_wa.state == WA_ST_LOGGED_IN) {
        ce->name_requested = 1;
        wa_request_group_info(&g_wa, &m->chat);
    }
    int in_open = a->chat_open && jid_same_user(&a->chat, &m->chat);
    if (!m->from_me && !in_open)
        ce->unread++;
    a->chats.dirty = 1;
    if (!m->from_me && m->push_name[0] != '\0' && !jid_is_group(&m->sender))
        contacts_set(&a->contacts, &m->sender, m->push_name);
    if (in_open) {
        visible_append(m, st);
        if (!m->from_me && g_wa.state == WA_ST_LOGGED_IN)
            wa_mark_read(&g_wa, &a->chat, &m->sender, m->id);
    }
}

/* ======================================================================== */
/* WhatsApp events                                                          */
/* ======================================================================== */

static void ev_state(void *user, wa_state st, const char *detail)
{
    (void)user;
    switch (st) {
    case WA_ST_CONNECTING:
        app_printf("Conectando%s%s...", detail ? " a " : "", detail ? detail : "");
        break;
    case WA_ST_PAIRING:
        app_printf("Conectado. Aguardando vincula\xc3\xa7\xc3\xa3o...");
        break;
    case WA_ST_LOGGED_IN:
        g_app.show_qr = 0;
        app_printf("Conectado.");
        notice("conectado");
        break;
    case WA_ST_DISCONNECTED:
        app_printf("Desconectado%s%s.", detail ? ": " : "", detail ? detail : "");
        break;
    default:
        break;
    }
    g_app.dirty = 1;
}

static void emit_qr_line(void *user, const char *line)
{
    (void)user;
    term_puts(line);
    term_puts("\n");
}

static void ev_qr(void *user, const char *payload)
{
    (void)user;
    if (qr_encode(&g_qr, (const uint8_t *)payload, strlen(payload), QR_ECC_LOW,
                  1, -1) != 0) {
        LOGE("app", "QR payload too long (%zu bytes)", strlen(payload));
        return;
    }
    if (term_is_interactive()) {
        g_app.show_qr = !g_app.chat_open;
        notice("escaneie o QR: WhatsApp > Aparelhos conectados > Conectar");
    } else {
        app_printf("Escaneie com o WhatsApp (Aparelhos conectados > Conectar aparelho):");
        qr_render(&g_qr, !g_app.cfg.ascii, 0, 2, emit_qr_line, NULL);
        term_flush();
    }
    g_app.dirty = 1;
}

static void ev_paired(void *user, const wa_jid *jid, const char *platform)
{
    (void)user;
    char s[WA_JID_STR_MAX];
    jid_format(jid, s, sizeof s);
    g_app.show_qr = 0;
    app_printf("Vinculado como %s (%s). Reconectando...", s, platform);
    g_app.dirty = 1;
}

static void ev_logged_out(void *user, const char *reason)
{
    (void)user;
    app_printf("Sess\xc3\xa3o encerrada: %s. Use /connect para vincular de novo.",
               reason);
    g_app.show_qr = 0;
}

static void ev_message(void *user, const wa_message *m)
{
    (void)user;
    record_message(m, m->from_me ? MS_SENT : MS_NONE);
    if (!term_is_interactive()) {
        char hh[8], nb[80], cb[80];
        plat_format_hhmm(m->timestamp, hh, sizeof hh);
        const char *chat = display_name(&m->chat, cb, sizeof cb);
        const char *who = sender_name(m, nb, sizeof nb);
        if (jid_is_group(&m->chat) || m->from_me)
            app_printf("[%s] %s / %s: %s", hh, chat, who, m->text);
        else
            app_printf("[%s] %s: %s", hh, who, m->text);
    } else if (!(g_app.chat_open && jid_same_user(&g_app.chat, &m->chat)) &&
               !m->from_me) {
        char nb[80];
        notice("nova mensagem de %s", display_name(&m->chat, nb, sizeof nb));
    }
}

static void ev_receipt(void *user, const wa_jid *chat, const char *id,
                       const char *type)
{
    (void)user;
    (void)chat;
    app_state *a = &g_app;
    msg_status st = strcmp(type, "sent") == 0        ? MS_SENT
                    : strcmp(type, "delivered") == 0 ? MS_DELIVERED
                    : strcmp(type, "error") == 0     ? MS_ERROR
                                                     : MS_READ;
    for (int i = a->msg_count - 1; i >= 0; i--) {
        if (a->msgs[i].from_me && strcmp(a->msgs[i].id, id) == 0) {
            if (st > a->status[i] || st == MS_ERROR)
                a->status[i] = st;
            a->dirty = 1;
            break;
        }
    }
    if (st == MS_ERROR)
        notice("falha ao enviar mensagem");
}

static void ev_chat_name(void *user, const wa_jid *chat, const char *name)
{
    (void)user;
    chat_entry *ce = chats_touch(&g_app.chats, chat);
    zstrlcpy(ce->name, name, sizeof ce->name);
    g_app.chats.dirty = 1;
    g_app.dirty = 1;
}

static void ev_history_chat(void *user, const wa_jid *chat, const char *name,
                            int64_t last_ts, unsigned unread,
                            const wa_message *msgs, int nmsgs)
{
    (void)user;
    app_state *a = &g_app;
    chat_entry *ce = chats_touch(&a->chats, chat);
    int64_t watermark = ce->last_ts; /* messages up to here are logged */
    if (name != NULL && name[0] != '\0' && ce->name[0] == '\0')
        zstrlcpy(ce->name, name, sizeof ce->name);
    int appended = 0;
    for (int i = 0; i < nmsgs; i++) {
        const wa_message *m = &msgs[i];
        if (m->timestamp <= watermark)
            continue;
        history_append(m);
        appended++;
        zstrlcpyn(ce->preview, m->text, utf8_fit(m->text, strlen(m->text), 40),
                  sizeof ce->preview);
        for (char *p = ce->preview; *p; p++)
            if (*p == '\n')
                *p = ' ';
        if (!m->from_me && m->push_name[0] != '\0' && !jid_is_group(&m->sender))
            contacts_set(&a->contacts, &m->sender, m->push_name);
    }
    if (last_ts > ce->last_ts)
        ce->last_ts = last_ts;
    int open = a->chat_open && jid_same_user(&a->chat, chat);
    if (!open && unread > ce->unread)
        ce->unread = unread;
    if (open && appended > 0)
        load_window(-1);
    a->chats.dirty = 1;
    a->dirty = 1;
}

static void ev_push_name(void *user, const wa_jid *jid, const char *name)
{
    (void)user;
    contacts_set(&g_app.contacts, jid, name);
}

static void ev_history_done(void *user, unsigned chats, unsigned messages)
{
    (void)user;
    notice("hist\xc3\xb3rico sincronizado: %u conversas, %u mensagens", chats,
           messages);
}

/* ======================================================================== */
/* commands                                                                 */
/* ======================================================================== */

static void cmd_help(void)
{
    app_printf("Comandos:");
    app_printf("  /help              esta ajuda");
    app_printf("  /connect           conectar (mostra QR se n\xc3\xa3o vinculado)");
    app_printf("  /disconnect        desconectar");
    app_printf("  /pair              vincular por QR code");
    app_printf("  /status            estado da conex\xc3\xa3o");
    app_printf("  /chats             listar conversas");
    app_printf("  /open <n|n\xc3\xbamero|jid>  abrir conversa");
    app_printf("  /send <texto>      enviar para a conversa aberta");
    app_printf("  /close             fechar a conversa");
    app_printf("  /contacts          contatos conhecidos");
    app_printf("  /mem               uso de mem\xc3\xb3ria");
    app_printf("  /debug             alternar log de depura\xc3\xa7\xc3\xa3o");
    app_printf("  /logout            desvincular este aparelho");
    app_printf("  /quit              sair");
    app_printf("Com uma conversa aberta, digite o texto e Enter para enviar.");
    app_printf("PgUp/PgDn rolam o hist\xc3\xb3rico.");
}

static void cmd_status(void)
{
    char jid[WA_JID_STR_MAX] = "-";
    if (g_wa.dev.paired)
        jid_format(&g_wa.dev.jid, jid, sizeof jid);
    app_printf("Estado: %s", wa_state_name(g_wa.state));
    app_printf("Conta: %s%s%s", jid, g_wa.dev.paired ? "  plataforma: " : "",
               g_wa.dev.paired ? g_wa.dev.platform : "");
    if (g_wa.fd >= 0)
        app_printf("TLS: %s %s", tls_version(g_wa.tls), tls_cipher(g_wa.tls));
    app_printf("Frames: %lu recebidos, %lu enviados (%lu/%lu bytes)",
               g_wa.frames_rx, g_wa.frames_tx, g_wa.bytes_rx, g_wa.bytes_tx);
    app_printf("Servidor: %s:%u%s  vers\xc3\xa3o WA %u.%u.%u", g_app.cfg.wa_host,
               (unsigned)g_app.cfg.wa_port, g_app.cfg.wa_path,
               (unsigned)g_wa.version[0], (unsigned)g_wa.version[1],
               (unsigned)g_wa.version[2]);
    app_printf("Estado salvo em: %s", storage_dir());
}

static void cmd_mem(void)
{
    plat_mem_stats st;
    zap_mem_counters mc;
    zap_mem_counters_get(&mc);
    if (plat_mem_stats_get(&st) == 0)
        app_printf("RSS: %lu KiB  pico: %lu KiB  virtual: %lu KiB  dados: %lu KiB",
                   st.rss_kb, st.peak_rss_kb, st.vm_kb, st.data_kb);
    else
        app_printf("RSS: indispon\xc3\xadvel");
    if (mc.enabled)
        app_printf("heap (zap_*): %zu blocos, %zu bytes, pico %zu bytes, %zu "
                   "aloca\xc3\xa7\xc3\xb5" "es",
                   mc.live_allocs, mc.live_bytes, mc.peak_bytes, mc.total_allocs);
    app_printf("buffers fixos: cliente %zu KiB, UI %zu KiB, QR %zu KiB",
               sizeof g_wa / 1024, sizeof g_app / 1024, sizeof g_qr / 1024);
    app_printf("arena de nodes: pico %zu de %zu bytes", g_wa.arena_peak,
               (size_t)ZAPC_NODE_ARENA_SIZE);
}

static void cmd_chats(void)
{
    chats_sort(&g_app.chats);
    if (g_app.chats.count == 0) {
        app_printf("Nenhuma conversa ainda. Mensagens recebidas aparecem aqui.");
        return;
    }
    app_printf("Conversas:");
    for (size_t i = 0; i < g_app.chats.count; i++) {
        chat_entry *e = &g_app.chats.chats[i];
        char nb[80], hh[8], unread[24] = "";
        plat_format_hhmm(e->last_ts, hh, sizeof hh);
        if (e->unread)
            snprintf(unread, sizeof unread, " (%u)", e->unread);
        app_printf("%2zu. %s%s  %s  %s", i + 1,
                   display_name(&e->jid, nb, sizeof nb), unread, hh, e->preview);
    }
}

static void cmd_contacts(void)
{
    if (g_app.contacts.count == 0) {
        app_printf("Nenhum contato conhecido ainda.");
        return;
    }
    for (size_t i = 0; i < g_app.contacts.count; i++)
        app_printf("%s@%s  %s", g_app.contacts.items[i].user,
                   g_app.contacts.items[i].server, g_app.contacts.items[i].name);
}

static int parse_target(const char *arg, wa_jid *out)
{
    char *end;
    unsigned long n = strtoul(arg, &end, 10);
    if (*end == '\0' && n >= 1 && n <= g_app.chats.count && strlen(arg) <= 3) {
        chats_sort(&g_app.chats);
        *out = g_app.chats.chats[n - 1].jid;
        return 0;
    }
    if (strchr(arg, '@') != NULL)
        return jid_parse(out, arg);
    /* phone number: keep digits only */
    char digits[32];
    size_t k = 0;
    for (const char *p = arg; *p && k < sizeof digits - 1; p++)
        if (*p >= '0' && *p <= '9')
            digits[k++] = *p;
    digits[k] = '\0';
    if (k < 6)
        return -1;
    return jid_make(out, digits, WA_SERVER_USER);
}

static void send_text(const char *text)
{
    app_state *a = &g_app;
    if (!a->chat_open) {
        notice("nenhuma conversa aberta (use /open)");
        return;
    }
    if (text[0] == '\0')
        return;
    char id[32];
    int r = wa_send_text(&g_wa, &a->chat, text, id, sizeof id);
    if (r == -2) {
        notice("aguarde o envio anterior terminar");
        return;
    }
    if (r != 0) {
        notice("n\xc3\xa3o conectado");
        return;
    }
    wa_message m;
    memset(&m, 0, sizeof m);
    zstrlcpy(m.id, id, sizeof m.id);
    m.chat = a->chat;
    m.sender = g_wa.dev.jid;
    m.sender.device = 0;
    m.from_me = 1;
    m.timestamp = plat_time_unix();
    zstrlcpy(m.text, text, sizeof m.text);
    record_message(&m, MS_PENDING);
    if (!term_is_interactive())
        app_printf("(enviando %s)", id);
}

static void handle_command(const char *line)
{
    app_state *a = &g_app;
    char cmd[32];
    const char *arg = "";
    size_t i = 0;
    while (line[i] && line[i] != ' ' && i < sizeof cmd - 1) {
        cmd[i] = line[i];
        i++;
    }
    cmd[i] = '\0';
    arg = line + i;
    while (*arg == ' ')
        arg++;

    if (strcmp(cmd, "/help") == 0 || strcmp(cmd, "/h") == 0) {
        close_chat();
        cmd_help();
    } else if (strcmp(cmd, "/quit") == 0 || strcmp(cmd, "/q") == 0) {
        a->quit = 1;
    } else if (strcmp(cmd, "/status") == 0) {
        close_chat();
        cmd_status();
    } else if (strcmp(cmd, "/connect") == 0) {
        if (g_wa.state != WA_ST_DISCONNECTED)
            notice("j\xc3\xa1 conectado (%s)", wa_state_name(g_wa.state));
        else
            wa_client_connect(&g_wa);
    } else if (strcmp(cmd, "/disconnect") == 0) {
        wa_client_disconnect(&g_wa);
    } else if (strcmp(cmd, "/pair") == 0) {
        if (g_wa.dev.paired) {
            app_printf("J\xc3\xa1 vinculado. Use /logout para desvincular.");
        } else if (g_wa.state == WA_ST_DISCONNECTED) {
            wa_client_connect(&g_wa);
        } else if (g_wa.state == WA_ST_PAIRING && g_qr.size > 0) {
            close_chat();
            a->show_qr = 1;
        } else {
            notice("aguardando QR do servidor...");
        }
    } else if (strcmp(cmd, "/chats") == 0) {
        close_chat();
        a->show_qr = 0;
        cmd_chats();
    } else if (strcmp(cmd, "/open") == 0) {
        wa_jid j;
        if (*arg == '\0' || parse_target(arg, &j) != 0)
            notice("uso: /open <n\xc3\xbamero da lista | telefone | jid>");
        else
            open_chat(&j);
    } else if (strcmp(cmd, "/close") == 0) {
        close_chat();
    } else if (strcmp(cmd, "/send") == 0) {
        send_text(arg);
    } else if (strcmp(cmd, "/contacts") == 0) {
        close_chat();
        cmd_contacts();
    } else if (strcmp(cmd, "/mem") == 0) {
        close_chat();
        cmd_mem();
    } else if (strcmp(cmd, "/debug") == 0) {
        close_chat();
        if (log_get_level() >= LOG_DEBUG) {
            log_set_level(a->cfg.log_level < LOG_DEBUG ? a->cfg.log_level : LOG_INFO);
        } else {
            log_set_level(LOG_DEBUG);
        }
        app_printf("N\xc3\xadvel de log: %s. \xc3\x9altimas linhas:",
                   log_level_name(log_get_level()));
        for (size_t k = 0; k < log_ring_count(); k++)
            app_printf("  %s", log_ring_get(k));
    } else if (strcmp(cmd, "/logout") == 0) {
        close_chat();
        wa_client_logout(&g_wa);
    } else if (strcmp(cmd, "/download") == 0 || strcmp(cmd, "/upload") == 0 ||
               strcmp(cmd, "/archive") == 0 || strcmp(cmd, "/mute") == 0 ||
               strcmp(cmd, "/block") == 0) {
        notice("%s ainda n\xc3\xa3o implementado", cmd);
    } else {
        notice("comando desconhecido: %s (veja /help)", cmd);
    }
    a->dirty = 1;
}

static void submit_line(const char *line)
{
    while (*line == ' ')
        line++;
    if (*line == '\0')
        return;
    if (line[0] == '/')
        handle_command(line);
    else
        send_text(line);
}

static void handle_key(const term_key *k)
{
    app_state *a = &g_app;
    switch (k->type) {
    case KEY_CHAR:
        line_insert(&a->input, k->utf8, strlen(k->utf8));
        break;
    case KEY_ENTER: {
        char line[ZAPC_INPUT_SIZE];
        zstrlcpy(line, a->input.buf, sizeof line);
        line_clear(&a->input);
        submit_line(line);
        break;
    }
    case KEY_BACKSPACE: line_backspace(&a->input); break;
    case KEY_DELETE: line_delete(&a->input); break;
    case KEY_LEFT: line_left(&a->input); break;
    case KEY_RIGHT: line_right(&a->input); break;
    case KEY_HOME: a->input.cursor = 0; break;
    case KEY_END: a->input.cursor = a->input.len; break;
    case KEY_CTRL_U: line_clear(&a->input); break;
    case KEY_CTRL_W: line_delete_word(&a->input); break;
    case KEY_PGUP: scroll_by(8); break;
    case KEY_PGDN: scroll_by(-8); break;
    case KEY_UP: scroll_by(1); break;
    case KEY_DOWN: scroll_by(-1); break;
    case KEY_ESC:
        if (a->chat_open)
            close_chat();
        else
            a->show_qr = 0;
        break;
    case KEY_CTRL_L: term_clear(); break;
    case KEY_CTRL_C:
        if (a->input.len > 0)
            line_clear(&a->input);
        else
            a->quit = 1;
        break;
    case KEY_CTRL_D:
    case KEY_EOF:
        if (a->input.len == 0)
            a->quit = 1;
        break;
    default:
        break;
    }
    a->dirty = 1;
}

/* ======================================================================== */
/* main loop                                                                */
/* ======================================================================== */

static void save_state(void)
{
    if (g_app.chats.dirty)
        chats_save(&g_app.chats);
    if (g_app.contacts.dirty)
        contacts_save(&g_app.contacts);
}

int app_run(const zapc_config *cfg, const app_options *opt)
{
    app_state *a = &g_app;
    memset(a, 0, sizeof *a);
    a->cfg = *cfg;
    a->opt = *opt;
    a->dirty = 1;

    if (storage_init(cfg->state_dir) != 0) {
        fprintf(stderr, "zapc: cannot create state directory %s\n",
                cfg->state_dir);
        return 1;
    }
    char logpath[ZAPC_PATH_MAX];
    if (cfg->log_file[0] != '\0')
        zstrlcpy(logpath, cfg->log_file, sizeof logpath);
    else
        storage_path(logpath, sizeof logpath, "zapc.log");
    log_open_file(logpath);

    term_init(!opt->plain);
    term_set_color(cfg->color);
    if (!term_is_interactive())
        log_set_stderr(0);
    log_set_sink(log_sink, NULL);

    chats_load(&a->chats);
    contacts_load(&a->contacts);

    wa_events ev = {NULL,          ev_state,        ev_qr,
                    ev_paired,     ev_logged_out,   ev_message,
                    ev_receipt,    ev_chat_name,    ev_history_chat,
                    ev_push_name,  ev_history_done};
    if (wa_client_init(&g_wa, &a->cfg, &ev) != 0) {
        term_shutdown();
        fprintf(stderr, "zapc: failed to initialise client (see %s)\n", logpath);
        return 1;
    }
    app_printf("ZapC - cliente WhatsApp para terminal. /help para ajuda.");
    if (g_wa.dev.paired) {
        char jid[WA_JID_STR_MAX];
        jid_format(&g_wa.dev.jid, jid, sizeof jid);
        app_printf("Sess\xc3\xa3o salva: %s", jid);
    } else {
        app_printf("Nenhuma sess\xc3\xa3o salva: um QR code ser\xc3\xa1 exibido ao conectar.");
    }
    if (cfg->auto_connect && !opt->no_connect)
        wa_client_connect(&g_wa);

    while (!a->quit) {
        if (term_resized())
            a->dirty = 1;
        if (a->dirty && term_is_interactive())
            render();

        struct pollfd pfd[2];
        int nfds = 0;
        pfd[nfds].fd = term_input_fd();
        pfd[nfds].events = POLLIN;
        pfd[nfds].revents = 0;
        nfds++;
        int wfd = wa_client_fd(&g_wa);
        if (wfd >= 0) {
            pfd[nfds].fd = wfd;
            pfd[nfds].events = POLLIN;
            pfd[nfds].revents = 0;
            nfds++;
        }
        int timeout = wa_client_next_timeout(&g_wa);
        if (a->notice_until != 0) {
            uint64_t now = plat_now_ms();
            int t = a->notice_until > now ? (int)(a->notice_until - now) + 10 : 0;
            if (timeout < 0 || t < timeout)
                timeout = t;
        }
        if (timeout < 0 || timeout > 30000)
            timeout = 30000;
        int r = poll(pfd, (nfds_t)nfds, timeout);
        if (r < 0) {
            continue; /* EINTR (e.g. SIGWINCH) */
        }
        if (a->notice_until != 0 && plat_now_ms() >= a->notice_until) {
            a->notice_until = 0;
            a->notice[0] = '\0';
            a->dirty = 1;
        }
        if (pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            if (term_is_interactive()) {
                term_key keys[32];
                int n = term_read_keys(keys, 32);
                for (int i = 0; i < n; i++)
                    handle_key(&keys[i]);
            } else {
                char line[ZAPC_INPUT_SIZE];
                int lr;
                while ((lr = term_read_line(line, sizeof line)) == 1)
                    submit_line(line);
                if (lr < 0) {
                    /* EOF on stdin: keep running while connected in plain
                     * mode only if explicitly piped with no commands left */
                    a->quit = 1;
                }
            }
        }
        if (nfds > 1 && (pfd[1].revents & (POLLIN | POLLHUP | POLLERR)))
            wa_client_on_readable(&g_wa);
        wa_client_tick(&g_wa);

        uint64_t now = plat_now_ms();
        if (now - a->last_save > 5000) {
            save_state();
            a->last_save = now;
        }
    }

    save_state();
    wa_client_free(&g_wa);
    term_shutdown();
    log_close();
    return 0;
}
