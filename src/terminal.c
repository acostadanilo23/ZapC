/*
 * ZapC - ANSI/termios terminal backend.
 */
#include "zapc/terminal.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static int g_interactive;
static int g_raw;
static int g_color = 1;
static struct termios g_saved;
static volatile sig_atomic_t g_resized;

static char g_out[ZAPC_TERM_OUT_SIZE];
static size_t g_out_len;

/* pending raw input bytes (escape sequences may arrive split) */
static unsigned char g_in[256];
static size_t g_in_len;

/* line mode buffer */
static char g_line[ZAPC_INPUT_SIZE];
static size_t g_line_len;
static int g_eof;

static void on_winch(int sig)
{
    (void)sig;
    g_resized = 1;
}

int term_init(int interactive)
{
    g_interactive = interactive && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    if (!g_interactive)
        return 0;
    if (tcgetattr(STDIN_FILENO, &g_saved) != 0) {
        g_interactive = 0;
        return 0;
    }
    struct termios raw = g_saved;
    raw.c_iflag &= ~(tcflag_t)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~(tcflag_t)OPOST;
    raw.c_cflag |= CS8;
    raw.c_lflag &= ~(tcflag_t)(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
        g_interactive = 0;
        return 0;
    }
    g_raw = 1;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_winch;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGWINCH, &sa, NULL);
    /* alternate screen */
    term_puts("\x1b[?1049h\x1b[H\x1b[2J");
    term_flush();
    return 0;
}

void term_shutdown(void)
{
    if (g_raw) {
        term_puts("\x1b[0m\x1b[?25h\x1b[?1049l");
        term_flush();
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);
        g_raw = 0;
    }
    term_flush();
}

int term_is_interactive(void) { return g_interactive; }
int term_input_fd(void) { return STDIN_FILENO; }

void term_size(int *cols, int *rows)
{
    struct winsize ws;
    *cols = 80;
    *rows = 24;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 &&
        ws.ws_row > 0) {
        *cols = ws.ws_col;
        *rows = ws.ws_row;
    }
}

int term_resized(void)
{
    int r = g_resized;
    g_resized = 0;
    return r;
}

/* ---- output -------------------------------------------------------------- */

void term_flush(void)
{
    size_t off = 0;
    while (off < g_out_len) {
        ssize_t n = write(STDOUT_FILENO, g_out + off, g_out_len - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        off += (size_t)n;
    }
    g_out_len = 0;
}

void term_write(const char *s, size_t n)
{
    while (n > 0) {
        if (g_out_len == sizeof g_out)
            term_flush();
        size_t room = sizeof g_out - g_out_len;
        size_t take = n < room ? n : room;
        memcpy(g_out + g_out_len, s, take);
        g_out_len += take;
        s += take;
        n -= take;
    }
}

void term_puts(const char *s) { term_write(s, strlen(s)); }

void term_printf(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0)
        term_write(buf, (size_t)n < sizeof buf ? (size_t)n : sizeof buf - 1);
}

void term_move(int row, int col)
{
    if (g_interactive)
        term_printf("\x1b[%d;%dH", row, col);
}

void term_clear(void)
{
    if (g_interactive)
        term_puts("\x1b[H\x1b[2J");
}

void term_clear_eol(void)
{
    if (g_interactive)
        term_puts("\x1b[K");
}

void term_cursor(int visible)
{
    if (g_interactive)
        term_puts(visible ? "\x1b[?25h" : "\x1b[?25l");
}

void term_set_color(int enabled) { g_color = enabled; }

void term_attr_set(term_attr a)
{
    static const char *const codes[] = {"0", "1", "2", "7", "32", "36", "33",
                                        "31"};
    if (!g_interactive)
        return;
    if (!g_color && a >= ATTR_GREEN)
        a = ATTR_BOLD;
    term_printf("\x1b[%sm", codes[a]);
}

/* ---- input --------------------------------------------------------------- */

static int fill_input(void)
{
    if (g_in_len == sizeof g_in)
        return 0;
    ssize_t n = read(STDIN_FILENO, g_in + g_in_len, sizeof g_in - g_in_len);
    if (n > 0) {
        g_in_len += (size_t)n;
        return 1;
    }
    if (n == 0)
        g_eof = 1;
    return 0;
}

static void consume(size_t n)
{
    memmove(g_in, g_in + n, g_in_len - n);
    g_in_len -= n;
}

size_t utf8_seq_len(unsigned char c)
{
    if (c < 0x80)
        return 1;
    if ((c & 0xE0) == 0xC0)
        return 2;
    if ((c & 0xF0) == 0xE0)
        return 3;
    if ((c & 0xF8) == 0xF0)
        return 4;
    return 1;
}

/* Decode one key from g_in; returns bytes used, 0 if incomplete. */
static size_t decode_key(term_key *k, int force)
{
    unsigned char c = g_in[0];
    memset(k, 0, sizeof *k);
    if (c == 0x1b) {
        if (g_in_len == 1) {
            if (!force)
                return 0;
            k->type = KEY_ESC;
            return 1;
        }
        if (g_in[1] == '[' || g_in[1] == 'O') {
            size_t i = 2;
            while (i < g_in_len && i < 16 && !(g_in[i] >= 0x40 && g_in[i] <= 0x7e))
                i++;
            if (i >= g_in_len) {
                if (!force)
                    return 0;
                k->type = KEY_ESC;
                return 1;
            }
            unsigned char fin = g_in[i];
            int num = 0;
            for (size_t j = 2; j < i && g_in[j] >= '0' && g_in[j] <= '9'; j++)
                num = num * 10 + (g_in[j] - '0');
            switch (fin) {
            case 'A': k->type = KEY_UP; break;
            case 'B': k->type = KEY_DOWN; break;
            case 'C': k->type = KEY_RIGHT; break;
            case 'D': k->type = KEY_LEFT; break;
            case 'H': k->type = KEY_HOME; break;
            case 'F': k->type = KEY_END; break;
            case '~':
                switch (num) {
                case 1: case 7: k->type = KEY_HOME; break;
                case 4: case 8: k->type = KEY_END; break;
                case 3: k->type = KEY_DELETE; break;
                case 5: k->type = KEY_PGUP; break;
                case 6: k->type = KEY_PGDN; break;
                default: k->type = KEY_NONE; break;
                }
                break;
            default: k->type = KEY_NONE; break;
            }
            return i + 1;
        }
        k->type = KEY_ESC;
        return 1;
    }
    switch (c) {
    case '\r':
    case '\n': k->type = KEY_ENTER; return 1;
    case 0x7f:
    case 0x08: k->type = KEY_BACKSPACE; return 1;
    case '\t': k->type = KEY_TAB; return 1;
    case 0x03: k->type = KEY_CTRL_C; return 1;
    case 0x04: k->type = KEY_CTRL_D; return 1;
    case 0x0c: k->type = KEY_CTRL_L; return 1;
    case 0x15: k->type = KEY_CTRL_U; return 1;
    case 0x17: k->type = KEY_CTRL_W; return 1;
    default: break;
    }
    if (c < 0x20) {
        k->type = KEY_NONE;
        return 1;
    }
    size_t n = utf8_seq_len(c);
    if (n > g_in_len)
        return force ? g_in_len : 0;
    for (size_t i = 1; i < n; i++)
        if ((g_in[i] & 0xC0) != 0x80) {
            k->type = KEY_NONE;
            return 1;
        }
    k->type = KEY_CHAR;
    memcpy(k->utf8, g_in, n);
    return n;
}

int term_read_keys(term_key *keys, int max)
{
    int count = 0;
    fill_input();
    while (g_in_len > 0 && count < max) {
        size_t used = decode_key(&keys[count], 0);
        if (used == 0) {
            /* incomplete sequence: try to read the rest right away */
            if (!fill_input()) {
                used = decode_key(&keys[count], 1);
                if (used == 0)
                    break;
            } else {
                continue;
            }
        }
        consume(used);
        if (keys[count].type != KEY_NONE)
            count++;
    }
    if (g_eof && count < max && g_in_len == 0) {
        keys[count].type = KEY_EOF;
        count++;
        g_eof = 0;
    }
    return count;
}

int term_read_line(char *line, size_t cap)
{
    for (;;) {
        char *nl = memchr(g_line, '\n', g_line_len);
        if (nl != NULL) {
            size_t n = (size_t)(nl - g_line);
            size_t copy = n < cap - 1 ? n : cap - 1;
            memcpy(line, g_line, copy);
            line[copy] = '\0';
            if (copy > 0 && line[copy - 1] == '\r')
                line[copy - 1] = '\0';
            memmove(g_line, nl + 1, g_line_len - n - 1);
            g_line_len -= n + 1;
            return 1;
        }
        if (g_line_len == sizeof g_line) /* overlong line: discard */
            g_line_len = 0;
        ssize_t r = read(STDIN_FILENO, g_line + g_line_len,
                         sizeof g_line - g_line_len);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            return 0;
        if (r == 0) {
            if (g_line_len > 0) { /* last line without newline */
                g_line[g_line_len++] = '\n';
                continue;
            }
            return -1;
        }
        g_line_len += (size_t)r;
        if (memchr(g_line, '\n', g_line_len) == NULL)
            return 0;
    }
}

/* ---- UTF-8 width --------------------------------------------------------- */

static uint32_t decode_cp(const char *s, size_t n, size_t *used)
{
    const unsigned char *p = (const unsigned char *)s;
    size_t len = utf8_seq_len(p[0]);
    if (len > n || len == 1) {
        *used = 1;
        return p[0];
    }
    uint32_t cp = p[0] & (0xFF >> (len + 1));
    for (size_t i = 1; i < len; i++) {
        if ((p[i] & 0xC0) != 0x80) {
            *used = 1;
            return 0xFFFD;
        }
        cp = (cp << 6) | (p[i] & 0x3F);
    }
    *used = len;
    return cp;
}

static int cp_width(uint32_t cp)
{
    if ((cp >= 0x0300 && cp <= 0x036F) || cp == 0x200D ||
        (cp >= 0xFE00 && cp <= 0xFE0F))
        return 0; /* combining marks, ZWJ, variation selectors */
    if ((cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2E80 && cp <= 0xA4CF) ||
        (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) ||
        (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0x1F300 && cp <= 0x1FAFF))
        return 2;
    return 1;
}

size_t utf8_width(const char *s, size_t n)
{
    size_t w = 0, i = 0;
    while (i < n) {
        size_t used;
        uint32_t cp = decode_cp(s + i, n - i, &used);
        w += (size_t)cp_width(cp);
        i += used;
    }
    return w;
}

size_t utf8_fit(const char *s, size_t n, size_t cols)
{
    size_t w = 0, i = 0;
    while (i < n) {
        size_t used;
        uint32_t cp = decode_cp(s + i, n - i, &used);
        size_t cw = (size_t)cp_width(cp);
        if (w + cw > cols)
            break;
        w += cw;
        i += used;
    }
    return i;
}

/* ---- line editor ----------------------------------------------------------- */

void line_clear(term_line *l)
{
    l->len = 0;
    l->cursor = 0;
    l->buf[0] = '\0';
}

void line_insert(term_line *l, const char *s, size_t n)
{
    if (n == 0 || l->len + n >= sizeof l->buf)
        return;
    memmove(l->buf + l->cursor + n, l->buf + l->cursor, l->len - l->cursor);
    memcpy(l->buf + l->cursor, s, n);
    l->len += n;
    l->cursor += n;
    l->buf[l->len] = '\0';
}

static size_t prev_boundary(const term_line *l, size_t pos)
{
    if (pos == 0)
        return 0;
    pos--;
    while (pos > 0 && ((unsigned char)l->buf[pos] & 0xC0) == 0x80)
        pos--;
    return pos;
}

static size_t next_boundary(const term_line *l, size_t pos)
{
    if (pos >= l->len)
        return l->len;
    pos++;
    while (pos < l->len && ((unsigned char)l->buf[pos] & 0xC0) == 0x80)
        pos++;
    return pos;
}

void line_backspace(term_line *l)
{
    size_t p = prev_boundary(l, l->cursor);
    memmove(l->buf + p, l->buf + l->cursor, l->len - l->cursor);
    l->len -= l->cursor - p;
    l->cursor = p;
    l->buf[l->len] = '\0';
}

void line_delete(term_line *l)
{
    size_t p = next_boundary(l, l->cursor);
    memmove(l->buf + l->cursor, l->buf + p, l->len - p);
    l->len -= p - l->cursor;
    l->buf[l->len] = '\0';
}

void line_left(term_line *l) { l->cursor = prev_boundary(l, l->cursor); }
void line_right(term_line *l) { l->cursor = next_boundary(l, l->cursor); }

void line_delete_word(term_line *l)
{
    size_t p = l->cursor;
    while (p > 0 && l->buf[p - 1] == ' ')
        p--;
    while (p > 0 && l->buf[p - 1] != ' ')
        p--;
    memmove(l->buf + p, l->buf + l->cursor, l->len - l->cursor);
    l->len -= l->cursor - p;
    l->cursor = p;
    l->buf[l->len] = '\0';
}
