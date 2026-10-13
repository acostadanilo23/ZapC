/*
 * ZapC - terminal abstraction.
 *
 * The default backend (src/terminal.c) uses termios + ANSI escape sequences.
 * Everything the UI needs goes through these functions so another backend
 * (e.g. a PS2 console) can replace that one file.
 */
#ifndef ZAPC_TERMINAL_H
#define ZAPC_TERMINAL_H

#include "zapc/build_config.h"

#include <stddef.h>
#include <stdint.h>

typedef enum {
    KEY_NONE = 0,
    KEY_CHAR,      /* printable character in .utf8 */
    KEY_ENTER,
    KEY_BACKSPACE,
    KEY_DELETE,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_UP,
    KEY_DOWN,
    KEY_HOME,
    KEY_END,
    KEY_PGUP,
    KEY_PGDN,
    KEY_TAB,
    KEY_ESC,
    KEY_CTRL_C,
    KEY_CTRL_D,
    KEY_CTRL_L,
    KEY_CTRL_U,
    KEY_CTRL_W,
    KEY_EOF
} term_key_type;

typedef struct {
    term_key_type type;
    char utf8[5];
} term_key;

/* interactive=1: raw mode + full-screen; 0: line mode (pipes, --plain). */
int term_init(int interactive);
void term_shutdown(void);
int term_is_interactive(void);
int term_input_fd(void);
void term_size(int *cols, int *rows);
/* Set by SIGWINCH; returns and clears the flag. */
int term_resized(void);

/* Read and decode available keys (interactive mode). Returns count. */
int term_read_keys(term_key *keys, int max);
/* Line mode: returns 1 and fills line when a full line is available,
 * 0 if not yet, -1 on EOF. */
int term_read_line(char *line, size_t cap);

/* Buffered output. */
void term_write(const char *s, size_t n);
void term_puts(const char *s);
void term_printf(const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;
void term_flush(void);

/* ANSI helpers (no-ops in line mode). */
void term_move(int row, int col); /* 1-based */
void term_clear(void);
void term_clear_eol(void);
void term_cursor(int visible);
typedef enum {
    ATTR_RESET = 0,
    ATTR_BOLD,
    ATTR_DIM,
    ATTR_REVERSE,
    ATTR_GREEN,
    ATTR_CYAN,
    ATTR_YELLOW,
    ATTR_RED
} term_attr;
void term_attr_set(term_attr a);
void term_set_color(int enabled);

/* ---- UTF-8 helpers ------------------------------------------------------ */
/* Display width (columns) of a UTF-8 string, assuming 1 col per code point
 * except combining marks (0) and common wide CJK/emoji ranges (2). */
size_t utf8_width(const char *s, size_t n);
/* Byte length of the longest prefix that fits in `cols` columns. */
size_t utf8_fit(const char *s, size_t n, size_t cols);
/* Length of the UTF-8 sequence starting with byte c (1 for invalid). */
size_t utf8_seq_len(unsigned char c);

/* ---- line editor -------------------------------------------------------- */
typedef struct {
    char buf[ZAPC_INPUT_SIZE];
    size_t len;
    size_t cursor; /* byte offset, always on a code point boundary */
} term_line;

void line_clear(term_line *l);
void line_insert(term_line *l, const char *s, size_t n);
void line_backspace(term_line *l);
void line_delete(term_line *l);
void line_left(term_line *l);
void line_right(term_line *l);
void line_delete_word(term_line *l);

#endif
