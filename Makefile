# ZapC - WhatsApp TUI client in C
#
#   make            default build (-O2)
#   make debug      -O0 -g, sanitizers, allocation counters
#   make release    -Os, stripped
#   make test       build and run unit tests
#   make clean
#
# Variables:
#   CC=clang                       compiler
#   TLS_BACKEND=openssl            TLS implementation (src/net/tls_<backend>.c)
#   CRYPTO_BACKEND=openssl         primitives (src/crypto/crypto_<backend>.c)
#   PLATFORM=unix                  portability layer (src/platform/<p>.c)
#   CFLAGS_EXTRA=-DZAPC_NET_RX_SIZE=8192   override compile-time limits

CC             ?= cc
MODE           ?= default
TLS_BACKEND    ?= openssl
CRYPTO_BACKEND ?= openssl
PLATFORM       ?= unix
PKG_CONFIG     ?= pkg-config

WARN = -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 \
       -Wstrict-prototypes -Wmissing-prototypes -Wvla -Wundef
BASE_CFLAGS = -std=c17 $(WARN) -Iinclude -D_POSIX_C_SOURCE=200809L

ifeq ($(MODE),debug)
  MODE_CFLAGS  = -O0 -g3 -DZAPC_MEM_DEBUG=1 -fsanitize=address,undefined -fno-omit-frame-pointer
  MODE_LDFLAGS = -fsanitize=address,undefined
else ifeq ($(MODE),release)
  MODE_CFLAGS  = -Os -DNDEBUG -ffunction-sections -fdata-sections
  MODE_LDFLAGS = -s -Wl,--gc-sections
else
  MODE_CFLAGS  = -O2 -g -DZAPC_MEM_DEBUG=1
  MODE_LDFLAGS =
endif

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo -lssl -lcrypto)

CFLAGS  ?=
LDFLAGS ?=
ALL_CFLAGS  = $(BASE_CFLAGS) $(MODE_CFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) $(CFLAGS_EXTRA)
ALL_LDFLAGS = $(MODE_LDFLAGS) $(LDFLAGS)
LIBS        = $(OPENSSL_LIBS)

BUILD = build/$(MODE)

# Everything except main.c goes into a static library shared with the tests.
CORE_SRC = \
	src/app.c \
	src/config.c \
	src/log.c \
	src/memory.c \
	src/terminal.c \
	src/qr.c \
	src/util/base64.c \
	src/util/buf.c \
	src/platform/$(PLATFORM).c \
	src/crypto/crypto_$(CRYPTO_BACKEND).c \
	src/crypto/curve25519.c \
	src/crypto/inflate.c \
	src/net/tcp.c \
	src/net/tls_$(TLS_BACKEND).c \
	src/net/websocket.c \
	src/net/http.c \
	src/wa/jid.c \
	src/wa/tokens.c \
	src/wa/binary_node.c \
	src/wa/protobuf.c \
	src/wa/noise.c \
	src/wa/frame.c \
	src/wa/keys.c \
	src/wa/signal.c \
	src/wa/pairing.c \
	src/wa/message.c \
	src/wa/media.c \
	src/wa/history_sync.c \
	src/wa/client.c \
	src/storage/storage.c \
	src/storage/credentials.c \
	src/storage/history.c

CORE_OBJ = $(CORE_SRC:%.c=$(BUILD)/%.o)
MAIN_OBJ = $(BUILD)/src/main.o
LIB      = $(BUILD)/libzapc.a
BIN      = $(BUILD)/zapc

TEST_SRC = $(wildcard tests/test_*.c)
TEST_BIN = $(TEST_SRC:tests/%.c=$(BUILD)/tests/%)

.PHONY: all debug release test clean interop

all: $(BIN)
	@ln -sf $(BIN) zapc

debug:
	$(MAKE) MODE=debug

release:
	$(MAKE) MODE=release

$(BIN): $(MAIN_OBJ) $(LIB)
	$(CC) $(ALL_LDFLAGS) -o $@ $^ $(LIBS)

$(LIB): $(CORE_OBJ)
	@rm -f $@
	ar rcs $@ $^

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/tests/%: tests/%.c tests/test.h $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -o $@ $< $(LIB) $(LIBS)

test: $(TEST_BIN)
	@fail=0; for t in $(TEST_BIN); do \
		if ./$$t; then :; else fail=1; fi; \
	done; \
	if [ $$fail -eq 0 ]; then echo "all tests passed"; else echo "TESTS FAILED"; exit 1; fi

# Signal wire-compatibility check against python-axolotl (an independent
# libsignal implementation).  Needs: pip install python-axolotl
PYTHON ?= python3
$(BUILD)/sigtool: tools/interop/sigtool.c $(LIB)
	$(CC) $(ALL_CFLAGS) -Wno-missing-prototypes $(ALL_LDFLAGS) -o $@ $< $(LIB) $(LIBS)

interop: $(BUILD)/sigtool
	PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python $(PYTHON) tools/interop/interop.py $(BUILD)/sigtool $(BUILD)/interop-run

clean:
	rm -rf build zapc

-include $(CORE_OBJ:.o=.d) $(MAIN_OBJ:.o=.d)
