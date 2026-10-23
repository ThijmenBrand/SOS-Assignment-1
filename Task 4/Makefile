# Makefile for Task 4.1 - password based AES-256-GCM encryptor/decryptor.
#
#   make          build both programs
#   make run-enc  build and run the encryptor
#   make run-dec  build and run the decryptor
#   make clean    remove binaries, objects and text.ct
#
# Supported: Linux (incl. WSL), macOS (Homebrew OpenSSL 3), Windows
# (MSYS2/MinGW-w64 shell, or cmd.exe with mingw32-make).
#
# Override anything from the command line, e.g.
#   make OPENSSL_PREFIX="C:/Program Files/OpenSSL-Win64"

# --- Platform detection ------------------------------------------------------
ifeq ($(OS),Windows_NT)
  PLATFORM := windows
else
  PLATFORM := $(shell uname -s)
endif

CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -O2
LDFLAGS :=
LDLIBS  := -lcrypto

EXE :=
RUN := ./
RM  := rm -f

# --- Per platform settings ---------------------------------------------------
ifeq ($(PLATFORM),Darwin)
  # macOS ships LibreSSL without headers, so use the Homebrew OpenSSL 3 keg
  # (brew install openssl@3). Apple Silicon first, then Intel.
  OPENSSL_PREFIX ?= $(firstword $(wildcard /opt/homebrew/opt/openssl@3 \
                                           /usr/local/opt/openssl@3))
endif

ifeq ($(PLATFORM),Linux)
  # apt install build-essential libssl-dev puts everything on the default
  # search paths, so no prefix is needed.
  OPENSSL_PREFIX ?=
endif

ifeq ($(PLATFORM),windows)
  EXE := .exe

  # make's built-in default is "cc", which does not exist on Windows.
  # Only override it when the user has not asked for something else.
  ifeq ($(origin CC),default)
    CC := gcc
  endif

  # MSYS2/MinGW shells set MSYSTEM and give us the POSIX tools; a bare
  # cmd.exe does not, so fall back to del and a bare executable name.
  ifdef MSYSTEM
    # MSYS2: pacman -S mingw-w64-ucrt-x86_64-{gcc,openssl} - already on path.
    OPENSSL_PREFIX ?=
  else
    RM  := del /Q /F
    RUN :=

    # Probe the usual install locations. $(wildcard) cannot be given a path
    # with a space in it, so the default OpenSSL installer directory is used
    # as a plain fallback instead of being probed; CFLAGS quotes it.
    WIN_OPENSSL := $(firstword $(wildcard C:/OpenSSL-Win64 \
                                          C:/msys64/ucrt64 \
                                          C:/msys64/mingw64))
    ifeq ($(WIN_OPENSSL),)
      WIN_OPENSSL := C:/Program Files/OpenSSL-Win64
    endif
    OPENSSL_PREFIX ?= $(WIN_OPENSSL)
  endif

  # Needed when linking OpenSSL statically; harmless otherwise.
  LDLIBS += -lws2_32 -lcrypt32
endif

# --- OpenSSL location --------------------------------------------------------
ifneq ($(strip $(OPENSSL_PREFIX)),)
CFLAGS  += -I"$(OPENSSL_PREFIX)/include"
LDFLAGS += -L"$(OPENSSL_PREFIX)/lib"
endif

# --- Targets -----------------------------------------------------------------
COMMON_OBJ := common.o
OBJS       := task41enc.o task41dec.o $(COMMON_OBJ)
BINS       := task41enc$(EXE) task41dec$(EXE)

.PHONY: all clean run-enc run-dec

all: $(BINS)

task41enc$(EXE): task41enc.o $(COMMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

task41dec$(EXE): task41dec.o $(COMMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c common.h
	$(CC) $(CFLAGS) -c -o $@ $<

run-enc: task41enc$(EXE)
	$(RUN)task41enc$(EXE)

run-dec: task41dec$(EXE)
	$(RUN)task41dec$(EXE)

clean:
	-$(RM) $(BINS) $(OBJS) text.ct
