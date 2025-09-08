
# Detect OS automatically
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    ARCH ?= linux
else ifeq ($(UNAME_S),Darwin)
    ARCH ?= osx
else
    ARCH ?= linux  # Default fallback for other Unix-like systems
endif

TOPDIR   ?= $(realpath $(CURDIR))
RULESDIR := $(TOPDIR)/rules

include $(RULESDIR)/arch-$(ARCH).mk

CFLAGS_linux    := -I$(SDKINC) -I$(SDKINC_TCPIP) -fPIC
CFLAGS_windows  := -I$(SDKINC) -I$(SDKINC_TCPIP) -I/opt/windows/32/include/libxml2 -static-libgcc -static-libstdc++
CFLAGS_win32    := $(CFLAGS_windows)
CFLAGS_win64    := $(CFLAGS_windows)

CFLAGS += $(CFLAGS_$(ARCH))

LDFLAGS_linux   := -Wl,--export-dynamic -Wl,--whole-archive $(SDKLIB)/libmmt_core.a -Wl,--no-whole-archive
LDFLAGS_windows := -Wl,--whole-archive $(SDKLIB)/libmmt_core.a -Wl,--no-whole-archive
LDFLAGS_win32   := $(LDFLAGS_windows)
LDFLAGS_win64   := $(LDFLAGS_windows)

LDFLAGS += $(LDFLAGS_$(ARCH))

