
ARCH     ?= linux
TOPDIR   ?= $(realpath $(CURDIR)/../../..)
RULESDIR := $(TOPDIR)/rules

include $(RULESDIR)/arch-$(ARCH).mk

CFLAGS_linux    := -I$(SDKINC) -I$(SDKINC_TCPIP) -fPIC

CFLAGS += $(CFLAGS_$(ARCH))

LDFLAGS_linux   := -Wl,--export-dynamic -Wl,--whole-archive $(SDKLIB)/libmmt_core.a -Wl,--no-whole-archive

LDFLAGS += $(LDFLAGS_$(ARCH))

