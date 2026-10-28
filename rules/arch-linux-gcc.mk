
CXX := g++ -std=c++11
CC  := gcc
AR  := ar rcsD

include $(RULESDIR)/common-linux.mk

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#  C   D I A L E C T   P I N   ( i s s u e   # 5 1 4 ,   F - D E P - 3 0 1 )
#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# GCC 11-14 default to gnu17 and GCC 15 to gnu23; the pin keeps every
# supported GCC on one C dialect. It sits after the include because
# rules/common.mk resets CFLAGS with `:=`, which would wipe an earlier
# assignment. MMT_EXTRA_CFLAGS comes last so the caller can override the pin
# (the last -std wins), e.g. `make -C sdk MMT_EXTRA_CFLAGS=-std=gnu23`. Both
# apply to C objects only (C++ uses CXX/CXXFLAGS) and only to this default
# GCC toolchain (ARCH=linux); arch-linux-clang.mk and arch-linux-icc.mk are
# unchanged.
CFLAGS += -std=gnu17
CFLAGS += $(MMT_EXTRA_CFLAGS)

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#  G C C   F L O O R   E N F O R C E M E N T   ( i s s u e   # 2 1 8 )
#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Fail fast when the configured C compiler is GCC below MMT_GCC_MIN (the
# floor constants live in rules/common.mk and match the oldest release-
# matrix toolchain; docs/AGENT_ENVIRONMENT.md §1 states the contract).
# A sub-floor compiler gets a clear error here instead of producing a
# binary outside the tested support contract.
#
# The compiler-identity probe in rules/common-linux.mk (issue #508, included
# above) reads the preprocessor's builtin macros on empty input — it never
# compiles anything. __GNUC__ is also defined by Clang (as 4) and icc, so the
# floor applies only when that probe identifies $(CC) as GCC; those
# toolchains keep their own arch-*.mk files. An unknown or failing $(CC)
# yields an empty MMT_GCC_MAJOR and is left to fail naturally at compile
# time rather than on a probe artifact.
#
# `clean`/`dist-clean` are exempt so an old toolchain can still wipe the
# tree.
ifeq ($(filter clean dist-clean uninstall,$(MAKECMDGOALS)),)
MMT_GCC_MAJOR := $(if $(filter gcc,$(MMT_CC_ID)),$(patsubst __GNUC__=%,%,$(filter __GNUC__=%,$(MMT_CC_MACROS))))
ifneq ($(MMT_GCC_MAJOR),)
ifneq ($(shell [ "$(MMT_GCC_MAJOR)" -ge "$(MMT_GCC_MIN)" ] 2>/dev/null && echo ok),ok)
$(error MMT-DPI requires GCC >= $(MMT_GCC_MIN); detected $(CC) reporting \
        __GNUC__=$(MMT_GCC_MAJOR). The floor tracks the oldest release-matrix \
        toolchain (GCC $(MMT_GCC_MIN), glibc $(MMT_GLIBC_MIN), libstdc++ \
        $(MMT_LIBSTDCXX_MIN)) — see docs/AGENT_ENVIRONMENT.md §1)
endif
endif
endif

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#  O P T - I N   C O M P I L E R   C A C H E   ( i s s u e   # 5 5 3 )
#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# MMT_CCACHE names a compiler launcher (normally `ccache`) put in front of
# $(CC) and $(CXX): `make -C sdk MMT_CCACHE=ccache`, or exported, so every
# SDK the test suites build inherits it (`MMT_CCACHE=ccache bash
# tests/run_all_tests.sh`). Unset — the default — leaves CC and CXX exactly
# as set above, so nothing changes without it. The block sits last so the
# compiler-identity, FORTIFY, CET and -frandom-seed probes (rules/common.mk,
# rules/common-linux.mk) still run on the bare compiler; `override` prefixes a
# command-line CC= too. BUILD=coverage stays uncached: a cached --coverage
# object carries the gcov counter path of the build that produced it, which
# breaks the per-suite counter harvest. CCACHE_BASEDIR defaults to the
# checkout, so ccache hashes paths under it relatively and another checkout
# or worktree of the same sources shares the entries. The compile lines it
# caches are stable across install prefixes and commits (rules/common.mk,
# issue #553 block).
ifneq ($(strip $(MMT_CCACHE)),)
ifeq ($(filter clean dist-clean uninstall,$(MAKECMDGOALS)),)
ifeq ($(shell command -v $(firstword $(MMT_CCACHE)) 2>/dev/null),)
$(error MMT_CCACHE=$(MMT_CCACHE): $(firstword $(MMT_CCACHE)) not found — install it or unset MMT_CCACHE)
endif
endif
ifneq ($(BUILD),coverage)
override CC  := $(MMT_CCACHE) $(CC)
override CXX := $(MMT_CCACHE) $(CXX)
CCACHE_BASEDIR ?= $(TOPDIR)
export CCACHE_BASEDIR
endif
endif
