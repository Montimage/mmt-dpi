
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
