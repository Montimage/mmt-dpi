
CXX := g++ -std=c++11
CC  := gcc
AR  := ar rcs

include $(RULESDIR)/common-linux.mk

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
# The probe reads the preprocessor's builtin macros on empty input — it
# never compiles anything. __GNUC__ is also defined by Clang (as 4) and
# icc, so the floor applies only when neither __clang__ nor
# __INTEL_COMPILER is present; those toolchains keep their own arch-*.mk
# files. An unknown or failing $(CC) yields an empty MMT_GCC_MAJOR and is
# left to fail naturally at compile time rather than on a probe artifact.
#
# `clean`/`dist-clean` are exempt so an old toolchain can still wipe the
# tree.
ifeq ($(filter clean dist-clean,$(MAKECMDGOALS)),)
MMT_GCC_MAJOR := $(shell echo | $(CC) -dM -E -x c - 2>/dev/null | \
    grep -q -e '__clang__' -e '__INTEL_COMPILER' || \
    echo | $(CC) -dM -E -x c - 2>/dev/null | \
    sed -n 's/^#define __GNUC__ //p')
ifneq ($(MMT_GCC_MAJOR),)
ifneq ($(shell [ "$(MMT_GCC_MAJOR)" -ge "$(MMT_GCC_MIN)" ] 2>/dev/null && echo ok),ok)
$(error MMT-DPI requires GCC >= $(MMT_GCC_MIN); detected $(CC) reporting \
        __GNUC__=$(MMT_GCC_MAJOR). The floor tracks the oldest release-matrix \
        toolchain (GCC $(MMT_GCC_MIN), glibc $(MMT_GLIBC_MIN), libstdc++ \
        $(MMT_LIBSTDCXX_MIN)) — see docs/AGENT_ENVIRONMENT.md §1)
endif
endif
endif
