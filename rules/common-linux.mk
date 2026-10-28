
include $(RULESDIR)/common.mk

$(CORE_OBJECTS) $(TCPIP_OBJECTS): CFLAGS   += -fPIC
$(CORE_OBJECTS) $(TCPIP_OBJECTS): CXXFLAGS += -fPIC
ifdef ENABLESEC
$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CFLAGS   += -fPIC
$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CXXFLAGS += -fPIC
# libxml2 include path via pkg-config (with guarded fallback), see common.mk.
$(SECURITY_OBJECTS): CFLAGS += $(LIBXML2_CFLAGS)
$(FUZZ_OBJECTS): CFLAGS += $(LIBXML2_CFLAGS)
endif

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#  R E L E A S E   O P T I M I Z A T I O N   &   H A R D E N I N G   ( B1, B2 )
#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Applied only to optimized release builds (the default -O3 path) on Linux.
# Skipped for DEBUG, VALGRIND and BUILD=asan so they do not perturb debugging,
# Valgrind traces or the sanitizer runtime.
#
# B1 - link-time optimization + dead-section GC:
#   -flto=auto                optimizes across translation units (GCC spelling).
#   -ffunction-sections
#   -fdata-sections           emit each function/datum in its own section so the
#   -Wl,--gc-sections         linker can drop everything unreferenced, shrinking
#                             the shared objects.
#   -fno-semantic-interposition  lets the compiler inline/clone within the .so
#                             instead of routing every call through the PLT.
#
# B2 - exploit hardening:
#   -D_FORTIFY_SOURCE=3       run-time bounds checks on libc str/mem calls,
#                             the stronger level (F-SEC-010): on top of the
#                             =2 checks it uses __builtin_dynamic_object_size
#                             so flexible/heap objects are covered too. The
#                             level is picked by a compiler capability probe
#                             (below) - GCC >= 12 / Clang >= 16 with a matching
#                             libc - and falls back to =2 where =3 is not
#                             implemented, so an older toolchain degrades
#                             instead of erroring. The macro is undefined
#                             first so a probe result never collides with a
#                             toolchain that pre-defines it.
#   -fcf-protection           control-flow protection (F-SEC-010): the compiler
#                             emits endbr64 landing pads and sets the IBT/SHSTK
#                             properties on the built objects, so the shipped
#                             .so can run under IBT/Shadow-Stack kernels.
#                             CET only exists on x86 — the flag is gated on a
#                             compile probe (below); on AArch64 the probe
#                             substitutes -mbranch-protection=standard
#                             (PAC/BTI), the platform's control-flow
#                             equivalent, so no shipped target goes without.
#   -fstack-protector-strong
#   -fstack-clash-protection  stack smashing / stack-clash hardening.
#   -Wl,-z,relro -Wl,-z,now   full RELRO: GOT resolved at load then made
#                             read-only (BIND_NOW).
#   -Wl,-z,noexecstack        mark the stack non-executable.
#
# This is a DISTRIBUTED shared library, so deliberately NO -march=native /
# -mtune=native here - those would emit instructions that SIGILL on older
# baseline CPUs.
#
# -flto=auto is GCC-only (Clang rejects the "auto" argument), so LTO is enabled
# for GCC alone; the remaining flags are accepted by both GCC and Clang. icc is
# excluded from the whole block.
#
# Compiler identity (issue #508): the block is keyed on what $(CC) IS, not on
# how it is spelled. A literal `gcc`/`clang` filter silently skipped the whole
# block for CC=/usr/bin/gcc, CC=gcc-13 or a wrapper. One preprocessor probe
# per compiler reads the builtin macros on empty input (it never compiles);
# __INTEL_COMPILER (icc) wins over __clang__, which wins over the __GNUC__
# that Clang and icc also define. rules/arch-linux.mk derives its GCC floor
# check from the same probe. An unknown or failing compiler leaves the
# identity empty, and the block is then skipped with a $(warning) below.
mmt_cc_probe = $(shell echo | $(1) -dM -E -x $(2) - 2>/dev/null | \
    sed -n -E 's/^#define (__INTEL_COMPILER|__clang__|__GNUC__|__GNUC_MINOR__|__GNUC_PATCHLEVEL__) +([0-9]+).*/\1=\2/p')
mmt_cc_id = $(if $(filter __INTEL_COMPILER=%,$(1)),icc,$(if $(filter __clang__=%,$(1)),clang,$(if $(filter __GNUC__=%,$(1)),gcc)))
MMT_CC_MACROS  := $(call mmt_cc_probe,$(CC),c)
MMT_CC_ID      := $(call mmt_cc_id,$(MMT_CC_MACROS))
# Issue #539: $(CXX) is not probed — no SDK library is linked with it any
# more, so the LTO gate below depends on $(CC) alone.
# Goals that compile (or install) something: the default goal or any goal
# but the cleaning ones. The hardening warnings below fire only for these.
MMT_BUILD_GOALS := $(if $(MAKECMDGOALS),$(filter-out clean dist-clean uninstall,$(MAKECMDGOALS)),default)

MMT_RELEASE_BUILD := 1
ifdef DEBUG
MMT_RELEASE_BUILD :=
endif
ifdef VALGRIND
MMT_RELEASE_BUILD :=
endif
ifeq ($(BUILD),asan)
MMT_RELEASE_BUILD :=
endif
# BUILD=tsan (issue #65) and BUILD=coverage (#387): like asan, no hardening/LTO
# so the TSan runtime and gcov's line/function attribution are not perturbed.
ifneq (,$(filter tsan coverage,$(BUILD)))
MMT_RELEASE_BUILD :=
endif

ifeq ($(MMT_RELEASE_BUILD),1)
ifneq (,$(filter gcc clang,$(MMT_CC_ID)))

# _FORTIFY_SOURCE level probe (F-SEC-010, issue #214): the stronger level =3
# needs a compiler that implements __builtin_dynamic_object_size-based
# fortification (__GNUC__ >= 12 / GCC, or Clang >= 16) AND headers that accept
# the level — a compiler capability check, not a version string parse.
# Rather than keying on a version string, compile a sentinel once per make run
# with -Werror: the probe source #errors out below the capability floor, and
# -D_FORTIFY_SOURCE=3 itself is on the probe line so a libc/compiler that rejects the
# level fails the compile too. Fallback is =2, never "no fortification".
MMT_FORTIFY_SOURCE_LEVEL := $(shell printf '%s\n' \
    '#if defined(__clang__)' \
    '#  if __clang_major__ < 16' \
    '#    error "clang < 16 lacks the _FORTIFY_SOURCE=3 runtime support"' \
    '#  endif' \
    '#elif !defined(__GNUC__) || __GNUC__ < 12' \
    '#  error "compiler too old for _FORTIFY_SOURCE=3"' \
    '#endif' \
    'int main(void){return 0;}' \
    | $(CC) -x c -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -Werror - -o /dev/null >/dev/null 2>&1 \
    && echo 3 || echo 2)

# Control-flow-protection probe (F-SEC-010, issue #214): -fcf-protection is
# Intel CET — GCC on non-x86 targets rejects it outright ("not supported for
# this target"), so it cannot be emitted unconditionally. Probe once per make
# run with -Werror (a warning-only rejection counts as unsupported). Where CET
# is unavailable, retry with AArch64's -mbranch-protection=standard (PAC/BTI):
# the same class of mitigation for that target. On targets with neither, the
# variable stays empty rather than breaking the build.
MMT_CF_PROTECTION := $(shell printf 'int main(void){return 0;}' \
    | $(CC) -x c -fcf-protection -Werror - -o /dev/null >/dev/null 2>&1 \
    && echo -fcf-protection)
ifeq ($(MMT_CF_PROTECTION),)
MMT_CF_PROTECTION := $(shell printf 'int main(void){return 0;}' \
    | $(CC) -x c -mbranch-protection=standard -Werror - -o /dev/null >/dev/null 2>&1 \
    && echo -mbranch-protection=standard)
endif

# Compile-time flags - applied to every C and C++ object.
MMT_HARDEN_CFLAGS := \
    -ffunction-sections -fdata-sections -fno-semantic-interposition \
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$(MMT_FORTIFY_SOURCE_LEVEL) \
    $(MMT_CF_PROTECTION) \
    -fstack-protector-strong -fstack-clash-protection

# Link-time flags. The .so recipes link with $(CC) $(CXXFLAGS) - CXXFLAGS is the
# link-flag carrier the BUILD=asan path relies on (issue #539 kept it) - so these
# are appended to CXXFLAGS (below) to reach every shared-library link line.
MMT_HARDEN_LDFLAGS := \
    -Wl,--gc-sections \
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

# AArch64 note (F-SEC-010): -mbranch-protection=standard puts BTI landing pads
# and PAC return-signing in every MMT object (real mitigation on PAC-capable
# hardware). The .so deliberately does NOT get -Wl,-z,force-bti: the crti/crtn
# stubs carry no GNU property note, and stamping BTI on the output anyway lets
# a BTI-enforcing kernel/loader SIGILL the process the moment control flow
# reaches those stubs (observed: every installed-tree suite dies at startup).
# The protection is therefore in the codegen, not the merged ELF note.

# LTO must be present at BOTH compile and link; -flto=auto is GCC-only. The
# objects are compiled and the libraries linked by the one $(CC) driver
# (issue #539: the SDK's last C++ TU is gone, so no recipe links with $(CXX)),
# so LTO bytecode never crosses compilers. Issue #508 required $(CC) and
# $(CXX) to be the same GCC release only because the link used to run through
# $(CXX); that check and its "LTO SKIPPED" warning went with the $(CXX) link.
# A Clang $(CC) keeps the rest of the hardening set without LTO, as before.
ifeq ($(MMT_CC_ID),gcc)
MMT_HARDEN_CFLAGS  += -flto=auto
MMT_HARDEN_LDFLAGS += -flto=auto
endif
# $(CXX) compiles no SDK object and links no SDK library; a $(CXX) of another
# GCC release than $(CC) therefore changes nothing here.


# TUNE=native (opt-in, NEVER the default - B5). When explicitly requested on the
# command line (make TUNE=native ...) the build targets the CPU of the build
# host with -march=native -mtune=native. This is UNSAFE for a redistributed
# shared library: native code generation can emit instructions (AVX-512, BMI2,
# ...) that SIGILL on older baseline CPUs. It is therefore gated behind an
# explicit opt-in and left off by default so the distributed .so stays portable.
ifeq ($(TUNE),native)
MMT_HARDEN_CFLAGS += -march=native -mtune=native
endif

CFLAGS   += $(MMT_HARDEN_CFLAGS)
CXXFLAGS += $(MMT_HARDEN_CFLAGS) $(MMT_HARDEN_LDFLAGS)

else
MMT_HARDEN_SKIPPED := 1
endif   # gcc/clang only
endif   # release builds only

# F-SEC-010 (issue #214): a build with the hardening block off must SAY so.
# DEBUG, VALGRIND and the sanitizer profiles all drop FORTIFY/stack-protector/
# CF-protection/LTO, and before this warning the only way to notice was to
# inspect the objects. Silent divergence between the tested and the shipped
# configuration is exactly the failure mode the finding reports, so the switch
# is loud. The warning is a BUILD warning: goals that never compile (clean,
# dist-clean) keep quiet. Issue #508: a release build whose $(CC) is not
# identified as GCC or Clang says so too.
ifneq (,$(MMT_BUILD_GOALS))
ifeq (,$(MMT_RELEASE_BUILD))
$(warning MMT-DPI: release hardening DISABLED for this build (DEBUG/VALGRIND/BUILD=$(BUILD)) - the libraries get no _FORTIFY_SOURCE, stack protector, -fcf-protection or LTO; do not ship this build)
endif
ifdef MMT_HARDEN_SKIPPED
$(warning MMT-DPI: release hardening SKIPPED - CC=$(CC) is not identified as GCC or Clang (preprocessor probe: $(or $(MMT_CC_ID),unknown)) - the libraries get no _FORTIFY_SOURCE, stack protector, -fcf-protection, full RELRO or LTO; do not ship this build)
endif
# Issue #539: no "LTO SKIPPED" warning any more — LTO depends on $(CC) alone
# (see the LTO block above), and an unidentified $(CC) is the SKIPPED case
# just above.
endif

#  - - - - - - - - - - - - - - -
#  L I N U X   L I B R A R I E S
#  - - - - - - - - - - - - - - -

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#  P E R - L I B R A R Y   L I N K   F L A G S   ( B3, B4 )
#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Link libraries now live on the link line (the .so recipes append $(LDLIBS),
# and $(LDFLAGS) for linker options). $(LDLIBS) defaults to -lm (common.mk);
# libmmt_core and the ENABLESEC engines (libxml2) add theirs here. No protocol
# library links an external library: the HTTP/2 library tcpip and tmobile
# once declared was never called, so its -l flag is gone (issue #495;
# `objdump -p` shows no NEEDED entry for it).
# libmmt_core dlopen()s the protocol plugins; keep -ldl explicit so the link is
# self-contained under -Wl,-z,defs even on toolchains that split libdl out of
# libc.
# Issue #22: the global plugin/protocol registries are now guarded by
# pthread_mutex for (un)registration, so the core needs -lpthread explicit too
# (some toolchains still split libpthread out of libc).
$(SDKLIB)/$(LIBCORE).so.$(VERSION):   LDLIBS += -ldl -lpthread

# -Wl,-z,defs (a.k.a. --no-undefined) makes the linker fail on any unresolved
# symbol. Only libmmt_core is fully self-contained: the protocol plugins
# (tcpip, tmobile, business_app, tdicom) and the ENABLESEC engines deliberately
# leave core symbols (mmt_malloc, register_protocol, ...) undefined and resolve
# them at load time when the MMT framework dlopen()s them into one address
# space, so they cannot satisfy --no-undefined. BUILD=asan also leaves the
# ASan/UBSan runtime symbols undefined by design (resolved via LD_PRELOAD, see
# common.mk), so the guard is skipped for the sanitizer profile. BUILD=tsan does
# the same with the ThreadSanitizer runtime symbols (issue #65), so it is
# skipped too.
ifeq (,$(filter asan tsan,$(BUILD)))
$(SDKLIB)/$(LIBCORE).so.$(VERSION):    LDFLAGS += -Wl,-z,defs
endif
ifdef ENABLESEC
$(SDKLIB)/$(LIBSECURITY).so.$(VERSION): LDLIBS += $(LIBXML2_LIBS)
$(SDKLIB)/$(LIBFUZZ).so.$(VERSION):     LDLIBS += $(LIBXML2_LIBS)
endif

libraries: \
	$(SDKLIB)/$(LIBCORE).so \
	$(SDKLIB)/$(LIBTCPIP).so \
	$(SDKLIB)/$(LIBMOBILE).so \
	$(SDKLIB)/$(LIBBAPP).so \
	$(SDKLIB)/$(LIBDICOM).so
ifdef ENABLESEC
libraries: \
	$(SDKLIB)/$(LIBFUZZ).so \
	$(SDKLIB)/$(LIBSECURITY).so
endif
# CORE

$(SDKLIB)/$(LIBCORE).so: $(SDKLIB)/$(LIBCORE).so.$(VERSION)

$(SDKLIB)/$(LIBCORE).so.$(VERSION): $(SDKLIB)/$(LIBCORE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBCORE).so $(LDLIBS)

# TCP/IP

$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)

$(SDKLIB)/$(LIBTCPIP).so.$(VERSION): $(SDKLIB)/$(LIBTCPIP).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBTCPIP).so $(LDLIBS)

$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)

# LIB_MOBILE 4G 5G
$(SDKLIB)/$(LIBMOBILE).so: $(SDKLIB)/$(LIBMOBILE).so.$(VERSION)

$(SDKLIB)/$(LIBMOBILE).so.$(VERSION): $(SDKLIB)/$(LIBMOBILE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBMOBILE).so $(LDLIBS)

# BUSINESS APP/PROTOCOLS
$(SDKLIB)/$(LIBBAPP).so: $(SDKLIB)/$(LIBBAPP).so.$(VERSION)

$(SDKLIB)/$(LIBBAPP).so.$(VERSION): $(SDKLIB)/$(LIBBAPP).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBBAPP).so $(LDLIBS)

ifdef ENABLESEC
# FUZZ

$(SDKLIB)/$(LIBFUZZ).so: $(SDKLIB)/$(LIBFUZZ).so.$(VERSION)

$(SDKLIB)/$(LIBFUZZ).so.$(VERSION): $(SDKLIB)/$(LIBFUZZ).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBFUZZ).so $(LDLIBS)

# SECURITY

$(SDKLIB)/$(LIBSECURITY).so: $(SDKLIB)/$(LIBSECURITY).so.$(VERSION)

$(SDKLIB)/$(LIBSECURITY).so.$(VERSION): $(SDKLIB)/$(LIBSECURITY).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBSECURITY).so $(LDLIBS)
endif

# DICOM
$(SDKLIB)/$(LIBDICOM).so: $(SDKLIB)/$(LIBDICOM).so.$(VERSION)

$(SDKLIB)/$(LIBDICOM).so.$(VERSION): $(SDKLIB)/$(LIBDICOM).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBDICOM).so $(LDLIBS)
