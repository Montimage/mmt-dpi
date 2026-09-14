VERSION  := 1.8.0
GIT_VERSION := $(shell git log --format="%h" -n 1)
MMT_BASE ?=/opt/mmt
MMT_DPI ?= $(MMT_BASE)/dpi
MMT_LIB ?= $(MMT_DPI)/lib
MMT_INC ?= $(MMT_DPI)/include
MMT_PLUGINS ?= $(MMT_BASE)/plugins
MMT_EXAMS ?= $(MMT_BASE)/examples

#  - - - - -
# DEFINE SOME COMMANDS
#  - - - - -

CP       := cp -R
RM       := rm -rf
MKDIR    := mkdir -p
#  - - - - -
# DEFINE VERBOSE MODE
#  - - - - -

ifndef VERBOSE
QUIET := @
export QUIET
endif

#  - - - - -
# DEFINE FLAG FOR COMPILE COMMAND
#  - - - - -

CFLAGS   := -Wall -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\" -DPLUGINS_REPOSITORY_OPT=\"$(MMT_PLUGINS)\"
CXXFLAGS := -Wall -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\" -DPLUGINS_REPOSITORY_OPT=\"$(MMT_PLUGINS)\"

# NDEBUG = 1 to show all messages from debug(), ... (i.e. keep asserts/debug()
# enabled by NOT defining the standard NDEBUG macro). The default build defines
# -DNDEBUG.
#   NOTE: the previous form "CFLAGS += $(CFLAGS)" was a bug - it appended CFLAGS
#   to itself (duplicating every flag) instead of toggling the NDEBUG macro.
ifdef NDEBUG
# NDEBUG=1 requested -> leave -DNDEBUG undefined so debug()/assert() stay active.
else
CFLAGS   += -DNDEBUG
CXXFLAGS += -DNDEBUG
endif

#  - - - - -
# LINK FLAGS / LINK LIBRARIES (B3, B4)
#  - - - - -
# -lm and -lnghttp2 are LINK libraries, not compile flags. Carrying them in
# CFLAGS made them silent no-ops (a "-c" compile never invokes the linker).
# They now live in LDFLAGS/LDLIBS and are added to the shared-library link
# recipes (see common-linux.mk). -L must point at a DIRECTORY, never at a file -
# the old "-L/usr/lib/.../libnghttp2.so" was a no-op and has been dropped.
LDFLAGS ?=
LDLIBS  := -lm

# nghttp2: prefer pkg-config, fall back to the historical hardcoded paths so the
# build still succeeds where the .pc file is absent (guarded - never emit empty
# flags that would silently break the link).
ifeq ($(shell pkg-config --exists libnghttp2 2>/dev/null && echo yes),yes)
NGHTTP2_CFLAGS := $(shell pkg-config --cflags libnghttp2)
NGHTTP2_LIBS   := $(shell pkg-config --libs libnghttp2)
else ifeq ($(shell printf 'int main(void){return 0;}' | $(CC) -x c - -lnghttp2 -o /dev/null 2>/dev/null && echo yes),yes)
# No pkg-config metadata, but the linker can still locate libnghttp2.
NGHTTP2_CFLAGS := -I/usr/include/nghttp2
NGHTTP2_LIBS   := -lnghttp2
else
# libnghttp2 is not installed. No built MMT library references any nghttp2_*
# symbol (the flag was historically a silent no-op on the compile line), so we
# emit nothing here rather than force "-lnghttp2" onto the link line and break
# the build where the library is absent (e.g. minimal CI images). When the
# library IS present it is still routed to the link line by the branches above.
NGHTTP2_CFLAGS :=
NGHTTP2_LIBS   :=
endif

# libxml2 (only the ENABLESEC security/fuzz engines need it): replace the
# hardcoded -I/usr/include/libxml2 with pkg-config, same guarded fallback.
ifeq ($(shell pkg-config --exists libxml-2.0 2>/dev/null && echo yes),yes)
LIBXML2_CFLAGS := $(shell pkg-config --cflags libxml-2.0)
LIBXML2_LIBS   := $(shell pkg-config --libs libxml-2.0)
else
LIBXML2_CFLAGS := -I/usr/include/libxml2
LIBXML2_LIBS   := -lxml2
endif

# DEBUG = 1 to enable debug mode
ifdef DEBUG
CFLAGS   += -g
CXXFLAGS += -g
else
CFLAGS   += -O3
CXXFLAGS += -O3
endif
# VALGRIND = 1 to compile for Valgrind test
ifdef VALGRIND
CFLAGS += -g -Wa,--gstabs -save-temps -O3
CXXFLAGS += -g -Wa,--gstabs -save-temps -O3
endif

# BUILD=asan to compile with AddressSanitizer + UndefinedBehaviorSanitizer.
#   This is the verification vehicle for the memory-safety hardening work
#   (see MASTER_IMPROVEMENT_PLAN.md, Phase 2): run crafted edge-case pcaps
#   through a library built with BUILD=asan to catch OOB reads/writes,
#   use-after-free and UB that an -O3 build silently tolerates.
#
#   Usage:
#     make BUILD=asan MMT_BASE=/tmp/mmt-asan
#     make BUILD=asan MMT_BASE=/tmp/mmt-asan install
#
#   The sanitizer flags are added to both CFLAGS and CXXFLAGS so they apply
#   at compile time AND to the link line of the shared libraries (the .so
#   recipes in common-{linux,osx}.mk link with $(CXXFLAGS)). The shared
#   objects leave the ASan/UBSan runtime symbols undefined; an instrumented
#   run resolves them by preloading the runtime, e.g.:
#     LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
#       ASAN_OPTIONS=detect_leaks=0 LD_LIBRARY_PATH=/tmp/mmt-asan/dpi/lib \
#       ./extract_all -t crafted.pcap
#   (leak detection is best left to Valgrind; ASan here targets memory-safety
#    and UB on untrusted packet input.)
ifeq ($(BUILD),asan)
SANITIZE_FLAGS := -g -O1 -fno-omit-frame-pointer -fno-common \
                  -fsanitize=address,undefined \
                  -fno-sanitize-recover=all \
                  -DMMT_BUILD_ASAN=1
CFLAGS   += $(SANITIZE_FLAGS)
CXXFLAGS += $(SANITIZE_FLAGS)
endif

# BUILD=tsan to compile with ThreadSanitizer.
#   This is the verification vehicle for the Phase 6 thread-safety hardening
#   work (issue #65, gating issues #22 registry mutexes and #23 per-session
#   RADIUS state). TSan only detects data races in code compiled with
#   -fsanitize=thread, and the race-prone code lives INSIDE the SDK libraries
#   (configured_protocols_mutex in packet_processing.c, plugin_handlers_list_mutex
#   in plugins_engine.c, per-session RADIUS state in proto_radius.c). So the SDK
#   itself must be built with this profile and the multi-threaded harness
#   (tools/phase0/tests/mt_tsan_harness.c) compiled + linked against it.
#
#   Usage:
#     make BUILD=tsan MMT_BASE=/tmp/mmt-tsan
#     make BUILD=tsan MMT_BASE=/tmp/mmt-tsan install
#
#   See tools/phase0/tests/run_mt_tsan_test.sh for the full build-install-run
#   pipeline and docs/THREADING.md for what the harness verifies.
#
#   As with the asan profile, the flags go on both CFLAGS and CXXFLAGS so they
#   reach the shared-library link lines (the .so recipes link with $(CXXFLAGS)).
#   The TSan runtime is linked directly into the instrumented harness; the .so
#   objects leave the runtime symbols undefined and resolve them at load time.
ifeq ($(BUILD),tsan)
SANITIZE_FLAGS := -g -O1 -fno-omit-frame-pointer -fno-common \
                  -fsanitize=thread \
                  -fno-sanitize-recover=all \
                  -DMMT_BUILD_TSAN=1
CFLAGS   += $(SANITIZE_FLAGS)
CXXFLAGS += $(SANITIZE_FLAGS)
endif

# SHOWLOG = 1 to show all the log from MMT_LOG() ...
ifdef SHOWLOG
CFLAGS   += -DDEBUG
CXXFLAGS += -DDEBUG
endif

# HTTP_PARSER_STRICT — strict-mode checks in the vendored HTTP parser
# (issue #204, F-BUG-060). This used to be coupled to SHOWLOG, so every
# release/CI build (no SHOWLOG) silently parsed leniently. It is now its own
# knob and defaults to 1; pass HTTP_PARSER_STRICT=0 to explicitly opt back
# into the lenient parser. http_parser.h defaults to 1 when the macro is
# undefined — keep the two in agreement.
ifndef HTTP_PARSER_STRICT
HTTP_PARSER_STRICT := 1
endif
CFLAGS   += -DHTTP_PARSER_STRICT=$(HTTP_PARSER_STRICT)
CXXFLAGS += -DHTTP_PARSER_STRICT=$(HTTP_PARSER_STRICT)

.PHONY: libraries includes tools documentation examples


#  - - - - -
#  P A T H S
#  - - - - -

SRCDIR       := $(TOPDIR)/src
SRCINC       := $(SRCDIR)/mmt_core/public_include  \
                $(SRCDIR)/mmt_core/private_include \
                $(SRCDIR)/mmt_tcpip/include \
                $(SRCDIR)/mmt_tcpip/lib \
                $(SRCDIR)/mmt_fuzz_engine

SDKDIR       := $(TOPDIR)/sdk
SDKDOC       := $(SDKDIR)/doc
SDKINC       := $(SDKDIR)/include
SDKINC_TCPIP := $(SDKDIR)/include/tcpip
SDKINC_MOBILE := $(SDKDIR)/include/mobile
SDKINC_B_APP  := $(SDKDIR)/include/business_app
SDKINC_DICOM := $(SDKDIR)/include/dicom
ifdef ENABLESEC
SDKINC_FUZZ  := $(SDKDIR)/include/fuzz
endif
SDKLIB       := $(SDKDIR)/lib
SDKBIN       := $(SDKDIR)/bin
SDKXAM       := $(SDKDIR)/examples

$(SDKLIB) $(SDKINC) $(SDKINC_TCPIP) $(SDKINC_MOBILE) $(SDKINC_B_APP) $(SDKINC_DICOM) $(SDKINC_FUZZ) $(SDKBIN) $(SDKDOC) $(SDKXAM) $(MMT_BASE) $(MMT_DPI) $(MMT_INC) $(MMT_PLUGINS) $(MMT_EXAMS) $(MMT_LIB):
	@mkdir -p $@


#  - - - - - - - - -
#  L I B R A R I E S
#  - - - - - - - - -

LIBCORE     := libmmt_core
LIBTCPIP    := libmmt_tcpip

#t to ensure libmmt_tmobile is after libmmt_tcpip in alphabet
#=> MMT will load libmmt_tcpip, then, libmmt_tmobile
LIBMOBILE   := libmmt_tmobile
LIBDICOM    := libmmt_tdicom
LIBBAPP     := libmmt_business_app
LIBEXTRACT  := libmmt_extract
ifdef ENABLESEC
LIBSECURITY := libmmt_security
LIBFUZZ     := libmmt_fuzz
endif

CORE_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_core/src/*.c)) \
 $(patsubst %.cpp,%.o,$(wildcard $(SRCDIR)/mmt_core/src/*.cpp))

# remove mmt_tcpip_init.o from CORE_OBJECTS
CORE_OBJECTS := $(filter-out $(SRCDIR)/mmt_core/src/mmt_tcpip_init.o,$(CORE_OBJECTS))

TCPIP_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_tcpip/lib/*.c)) \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_tcpip/lib/protocols/*.c))

LIBBAPP_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_business_app/*.c))

$(LIBBAPP_OBJECTS): CFLAGS +=  -Wno-unused-variable -fPIC

LIBDICOM_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_dicom/*.c))

$(LIBDICOM_OBJECTS): CFLAGS +=  -Wno-unused-variable -fPIC

# Extra diagnostic warnings (B5). These surface latent defects - format-string
# bugs, NULL dereferences, variable-length arrays - for triage. They are
# deliberately NOT -Werror: they only emit warnings, so the build still exits 0
# (golden/ASan gates stay green). Scoped to MMT's own core + tcpip sources to
# keep the output actionable rather than flooding it with diagnostics from the
# vendored/generated third-party code (http_parser, asn1c, ...).
#
# The default set is the high-signal, zero-noise subset: format-string, NULL-deref
# and VLA checks (the safety classes B5 targets) currently emit no warnings on
# MMT's own code. -Wextra is intentionally NOT enabled by default: its triage found
# only low-value style diagnostics (missing-field-initializers, unused-parameter,
# sign-compare - ~1.7k lines, zero real defects) that flooded the build output.
# To run that broad sweep again: make MMT_WARN_FLAGS='-Wextra -Wformat=2 -Wformat-security -Wnull-dereference -Wvla'
# To silence all extra warnings: make MMT_WARN_FLAGS=
MMT_WARN_FLAGS ?= -Wformat=2 -Wformat-security -Wnull-dereference -Wvla

$(CORE_OBJECTS) $(TCPIP_OBJECTS): CFLAGS += -D_MMT_BUILD_SDK $(MMT_WARN_FLAGS) $(patsubst %,-I%,$(SRCINC))
$(CORE_OBJECTS) $(TCPIP_OBJECTS): CXXFLAGS += -D_MMT_BUILD_SDK $(MMT_WARN_FLAGS) $(patsubst %,-I%,$(SRCINC))

LIBMOBILE_OBJECTS := \
	$(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_mobile/*.c))     \
	$(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_mobile/*/*.c))   \
	$(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_mobile/*/*/*.c))

#specific include paths for mmt_mobile
LIBMOBILE_INC := $(SRCINC)          \
   $(SRCDIR)/mmt_mobile/            \
   $(SRCDIR)/mmt_mobile/include     \
	$(SRCDIR)/mmt_mobile/nas         \
	$(SRCDIR)/mmt_mobile/nas/util    \
	$(SRCDIR)/mmt_mobile/nas/emm     \
	$(SRCDIR)/mmt_mobile/asn1c/common\
	$(SRCDIR)/mmt_mobile/asn1c/s1ap  \
	$(SRCDIR)/mmt_mobile/asn1c/ngap

# Link libraries (-lm, -lnghttp2) belong on the link line (LDLIBS), not here:
# the nghttp2 include path is provided via $(NGHTTP2_CFLAGS) for any header use.
$(LIBMOBILE_OBJECTS): CFLAGS +=  -Wno-unused-but-set-variable -Wno-unused-variable -fPIC $(NGHTTP2_CFLAGS) -D_MMT_BUILD_SDK $(patsubst %,-I%,$(LIBMOBILE_INC))

$(TCPIP_OBJECTS): CFLAGS +=   $(NGHTTP2_CFLAGS)
ifdef ENABLESEC
FUZZ_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_fuzz_engine/*.c))

SECURITY_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_security/*.c))

$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CFLAGS += -D_MMT_BUILD_SDK $(patsubst %,-I%,$(SRCINC))
$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CXXFLAGS += -D_MMT_BUILD_SDK $(patsubst %,-I%,$(SRCINC))
endif

# CORE

$(SDKLIB)/$(LIBCORE).a: $(SDKLIB) $(CORE_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(CORE_OBJECTS)

# TCP/IP

$(SDKLIB)/$(LIBTCPIP).a: $(SDKLIB) $(TCPIP_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(TCPIP_OBJECTS)

# MOBILE

$(SDKLIB)/$(LIBMOBILE).a: $(SDKLIB) $(LIBMOBILE_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(LIBMOBILE_OBJECTS)

# BUSINESS APP/PROTOCOL
$(SDKLIB)/$(LIBBAPP).a: $(SDKLIB) $(LIBBAPP_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(LIBBAPP_OBJECTS)
ifdef ENABLESEC
# FUZZ

$(SDKLIB)/$(LIBFUZZ).a: $(SDKLIB) $(FUZZ_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(FUZZ_OBJECTS)

# SECURITY

$(SDKLIB)/$(LIBSECURITY).a: $(SDKLIB) $(SECURITY_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(SECURITY_OBJECTS)
endif

# DICOM
$(SDKLIB)/$(LIBDICOM).a: $(SDKLIB) $(LIBDICOM_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(LIBDICOM_OBJECTS)

#  - - - - - - - -
#  I N C L U D E S
#  - - - - - - - -

MMT_HEADERS       = $(wildcard $(SRCDIR)/mmt_core/public_include/*.h)
SDK_HEADERS       = $(addprefix $(SDKINC)/,$(notdir $(MMT_HEADERS)))

MMT_TCPIP_HEADERS = $(wildcard $(SRCDIR)/mmt_tcpip/include/*.h)
SDK_TCPIP_HEADERS = $(addprefix $(SDKINC_TCPIP)/,$(notdir $(MMT_TCPIP_HEADERS)))

mmt_mobile_HEADERS = $(wildcard $(SRCDIR)/mmt_mobile/include/*.h)
SDK_MOBILE_HEADERS = $(addprefix $(SDKINC_MOBILE)/,$(notdir $(mmt_mobile_HEADERS)))

B_APP_HEADERS = $(wildcard $(SRCDIR)/mmt_business_appinclude/*.h)
SDK_B_APP_HEADERS = $(addprefix $(SDKINC_B_APP)/,$(notdir $(B_APP_HEADERS)))

DICOM_HEADERS = $(wildcard $(SRCDIR)/mmt_dicom/include/*.h)
SDK_DICOM_HEADERS = $(addprefix $(SDKINC_DICOM)/,$(notdir $(DICOM_HEADERS)))

includes: $(SDK_HEADERS) $(SDK_TCPIP_HEADERS) $(SDK_MOBILE_HEADERS) $(SDK_B_APP_HEADERS) $(SDK_DICOM_HEADERS)

ifdef ENABLESEC
MMT_FUZZ_HEADERS = $(wildcard $(SRCDIR)/mmt_fuzz_engine/*.h)
SDK_FUZZ_HEADERS = $(addprefix $(SDKINC_FUZZ)/,$(notdir $(MMT_FUZZ_HEADERS)))
includes: $(SDK_FUZZ_HEADERS)
endif

$(SDKINC)/%.h: $(SRCDIR)/mmt_core/public_include/%.h
	@echo "[INCLUDE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDKINC_TCPIP)/%.h: $(SRCDIR)/mmt_tcpip/include/%.h
	@echo "[INCLUDE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDKINC_MOBILE)/%.h: $(SRCDIR)/mmt_mobile/include/%.h
	@echo "[INCLUDE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDKINC_B_APP)/%.h: $(SRCDIR)/mmt_business_app/include/%.h
	@echo "[INCLUDE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDKINC_DICOM)/%.h: $(SRCDIR)/mmt_dicom/include/%.h
	@echo "[INCLUDE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDK_HEADERS): $(SDKINC) $(SDKINC_TCPIP) $(SDKINC_MOBILE) $(SDKINC_B_APP) $(SDKINC_DICOM)

ifdef ENABLESEC
$(SDKINC_FUZZ)/%.h: $(SRCDIR)/mmt_fuzz_engine/%.h
	@echo "[INCLUDE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDK_HEADERS): $(SDKINC_FUZZ)
endif




#  - - - - -
#  T O O L S
#  - - - - -

tools: $(SDKBIN)


#  - - - - - - - - - - - - -
#  D O C U M E N T A T I O N
#  - - - - - - - - - - - - -

documentation: $(SDKDOC)


#  - - - - - - - -
#  E X A M P L E S
#  - - - - - - - -

MMT_EXAMPLES_SRC = attribute_handler_session_counter.c extract_all.c google-fr.pcap html_integration.c html_integration.h MAC_extraction.c packet_handler.c proto_attributes_iterator.c reconstruct_body.c simple_traffic_reporting.c
SDK_EXAMPLES_SRC = $(addprefix $(SDKXAM)/,$(MMT_EXAMPLES_SRC))

examples: $(SDK_EXAMPLES_SRC)
#  $(QUIET) $(MAKE) -C $(SRCDIR)/examples -f Makefile.mmt SDKROOT=$(TOPDIR)/sdk

$(SDKXAM)/%.c: $(SRCDIR)/examples/%.c
	@echo "[EXAMPLE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDK_EXAMPLES_SRC): $(SDKXAM)


#  - - - - -
#  R U L E S
#  - - - - -

%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) -I. -o $@ -c $<

%.o: %.cc
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -I. -o $@ -c $<

%.o: %.cpp
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -I. -o $@ -c $<

