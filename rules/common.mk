VERSION  := 1.7.8
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

CFLAGS   := -lm -Wall -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\" -DPLUGINS_REPOSITORY_OPT=\"$(MMT_PLUGINS)\"
CXXFLAGS := -lm -Wall -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\" -DPLUGINS_REPOSITORY_OPT=\"$(MMT_PLUGINS)\"

# NDEBUG = 1 to show all message come from debug(), ...
ifdef NDEBUG
CFLAGS   += $(CFLAGS)
CXXFLAGS += $(CXXFLAGS)
else
CFLAGS   += -DNDEBUG
CXXFLAGS += -DNDEBUG
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

# SHOWLOG = 1 to show all the log from MMT_LOG() ...
ifdef SHOWLOG
CFLAGS   += -DDEBUG -DHTTP_PARSER_STRICT=1
CXXFLAGS += -DDEBUG -DHTTP_PARSER_STRICT=1
else
CFLAGS   += -DHTTP_PARSER_STRICT=0
CXXFLAGS += -DHTTP_PARSER_STRICT=0
endif

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
ifdef ENABLESEC
SDKINC_FUZZ  := $(SDKDIR)/include/fuzz
endif
SDKLIB       := $(SDKDIR)/lib
SDKBIN       := $(SDKDIR)/bin
SDKXAM       := $(SDKDIR)/examples

$(SDKLIB) $(SDKINC) $(SDKINC_TCPIP) $(SDKINC_MOBILE) $(SDKINC_B_APP) $(SDKINC_FUZZ) $(SDKBIN) $(SDKDOC) $(SDKXAM) $(MMT_BASE) $(MMT_DPI) $(MMT_INC) $(MMT_PLUGINS) $(MMT_EXAMS) $(MMT_LIB):
	@mkdir -p $@


#  - - - - - - - - -
#  L I B R A R I E S
#  - - - - - - - - -

LIBCORE     := libmmt_core
LIBTCPIP    := libmmt_tcpip

#t to ensure libmmt_tmobile is after libmmt_tcpip in alphabet
#=> MMT will load libmmt_tcpip, then, libmmt_tmobile
LIBMOBILE   := libmmt_tmobile
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

$(LIBBAPP_OBJECTS): CFLAGS +=  -lm -Wno-unused-variable -fPIC

$(CORE_OBJECTS) $(TCPIP_OBJECTS): CFLAGS += -D_MMT_BUILD_SDK $(patsubst %,-I%,$(SRCINC))
$(CORE_OBJECTS) $(TCPIP_OBJECTS): CXXFLAGS += -D_MMT_BUILD_SDK $(patsubst %,-I%,$(SRCINC))

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

$(LIBMOBILE_OBJECTS): CFLAGS +=  -Wno-unused-but-set-variable -lm -Wno-unused-variable -fPIC -lnghttp2 -D_MMT_BUILD_SDK $(patsubst %,-I%,$(LIBMOBILE_INC))
	
$(TCPIP_OBJECTS): CFLAGS +=   -I/usr/include/nghttp2 -lnghttp2 -L/usr/lib/x86_64-linux-gnu/libnghttp2.so
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

includes: $(SDK_HEADERS) $(SDK_TCPIP_HEADERS) $(SDK_MOBILE_HEADERS) $(SDK_B_APP_HEADERS)

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
	
$(SDK_HEADERS): $(SDKINC) $(SDKINC_TCPIP) $(SDKINC_MOBILE) $(SDKINC_B_APP)

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
	$(QUIET) $(CC) $(CFLAGS) -I. -I/usr/include/nghttp2 -lnghttp2 -o $@ -lnghttp2  -c $<

%.o: %.cc
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -I. -o $@ -c $<

%.o: %.cpp
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -I. -o $@ -c $<

