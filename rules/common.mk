 
VERSION  := 0.100
PREFIX   ?= /opt/mmt

CFLAGS   := -Wall
CXXFLAGS := -Wall

CP       := cp -R
RM       := rm -rf

ifndef VERBOSE
 QUIET := @
 export QUIET
endif

ifdef DEBUG
CFLAGS   += -g -DDEBUG
CXXFLAGS += -g -DDEBUG
endif

.PHONY: libraries includes tools documentation examples


#  - - - - -
#  P A T H S
#  - - - - -

SRCDIR       := $(TOPDIR)/src
SRCINC       := $(SRCDIR)/mmt_core/public_include  \
                $(SRCDIR)/mmt_core/private_include \
                $(SRCDIR)/mmt_fuzz_engine          \
                $(SRCDIR)/mmt_tcpip/include        \
                $(SRCDIR)/mmt_tcpip/lib

SDKDIR       := $(TOPDIR)/sdk
SDKDOC       := $(SDKDIR)/doc
SDKINC       := $(SDKDIR)/include
SDKINC_TCPIP := $(SDKDIR)/include/tcpip
SDKINC_FUZZ  := $(SDKDIR)/include/fuzz
SDKLIB       := $(SDKDIR)/lib
SDKBIN       := $(SDKDIR)/bin
SDKXAM       := $(SDKDIR)/examples

$(SDKLIB) $(SDKINC) $(SDKINC_TCPIP) $(SDKINC_FUZZ) $(SDKBIN) $(SDKDOC) $(SDKXAM) $(PREFIX):
	@mkdir -p $@


#  - - - - - - - - -
#  L I B R A R I E S
#  - - - - - - - - -

LIBCORE     := libmmt_core
LIBTCPIP    := libmmt_tcpip
LIBEXTRACT  := libmmt_extract
LIBSECURITY := libmmt_security
LIBFUZZ     := libmmt_fuzz

CORE_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_core/src/*.c)) \
 $(patsubst %.cpp,%.o,$(wildcard $(SRCDIR)/mmt_core/src/*.cpp))

# remove mmt_tcpip_init.o from CORE_OBJECTS
CORE_OBJECTS := $(filter-out $(SRCDIR)/mmt_core/src/mmt_tcpip_init.o,$(CORE_OBJECTS))

TCPIP_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_tcpip/lib/*.c)) \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_tcpip/lib/protocols/*.c)) 

FUZZ_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_fuzz_engine/*.c))

SECURITY_OBJECTS := \
 $(patsubst %.c,%.o,$(wildcard $(SRCDIR)/mmt_security/*.c))

$(CORE_OBJECTS) $(TCPIP_OBJECTS) $(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CFLAGS   += -D_MMT_BUILD_SDK $(patsubst %,-I%,$(SRCINC))
$(CORE_OBJECTS) $(TCPIP_OBJECTS) $(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CXXFLAGS += -D_MMT_BUILD_SDK $(patsubst %,-I%,$(SRCINC))

# CORE

$(SDKLIB)/$(LIBCORE).a: $(SDKLIB) $(CORE_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(CORE_OBJECTS)

# TCP/IP

$(SDKLIB)/$(LIBTCPIP).a: $(SDKLIB) $(TCPIP_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(TCPIP_OBJECTS)

# FUZZ

$(SDKLIB)/$(LIBFUZZ).a: $(SDKLIB) $(FUZZ_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(FUZZ_OBJECTS)

# SECURITY

$(SDKLIB)/$(LIBSECURITY).a: $(SDKLIB) $(SECURITY_OBJECTS)
	@echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $@ $(SECURITY_OBJECTS)


#  - - - - - - - -
#  I N C L U D E S
#  - - - - - - - -

MMT_HEADERS       = $(wildcard $(SRCDIR)/mmt_core/public_include/*.h)
SDK_HEADERS       = $(addprefix $(SDKINC)/,$(notdir $(MMT_HEADERS)))

MMT_TCPIP_HEADERS = $(wildcard $(SRCDIR)/mmt_tcpip/include/*.h)
SDK_TCPIP_HEADERS = $(addprefix $(SDKINC_TCPIP)/,$(notdir $(MMT_TCPIP_HEADERS)))

MMT_FUZZ_HEADERS = $(wildcard $(SRCDIR)/mmt_fuzz_engine/*.h)
SDK_FUZZ_HEADERS = $(addprefix $(SDKINC_FUZZ)/,$(notdir $(MMT_FUZZ_HEADERS)))

includes: $(SDK_HEADERS) $(SDK_TCPIP_HEADERS) $(SDK_FUZZ_HEADERS)

$(SDKINC)/%.h: $(SRCDIR)/mmt_core/public_include/%.h
	@echo "[INCLUDE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDKINC_TCPIP)/%.h: $(SRCDIR)/mmt_tcpip/include/%.h
	@echo "[INCLUDE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDKINC_FUZZ)/%.h: $(SRCDIR)/mmt_fuzz_engine/%.h
	@echo "[INCLUDE] $(notdir $@)"
	$(QUIET) cp -f $< $@

$(SDK_HEADERS): $(SDKINC) $(SDKINC_TCPIP) $(SDKINC_FUZZ)


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

MMT_EXAMPLES_SRC = extract_all.c proto_attributes_iterator.c attribute_handler_session_counter.c packet_handler.c simple_traffic_reporting.c tcp_plugin_image.pcap
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

