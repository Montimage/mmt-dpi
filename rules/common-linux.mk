
include $(RULESDIR)/common.mk

$(CORE_OBJECTS) $(TCPIP_OBJECTS): CFLAGS   += -fPIC
$(CORE_OBJECTS) $(TCPIP_OBJECTS): CXXFLAGS += -fPIC
ifdef ENABLESEC
$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CFLAGS   += -fPIC
$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CXXFLAGS += -fPIC
$(SECURITY_OBJECTS): CFLAGS += -I/usr/include/libxml2
$(FUZZ_OBJECTS): CFLAGS += -I/usr/include/libxml2 
endif
CXXFLAGS += 
#  - - - - - - - - - - - - - - -
#  L I N U X   L I B R A R I E S
#  - - - - - - - - - - - - - - -


libraries: \
	$(SDKLIB)/$(LIBCORE).so \
	$(SDKLIB)/$(LIBTCPIP).so \
	$(SDKLIB)/$(LIBMOBILE).so \
	$(SDKLIB)/$(LIBBAPP).so
ifdef ENABLESEC
libraries: \
	$(SDKLIB)/$(LIBFUZZ).so \
	$(SDKLIB)/$(LIBSECURITY).so
endif
# CORE

$(SDKLIB)/$(LIBCORE).so: $(SDKLIB)/$(LIBCORE).so.$(VERSION)

$(SDKLIB)/$(LIBCORE).so.$(VERSION): $(SDKLIB)/$(LIBCORE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBCORE).so

# TCP/IP

$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)

$(SDKLIB)/$(LIBTCPIP).so.$(VERSION): $(SDKLIB)/$(LIBTCPIP).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -I/usr/include/nghttp2 -shared  -L/usr/lib/x86_64-linux-gnu/ -o  $@  -Wl,--whole-archive $^ -lnghttp2 -Wl,--no-whole-archive -Wl,--soname=$(LIBTCPIP).so
#libraries to be linked must be after $^ symbol
$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)

# LIB_MOBILE 4G 5G
$(SDKLIB)/$(LIBMOBILE).so: $(SDKLIB)/$(LIBMOBILE).so.$(VERSION)

$(SDKLIB)/$(LIBMOBILE).so.$(VERSION): $(SDKLIB)/$(LIBMOBILE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBMOBILE).so
	
# BUSINESS APP/PROTOCOLS
$(SDKLIB)/$(LIBBAPP).so: $(SDKLIB)/$(LIBBAPP).so.$(VERSION)

$(SDKLIB)/$(LIBBAPP).so.$(VERSION): $(SDKLIB)/$(LIBBAPP).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBBAPP).so
	
ifdef ENABLESEC
# FUZZ

$(SDKLIB)/$(LIBFUZZ).so: $(SDKLIB)/$(LIBFUZZ).so.$(VERSION)

$(SDKLIB)/$(LIBFUZZ).so.$(VERSION): $(SDKLIB)/$(LIBFUZZ).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBFUZZ).so

# SECURITY

$(SDKLIB)/$(LIBSECURITY).so: $(SDKLIB)/$(LIBSECURITY).so.$(VERSION)

$(SDKLIB)/$(LIBSECURITY).so.$(VERSION): $(SDKLIB)/$(LIBSECURITY).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBSECURITY).so
endif
