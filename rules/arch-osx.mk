include $(RULESDIR)/common.mk

CFLAGS   += -D_OSX #-I/usr/local/Cellar/gcc48/4.8.4/include/c++/4.8.4/
CXXFLAGS += -D_OSX #-I/usr/local/Cellar/gcc48/4.8.4/include/c++/4.8.4/ #-Wno-missing-declarations -Wno-format

LDFLAGS  += -L$(SDKLIB)

$(CORE_OBJECTS) $(TCPIP_OBJECTS): CFLAGS   += -fPIC
$(CORE_OBJECTS) $(TCPIP_OBJECTS): CXXFLAGS += -fPIC

ifdef ENABLESEC
$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CFLAGS   += -fPIC
$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CXXFLAGS += -fPIC
$(SECURITY_OBJECTS): CFLAGS += -I/opt/homebrew/opt/libxml2/include/libxml2/
$(FUZZ_OBJECTS): CFLAGS += -I/opt/homebrew/opt/libxml2/include/libxml2/
endif
#  - - - - - - - - - - - - - - -
#  L I N U X   L I B R A R I E S
#  - - - - - - - - - - - - - - -

libraries: \
 $(SDKLIB)/$(LIBCORE).so \
 $(SDKLIB)/$(LIBTCPIP).so
ifdef ENABLESEC
libraries: \
 $(SDKLIB)/$(LIBSECURITY).so #\
 $(SDKLIB)/$(LIBFUZZ).so
endif
# CORE

$(SDKLIB)/$(LIBCORE).so: $(SDKLIB)/$(LIBCORE).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(notdir $<) $@

$(SDKLIB)/$(LIBCORE).so.$(VERSION): $(SDKLIB)/$(LIBCORE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,-force_load,$^ -Wl,-install_name,@rpath/$(LIBCORE).so.$(VERSION) -Wl,-rpath,@loader_path

# TCP/IP

$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(notdir $<) $@

$(SDKLIB)/$(LIBTCPIP).so.$(VERSION): $(SDKLIB)/$(LIBTCPIP).a $(SDKLIB)/$(LIBCORE).so.$(VERSION)
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,-force_load,$(SDKLIB)/$(LIBTCPIP).a -L$(SDKLIB) -lmmt_core -Wl,-install_name,@rpath/$(LIBTCPIP).so.$(VERSION) -Wl,-rpath,@loader_path

ifdef ENABLESEC
# FUZZ

$(SDKLIB)/$(LIBFUZZ).so: $(SDKLIB)/$(LIBFUZZ).so.$(VERSION)

$(SDKLIB)/$(LIBFUZZ).so.$(VERSION): $(SDKLIB)/$(LIBFUZZ).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(LDFLAGS) -lmmt_core -lxml2 -shared -o $@ -Wl,-all_load $^ -Wl,-install_name, -o $(LIBFUZZ).so

# SECURITY

$(SDKLIB)/$(LIBSECURITY).so: $(SDKLIB)/$(LIBSECURITY).so.$(VERSION)

$(SDKLIB)/$(LIBSECURITY).so.$(VERSION): $(SDKLIB)/$(LIBSECURITY).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(LDFLAGS) -lmmt_core -lxml2 -shared -o $@ -Wl,-all_load $^ -Wl,-install_name,$(LIBSECURITY).so
endif

CXX := clang++
CC  := clang
AR  := ar rcs
