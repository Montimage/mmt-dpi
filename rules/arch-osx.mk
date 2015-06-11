include $(RULESDIR)/common.mk

CFLAGS   += -D_OSX #-I/usr/local/Cellar/gcc48/4.8.4/include/c++/4.8.4/
CXXFLAGS += -D_OSX #-I/usr/local/Cellar/gcc48/4.8.4/include/c++/4.8.4/ #-Wno-missing-declarations -Wno-format

LDFLAGS  += -L$(SDKLIB)

$(CORE_OBJECTS) $(TCPIP_OBJECTS) $(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CFLAGS   += -fPIC
$(CORE_OBJECTS) $(TCPIP_OBJECTS) $(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CXXFLAGS += -fPIC

$(SECURITY_OBJECTS): CFLAGS += -I/usr/local/Cellar/libxml2/2.9.2/include/libxml2/
$(FUZZ_OBJECTS): CFLAGS += -I/usr/local/Cellar/libxml2/2.9.2/include/libxml2/

#  - - - - - - - - - - - - - - -
#  L I N U X   L I B R A R I E S
#  - - - - - - - - - - - - - - -

libraries: \
 $(SDKLIB)/$(LIBCORE).so \
 $(SDKLIB)/$(LIBTCPIP).so \
 $(SDKLIB)/$(LIBSECURITY).so #\
 $(SDKLIB)/$(LIBFUZZ).so

# CORE

$(SDKLIB)/$(LIBCORE).so: $(SDKLIB)/$(LIBCORE).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(LIBCORE).so.$(VERSION) $@

$(SDKLIB)/$(LIBCORE).so.$(VERSION): $(SDKLIB)/$(LIBCORE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,-force_load $^ -Wl,-install_name,$(LIBCORE).so

# TCP/IP

$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(LIBTCPIP).so.$(VERSION) $@

$(SDKLIB)/$(LIBTCPIP).so.$(VERSION): $(SDKLIB)/$(LIBTCPIP).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(LDFLAGS) -lmmt_core -shared -o $@ -Wl,-all_load $^ -Wl,-install_name,$(LIBTCPIP).so

# FUZZ

$(SDKLIB)/$(LIBFUZZ).so: $(SDKLIB)/$(LIBFUZZ).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(LIBFUZZ).so.$(VERSION) $@

$(SDKLIB)/$(LIBFUZZ).so.$(VERSION): $(SDKLIB)/$(LIBFUZZ).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(LDFLAGS) -lmmt_core -lxml2 -shared -o $@ -Wl,-all_load $^ -Wl,-install_name, -o $(LIBFUZZ).so

# SECURITY

$(SDKLIB)/$(LIBSECURITY).so: $(SDKLIB)/$(LIBSECURITY).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(LIBSECURITY).so.$(VERSION) $@

$(SDKLIB)/$(LIBSECURITY).so.$(VERSION): $(SDKLIB)/$(LIBSECURITY).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(LDFLAGS) -lmmt_core -lxml2 -shared -o $@ -Wl,-all_load $^ -Wl,-install_name,$(LIBSECURITY).so


CXX := g++48
CC  := gcc48
AR  := ar rcs