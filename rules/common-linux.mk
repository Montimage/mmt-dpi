
include $(RULESDIR)/common.mk

$(CORE_OBJECTS) $(TCPIP_OBJECTS) $(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CFLAGS   += -fPIC
$(CORE_OBJECTS) $(TCPIP_OBJECTS) $(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CXXFLAGS += -fPIC

$(SECURITY_OBJECTS): CFLAGS += -I/usr/include/libxml2
$(FUZZ_OBJECTS): CFLAGS += -I/usr/include/libxml2

#  - - - - - - - - - - - - - - -
#  L I N U X   L I B R A R I E S
#  - - - - - - - - - - - - - - -

libraries: \
 $(SDKLIB)/$(LIBCORE).so \
 $(SDKLIB)/$(LIBFUZZ).so \
 $(SDKLIB)/$(LIBTCPIP).so \
 $(SDKLIB)/$(LIBSECURITY).so

# CORE

$(SDKLIB)/$(LIBCORE).so: $(SDKLIB)/$(LIBCORE).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(LIBCORE).so.$(VERSION) $@

$(SDKLIB)/$(LIBCORE).so.$(VERSION): $(SDKLIB)/$(LIBCORE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBCORE).so

# TCP/IP

$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(LIBTCPIP).so.$(VERSION) $@

$(SDKLIB)/$(LIBTCPIP).so.$(VERSION): $(SDKLIB)/$(LIBTCPIP).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBTCPIP).so

# FUZZ

$(SDKLIB)/$(LIBFUZZ).so: $(SDKLIB)/$(LIBFUZZ).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(LIBFUZZ).so.$(VERSION) $@

$(SDKLIB)/$(LIBFUZZ).so.$(VERSION): $(SDKLIB)/$(LIBFUZZ).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBFUZZ).so

# SECURITY

$(SDKLIB)/$(LIBSECURITY).so: $(SDKLIB)/$(LIBSECURITY).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(LIBSECURITY).so.$(VERSION) $@

$(SDKLIB)/$(LIBSECURITY).so.$(VERSION): $(SDKLIB)/$(LIBSECURITY).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBSECURITY).so


