
include $(RULESDIR)/common.mk

CFLAGS   += -D_WIN32_WINNT=0x0601
CFLAGS   += $(patsubst %,-I%,$(SRCINC))

CXXFLAGS += -D_WIN32_WINNT=0x0601
CXXFLAGS += $(patsubst %,-I%,$(SRCINC))

LDFLAGS  += -L$(SDKLIB) -static-libgcc -static-libstdc++


#  - - - - - - - - - - - - - - - - -
#  W I N D O W S   L I B R A R I E S
#  - - - - - - - - - - - - - - - - -

libraries: \
 $(SDKLIB)/$(LIBCORE).dll \
 $(SDKLIB)/$(LIBTCPIP).dll

# CORE

$(SDKLIB)/$(LIBCORE).dll: $(SDKLIB)/$(LIBCORE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--output-def,$(SDKLIB)/$(LIBCORE).def,--out-implib,$(SDKLIB)/$(LIBCORE)_dll.a -Wl,--soname=$(LIBCORE).dll $(LDFLAGS) -lws2_32

# TCP/IP

$(SDKLIB)/$(LIBTCPIP).dll: $(SDKLIB)/$(LIBTCPIP).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--output-def,$(SDKLIB)/$(LIBTCPIP).def,--out-implib,$(SDKLIB)/$(LIBTCPIP)_dll.a -Wl,--soname=$(LIBTCPIP).dll $(LDFLAGS) -Wl,-Bstatic -lz -Wl,-Bdynamic -lmmt_core -lws2_32

$(SDKLIB)/$(LIBTCPIP)_lib.a: $(SDKLIB)/$(LIBTCPIP).a
	@echo "[DLLTOOL] $(notdir $@)"
	$(QUIET) $(DLLTOOL) -l $@ $^

.INTERMEDIATE: $(SDKLIB)/$(LIBTCPIP)_lib.a

# SECURITY

$(SDKLIB)/$(LIBSECURITY).dll: $(SDKLIB)/$(LIBSECURITY).a $(SDKLIB)/$(LIBTCPIP)_lib.a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--output-def,$(SDKLIB)/$(LIBSECURITY).def,--out-implib,$(SDKLIB)/$(LIBSECURITY)_dll.a -Wl,--soname=$(LIBSECURITY).dll $(LDFLAGS) -lmmt_core -lxml2-2 -lws2_32

