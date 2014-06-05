
ARCH         ?= linux
TOPDIR       := $(realpath $(CURDIR)/..)
RULESDIR     := $(TOPDIR)/rules

default: sdk
.PHONY: sdk install clean

include $(RULESDIR)/arch-$(ARCH).mk


#  - - -
#  S D K
#  - - -

sdk: libraries includes tools documentation examples


#  - - - - - - -
#  I N S T A L L
#  - - - - - - -

install: sdk $(PREFIX)
	$(CP) $(SDKLIB) $(PREFIX)
	$(CP) $(SDKBIN) $(PREFIX)
	$(CP) $(SDKINC) $(PREFIX)
	$(CP) $(SDKDOC) $(PREFIX)
	$(CP) $(SDKXAM) $(PREFIX)


#  - - - - -
#  C L E A N
#  - - - - -

clean:
	$(QUIET) $(RM) $(CORE_OBJECTS) $(TCPIP_OBJECTS) $(FUZZ_OBJECTS) $(SECURITY_OBJECTS)
	$(QUIET) $(RM) $(SDKLIB) $(SDKBIN) $(SDKINC) $(SDKDOC) $(SDKXAM)

