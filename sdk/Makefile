ARCH         ?= linux
TOPDIR       := $(realpath $(CURDIR)/..)
RULESDIR     := $(TOPDIR)/rules
VENDORDIR	 := $(TOPDIR)/vendors/

default: sdk
.PHONY: sdk install clean dist-clean

include $(RULESDIR)/arch-$(ARCH).mk


#  - - -
#  S D K
#  - - -

sdk: ntoh libraries includes tools documentation examples


#  - - -
#  S D K
#  - - -

ntoh:
	cd $(VENDORDIR)/libntoh/src;mkdir build;cd build;cmake .. -DCMAKE_INSTALL_PREFIX=$(PREFIX);make;sudo make install;
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


# - - - - - - - - - - 
# D I S T - C L E A N
# - - - - - - - - - - 

dist-clean:
	$(QUIET) $(RM) $(PREFIX)/*

