ARCH         ?= linux
TOPDIR       := $(realpath $(CURDIR)/..)
RULESDIR     := $(TOPDIR)/rules
VENDORDIR	 := $(TOPDIR)/vendors

default: sdk
.PHONY: sdk install clean dist-clean

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
	if ! grep -Fxq "$(PREFIX)/lib" /etc/ld.so.conf;then \
		echo "$(PREFIX)/lib" >> /etc/ld.so.conf; \
		ldconfig; \
	fi
	if ! grep -Fxq "/usr/local/lib" /etc/ld.so.conf;then \
		echo "/usr/local/lib" >> /etc/ld.so.conf; \
		ldconfig;\
	fi 	
	mkdir -p "/opt/mmt/plugins"
	$(CP) $(SDKLIB)/libmmt_tcpip.so.$(VERSION) $(PREFIX)/plugins/libmmt_tcpip.so

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

