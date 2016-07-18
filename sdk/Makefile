ARCH         ?= linux
TOPDIR       := $(realpath $(CURDIR)/..)
RULESDIR     := $(TOPDIR)/rules

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

install: sdk $(MMT_BASE) $(MMT_DPI) $(MMT_INC) $(MMT_PLUGINS) $(MMT_EXAMS) $(MMT_LIB)
	@ cp $(SDKLIB)/* $(MMT_LIB)
	@ echo "[MMT-]> Installed  "$(SDKLIB)" at "$(MMT_LIB)
	@ cp -R $(SDKINC)/* $(MMT_INC)
	@ echo "[MMT-]> Installed  "$(SDKINC)" at "$(MMT_INC)
	@ cp -R $(SDKXAM)/* $(MMT_EXAMS)
	@ echo "[MMT-]> Installed  "$(SDKXAM)" at "$(MMT_EXAMS)
	@ cp $(SDKLIB)/libmmt_tcpip.so.$(VERSION) $(MMT_PLUGINS)/libmmt_tcpip.so
	@ echo "[MMT-]> Installed "$(MMT_PLUGINS)/libmmt_tcpip.so
	@ echo $(MMT_DPI)"/lib" >> /etc/ld.so.conf.d/mmt.conf
	@ ldconfig
	@ echo "[MMT-]> Done! "
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
	@ echo "[MMT-]> Going to remove MMT"
	$(QUIET) $(RM) $(MMT_DPI)
	$(QUIET) $(RM) /etc/ld.so.conf.d/mmt.conf
	@ echo "[MMT-]> Done!"