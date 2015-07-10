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

install: sdk $(USR_INCLUDE) $(OPT_MMT_PLUGINS) 
	@ cp $(SDKLIB)/* $(USR_LIB)
	@ echo "Installed  "$(SDKLIB)" at "$(USR_LIB)
	@ cp -R $(SDKINC) $(USR_INCLUDE)
	@ echo "Installed  "$(SDKINC)" at "$(USR_INCLUDE)
	@ echo "# include \"mmt/mmt_core.h\"" >> /usr/include/mmt_core.h
	@ echo "Installed /usr/include/mmt_core.h"
	@ cp $(SDKLIB)/libmmt_tcpip.so.$(VERSION) $(OPT_MMT_PLUGINS)/libmmt_tcpip.so
	@ echo "Installed  "$(SDKLIB)/libmmt_tcpip.so.$(VERSION)" at "$(OPT_MMT_PLUGINS)/libmmt_tcpip.so

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
	$(QUIET) $(RM) $(USR_LIB)/libmmt_*
	@ echo "Removed " $(USR_LIB)/libmmt_*
	$(QUIET) $(RM) $(USR_INCLUDE)/*
	@ echo "Removed " $(USR_INCLUDE)
	$(QUIET) $(RM) $(OPT_MMT_PLUGINS)
	@ echo "Removed " $(OPT_MMT_PLUGINS)
	$(QUIET) rm -f /usr/include/mmt_core.h
	@ echo "Removed " /usr/include/mmt_core.h

