VERSION  := 1.6.3.0
MMT_BASE ?=/opt/mmt
MMT_LIB ?= $(MMT_BASE)/lib
MMT_INC ?= $(MMT_BASE)/include
OPT_MMT_PLUGINS ?= $(MMT_BASE)/plugins
OPT_MMT_EXAMS ?= $(MMT_BASE)/examples

SDKINC       := ${shell pwd}/include
SDKLIB       := ${shell pwd}/lib
SDKXAM       := ${shell pwd}/examples

#  - - - - - - -
#  I N S T A L L
#  - - - - - - -
install:
	@ echo "Preparing location: "$(MMT_BASE)
	@ mkdir -p $(MMT_BASE)
	@ mkdir -p $(MMT_LIB)
	@ mkdir -p $(MMT_INC)
	@ mkdir -p $(OPT_MMT_PLUGINS)
	@ mkdir -p $(OPT_MMT_EXAMS)
	@ cp $(SDKLIB)/* $(MMT_LIB)
	@ echo "[MMT-]> Installed  "$(SDKLIB)" at "$(MMT_LIB)
	@ cp -R $(SDKINC)/* $(MMT_INC)
	@ echo "[MMT-]> Installed  "$(SDKINC)" at "$(MMT_INC)
	@ cp -R $(SDKXAM)/* $(OPT_MMT_EXAMS)
	@ echo "[MMT-]> Installed  "$(SDKXAM)" at "$(OPT_MMT_EXAMS)
	@ cp $(SDKLIB)/libmmt_tcpip.so.$(VERSION) $(OPT_MMT_PLUGINS)/libmmt_tcpip.so
	@ echo "[MMT-]> Installed "$(OPT_MMT_PLUGINS)/libmmt_tcpip.so
	@ echo "/opt/mmt/lib" >> /etc/ld.so.conf.d/mmt.conf
	@ ldconfig
	@ echo "[MMT-]> Done! "
	@ echo "Thanks you for installing mmt-sdk, you can learn more about mmt-sdk at: http://www.montimage.com"
# - - - - - - - - -  
# U N I N S T A L L 
# - - - - - - - - -  

uninstall:
	@ echo "[MMT-]> Going to remove MMT"
	@ rm -rf $(MMT_BASE)
	@ rm -rf /etc/ld.so.conf.d/mmt.conf
	@ echo "[MMT-]> Done!"