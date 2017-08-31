ARCH         ?= linux
TOPDIR       := $(realpath $(CURDIR)/..)
RULESDIR     := $(TOPDIR)/rules
# Set name of package with given version
BUILD_DIR	 :=mmt-dpi_$(VERSION)_`uname -s`_`uname -p`_`date +%s`

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

#  - - - - - - -
#  B U I L D   D E B
#  - - - - - - -
SYS_NAME    = $(shell uname -s)
SYS_VERSION = $(shell uname -p)

ifdef DEBUG
	BUILD_DIR = mmt-dpi_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)_debug
else
	BUILD_DIR = mmt-dpi_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)
endif

deb: sdk $(SDKLIB) $(SDKINC) $(SDKXAM)
	echo $(BUILD_DIR)
	# Remove old build
	$(QUIET) $(RM) $(BUILD_DIR)
	# Create new build location
	$(QUIET) $(MKDIR) $(BUILD_DIR)/DEBIAN
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/dpi
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/dpi/lib
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/dpi/include
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/examples
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/plugins
	$(QUIET) $(MKDIR) $(BUILD_DIR)/etc
	$(QUIET) $(MKDIR) $(BUILD_DIR)/etc/ld.so.conf.d/

	$(QUIET) echo "Package: mmt-dpi \
        \nVersion: $(VERSION)-$(GIT_VERSION)\
        \nSection: base \
        \nPriority: standard \
        \nArchitecture: all \
        \nMaintainer: Montimage <contact@montimage.com> \
        \nDescription: MMT-DPI:  \
        \n (Built time: `date +"%Y-%m-%d %H:%M:%S"`) \
        \n A software C library desinged to extract data attributes from network packets, server logs, and from structured events in general, in odrder to make them available for analysis \
        \n Homepage: http://www.montimage.com" \
		> $(BUILD_DIR)/DEBIAN/control
	# Copy resources
	echo $(SDKLIB)
	$(QUIET) $(CP) $(SDKLIB)/* $(BUILD_DIR)/opt/mmt/dpi/lib
	$(QUIET) ln -s $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_core.so.* $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_core.so
	$(QUIET) ln -s $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_fuzz.so.* $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_fuzz.so
	$(QUIET) ln -s $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_security.so.* $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_security.so
	$(QUIET) ln -s $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_tcpip.so.* $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_tcpip.so
	$(QUIET) $(CP) -r $(SDKINC) $(BUILD_DIR)/opt/mmt/dpi
	# $(QUIET) $(CP) -r $(SDKINC) $(BUILD_DIR)/opt/mmt/dpi
	# $(QUIET) $(CP) -r $(SDKINC) $(BUILD_DIR)/opt/mmt/dpi
	$(QUIET) $(CP) -r $(SDKXAM) $(BUILD_DIR)/opt/mmt
	$(QUIET) $(CP) $(SDKLIB)/libmmt_tcpip.so.$(VERSION) $(BUILD_DIR)/opt/mmt/plugins/libmmt_tcpip.so
	echo "/opt/mmt/dpi/lib" >> $(BUILD_DIR)/etc/ld.so.conf.d/mmt-dpi.conf
	
	$(QUIET) dpkg-deb -b $(BUILD_DIR)
	$(QUIET) $(RM) $(BUILD_DIR)

#  - - - - - - - - - -
#  B U I L D   R P M
#  - - - - - - - - - -

rpm: sdk $(SDKLIB) $(SDKINC) $(SDKXAM)
	echo $(BUILD_DIR)
	# Remove old build
	$(QUIET) $(RM) $(BUILD_DIR)
	# Create new build location
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/dpi
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/dpi/lib
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/dpi/include
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/examples
	$(QUIET) $(MKDIR) $(BUILD_DIR)/opt/mmt/plugins
	$(QUIET) $(MKDIR) $(BUILD_DIR)/etc
	$(QUIET) $(MKDIR) $(BUILD_DIR)/etc/ld.so.conf.d/
	# Copy resources
	echo $(SDKLIB)
	$(QUIET) $(CP) $(SDKLIB)/* $(BUILD_DIR)/opt/mmt/dpi/lib	
	$(QUIET) $(CP) -r $(SDKINC) $(BUILD_DIR)/opt/mmt/dpi
	$(QUIET) $(CP) -r $(SDKXAM) $(BUILD_DIR)/opt/mmt
	$(QUIET) $(CP) $(SDKLIB)/libmmt_tcpip.so.$(VERSION) $(BUILD_DIR)/opt/mmt/plugins/libmmt_tcpip.so
	echo "/opt/mmt/dpi/lib" >> $(BUILD_DIR)/etc/ld.so.conf.d/mmt-dpi.conf
	# Make links
	$(QUIET) ln -s $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_core.so.* $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_core.so
	$(QUIET) ln -s $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_fuzz.so.* $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_fuzz.so
	$(QUIET) ln -s $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_security.so.* $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_security.so
	$(QUIET) ln -s $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_tcpip.so.* $(BUILD_DIR)/opt/mmt/dpi/lib/libmmt_tcpip.so
	
	# Build .rpm file ...
	mkdir -p ./rpmbuild/{RPMS,BUILD}

	$(QUIET) echo -e\
	    "Summary:  MMT-DPI\
	    \nName: mmt-dpi\
	    \nVersion: $(GIT_VERSION)\
	    \nRelease: $(VERSION)\
	    \nLicense: proprietary\
	    \nGroup: Development/Libraries\
	    \nURL: http://montimage.com/\
	    \n\
	    \nBuildRoot: %{_topdir}/BUILD/$(BUILD_DIR)\
	    \n\
	    \n%description\
	    \nMMT-DPI is a library for deep packet inspection.\
	    \nBuild date: `date +"%Y-%m-%d %H:%M:%S"`\
	    \n\
	    \n%prep\
	    \nrm -rf %{buildroot}\
	    \nmkdir -p %{buildroot}/\
	    \ncp -r %{_topdir}/../$(BUILD_DIR)/* %{buildroot}/\
	    \nmkdir -p %{buildroot}/etc/ld.so.conf.d/\
	    \n\
	    \n%clean\
	    \nrm -rf %{buildroot}\
	    \n\
	    \n%files\
	    \n%defattr(-,root,root,-)\
	    \n/opt/mmt/*\
	    \n/etc/ld.so.conf.d/mmt-dpi.conf\
	    \n%post\
	    \nldconfig\
	" > ./mmt-dpi.spec

	rpmbuild --quiet --rmspec --define "_topdir `pwd`/rpmbuild" --define "_rpmfilename ../../$(BUILD_DIR).rpm" -bb ./mmt-dpi.spec

	$(QUIET) $(RM) $(BUILD_DIR) rpmbuild mmt-dpi.spec

#  - - - - -
#  C L E A N
#  - - - - -

clean:
	$(QUIET) $(RM) $(CORE_OBJECTS) $(TCPIP_OBJECTS) $(FUZZ_OBJECTS) $(SECURITY_OBJECTS)
	$(QUIET) $(RM) $(SDKLIB) $(SDKBIN) $(SDKINC) $(SDKDOC) $(SDKXAM) $(BUILD_DIR) rpmbuild mmt-dpi.spec


# - - - - - - - - - - 
# D I S T - C L E A N
# - - - - - - - - - - 

dist-clean:
	@ echo "[MMT-]> Going to remove MMT"
	$(QUIET) $(RM) $(MMT_DPI)
	$(QUIET) $(RM) /etc/ld.so.conf.d/mmt.conf
	@ echo "[MMT-]> Done!"

# - - - - - - - - - - 
# T E S T
# - - - - - - - - - -

test:
	@ echo "Start testing..."
	gcc -o proto_attributes_iterator /opt/mmt/examples/proto_attributes_iterator.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl
	./proto_attributes_iterator