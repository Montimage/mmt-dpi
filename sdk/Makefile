ARCH         ?= linux
TOPDIR       := $(realpath $(CURDIR)/..)
RULESDIR     := $(TOPDIR)/rules
# Set name of package with given version
BUILD_DIR	 :=mmt-dpi_$(VERSION)_`uname -s`_`uname -p`_`date +%s`

#Directory given by user (e.g., make install INSTALL_DIR=/home/tata/mmt) to install MMT-DPI to
ifdef MMT_BASE
  $(info Change default install directory to $(MMT_BASE))
else
  MMT_BASE             := /opt/mmt
  NEED_ROOT_PERMISSION := 1
endif

default: sdk
.PHONY: sdk install clean dist-clean

include $(RULESDIR)/arch-$(ARCH).mk

# This target is to deal with the issue when user uses 
#   2 differrent values of INSTALL_DIR for "make" and "make install"
# Ex: make; sudo make install INSTALL_DIR=/tmp/mmt
#   - the first "make" will set in the codes PLUGINS_REPOSITORY_OPT to /opt/mmt/plugins
#   - while the second "make install" will install to /tmp/mmt
# Thus we need to recompile the codes that use PLUGINS_REPOSITORY_OPT to update the new directory.
# The following target will remove the object files of the codes, thus it will trigger to recompile them.
# So, in the example above, the PLUGINS_REPOSITORY_OPT will be update to /tmp/mmt/plugins.
--refresh-plugin-engine:
	$(QUIET) $(RM) $(SRCDIR)/mmt_core/src/plugins_engine.o
	
#  - - -
#  S D K
#  - - -

sdk: --refresh-plugin-engine libraries includes tools documentation examples


#  - - - - - - -
#  I N S T A L L
#  - - - - - - -

install: sdk $(MMT_BASE) $(MMT_DPI) $(MMT_INC) $(MMT_PLUGINS) $(MMT_EXAMS) $(MMT_LIB)
	@ cp $(SDKLIB)/* $(MMT_LIB)
# Make links
	@ln -sf $(MMT_LIB)/libmmt_core.so.$(VERSION)     $(MMT_LIB)/libmmt_core.so
	@ln -sf $(MMT_LIB)/libmmt_fuzz.so.$(VERSION)     $(MMT_LIB)/libmmt_fuzz.so
	@ln -sf $(MMT_LIB)/libmmt_security.so.$(VERSION) $(MMT_LIB)/libmmt_security.so
	@ln -sf $(MMT_LIB)/libmmt_tcpip.so.$(VERSION)    $(MMT_LIB)/libmmt_tcpip.so
	
	@ echo "[MMT-]> Installed  "$(SDKLIB)" at "$(MMT_LIB)
	@ cp -R $(SDKINC)/* $(MMT_INC)
	@ echo "[MMT-]> Installed  "$(SDKINC)" at "$(MMT_INC)
	@ cp -R $(SDKXAM)/* $(MMT_EXAMS)
	@ echo "[MMT-]> Installed  "$(SDKXAM)" at "$(MMT_EXAMS)
	@ cp $(SDKLIB)/libmmt_tcpip.so.$(VERSION) $(MMT_PLUGINS)/libmmt_tcpip.so
	@ echo "[MMT-]> Installed "$(MMT_PLUGINS)/libmmt_tcpip.so
	
ifdef NEED_ROOT_PERMISSION
	@ echo "$(MMT_LIB)" > /etc/ld.so.conf.d/mmt-dpi.conf
	@ ldconfig
endif
	@ echo "[MMT-]> Done! "

#  - - - - - - -
#  B U I L D   D E B
#  - - - - - - -
SYS_NAME    = $(shell uname -s)
SYS_VERSION = $(shell uname -p)

BUILD_DIR = mmt-dpi_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)

--private-prepare-build-dir:
	echo $(BUILD_DIR)
	# Remove old build
	$(QUIET) $(RM) $(BUILD_DIR)
	# Create new build location
	$(QUIET) $(MKDIR) -p $(BUILD_DIR)$(MMT_LIB)
	$(QUIET) $(MKDIR) -p $(BUILD_DIR)$(MMT_INCLUDE)
	$(QUIET) $(MKDIR) -p $(BUILD_DIR)$(MMT_EXAMS)
	$(QUIET) $(MKDIR) -p $(BUILD_DIR)$(MMT_PLUGINS)
	$(QUIET) $(MKDIR) -p $(BUILD_DIR)/etc/ld.so.conf.d/
	# Copy resources
	echo $(SDKLIB)
	$(QUIET) $(CP)    $(SDKLIB)/* $(BUILD_DIR)$(MMT_BASE)/dpi/lib
	$(QUIET) $(CP) -r $(SDKINC)   $(BUILD_DIR)$(MMT_BASE)/dpi
	$(QUIET) $(CP) -r $(SDKXAM)   $(BUILD_DIR)$(MMT_BASE)
	$(QUIET) $(CP) $(SDKLIB)/libmmt_tcpip.so.$(VERSION)     $(BUILD_DIR)$(MMT_PLUGINS)/libmmt_tcpip.so
	# Make links
	$(QUIET) ln -s $(MMT_LIB)/libmmt_core.so.$(VERSION)     $(BUILD_DIR)$(MMT_LIB)/libmmt_core.so
	$(QUIET) ln -s $(MMT_LIB)/libmmt_fuzz.so.$(VERSION)     $(BUILD_DIR)$(MMT_LIB)/libmmt_fuzz.so
	$(QUIET) ln -s $(MMT_LIB)/libmmt_security.so.$(VERSION) $(BUILD_DIR)$(MMT_LIB)/libmmt_security.so
	$(QUIET) ln -s $(MMT_LIB)/libmmt_tcpip.so.$(VERSION)    $(BUILD_DIR)$(MMT_LIB)/libmmt_tcpip.so
	#tell ldconfig to find mmt-dpi libraries at the installed folder
	echo "$(MMT_LIB)" > $(BUILD_DIR)/etc/ld.so.conf.d/mmt-dpi.conf
	
deb: sdk $(SDKLIB) $(SDKINC) $(SDKXAM) --private-prepare-build-dir
	$(QUIET) $(MKDIR) $(BUILD_DIR)/DEBIAN
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

	$(QUIET) dpkg-deb -b $(BUILD_DIR)
	$(QUIET) $(RM) $(BUILD_DIR)

#  - - - - - - - - - -
#  B U I L D   R P M
#  - - - - - - - - - -

rpm: sdk $(SDKLIB) $(SDKINC) $(SDKXAM) --private-prepare-build-dir
	# Build .rpm file ...
	$(QUIET) $(MKDIR) ./rpmbuild/{RPMS,BUILD}

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


#  - - - - - - - - - -
#  B U I L D   Z I P
#  - - - - - - - - - -


zip: sdk $(SDKLIB) $(SDKINC) $(SDKXAM)
	echo $(BUILD_DIR)
	# Remove old build
	$(QUIET) $(RM) $(BUILD_DIR)
	$(QUIET) $(MKDIR) $(BUILD_DIR)
	# Copy make file
	$(QUIET) $(CP) ../dist/ZIP/* $(BUILD_DIR)
	# Copy source to zip file
	$(QUIET) $(CP) -R $(SDKLIB) $(BUILD_DIR)
	$(QUIET) $(CP) -R $(SDKINC) $(BUILD_DIR)
	$(QUIET) $(CP) -R $(SDKXAM) $(BUILD_DIR)
	# Make zip file
	zip -r $(BUILD_DIR).zip $(BUILD_DIR)

	$(QUIET) $(RM) $(BUILD_DIR)
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
ifdef NEED_ROOT_PERMISSION
	$(QUIET) $(RM) /etc/ld.so.conf.d/mmt.conf
endif
	@ echo "[MMT-]> Done!"

# - - - - - - - - - -
# T E S T
# - - - - - - - - - -

test:
	@ echo "Start testing..."
	gcc -o proto_attributes_iterator $(MMT_EXAMS)/proto_attributes_iterator.c -I $(MMT_INC) -L $(MMT_LIB) -lmmt_core -ldl
	./proto_attributes_iterator