ARCH         ?= linux
TOPDIR       := $(realpath $(CURDIR)/..)
RULESDIR     := $(TOPDIR)/rules
# Name of the package staging dir — the sole BUILD_DIR definition lives with
# the package targets below and must carry no wall-clock component (issue #220, F-CI-011)

#Directory given by user (e.g., make install INSTALL_DIR=/home/tata/mmt) to install MMT-DPI to
ifdef MMT_BASE
  $(info Change default install directory to $(MMT_BASE))
else
  MMT_BASE             := /opt/mmt
endif

default: sdk
.PHONY: sdk install uninstall clean dist-clean --check-built --check-prefix FORCE

include $(RULESDIR)/arch-$(ARCH).mk

# The plugin directory is baked into plugins_engine.o (PLUGINS_REPOSITORY_OPT,
# rules/common.mk), so that object depends on a stamp holding the value it was
# compiled with. The stamp is rewritten only when MMT_PLUGINS changes, which
# recompiles exactly that object — a rebuild with the same prefix compiles
# nothing (issue #485, F-CI-116; this replaces an unconditional delete of
# plugins_engine.o on every invocation, `make install` included).
PLUGINS_PATH_STAMP := $(SRCDIR)/mmt_core/src/plugins_engine.path
$(PLUGINS_PATH_STAMP): FORCE
	$(QUIET) if [ "`cat $@ 2>/dev/null`" != "$(MMT_PLUGINS)" ]; then echo "$(MMT_PLUGINS)" > $@; fi
$(SRCDIR)/mmt_core/src/plugins_engine.o: $(PLUGINS_PATH_STAMP)
FORCE:

#  - - -
#  S D K
#  - - -

sdk: libraries includes tools documentation examples


#  - - - - - - -
#  I N S T A L L
#  - - - - - - -

# F-SEC-012 (issue #214): this target usually runs as root and adds $(MMT_LIB)
# to the system library search path (ld.so.conf.d + ldconfig). Every file it
# lays down therefore gets an EXPLICIT mode under an explicit umask — a
# group/world-writable library in the loader path is a local
# privilege-escalation primitive. The find(1) assertion at the end refuses to
# leave a writable library behind.
#
# Issue #485 (F-CI-104, F-SEC-005, F-CI-116):
#   * `install` consumes the artifacts of a prior `make -C sdk` and never
#     compiles — `sudo make install` must not run the compiler as root.
#     --check-built refuses a missing build, or one whose baked-in plugin
#     directory is not this install's $(MMT_PLUGINS).
#   * the loader is registered by privilege, not by whether MMT_BASE was
#     given: LDCONF=auto (default) writes $(LDCONF_FILE) and runs
#     $(LDCONFIG) when installing as root; LDCONF=0 opts out, LDCONF=1 forces
#     it (LDCONF_DIR/LDCONFIG relocate both, e.g. for a staged test).
LDCONF      ?= auto
LDCONF_DIR  ?= /etc/ld.so.conf.d
LDCONFIG    ?= ldconfig
LDCONF_FILE := $(LDCONF_DIR)/mmt-dpi.conf
# Shell snippet: sets $$register to 1 when the loader drop-in is to be managed.
LDCONF_DECIDE = case "$(LDCONF)" in \
	    0) register=0 ;; \
	    1) register=1 ;; \
	    auto) if [ "`id -u`" -eq 0 ]; then register=1; else register=0; fi ;; \
	    *) echo "ERROR: LDCONF must be auto, 0 or 1 (got '$(LDCONF)')" >&2; exit 1 ;; \
	esac

--check-built:
	@ if [ ! -f $(SDKLIB)/libmmt_core.so.$(VERSION) ]; then \
		echo "ERROR: no SDK build under $(SDKLIB) — run 'make -C sdk MMT_BASE=$(MMT_BASE)' (as your user) before 'make install'" >&2; \
		exit 1; \
	fi
	@ built="`cat $(PLUGINS_PATH_STAMP) 2>/dev/null`"; \
	if [ "$$built" != "$(MMT_PLUGINS)" ]; then \
		echo "ERROR: the SDK under $(SDKLIB) was built for plugin directory '$$built', but this install targets '$(MMT_PLUGINS)'." >&2; \
		echo "       Rebuild with the install prefix: make -C sdk clean && make -C sdk MMT_BASE=$(MMT_BASE)" >&2; \
		exit 1; \
	fi

install: --check-built --check-prefix
	@ $(LDCONF_DECIDE)
	@ install -d -m 0755 $(MMT_BASE) $(MMT_DPI) $(MMT_INC) $(MMT_PLUGINS) $(MMT_EXAMS) $(MMT_LIB)
	@ install -m 0755 $(SDKLIB)/*.so.* $(MMT_LIB)/
	@ install -m 0644 $(SDKLIB)/*.a    $(MMT_LIB)/
# Make links
	@ln -sf $(MMT_LIB)/libmmt_core.so.$(VERSION)     $(MMT_LIB)/libmmt_core.so
	@ln -sf $(MMT_LIB)/libmmt_fuzz.so.$(VERSION)     $(MMT_LIB)/libmmt_fuzz.so
	@ln -sf $(MMT_LIB)/libmmt_security.so.$(VERSION) $(MMT_LIB)/libmmt_security.so
	@ln -sf $(MMT_LIB)/libmmt_tcpip.so.$(VERSION)    $(MMT_LIB)/libmmt_tcpip.so
	@ln -sf $(MMT_LIB)/$(LIBMOBILE).so.$(VERSION)    $(MMT_LIB)/$(LIBMOBILE).so
	@ln -sf $(MMT_LIB)/$(LIBBAPP).so.$(VERSION)      $(MMT_LIB)/$(LIBBAPP).so
	@ln -sf $(MMT_LIB)/$(LIBDICOM).so.$(VERSION)      $(MMT_LIB)/$(LIBDICOM).so

	@ echo "[MMT-]> Installed  "$(SDKLIB)" at "$(MMT_LIB)
	@ umask 022 && cp -R $(SDKINC)/* $(MMT_INC) \
		&& find $(MMT_INC) -type d -exec chmod 0755 {} + \
		&& find $(MMT_INC) -type f -exec chmod 0644 {} +
	@ echo "[MMT-]> Installed  "$(SDKINC)" at "$(MMT_INC)
	@ umask 022 && cp -R $(SDKXAM)/* $(MMT_EXAMS) \
		&& find $(MMT_EXAMS) -type d -exec chmod 0755 {} + \
		&& find $(MMT_EXAMS) -type f -exec chmod 0644 {} +
	@ echo "[MMT-]> Installed  "$(SDKXAM)" at "$(MMT_EXAMS)
	@ install -m 0755 $(SDKLIB)/libmmt_tcpip.so.$(VERSION) $(MMT_PLUGINS)/libmmt_tcpip.so
	@ echo "[MMT-]> Installed "$(MMT_PLUGINS)/libmmt_tcpip.so

	@ install -m 0755 $(SDKLIB)/$(LIBMOBILE).so.$(VERSION) $(MMT_PLUGINS)/$(LIBMOBILE).so
	@ echo "[MMT-]> Installed "$(MMT_PLUGINS)/$(LIBMOBILE).so

	@ install -m 0755 $(SDKLIB)/$(LIBDICOM).so.$(VERSION) $(MMT_PLUGINS)/$(LIBDICOM).so
	@ echo "[MMT-]> Installed "$(MMT_PLUGINS)/$(LIBDICOM).so

	@ install -m 0755 $(SDKLIB)/$(LIBBAPP).so.$(VERSION) $(MMT_PLUGINS)/$(LIBBAPP).so
	@ echo "[MMT-]> Installed "$(MMT_PLUGINS)/$(LIBBAPP).so
# Assert nothing under the library directory is group- or world-writable —
# the directory goes on the system search path below, so a permissive mode
# here would hand any local user write access to code loaded by everyone.
	@ if find $(MMT_LIB) -type f -perm /022 -print -quit | grep -q .; then \
		echo "ERROR: group/world-writable file under $(MMT_LIB) — refusing to leave it in the loader path" >&2; \
		exit 1; \
	fi
	@ $(LDCONF_DECIDE); \
	if [ "$$register" = 1 ]; then \
		umask 022 && install -d -m 0755 $(LDCONF_DIR) \
		&& echo "$(MMT_LIB)" > $(LDCONF_FILE) && chmod 0644 $(LDCONF_FILE) \
		&& $(LDCONFIG) \
		&& echo "[MMT-]> Registered $(MMT_LIB) with the dynamic loader ($(LDCONF_FILE))"; \
	else \
		echo "[MMT-]> Loader not registered (LDCONF=$(LDCONF); auto registers only as root): run consumers with LD_LIBRARY_PATH=$(MMT_LIB)"; \
	fi
# Record every entry laid down above in $(MMT_MANIFEST), merged with the one a
# previous install left, so `uninstall` removes exactly those (issue #485).
# Written to a fresh mktemp file and renamed into place, so a symlink planted
# at the manifest name is replaced, never written through.
	@ umask 022; if [ -L $(MMT_MANIFEST) ]; then echo "ERROR: $(MMT_MANIFEST) is a symlink — refusing to use it" >&2; exit 1; fi; \
	tmp=`mktemp $(MMT_MANIFEST).XXXXXX` || exit 1; \
	{ { if [ -f $(MMT_MANIFEST) ]; then grep -v '^#' $(MMT_MANIFEST); fi; $(MMT_LIST_INSTALLED); } | LC_ALL=C sort -u \
	  | { echo "# mmt-dpi install manifest: paths relative to $(MMT_BASE), read by make uninstall"; cat; } > "$$tmp" \
	  && chmod 0644 "$$tmp" && mv -f -- "$$tmp" $(MMT_MANIFEST); } || { rm -f -- "$$tmp"; exit 1; }
	@ echo "[MMT-]> Done! "

#  - - - - - - - - -
#  U N I N S T A L L
#  - - - - - - - - -

# Removes exactly the entries `install` recorded in $(MMT_MANIFEST) — never a
# whole directory tree: install merges into directories that may hold another
# product's files (e.g. MMT_BASE=/usr/local), and those survive. Directories
# are then removed with rmdir, deepest first, only when empty — the recorded
# ones and the SDK directories, never anything above $(MMT_BASE). An install
# that predates the manifest is reconstructed from this checkout's sdk/include
# and sdk/examples when they exist; otherwise only the libmmt_* libraries and
# plugins go and the include/examples trees are kept with a warning. A
# symlinked manifest is refused, and an entry is removed only when its parent
# directory resolves (cd -P) inside the real $(MMT_BASE): a directory symlink
# planted under the prefix cannot redirect a root uninstall elsewhere. The
# drop-in is removed only when it names this $(MMT_LIB) — never one
# registering another prefix (issue #485, F-UX-007).
uninstall: --check-prefix
	@ echo "[MMT-]> Removing MMT-DPI from $(MMT_BASE)"
	$(QUIET) set -e; base='$(MMT_BASE)'; list=`mktemp`; trap 'rm -f "$$list"' EXIT; \
	if [ -L $(MMT_MANIFEST) ]; then echo "ERROR: $(MMT_MANIFEST) is a symlink — refusing to uninstall" >&2; exit 1; fi; \
	rbase=`cd -P -- "$$base" 2>/dev/null && pwd -P` || rbase="$$base"; \
	inside() { r=`cd -P -- "$$1" 2>/dev/null && pwd -P` || return 1; case "$$r" in "$$rbase"|"$$rbase"/*) return 0 ;; esac; return 1; }; \
	if [ -f $(MMT_MANIFEST) ]; then \
		grep -v '^#' $(MMT_MANIFEST) > "$$list" || true; \
	else \
		echo "[MMT-]> No install manifest ($(MMT_MANIFEST)): the install predates it"; \
		{ (cd '$(MMT_LIB)' 2>/dev/null && ls -d libmmt_*.so libmmt_*.so.* libmmt_*.a 2>/dev/null) | sed 's|^|$(call mmt_rel,$(MMT_LIB))/|'; \
		  for f in $(MMT_PLUGIN_FILES); do echo "$(call mmt_rel,$(MMT_PLUGINS))/$$f"; done; } > "$$list" || true; \
		if [ -d $(SDKINC) ] && [ -d $(SDKXAM) ]; then \
			echo "[MMT-]> Removing the headers and examples this checkout installs ($(SDKINC), $(SDKXAM))"; \
			{ $(MMT_LIST_TREES); } >> "$$list"; \
		else \
			echo "[MMT-]> WARNING: kept $(MMT_INC) and $(MMT_EXAMS) — no file list for them; remove them by hand" >&2; \
		fi; \
	fi; \
	while IFS= read -r rel; do \
		case "$$rel" in ''|/*|.|..|./*|../*|*/.|*/..|*/./*|*/../*|*//*|*[!A-Za-z0-9._/+-]*) \
			echo "ERROR: unsafe manifest entry '$$rel' — refusing to uninstall" >&2; exit 1 ;; esac; \
	done < "$$list"; \
	while IFS= read -r rel; do \
		p="$$base/$$rel"; \
		if [ -L "$$p" ] || { [ -e "$$p" ] && [ ! -d "$$p" ]; }; then \
			if inside "$${p%/*}"; then rm -f -- "$$p"; else echo "[MMT-]> WARNING: skipped $$p — its directory resolves outside $$rbase" >&2; fi; \
		fi; \
	done < "$$list"; \
	{ while IFS= read -r rel; do if [ -d "$$base/$$rel" ] && [ ! -L "$$base/$$rel" ]; then echo "$$rel"; fi; done < "$$list"; \
	  for d in $(foreach d,$(MMT_INC) $(MMT_EXAMS) $(MMT_LIB) $(MMT_PLUGINS) $(MMT_DPI),$(call mmt_rel,$(d))); do echo "$$d"; done; } \
	| LC_ALL=C sort -r -u | while IFS= read -r rel; do \
		if [ -d "$$base/$$rel" ] && [ ! -L "$$base/$$rel" ] && inside "$$base/$$rel"; then rmdir -- "$$base/$$rel" 2>/dev/null || echo "[MMT-]> Kept non-empty $$base/$$rel"; fi; \
	done; \
	rm -f $(MMT_MANIFEST); \
	if [ -d "$$base" ]; then rmdir -- "$$base" 2>/dev/null || echo "[MMT-]> Kept non-empty $$base"; fi
	@ removed=0; \
	for f in $(LDCONF_FILE) $(LDCONF_DIR)/mmt.conf; do \
		if [ -f "$$f" ] && [ "`cat $$f`" = "$(MMT_LIB)" ]; then rm -f "$$f" && removed=1 && echo "[MMT-]> Removed $$f"; fi; \
	done; \
	if [ "$$removed" = 1 ]; then $(LDCONFIG); fi
	@ echo "[MMT-]> Done!"

# install and uninstall run as root and act on user-overridable paths, so
# every one is checked first: MMT_BASE and MMT_DPI/MMT_LIB/MMT_INC/
# MMT_PLUGINS/MMT_EXAMS must be absolute, at most 256 characters, made of
# [A-Za-z0-9._/-] only (no whitespace, quote or glob character), with no
# empty, '.' or '..' component and no trailing slash — so '/', '//', '/.'
# and '/opt/*' are refused — and each SDK directory must lie strictly under
# MMT_BASE. Same rules as install.sh's validate_mmt_base (issue #485).
--check-prefix:
	@ base='$(MMT_BASE)'; sub=; \
	for p in "$$base" '$(MMT_DPI)' '$(MMT_LIB)' '$(MMT_INC)' '$(MMT_PLUGINS)' '$(MMT_EXAMS)'; do \
		why=; \
		case "$$p" in /*) ;; *) why="is not an absolute path" ;; esac; \
		case "$$p" in *[!A-Za-z0-9._/-]*) why="contains characters outside [A-Za-z0-9._/-]" ;; esac; \
		case "$$p/" in *//*|*/./*|*/../*) why="has an empty, '.' or '..' component or a trailing slash" ;; esac; \
		if [ $${#p} -gt 256 ]; then why="is longer than 256 characters"; fi; \
		if [ -n "$$sub" ]; then case "$$p" in "$$base"/?*) ;; *) why="is not under MMT_BASE=$$base" ;; esac; fi; \
		if [ -n "$$why" ]; then echo "ERROR: install path '$$p' $$why — refusing to $(MAKECMDGOALS)" >&2; exit 1; fi; \
		sub=1; \
	done

# Install manifest (issue #485): one path per line, relative to $(MMT_BASE).
MMT_MANIFEST     = $(MMT_BASE)/.mmt-dpi-manifest
mmt_rel          = $(patsubst $(MMT_BASE)/%,%,$(1))
MMT_LIB_LINKS    = libmmt_core.so libmmt_fuzz.so libmmt_security.so libmmt_tcpip.so $(LIBMOBILE).so $(LIBBAPP).so $(LIBDICOM).so
MMT_PLUGIN_FILES = libmmt_tcpip.so $(LIBMOBILE).so $(LIBDICOM).so $(LIBBAPP).so
# Shell snippets printing the entries `install` copies from this build.
MMT_LIST_TREES   = (cd $(SDKINC) && find . -mindepth 1) | sed 's|^\./|$(call mmt_rel,$(MMT_INC))/|'; \
	(cd $(SDKXAM) && find . -mindepth 1) | sed 's|^\./|$(call mmt_rel,$(MMT_EXAMS))/|'
MMT_LIST_INSTALLED = (cd $(SDKLIB) && ls -d *.so.* *.a) | sed 's|^|$(call mmt_rel,$(MMT_LIB))/|'; \
	for f in $(MMT_LIB_LINKS); do echo "$(call mmt_rel,$(MMT_LIB))/$$f"; done; \
	for f in $(MMT_PLUGIN_FILES); do echo "$(call mmt_rel,$(MMT_PLUGINS))/$$f"; done; \
	$(MMT_LIST_TREES)

#  - - - - - - -
#  B U I L D   D E B
#  - - - - - - -
SYS_NAME    = $(shell uname -s)
SYS_VERSION = $(shell uname -p)
# Debian architecture: use dpkg if available, otherwise map uname -m to Debian arch names
# Only evaluate when the deb target is invoked to avoid unnecessary shell calls
ifneq ($(filter deb,$(MAKECMDGOALS)),)
DEB_ARCH ?= $(shell dpkg --print-architecture 2>/dev/null || (uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/i686/i386/;s/armv7l/armhf/;s/ppc64le/ppc64el/'))
endif

BUILD_DIR = mmt-dpi_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)

# F-SEC-012 (issue #214): this staging tree becomes a .deb/.rpm installed by
# root, so it gets the same treatment as `install` — explicit umask, explicit
# modes, and a group/world-writability assertion on the library directory
# before the package is assembled.
--private-prepare-build-dir:
	echo $(BUILD_DIR)
	# Remove old build
	$(QUIET) $(RM) $(BUILD_DIR)
	# Create new build location
	$(QUIET) install -d -m 0755 $(BUILD_DIR)$(MMT_LIB)
	$(QUIET) install -d -m 0755 $(BUILD_DIR)$(MMT_INC)
	$(QUIET) install -d -m 0755 $(BUILD_DIR)$(MMT_EXAMS)
	$(QUIET) install -d -m 0755 $(BUILD_DIR)$(MMT_PLUGINS)
	$(QUIET) install -d -m 0755 $(BUILD_DIR)/etc/ld.so.conf.d/
	# Copy resources
	echo $(SDKLIB)
	$(QUIET) umask 022 && install -m 0755 $(SDKLIB)/*.so.* $(BUILD_DIR)$(MMT_BASE)/dpi/lib/ \
	                  && install -m 0644 $(SDKLIB)/*.a    $(BUILD_DIR)$(MMT_BASE)/dpi/lib/
	# Scope the mode-normalizing finds to the trees just copied: running them
	# over dpi/ or $(MMT_BASE) would also hit dpi/lib/*.so.* and undo the
	# install -m 0755 above, silently shipping the libraries at 0644.
	$(QUIET) umask 022 && $(CP) -r $(SDKINC)   $(BUILD_DIR)$(MMT_BASE)/dpi \
	                  && find $(BUILD_DIR)$(MMT_BASE)/dpi/include -type d -exec chmod 0755 {} + \
	                  && find $(BUILD_DIR)$(MMT_BASE)/dpi/include -type f -exec chmod 0644 {} +
	$(QUIET) umask 022 && $(CP) -r $(SDKXAM)   $(BUILD_DIR)$(MMT_BASE) \
	                  && find $(BUILD_DIR)$(MMT_BASE)/examples -type d -exec chmod 0755 {} + \
	                  && find $(BUILD_DIR)$(MMT_BASE)/examples -type f -exec chmod 0644 {} +
	$(QUIET) install -m 0755 $(SDKLIB)/libmmt_tcpip.so.$(VERSION)     $(BUILD_DIR)$(MMT_PLUGINS)/libmmt_tcpip.so
	$(QUIET) install -m 0755 $(SDKLIB)/$(LIBMOBILE).so.$(VERSION)     $(BUILD_DIR)$(MMT_PLUGINS)/$(LIBMOBILE).so
	$(QUIET) install -m 0755 $(SDKLIB)/$(LIBBAPP).so.$(VERSION)     $(BUILD_DIR)$(MMT_PLUGINS)/$(LIBBAPP).so
	$(QUIET) install -m 0755 $(SDKLIB)/$(LIBDICOM).so.$(VERSION)     $(BUILD_DIR)$(MMT_PLUGINS)/$(LIBDICOM).so
	# Make links
	$(QUIET) ln -s $(MMT_LIB)/libmmt_core.so.$(VERSION)     $(BUILD_DIR)$(MMT_LIB)/libmmt_core.so
	$(QUIET) ln -s $(MMT_LIB)/libmmt_fuzz.so.$(VERSION)     $(BUILD_DIR)$(MMT_LIB)/libmmt_fuzz.so
	$(QUIET) ln -s $(MMT_LIB)/libmmt_security.so.$(VERSION) $(BUILD_DIR)$(MMT_LIB)/libmmt_security.so
	$(QUIET) ln -s $(MMT_LIB)/libmmt_tcpip.so.$(VERSION)    $(BUILD_DIR)$(MMT_LIB)/libmmt_tcpip.so
	$(QUIET) ln -s $(MMT_LIB)/$(LIBMOBILE).so.$(VERSION)    $(BUILD_DIR)$(MMT_LIB)/$(LIBMOBILE).so
	$(QUIET) ln -s $(MMT_LIB)/$(LIBBAPP).so.$(VERSION)    $(BUILD_DIR)$(MMT_LIB)/$(LIBBAPP).so
	$(QUIET) ln -s $(MMT_LIB)/$(LIBDICOM).so.$(VERSION)    $(BUILD_DIR)$(MMT_LIB)/$(LIBDICOM).so

	#tell ldconfig to find mmt-dpi libraries at the installed folder
	umask 022 && echo "$(MMT_LIB)" > $(BUILD_DIR)/etc/ld.so.conf.d/mmt-dpi.conf \
	    && chmod 0644 $(BUILD_DIR)/etc/ld.so.conf.d/mmt-dpi.conf
	# The package is installed by root into the system search path — assert the
	# staged library dir carries no group/world-writable file (F-SEC-012).
	$(QUIET) if find $(BUILD_DIR)$(MMT_LIB) -type f -perm /022 -print -quit | grep -q .; then \
		echo "ERROR: group/world-writable file under $(BUILD_DIR)$(MMT_LIB)" >&2; exit 1; \
	fi

deb: sdk $(SDKLIB) $(SDKINC) $(SDKXAM) --private-prepare-build-dir
	$(QUIET) $(MKDIR) $(BUILD_DIR)/DEBIAN
	# Depends is derived from the NEEDED entries of the shipped shared
	# objects (issue #219, F-DEP-203/204): tools/ci/shlib-deps.sh maps each
	# soname to the Debian package providing it and fails on an unmapped
	# soname, so the declaration can never drift from the payload again.
	# libpcap/libnghttp2 are deliberately absent — nothing shipped links them.
	$(QUIET) deps=`sh '$(TOPDIR)/tools/ci/shlib-deps.sh' deb '$(BUILD_DIR)$(MMT_LIB)' '$(BUILD_DIR)$(MMT_PLUGINS)'` \
	    && echo "Package: mmt-dpi \
        \nVersion: $(VERSION)-$(GIT_VERSION)\
        \nSection: base \
        \nPriority: standard \
        \nArchitecture: $(DEB_ARCH)\
        \nMaintainer: Montimage <contact@montimage.eu> \
        \nDepends: $$deps \
        \nDescription: MMT-DPI:  \
        \n (Built time: $(BUILD_DATE)) \
        \n A software C library designed to extract data attributes from network packets, server logs, and from structured events in general, in order to make them available for analysis \
        \n Homepage: http://www.montimage.eu" \
		> $(BUILD_DIR)/DEBIAN/control
	$(QUIET) echo '#!/bin/sh' > $(BUILD_DIR)/DEBIAN/postinst
	$(QUIET) echo 'set -e' >> $(BUILD_DIR)/DEBIAN/postinst
	$(QUIET) echo "echo 'Running ldconfig for mmt-dpi...'" >> $(BUILD_DIR)/DEBIAN/postinst
	$(QUIET) echo 'ldconfig' >> $(BUILD_DIR)/DEBIAN/postinst
	$(QUIET) chmod +x $(BUILD_DIR)/DEBIAN/postinst
	$(QUIET) echo '#!/bin/sh' > $(BUILD_DIR)/DEBIAN/postrm
	$(QUIET) echo 'set -e' >> $(BUILD_DIR)/DEBIAN/postrm
	$(QUIET) echo 'if [ "$$1" = "remove" ] || [ "$$1" = "purge" ]; then' >> $(BUILD_DIR)/DEBIAN/postrm
	$(QUIET) echo "    echo 'Updating ldconfig after mmt-dpi removal...'" >> $(BUILD_DIR)/DEBIAN/postrm
	$(QUIET) echo '    ldconfig' >> $(BUILD_DIR)/DEBIAN/postrm
	$(QUIET) echo 'fi' >> $(BUILD_DIR)/DEBIAN/postrm
	$(QUIET) chmod +x $(BUILD_DIR)/DEBIAN/postrm

	# Reproducibility (issue #220, F-CI-011): clamp every staged mtime —
	# payload, DEBIAN metadata and symlinks (-h, the targets do not exist
	# during staging) — to SOURCE_DATE_EPOCH, and normalise uid/gid to root
	# so the archive does not record who built it.
	$(QUIET) find $(BUILD_DIR) -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} + && dpkg-deb --root-owner-group -b $(BUILD_DIR)
	$(QUIET) $(RM) $(BUILD_DIR)

#  - - - - - - - - - -
#  B U I L D   R P M
#  - - - - - - - - - -

rpm: sdk $(SDKLIB) $(SDKINC) $(SDKXAM) --private-prepare-build-dir
	# Build .rpm file ...
	$(QUIET) $(MKDIR) ./rpmbuild/{RPMS,BUILD}

	# Version/Release are ordered as Debian does (issue #219, F-CI-013):
	# Version: is the upstream $(VERSION) — `rpm -qp --qf '%{VERSION}'`
	# reports it, not the git hash — and Release: carries $(GIT_VERSION).
	# Requires: is derived from the shipped .so NEEDED entries through the
	# same tools/ci/shlib-deps.sh mapping the deb Depends uses (F-DEP-206);
	# BuildRequires: mirrors the packages install_build_deps_rhel()
	# (tools/ci/build-package.sh) installs, floored at $(MMT_GCC_MIN).
	$(QUIET) reqs=`sh '$(TOPDIR)/tools/ci/shlib-deps.sh' rpm '$(BUILD_DIR)$(MMT_LIB)' '$(BUILD_DIR)$(MMT_PLUGINS)'` \
	    && echo -e\
	    "Summary:  MMT-DPI\
	    \nName: mmt-dpi\
	    \nVersion: $(VERSION)\
	    \nRelease: $(GIT_VERSION)\
	    \nLicense: proprietary\
	    \nGroup: Development/Libraries\
	    \nURL: http://montimage.eu/\
	    \nRequires: $$reqs\
	    \nBuildRequires: gcc >= $(MMT_GCC_MIN), gcc-c++ >= $(MMT_GCC_MIN), make, git, file, findutils, which, binutils, libxml2-devel, libpcap-devel, rpm-build\
	    \n\
	    \nBuildRoot: %{_topdir}/BUILD/$(BUILD_DIR)\
	    \n\
	    \n%description\
	    \nMMT-DPI is a library for deep packet inspection.\
	    \nBuild date: $(BUILD_DATE)\
	    \n\
	    \n%prep\
	    \nrm -rf %{buildroot}\
	    \nmkdir -p %{buildroot}/\
	    \ncp -rp %{_topdir}/../$(BUILD_DIR)/. %{buildroot}/\
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

	# Reproducibility (issue #220, F-CI-011): clamp the staged mtimes to
	# SOURCE_DATE_EPOCH before rpmbuild copies the tree, pin %_buildhost —
	# the hostname otherwise leaks into RPMTAG_BUILDHOST and the build
	# cookie — and opt in to rpm's SDE handling: %_buildhost alone leaves
	# RPMTAG_BUILDTIME at the wall clock (rpm needs the two explicit
	# macros; merely exporting the variable is not enough on rpm 4.16).
	$(QUIET) find $(BUILD_DIR) -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} +
	rpmbuild --quiet --rmspec --define "_topdir `pwd`/rpmbuild" --define "_rpmfilename ../../$(BUILD_DIR).rpm" --define "_buildhost mmt-dpi" --define "use_source_date_epoch_as_buildtime 1" --define "clamp_mtime_to_source_date_epoch 1" -bb ./mmt-dpi.spec

	$(QUIET) $(RM) $(BUILD_DIR) rpmbuild mmt-dpi.spec


#  - - - - - - - - - -
#  B U I L D   Z I P
#  - - - - - - - - - -


zip: sdk $(SDKLIB) $(SDKINC) $(SDKXAM)
	echo $(BUILD_DIR)
	# Remove old build
	$(QUIET) $(RM) $(BUILD_DIR)
	$(QUIET) $(MKDIR) $(BUILD_DIR)
	# Copy installer scripts (common + install/uninstall) and README
	$(QUIET) $(CP) ../dist/ZIP/* $(BUILD_DIR)
	# Stamp VERSION from the single source of truth (rules/common.mk) into
	# the bundled common file so the ZIP never drifts from the build.
	$(QUIET) sed -i 's/^VERSION="$${VERSION:-.*}"/VERSION="$(VERSION)"/' $(BUILD_DIR)/mmt-install-common.sh 2>/dev/null || \
	         sed -i 's/^VERSION="$${VERSION:-.*}"/VERSION="$(VERSION)"/' $(BUILD_DIR)/mmt-install-common.sh
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
	$(QUIET) $(RM) $(CORE_OBJECTS) $(TCPIP_OBJECTS) $(FUZZ_OBJECTS) $(SECURITY_OBJECTS) $(LIBMOBILE_OBJECTS) $(LIBBAPP_OBJECTS) $(LIBDICOM_OBJECTS)
	$(QUIET) $(RM) $(SDKLIB) $(SDKBIN) $(SDKINC) $(SDKDOC) $(SDKXAM) $(BUILD_DIR) rpmbuild mmt-dpi.spec $(PLUGINS_PATH_STAMP)
	$(QUIET) $(RM) $(TOPDIR)/*.log $(TOPDIR)/*.tmp $(TOPDIR)/*.bak $(TOPDIR)/coverage.info $(TOPDIR)/coverage.json $(TOPDIR)/lcov.info
	$(QUIET) $(RM) $(TOPDIR)/cppcheck*.xml $(TOPDIR)/cppcheck_output.xml $(TOPDIR)/cppcheck-report.xml $(TOPDIR)/PVS-Studio.log $(TOPDIR)/pvs.log
	$(QUIET) $(RM) $(TOPDIR)/mmt-dpi_*.deb $(TOPDIR)/mmt-dpi_*.rpm $(TOPDIR)/mmt-dpi_*.zip
	$(QUIET) $(RM) $(TOPDIR)/sdk/mmt-dpi_*.deb $(TOPDIR)/sdk/mmt-dpi_*.rpm $(TOPDIR)/sdk/mmt-dpi_*.zip 2>/dev/null || true
	$(QUIET) $(RM) mmt-dpi_*.deb mmt-dpi_*.rpm mmt-dpi_*.zip *.gcda *.gcno *.gcov 2>/dev/null || true
	# F-DEAD-016 (issue #229): stale example binaries compiled in-tree sit
	# inside the source directory (gitignored, so a plain build never
	# refreshes them) — sweep every binary name src/examples can produce.
	$(QUIET) $(RM) $(addprefix $(SRCDIR)/examples/,extract_all proto_attribute_list proto_attributes_iterator sessions_count simple_packet_handler)


# - - - - - - - - - -
# D I S T - C L E A N
# - - - - - - - - - -

# Historical name for `uninstall`, kept so existing instructions still work.
dist-clean: uninstall

# - - - - - - - - - -
# T E S T
# - - - - - - - - - -

test:
	@ echo "Start testing..."
	# F-SEC-010 (issue #214): the installed examples compile as PIE
	# (-fPIE + -pie + RELRO/noexecstack via MMT_EXAMPLE_* in rules/common.mk).
	$(CC) $(MMT_EXAMPLE_CFLAGS) -o proto_attributes_iterator $(MMT_EXAMS)/proto_attributes_iterator.c -I $(MMT_INC) -L $(MMT_LIB) $(MMT_EXAMPLE_LDFLAGS) -lmmt_core -ldl
	./proto_attributes_iterator
# `make sdk install` in one invocation: install no longer depends on sdk, so
# order it after the build when both are requested (issue #485).
ifneq ($(filter sdk default,$(MAKECMDGOALS)),)
install: | sdk
--check-built: | sdk
endif
