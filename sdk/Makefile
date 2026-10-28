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
.PHONY: sdk install install-fhs uninstall clean dist-clean --check-built --check-prefix FORCE

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
# Runtime (SONAME) links, issue #536: lib<name>.so.$(SOVERSION) is what a
# consumer's NEEDED entry names, so the loader needs it even when ldconfig
# never runs (an unprivileged install). Only for the libraries installed.
# Any other lib<name>.so.<n> there is a stale earlier version: one from v1.9.1
# or before has SONAME lib<name>.so, so ldconfig would repoint the development
# link at it. Removed (regular files and links only) before ldconfig runs.
	@ for l in $(MMT_SONAME_LIBS); do \
		if [ -f $(MMT_LIB)/$$l.so.$(VERSION) ]; then \
			for f in $(MMT_LIB)/$$l.so.[0-9]*; do \
				case "$${f##*/}" in $$l.so.$(VERSION)|$$l.so.$(SOVERSION)) continue ;; esac; \
				if [ -L "$$f" ] || [ -f "$$f" ]; then rm -f -- "$$f" && echo "[MMT-]> Removed stale $$f"; fi; \
			done; \
			ln -sf $$l.so.$(VERSION) $(MMT_LIB)/$$l.so.$(SOVERSION); \
		fi; \
	done

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
# Licence files (issue #497), laid out as the two packages lay them out.
	@ umask 022 && install -d -m 0755 $(MMT_DOC) && install -m 0644 $(PKG_LICENSE_FILES) $(MMT_DOC)/
	@ if $(SEC_ENGINES_BUILT); then \
		umask 022 && install -d -m 0755 $(MMT_SEC_DOC) \
		&& install -m 0644 $(PKG_LICENSE_FILES) $(MMT_SEC_DOC)/ \
		&& install -m 0644 $(GPL_LICENSE_TEXT) $(MMT_SEC_DOC)/COPYING; \
	fi
	@ echo "[MMT-]> Installed the licence files at "$(MMT_DOCDIR)
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
# Every shared library, by base name; each gets its SONAME link (issue #536).
MMT_SONAME_LIBS  = libmmt_core libmmt_fuzz libmmt_security libmmt_tcpip $(LIBMOBILE) $(LIBBAPP) $(LIBDICOM)
MMT_PLUGIN_FILES = libmmt_tcpip.so $(LIBMOBILE).so $(LIBDICOM).so $(LIBBAPP).so
# Shell snippets printing the entries `install` copies from this build.
MMT_LIST_TREES   = (cd $(SDKINC) && find . -mindepth 1) | sed 's|^\./|$(call mmt_rel,$(MMT_INC))/|'; \
	(cd $(SDKXAM) && find . -mindepth 1) | sed 's|^\./|$(call mmt_rel,$(MMT_EXAMS))/|'
MMT_LIST_INSTALLED = (cd $(SDKLIB) && ls -d *.so.* *.a) | sed 's|^|$(call mmt_rel,$(MMT_LIB))/|'; \
	for f in $(MMT_LIB_LINKS) $(addsuffix .so.$(SOVERSION),$(MMT_SONAME_LIBS)); do echo "$(call mmt_rel,$(MMT_LIB))/$$f"; done; \
	for f in $(MMT_PLUGIN_FILES); do echo "$(call mmt_rel,$(MMT_PLUGINS))/$$f"; done; \
	$(MMT_LIST_TREES); \
	$(MMT_LIST_DOCS)

# Licence files (issue #497): <MMT_DPI>/share/doc/<package>/, one directory per
# package so the two packages never own the same path. The directories are
# recorded too, so uninstall removes them once empty.
MMT_DOCDIR        = $(MMT_DPI)/share/doc
MMT_DOC           = $(MMT_DOCDIR)/mmt-dpi
MMT_SEC_DOC       = $(MMT_DOCDIR)/mmt-dpi-security
PKG_LICENSE_FILES = $(TOPDIR)/LICENSE $(TOPDIR)/THIRD-PARTY-NOTICES
GPL_LICENSE_TEXT  = $(TOPDIR)/LICENSES/GPL-3.0-or-later.txt
# Shell condition: the ENABLESEC engines are in this build (tested when the
# recipe runs, so `make sdk deb` sees the libraries the same invocation built).
SEC_ENGINES_BUILT = { [ -e $(SDKLIB)/libmmt_security.so.$(VERSION) ] || [ -e $(SDKLIB)/libmmt_fuzz.so.$(VERSION) ]; }
MMT_LIST_DOCS     = for d in $(call mmt_rel,$(MMT_DPI)/share $(MMT_DOCDIR) $(MMT_DOC)); do echo "$$d"; done; \
	for f in LICENSE THIRD-PARTY-NOTICES; do echo "$(call mmt_rel,$(MMT_DOC))/$$f"; done; \
	if $(SEC_ENGINES_BUILT); then \
		echo "$(call mmt_rel,$(MMT_SEC_DOC))"; \
		for f in LICENSE THIRD-PARTY-NOTICES COPYING; do echo "$(call mmt_rel,$(MMT_SEC_DOC))/$$f"; done; \
	fi

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
# The ENABLESEC engines ship in their own package (issue #497), because their
# licence differs from the rest of the SDK. mmt-dpi never requires it; it
# requires the same mmt-dpi version, since libmmt_security resolves
# libmmt_core symbols at load time (rules/common-linux.mk, -z,defs note) and
# the engines sit in the library directory mmt-dpi registers with the loader.
SEC_BUILD_DIR = mmt-dpi-security_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)
# The libraries the mmt-dpi package itself ships (rpm %files).
MMT_PKG_LIBS  = libmmt_core libmmt_tcpip $(LIBMOBILE) $(LIBBAPP) $(LIBDICOM)

# SPDX licence expressions of the two packages (issue #497). Not hand-picked:
# `tools/ci/vendored-components.py notices --check` recomputes them from the
# repository LICENSE, tools/ci/vendored-components.json and the notices in the
# engine sources, and fails when these lines or THIRD-PARTY-NOTICES drift.
PKG_LICENSE := Apache-2.0 AND BSD-2-Clause AND MIT
SEC_PKG_LICENSE := GPL-3.0-or-later AND Apache-2.0

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
	# SONAME links (issue #536), as `install` lays them down: shipped in the
	# package, not left to the postinst ldconfig, so dpkg/rpm own them.
	$(QUIET) for l in $(MMT_SONAME_LIBS); do \
		if [ -f $(BUILD_DIR)$(MMT_LIB)/$$l.so.$(VERSION) ]; then ln -s $$l.so.$(VERSION) $(BUILD_DIR)$(MMT_LIB)/$$l.so.$(SOVERSION); fi; \
	done

	#tell ldconfig to find mmt-dpi libraries at the installed folder
	umask 022 && echo "$(MMT_LIB)" > $(BUILD_DIR)/etc/ld.so.conf.d/mmt-dpi.conf \
	    && chmod 0644 $(BUILD_DIR)/etc/ld.so.conf.d/mmt-dpi.conf
	# Licence files (issue #497): LICENSE and THIRD-PARTY-NOTICES in each
	# package, under its own doc directory.
	$(QUIET) umask 022 && install -d -m 0755 $(BUILD_DIR)$(MMT_DOC) \
	                  && install -m 0644 $(PKG_LICENSE_FILES) $(BUILD_DIR)$(MMT_DOC)/
	# Split the ENABLESEC engines into the mmt-dpi-security tree (issue #497):
	# their libraries, links and archives, the fuzz headers and, beside
	# LICENSE and THIRD-PARTY-NOTICES, the GPL text as COPYING. Without the
	# engines no security tree is staged and the links that would dangle
	# are dropped.
	$(QUIET) $(RM) $(SEC_BUILD_DIR)
	$(QUIET) if $(SEC_ENGINES_BUILT); then \
		umask 022 && install -d -m 0755 $(SEC_BUILD_DIR)$(MMT_LIB) $(SEC_BUILD_DIR)$(MMT_INC) \
		    $(SEC_BUILD_DIR)$(MMT_SEC_DOC) \
		&& for f in $(BUILD_DIR)$(MMT_LIB)/libmmt_security.* $(BUILD_DIR)$(MMT_LIB)/libmmt_fuzz.*; do \
			if [ -e "$$f" ] || [ -L "$$f" ]; then mv "$$f" $(SEC_BUILD_DIR)$(MMT_LIB)/; fi; \
		done \
		&& if [ -d $(BUILD_DIR)$(MMT_INC)/fuzz ]; then mv $(BUILD_DIR)$(MMT_INC)/fuzz $(SEC_BUILD_DIR)$(MMT_INC)/; fi \
		&& install -m 0644 $(PKG_LICENSE_FILES) $(SEC_BUILD_DIR)$(MMT_SEC_DOC)/ \
		&& install -m 0644 $(GPL_LICENSE_TEXT) $(SEC_BUILD_DIR)$(MMT_SEC_DOC)/COPYING; \
	else \
		$(RM) $(BUILD_DIR)$(MMT_LIB)/libmmt_security.so $(BUILD_DIR)$(MMT_LIB)/libmmt_fuzz.so; \
	fi
	# The package is installed by root into the system search path — assert the
	# staged library dir carries no group/world-writable file (F-SEC-012).
	$(QUIET) for d in $(BUILD_DIR)$(MMT_LIB) $(SEC_BUILD_DIR)$(MMT_LIB); do \
		if [ -d $$d ] && find $$d -type f -perm /022 -print -quit | grep -q .; then \
			echo "ERROR: group/world-writable file under $$d" >&2; exit 1; \
		fi; \
	done

deb: sdk $(SDKLIB) $(SDKINC) $(SDKXAM) --private-prepare-build-dir
	$(QUIET) $(MKDIR) $(BUILD_DIR)/DEBIAN
	# Depends is derived from the NEEDED entries of the shipped shared
	# objects (issue #219, F-DEP-203/204): tools/ci/shlib-deps.sh maps each
	# soname to the Debian package providing it and fails on an unmapped
	# soname, so the declaration can never drift from the payload again.
	# libpcap is deliberately absent — nothing shipped links it.
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

	# mmt-dpi-security (issue #497): Depends derived from its own libraries
	# exactly as above, plus the same mmt-dpi version (see SEC_BUILD_DIR);
	# check-package-deps.sh --verify-package requires exactly that entry.
	# Replaces: lets it take over the engine files an mmt-dpi built before
	# the split still owns — unversioned, because the revision is a git hash
	# and does not order. Same timestamp clamping.
	$(QUIET) if [ -d $(SEC_BUILD_DIR) ]; then \
		$(MKDIR) $(SEC_BUILD_DIR)/DEBIAN \
		&& secdeps=`sh '$(TOPDIR)/tools/ci/shlib-deps.sh' deb '$(SEC_BUILD_DIR)$(MMT_LIB)'` \
		&& printf '%s\n' "Package: mmt-dpi-security" "Version: $(VERSION)-$(GIT_VERSION)" \
		    "Section: libs" "Priority: optional" "Architecture: $(DEB_ARCH)" \
		    "Maintainer: Montimage <contact@montimage.eu>" \
		    "Depends: $$secdeps, mmt-dpi (= $(VERSION)-$(GIT_VERSION))" "Replaces: mmt-dpi" \
		    "Description: MMT-DPI security and fuzz engines" \
		    " (Built time: $(BUILD_DATE))" \
		    " The optional engines of MMT-DPI built with ENABLESEC=1: the libmmt_security" \
		    " rule engine (GPL-3.0-or-later) and the libmmt_fuzz quality-estimation" \
		    " engine, with the fuzz headers." \
		    " Homepage: http://www.montimage.eu" > $(SEC_BUILD_DIR)/DEBIAN/control \
		&& printf '%s\n' '#!/bin/sh' 'set -e' 'ldconfig' > $(SEC_BUILD_DIR)/DEBIAN/postinst \
		&& printf '%s\n' '#!/bin/sh' 'set -e' 'if [ "$$1" = "remove" ] || [ "$$1" = "purge" ]; then' \
		    '    ldconfig' 'fi' > $(SEC_BUILD_DIR)/DEBIAN/postrm \
		&& chmod 0755 $(SEC_BUILD_DIR)/DEBIAN/postinst $(SEC_BUILD_DIR)/DEBIAN/postrm \
		&& find $(SEC_BUILD_DIR) -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} + \
		&& dpkg-deb --root-owner-group -b $(SEC_BUILD_DIR); \
	fi
	$(QUIET) $(RM) $(BUILD_DIR) $(SEC_BUILD_DIR)

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
	# BuildRequires: is checked against tools/ci/build-deps.txt (issue #495),
	# floored at $(MMT_GCC_MIN); no shipped library links libpcap.
	# License: is the SPDX expression of each package (issue #497); the
	# security subpackage is emitted only when the engines were staged, its
	# Requires: derived from its own libraries. The main %files names its
	# libraries rather than globbing /opt/mmt: rpm would otherwise generate
	# build-id links for the engine libraries in the main package as well.
	$(QUIET) reqs=`sh '$(TOPDIR)/tools/ci/shlib-deps.sh' rpm '$(BUILD_DIR)$(MMT_LIB)' '$(BUILD_DIR)$(MMT_PLUGINS)'` \
	    && sec= && if [ -d $(SEC_BUILD_DIR) ]; then sec=1 \
	    && secreqs=`sh '$(TOPDIR)/tools/ci/shlib-deps.sh' rpm '$(SEC_BUILD_DIR)$(MMT_LIB)'`; fi \
	    && { echo -e\
	    "Summary:  MMT-DPI\
	    \nName: mmt-dpi\
	    \nVersion: $(VERSION)\
	    \nRelease: $(GIT_VERSION)\
	    \nLicense: $(PKG_LICENSE)\
	    \nGroup: Development/Libraries\
	    \nURL: http://montimage.eu/\
	    \nRequires: $$reqs\
	    \nBuildRequires: gcc >= $(MMT_GCC_MIN), gcc-c++ >= $(MMT_GCC_MIN), make, git, file, findutils, which, binutils, libxml2-devel, rpm-build\
	    \n\
	    \nBuildRoot: %{_topdir}/BUILD/$(BUILD_DIR)\
	    \n\
	    \n%description\
	    \nMMT-DPI is a library for deep packet inspection.\
	    \nBuild date: $(BUILD_DATE)\
	    \n"; \
	    if [ -n "$$sec" ]; then echo -e\
	    "%package security\
	    \nSummary:  MMT-DPI security and fuzz engines\
	    \nLicense: $(SEC_PKG_LICENSE)\
	    \nRequires: $$secreqs, mmt-dpi = $(VERSION)-$(GIT_VERSION)\
	    \n\
	    \n%description security\
	    \nThe optional engines of MMT-DPI built with ENABLESEC=1: the libmmt_security\
	    \nrule engine (GPL-3.0-or-later) and the libmmt_fuzz quality-estimation\
	    \nengine, with the fuzz headers.\
	    \nBuild date: $(BUILD_DATE)\
	    \n"; fi; \
	    echo -e\
	    "%prep\
	    \nrm -rf %{buildroot}\
	    \nmkdir -p %{buildroot}/\
	    \ncp -rp %{_topdir}/../$(BUILD_DIR)/. %{buildroot}/\
	    \nmkdir -p %{buildroot}/etc/ld.so.conf.d/"; \
	    if [ -n "$$sec" ]; then echo "cp -rp %{_topdir}/../$(SEC_BUILD_DIR)/. %{buildroot}/"; fi; \
	    echo -e\
	    "\n%clean\
	    \nrm -rf %{buildroot}\
	    \n\
	    \n%files\
	    \n%defattr(-,root,root,-)\
	    \n%dir $(MMT_DPI)\
	    \n%dir $(MMT_LIB)$(foreach l,$(MMT_PKG_LIBS),\n$(MMT_LIB)/$(l)*)\
	    \n$(MMT_INC)\
	    \n%exclude $(MMT_INC)/fuzz\
	    \n$(MMT_PLUGINS)\
	    \n$(MMT_EXAMS)\
	    \n%dir $(MMT_DPI)/share\
	    \n%dir $(MMT_DOCDIR)\
	    \n$(MMT_DOC)\
	    \n/etc/ld.so.conf.d/mmt-dpi.conf"; \
	    echo -e\
	    "%post\
	    \nldconfig"; \
	    if [ -n "$$sec" ]; then echo -e\
	    "\n%files security\
	    \n%defattr(-,root,root,-)\
	    \n$(MMT_LIB)/libmmt_security*\
	    \n$(MMT_LIB)/libmmt_fuzz*\
	    \n$(MMT_INC)/fuzz\
	    \n$(MMT_SEC_DOC)\
	    \n%post security\
	    \nldconfig\
	    \n%postun security\
	    \nldconfig"; fi; \
	    } > ./mmt-dpi.spec

	# Reproducibility (issue #220, F-CI-011): clamp the staged mtimes to
	# SOURCE_DATE_EPOCH before rpmbuild copies the tree, pin %_buildhost —
	# the hostname otherwise leaks into RPMTAG_BUILDHOST and the build
	# cookie — and opt in to rpm's SDE handling: %_buildhost alone leaves
	# RPMTAG_BUILDTIME at the wall clock (rpm needs the two explicit
	# macros; merely exporting the variable is not enough on rpm 4.16).
	# _rpmfilename is per package: %%{NAME} survives macro expansion as the
	# header tag %{NAME}, so mmt-dpi_… and mmt-dpi-security_… do not collide
	# (issue #497), named like the .deb files.
	$(QUIET) find $(BUILD_DIR) -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} + \
	    && if [ -d $(SEC_BUILD_DIR) ]; then find $(SEC_BUILD_DIR) -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} +; fi
	rpmbuild --quiet --rmspec --define "_topdir `pwd`/rpmbuild" --define "_rpmfilename ../../%%{NAME}_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION).rpm" --define "_buildhost mmt-dpi" --define "use_source_date_epoch_as_buildtime 1" --define "clamp_mtime_to_source_date_epoch 1" -bb ./mmt-dpi.spec

	$(QUIET) $(RM) $(BUILD_DIR) $(SEC_BUILD_DIR) rpmbuild mmt-dpi.spec


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
	# Likewise SOVERSION, which names the SONAME links its install.sh creates (issue #536).
	$(QUIET) sed -i 's/^SOVERSION="$${SOVERSION:-.*}"/SOVERSION="$(SOVERSION)"/' $(BUILD_DIR)/mmt-install-common.sh
	# Licence files (issue #497): the ZIP carries every library, so it ships
	# LICENSE, THIRD-PARTY-NOTICES and, with the engines, the GPL text as COPYING.
	$(QUIET) umask 022 && install -m 0644 $(PKG_LICENSE_FILES) $(BUILD_DIR)/ \
	    && if $(SEC_ENGINES_BUILT); then install -m 0644 $(GPL_LICENSE_TEXT) $(BUILD_DIR)/COPYING; fi
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
	$(QUIET) $(RM) $(SDKLIB) $(SDKBIN) $(SDKINC) $(SDKDOC) $(SDKXAM) $(BUILD_DIR) $(SEC_BUILD_DIR) rpmbuild mmt-dpi.spec $(PLUGINS_PATH_STAMP)
	$(QUIET) $(RM) $(TOPDIR)/*.log $(TOPDIR)/*.tmp $(TOPDIR)/*.bak $(TOPDIR)/coverage.info $(TOPDIR)/coverage.json $(TOPDIR)/lcov.info
	$(QUIET) $(RM) $(TOPDIR)/cppcheck*.xml $(TOPDIR)/cppcheck_output.xml $(TOPDIR)/cppcheck-report.xml $(TOPDIR)/PVS-Studio.log $(TOPDIR)/pvs.log
	$(QUIET) $(RM) $(TOPDIR)/mmt-dpi_*.deb $(TOPDIR)/mmt-dpi_*.rpm $(TOPDIR)/mmt-dpi_*.zip
	$(QUIET) $(RM) $(TOPDIR)/sdk/mmt-dpi_*.deb $(TOPDIR)/sdk/mmt-dpi_*.rpm $(TOPDIR)/sdk/mmt-dpi_*.zip 2>/dev/null || true
	$(QUIET) $(RM) $(TOPDIR)/mmt-dpi-security_*.deb $(TOPDIR)/mmt-dpi-security_*.rpm $(TOPDIR)/sdk/mmt-dpi-security_*.deb $(TOPDIR)/sdk/mmt-dpi-security_*.rpm 2>/dev/null || true
	$(QUIET) $(RM) mmt-dpi_*.deb mmt-dpi_*.rpm mmt-dpi_*.zip *.gcda *.gcno *.gcov 2>/dev/null || true
	$(QUIET) $(RM) mmt-dpi-security_*.deb mmt-dpi-security_*.rpm $(SEC_BUILD_DIR) 2>/dev/null || true
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

# The rule engine's default reaction folder (issue #512) is baked into
# tips_report.o as MMT_SEC_REACTION_DIR_OPT (rules/common.mk): like
# plugins_engine.o above, that object depends on a stamp holding the value.
ifdef ENABLESEC
REACTION_DIR_STAMP := $(SRCDIR)/mmt_security/tips_report.path
$(REACTION_DIR_STAMP): FORCE
	$(QUIET) if [ "`cat $@ 2>/dev/null`" != "$(MMT_SEC_REACTION_DIR_DEFAULT)" ]; then echo "$(MMT_SEC_REACTION_DIR_DEFAULT)" > $@; fi
$(SRCDIR)/mmt_security/tips_report.o: $(REACTION_DIR_STAMP)
endif

#  - - - - - - - - - - - - - -
#  I N S T A L L - F H S
#  - - - - - - - - - - - - - -
# Distribution layout (issue #475): install under $(DESTDIR) at the FHS
# locations the caller names — the lib<name>.so.$(SOVERSION) runtime links
# and lib<name>.so development links (relative), the plugin directory as
# relative links to those libraries, a pkg-config file. No
# /etc/ld.so.conf.d drop-in, no ldconfig call (the dpkg/rpm triggers run it),
# no licence files (debian/copyright carries them) and no install manifest
# (the package manager owns the file list). `install` and the MMT_BASE
# contract are unchanged.
#
# The directories are the existing MMT_LIB/MMT_INC/MMT_PLUGINS/MMT_EXAMS
# variables, and they must reach the build as well as this target:
# MMT_PLUGINS is compiled into plugins_engine.o (PLUGINS_REPOSITORY_OPT), so
# a library built for /opt/mmt would look for its plugins there; like
# `install`, this target never compiles and --check-built refuses that
# mismatch. Example (debian/rules does the same):
#   V="MMT_LIB=/usr/lib/x86_64-linux-gnu MMT_INC=/usr/include/mmt-dpi \
#      MMT_PLUGINS=/usr/lib/x86_64-linux-gnu/mmt-dpi/plugins \
#      MMT_EXAMS=/usr/share/doc/libmmt-dpi-dev/examples"
#   make -C sdk $V && make -C sdk $V DESTDIR=/tmp/stage install-fhs
# INSTALL_STATIC=1 also installs the static archives (off: distros seldom want them).
ifneq ($(filter install-fhs,$(MAKECMDGOALS)),)
$(foreach v,MMT_LIB MMT_INC MMT_PLUGINS MMT_EXAMS,$(if $(filter file default undefined,$(origin $(v))),$(error install-fhs needs $(v)=<dir> on the build and on this target: the /opt/mmt default is not an FHS location)))
endif

DESTDIR       ?=
MMT_PKGCONFIG ?= $(MMT_LIB)/pkgconfig
FHS_LIBS      := $(LIBCORE) $(LIBTCPIP) $(LIBMOBILE) $(LIBBAPP) $(LIBDICOM)
FHS_PLUGINS   := $(LIBTCPIP) $(LIBMOBILE) $(LIBBAPP) $(LIBDICOM)
ifdef ENABLESEC
FHS_LIBS      += $(LIBSECURITY) $(LIBFUZZ)
endif

install-fhs: --check-built
	@ install -d -m 0755 $(DESTDIR)$(MMT_LIB) $(DESTDIR)$(MMT_INC) $(DESTDIR)$(MMT_PLUGINS) $(DESTDIR)$(MMT_EXAMS) $(DESTDIR)$(MMT_PKGCONFIG)
	@ for lib in $(FHS_LIBS); do \
		install -m 0755 $(SDKLIB)/$$lib.so.$(VERSION) $(DESTDIR)$(MMT_LIB)/ \
		&& ln -sf $$lib.so.$(VERSION) $(DESTDIR)$(MMT_LIB)/$$lib.so.$(SOVERSION) \
		&& ln -sf $$lib.so.$(SOVERSION) $(DESTDIR)$(MMT_LIB)/$$lib.so || exit 1; \
	done
# The plugin directory holds relative links to the one installed copy: the
# core dlopen()s every *.so in it, and a link resolves to the same object an
# application that links the library directly already has mapped.
	@ rel=`realpath -s --relative-to=$(DESTDIR)$(MMT_PLUGINS) $(DESTDIR)$(MMT_LIB)` \
	&& for lib in $(FHS_PLUGINS); do \
		ln -sf $$rel/$$lib.so.$(SOVERSION) $(DESTDIR)$(MMT_PLUGINS)/$$lib.so || exit 1; \
	done
	@ $(if $(INSTALL_STATIC),install -m 0644 $(SDKLIB)/*.a $(DESTDIR)$(MMT_LIB)/,:)
	@ umask 022 && cp -R $(SDKINC)/. $(DESTDIR)$(MMT_INC)/ \
		&& find $(DESTDIR)$(MMT_INC) -type d -exec chmod 0755 {} + \
		&& find $(DESTDIR)$(MMT_INC) -type f -exec chmod 0644 {} +
	@ umask 022 && cp -R $(SDKXAM)/. $(DESTDIR)$(MMT_EXAMS)/ \
		&& find $(DESTDIR)$(MMT_EXAMS) -type d -exec chmod 0755 {} + \
		&& find $(DESTDIR)$(MMT_EXAMS) -type f -exec chmod 0644 {} +
	@ umask 022 && printf '%s\n' \
		'libdir=$(MMT_LIB)' 'includedir=$(MMT_INC)' 'plugindir=$(MMT_PLUGINS)' '' \
		'Name: mmt-dpi' 'Description: MMT-DPI deep packet inspection library' \
		'URL: https://github.com/montimage-projects/mmt-dpi' 'Version: $(VERSION)' \
		'Libs: -L$${libdir} -lmmt_core' 'Libs.private: -ldl -lpthread -lm' \
		'Cflags: -I$${includedir}' > $(DESTDIR)$(MMT_PKGCONFIG)/mmt-dpi.pc \
		&& chmod 0644 $(DESTDIR)$(MMT_PKGCONFIG)/mmt-dpi.pc
# Same assertion as `install`: nothing group/world-writable in the loader path.
	@ if find $(DESTDIR)$(MMT_LIB) -type f -perm /022 -print -quit | grep -q .; then \
		echo "ERROR: group/world-writable file under $(DESTDIR)$(MMT_LIB)" >&2; exit 1; \
	fi
	@ echo "[MMT-]> Installed the FHS layout under $(DESTDIR)$(MMT_LIB)"
