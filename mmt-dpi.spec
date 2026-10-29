# RPM recipe for MMT-DPI (issue #550): the distribution build, from the
# reproducible release source tarball (tools/ci/build-source-tarball.sh,
# published with every release), through the FHS install mode
# (`make -C sdk install-fhs`, issue #475) — the RPM counterpart of debian/.
# Usable as is by COPR or OBS:
#   bash tools/ci/build-source-tarball.sh --out ~/rpmbuild/SOURCES
#   rpmbuild -ba mmt-dpi.spec
# CI builds, lints, installs and exercises it on every EL release image
# (tools/ci/build-rpm-package.sh, release-packages.yml `rpm-package`).
# The upstream /opt/mmt packages that GitHub Releases ship still come from
# `make -C sdk rpm` (docs/DECISIONS.md, #550). This recipe is their intended
# successor and keeps the Name mmt-dpi, so the two are alternatives, never
# installed side by side: their layouts differ and their Release fields (a
# git hash there, a counter plus the dist tag here) do not order.
#
# Version must equal rules/common.mk VERSION (scripts/validate-release-prep.sh).

# SOURCE_DATE_EPOCH from the newest changelog entry: package timestamps never
# come from the wall clock (rules/common.mk derives it from git otherwise,
# and the tarball carries no .git).
%global source_date_epoch_from_changelog 1

# The same variables reach the build and the install: the plugin directory is
# compiled into libmmt_core (rules/common.mk, PLUGINS_REPOSITORY_OPT).
%global mmt_vars MMT_LIB=%{_libdir} MMT_INC=%{_includedir}/%{name} MMT_PLUGINS=%{_libdir}/%{name}/plugins MMT_EXAMS=%{_docdir}/%{name}-devel/examples GIT_VERSION=%{version}-%{release}

Name:           mmt-dpi
Version:        1.9.1
Release:        1%{?dist}
Summary:        Deep packet inspection library

# The SDK's own code is Apache-2.0; the vendored llhttp parser is MIT and the
# asn1c runtime BSD-2-Clause (THIRD-PARTY-NOTICES). Same expression as the
# mmt-dpi package sdk/Makefile builds (PKG_LICENSE). The GPL-3.0-or-later
# security engine (ENABLESEC=1) is not built here.
License:        Apache-2.0 AND BSD-2-Clause AND MIT
URL:            https://github.com/montimage-projects/mmt-dpi
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make

%description
MMT-DPI extracts data attributes from network packets, server logs and other
structured events, and classifies the application protocol of each flow, so
that the results can be analyzed or monitored in real time.

The core engine loads its protocol dissectors as plugins: TCP/IP, mobile core
(S1AP, NGAP, GTPv2, NAS, Diameter), DICOM and business applications. This
package contains the shared libraries and the protocol plugins.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
The C headers, the development library links, the build-flags file and
the example programs for developing applications that use %{name}.

%prep
%autosetup

%build
# The distribution flags go after the SDK's own (MMT_EXTRA_CFLAGS is appended
# after them, rules/arch-linux.mk), so -g reaches the debuginfo extraction.
# LDFLAGS goes through the environment, never the make command line: a
# command-line value would override the `LDFLAGS += -Wl,-z,defs` that
# rules/common-linux.mk adds to libmmt_core's link.
LDFLAGS="%{build_ldflags}" %make_build -C sdk %{mmt_vars} MMT_EXTRA_CFLAGS="%{optflags}"

%install
%make_build -C sdk %{mmt_vars} DESTDIR=%{buildroot} install-fhs

%check
# Only the suites that need nothing but the compiler, as debian/rules runs:
# the others build and install the whole SDK into a throwaway prefix. The
# packaged libraries are exercised end to end by the CI consumer.
bash tests/run_all_tests.sh hexdump mmt_utils mmt_inet_ntop avltree memory

%files
%license LICENSE THIRD-PARTY-NOTICES
%doc README.md
%{_libdir}/libmmt_*.so.*
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/plugins/

%files devel
%{_includedir}/%{name}/
%{_libdir}/libmmt_*.so
%{_libdir}/pkgconfig/%{name}.pc
%{_docdir}/%{name}-devel/

%changelog
* Thu Oct 29 2026 Montimage <developer@montimage.eu> - 1.9.1-1
- RPM recipe from the release source tarball (#550)
