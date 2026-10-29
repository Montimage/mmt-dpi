#!/usr/bin/env bash
#
# build-rpm-package.sh — build, lint, install and exercise the RPM packages
# that mmt-dpi.spec produces (issue #550).
#
# This is the package a distribution (COPR, OBS, Fedora/EPEL) would build
# itself: `rpmbuild -ba mmt-dpi.spec` from the reproducible release source
# tarball, the FHS layout (`make -C sdk install-fhs`), versioned sonames, no
# /opt/mmt. It is NOT the upstream `make rpm` package that build-package.sh
# ships to GitHub Releases, and nothing built here is published.
#
# Runs as root inside an EL container with the checkout at $PWD (the
# release-packages.yml convention). The source tarball is `git archive` of
# HEAD (tools/ci/build-source-tarball.sh), so the build sees exactly the
# committed tree; rpmbuild works in a scratch _topdir.
#
# Steps: tarball -> rpmbuild -ba (runs the spec's %check) -> rpmlint on the
# spec, the source and the binary packages (an error fails, warnings are
# listed) -> install mmt-dpi + mmt-dpi-devel -> pkg-config finds mmt-dpi with
# no PKG_CONFIG_PATH -> tools/ci/tests/run-installed-consumer.sh, compiled
# through pkg-config, on the vendored fixtures. The packages are collected
# into dist/rpm-packages/.
#
# Usage: build-rpm-package.sh [<distro-id>]
# Exit: 0 = every step passed, non-zero = the first failing step.
set -euo pipefail

DISTRO="${1:-el}"
SRC="$PWD"
[ -f "${SRC}/mmt-dpi.spec" ] || { echo "✗ run from the repository root (no mmt-dpi.spec)" >&2; exit 2; }

log() { printf '\n==> %s\n' "$*"; }

log "Installing the packaging tools (${DISTRO})"
pm=dnf
command -v dnf >/dev/null 2>&1 || pm=yum
# libpcap-devel (the consumer's own capture reader) lives in the CRB repo,
# which EL9/EL10 ship disabled. rpmlint is in EL9's AppStream but only in
# EPEL on EL10: the distribution's own epel-release package adds it there.
"$pm" install -y -q dnf-plugins-core >/dev/null
"$pm" config-manager --set-enabled crb 2>/dev/null \
    || "$pm" config-manager --set-enabled powertools 2>/dev/null || true
if ! "$pm" -q list --available rpmlint >/dev/null 2>&1; then
    "$pm" install -y -q epel-release >/dev/null
fi
"$pm" install -y -q rpm-build rpmlint git gzip tar gcc make \
    pkgconf-pkg-config libpcap-devel >/dev/null

git config --global --add safe.directory "${SRC}"
TOP="$(mktemp -d)"
trap 'rm -rf "${TOP}"' EXIT
mkdir -p "${TOP}/SOURCES"

log "Source tarball and rpmbuild -ba"
bash tools/ci/build-source-tarball.sh --out "${TOP}/SOURCES"
rpmbuild -ba --define "_topdir ${TOP}" mmt-dpi.spec

log "rpmlint (errors fail the build, warnings are listed)"
mapfile -t rpms < <(find "${TOP}/SRPMS" "${TOP}/RPMS" -name '*.rpm' | LC_ALL=C sort)
rpmlint mmt-dpi.spec "${rpms[@]}"

log "Install the packages and run the consumer through pkg-config"
mapfile -t install_rpms < <(find "${TOP}/RPMS" \( -name 'mmt-dpi-[0-9]*.rpm' -o -name 'mmt-dpi-devel-[0-9]*.rpm' \) | LC_ALL=C sort)
[ "${#install_rpms[@]}" -eq 2 ] || { echo "✗ expected mmt-dpi and mmt-dpi-devel, found ${install_rpms[*]:-none}" >&2; exit 1; }
"$pm" install -y -q "${install_rpms[@]}" >/dev/null
libdir="$(rpm --eval '%{_libdir}')"
# The FHS .pc sits on pkg-config's default search path: no PKG_CONFIG_PATH.
env -u PKG_CONFIG_PATH pkg-config --exists mmt-dpi \
    || { echo "✗ pkg-config does not find mmt-dpi after installing the packages" >&2; exit 1; }
bash tools/ci/tests/run-installed-consumer.sh --no-engines \
    --libdir "${libdir}" --includedir /usr/include/mmt-dpi \
    --plugindir "${libdir}/mmt-dpi/plugins" \
    --distro "${DISTRO}" --arch "$(uname -m)"

mkdir -p "${SRC}/dist/rpm-packages"
cp "${rpms[@]}" "${SRC}/dist/rpm-packages/"
# The container runs as root: hand the output (and dist/, when this run
# created it) back to the checkout owner.
chown --reference="${SRC}" "${SRC}/dist"
chown -R --reference="${SRC}" "${SRC}/dist/rpm-packages"
ls -l "${SRC}/dist/rpm-packages"
