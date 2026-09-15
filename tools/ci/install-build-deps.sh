#!/usr/bin/env bash
#
# install-build-deps.sh — install the per-distro package build dependencies
# (extracted from build-package.sh for issue #220, F-CI-011).
#
# The dependency set is a single source of truth: build-package.sh installs
# it for the real package build and check-reproducible-build.sh installs the
# identical set for the double-build gate, so the two can never drift apart.
# Intended to run as root inside a per-distro container from
# release-packages.yml.
#
# Arguments:
#   $1  DISTRO_ID   short, filesystem-safe distro tag (e.g. ubuntu-24.04, rocky-9)
#   $2  PKG_TYPE    deb | rpm
#
set -euo pipefail

DISTRO_ID="${1:?usage: install-build-deps.sh <distro-id> <deb|rpm>}"
PKG_TYPE="${2:?usage: install-build-deps.sh <distro-id> <deb|rpm>}"

log() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }

install_build_deps_debian() {
  log "Installing build dependencies (Debian/Ubuntu: $DISTRO_ID)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  # Compile-time deps only (issue #219): libxml2-dev is linked by the
  # ENABLESEC engines built below; libpcap-dev provides <pcap/pcap.h> for
  # src/mmt_security/public_defs.h — neither lands in the package's Depends,
  # which is derived from the shipped libraries' NEEDED entries instead.
  # binutils provides objdump for that derivation (tools/ci/shlib-deps.sh).
  # libnghttp2-dev is intentionally absent: no built library references any
  # nghttp2_* symbol, so the linker's --as-needed would drop it anyway.
  # python3 runs the --verify-package leg of check-package-deps.sh.
  apt-get install -y --no-install-recommends \
    build-essential g++ make git ca-certificates file binutils \
    libxml2-dev libpcap-dev dpkg-dev python3
}

install_build_deps_rhel() {
  log "Installing build dependencies (RHEL family: $DISTRO_ID)"
  local pm=dnf
  command -v dnf >/dev/null 2>&1 || pm=yum
  # libpcap-devel lives in the CRB (CodeReady Builder / PowerTools) repo on
  # EL9, which ships disabled — enable it before installing the -devel packages.
  # binutils provides objdump for the NEEDED -> Requires derivation (issue
  # #219); see install_build_deps_debian for the libxml2/libpcap rationale.
  "$pm" install -y dnf-plugins-core || true
  "$pm" config-manager --set-enabled crb 2>/dev/null \
    || "$pm" config-manager --set-enabled powertools 2>/dev/null || true
  # python3 runs the --verify-package leg of check-package-deps.sh.
  "$pm" install -y \
    gcc gcc-c++ make git file findutils which binutils \
    libxml2-devel libpcap-devel rpm-build python3
}

case "$PKG_TYPE" in
  deb) install_build_deps_debian ;;
  rpm) install_build_deps_rhel ;;
  *) echo "✗ Unknown package type: $PKG_TYPE (expected deb|rpm)" >&2; exit 2 ;;
esac
