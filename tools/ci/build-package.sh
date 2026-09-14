#!/usr/bin/env bash
#
# build-package.sh — distro-aware native package builder for MMT-DPI.
#
# Compiles the SDK and produces a single installable package (.deb or .rpm)
# for the running container's distribution, then verifies the package installs
# cleanly. Intended to be invoked inside a per-distro container by the
# release-packages.yml GitHub Actions workflow, e.g.:
#
#   docker run --rm --platform linux/amd64 -v "$PWD":/work -w /work \
#       ubuntu:24.04 bash tools/ci/build-package.sh ubuntu-24.04 deb
#
# Arguments:
#   $1  DISTRO_ID   short, filesystem-safe distro tag (e.g. ubuntu-24.04, rocky-9)
#   $2  PKG_TYPE    deb | rpm
#
# Output: dist/packages/<pkg>_<DISTRO_ID>_<arch>.<PKG_TYPE>
#
set -euo pipefail

# `--dry-run` prints the plan and exits — a cheap self-check usable outside a
# container (issue #211: it is the documented verify path for this script).
if [ "${1:-}" = "--dry-run" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  cat <<'EOF'
build-package.sh — distro-aware native package builder for MMT-DPI.

Usage:
  build-package.sh --dry-run                 print this plan and exit
  build-package.sh <distro-id> <deb|rpm>     build inside the distro container

A real run performs, in order:
  1. install distro build dependencies (apt-get, or dnf/yum with CRB enabled)
  2. make -C sdk && make -C sdk <deb|rpm>    (GIT_VERSION pinned explicitly)
  3. clear dist/packages/, then collect the freshly built artifact there —
     the directory is bind-mounted from the host and shared across matrix
     jobs, so a stale sibling artifact must never be picked up
  4. smoke-test: install exactly the artifact just built (tracked path, not
     a directory glob) and check /opt/mmt/dpi/lib/libmmt_core.so exists
EOF
  exit 0
fi

DISTRO_ID="${1:?usage: build-package.sh <distro-id> <deb|rpm>}"
PKG_TYPE="${2:?usage: build-package.sh <distro-id> <deb|rpm>}"

log() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }

install_build_deps_debian() {
  log "Installing build dependencies (Debian/Ubuntu: $DISTRO_ID)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  # libxml2-dev + libpcap-dev are the only compile-time deps; libnghttp2 is a
  # runtime dependency of the package, pulled in at install time.
  apt-get install -y --no-install-recommends \
    build-essential g++ make git ca-certificates file \
    libxml2-dev libpcap-dev dpkg-dev
}

install_build_deps_rhel() {
  log "Installing build dependencies (RHEL family: $DISTRO_ID)"
  local pm=dnf
  command -v dnf >/dev/null 2>&1 || pm=yum
  # libpcap-devel lives in the CRB (CodeReady Builder / PowerTools) repo on
  # EL9, which ships disabled — enable it before installing the -devel packages.
  "$pm" install -y dnf-plugins-core || true
  "$pm" config-manager --set-enabled crb 2>/dev/null \
    || "$pm" config-manager --set-enabled powertools 2>/dev/null || true
  "$pm" install -y \
    gcc gcc-c++ make git file findutils which \
    libxml2-devel libpcap-devel rpm-build
}

case "$PKG_TYPE" in
  deb) install_build_deps_debian ;;
  rpm) install_build_deps_rhel ;;
  *) echo "✗ Unknown package type: $PKG_TYPE (expected deb|rpm)" >&2; exit 2 ;;
esac

# The repo is bind-mounted from the host; git refuses to operate on a tree owned
# by another uid unless it is marked safe. GIT_VERSION (short hash) needs this.
git config --global --add safe.directory "$(pwd)" 2>/dev/null || true

# Resolve the short commit hash used for package versioning. The Makefile derives
# it from `git log`, which yields an empty string when git history is missing
# (shallow checkout, tarball build, detached worktree) — and an empty revision
# makes both dpkg-deb ("revision number is empty") and rpmbuild fail. Compute it
# here with a date-stamp fallback and pass it explicitly so the Version is never
# left empty.
GIT_VERSION="$(git log --format='%h' -n 1 2>/dev/null || true)"
if [ -z "$GIT_VERSION" ]; then
  GIT_VERSION="$(date -u +%Y%m%d)"
  echo "⚠ git history unavailable — using fallback GIT_VERSION=$GIT_VERSION"
fi

log "Building SDK (GIT_VERSION=$GIT_VERSION)"
# Note: the deb/rpm targets populate their package tree from the SDK build
# output (see `--private-prepare-build-dir`), not from an installed /opt/mmt —
# so `make install` is deliberately NOT run here. Skipping it keeps /opt/mmt
# empty until the package itself is installed, which is what makes the smoke
# test below a genuine check of the package's contents (and saves build time,
# especially under arm64 emulation).
make -C sdk -j"$(nproc)" GIT_VERSION="$GIT_VERSION"
make -C sdk "$PKG_TYPE" GIT_VERSION="$GIT_VERSION"

log "Collecting package artifact"
arch="$(uname -m)"
# The Makefile names artifacts mmt-dpi_<version>_<githash>_<uname-s>_<uname-p>.
# Strip that trailing platform segment so we can append a single, unambiguous
# <distro>_<arch> suffix — otherwise the arch appears twice and `uname -p`
# (often "unknown" on minimal images) leaks into the filename.
sys_suffix="_$(uname -s)_$(uname -p)"
# dist/packages is bind-mounted from the host and shared across matrix jobs:
# clear it before collecting so a stale artifact left by a sibling job can
# never be picked up here or by the smoke test below (issue #211, F-BUG-117).
rm -rf dist/packages
mkdir -p dist/packages
shopt -s nullglob
artifacts=()
for f in sdk/*."$PKG_TYPE"; do
  base="$(basename "$f" ".$PKG_TYPE")"
  base="${base%"$sys_suffix"}"
  dest="./dist/packages/${base}_${DISTRO_ID}_${arch}.${PKG_TYPE}"
  mv "$f" "$dest"
  echo "  built: $dest"
  artifacts+=("$dest")
done
if [ "${#artifacts[@]}" -eq 0 ]; then
  echo "✗ No .$PKG_TYPE produced under sdk/" >&2
  exit 1
fi

# Smoke-test: the package must install on its own distro and expose the core
# lib. Install exactly the artifact paths collected above — never a glob over
# the shared directory (issue #211, F-BUG-117).
log "Verifying package installs"
if [ "$PKG_TYPE" = "deb" ]; then
  apt-get install -y "${artifacts[@]}"
  ldconfig
else
  pm=dnf; command -v dnf >/dev/null 2>&1 || pm=yum
  "$pm" install -y "${artifacts[@]}"
  ldconfig
fi
test -e /opt/mmt/dpi/lib/libmmt_core.so
log "OK — package built and installs cleanly ($DISTRO_ID/$arch)"
