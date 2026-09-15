#!/usr/bin/env bash
#
# check-reproducible-build.sh — prove the package build is byte-identical
# across two runs of the same commit (issue #220, F-CI-011).
#
# The release workflow used to stamp wall-clock seconds into the staging path
# and the package metadata, and silently fell back to a date-derived version
# when git history was missing — no two builds could ever agree. The deb/rpm
# targets now pin every timestamp to SOURCE_DATE_EPOCH (exported by
# rules/common.mk from the commit's own timestamp when unset), normalise
# staged file mtimes and pass a fixed -frandom-seed per source file, so a
# double build must produce identical sha256 sums.
#
# Intended to run inside a per-distro container from release-packages.yml:
#
#   docker run --rm -e CI -v "$PWD":/work -w /work <image> \
#       bash tools/ci/check-reproducible-build.sh --install-deps <distro-id> <deb|rpm>
#
# Arguments:
#   --install-deps  first run tools/ci/install-build-deps.sh (as root, in the
#                   container); omit it where the build deps already exist —
#                   that is what makes a local run possible
#   $1  DISTRO_ID   short distro tag, only used for the dep install / logging
#   $2  PKG_TYPE    deb | rpm
#
# Exit codes: 0 = byte-identical, 1 = builds differ or build failed,
#             2 = bad usage / helper broken.
#
set -euo pipefail

if [ "${1:-}" = "--install-deps" ]; then
  INSTALL_DEPS=1
  shift
else
  INSTALL_DEPS=0
fi
DISTRO_ID="${1:?usage: check-reproducible-build.sh [--install-deps] <distro-id> <deb|rpm>}"
PKG_TYPE="${2:?usage: check-reproducible-build.sh [--install-deps] <distro-id> <deb|rpm>}"
case "$PKG_TYPE" in
  deb|rpm) ;;
  *) echo "✗ Unknown package type: $PKG_TYPE (expected deb|rpm)" >&2; exit 2 ;;
esac

log() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }

# Same dep set the real package build installs — the list lives in
# install-build-deps.sh so the two can never drift apart (issue #220).
if [ "$INSTALL_DEPS" -eq 1 ]; then
  bash "$(dirname "$0")/install-build-deps.sh" "$DISTRO_ID" "$PKG_TYPE"
fi

# The repo is bind-mounted from the host in the container; git refuses to
# operate on a tree owned by another uid unless it is marked safe (same as
# build-package.sh).
git config --global --add safe.directory "$(pwd)" 2>/dev/null || true

# Pin the two inputs reproducibility is measured against — the revision in
# the package metadata and the epoch every stamped timestamp is clamped to.
# Without git history there is nothing deterministic to pin them to: fail
# here rather than produce a "reproducible" artifact stamped with the wall
# clock (rules/common.mk independently hard-errors on this under CI).
GIT_VERSION="${GIT_VERSION:-$(git log --format='%h' -n 1 2>/dev/null || true)}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || true)}"
if [ -z "$GIT_VERSION" ] || [ -z "$SOURCE_DATE_EPOCH" ]; then
  echo "✗ no git history — cannot derive GIT_VERSION / SOURCE_DATE_EPOCH;" >&2
  echo "  reproducibility is unprovable without a commit to pin them to" >&2
  exit 1
fi
export SOURCE_DATE_EPOCH

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# One full build cycle: clean tree -> compile SDK -> assemble package ->
# stash the artifact. `make clean` between cycles removes objects AND the
# previous package, so the second build starts from the same state a fresh
# checkout would.
build_once() {
  local dest="$1"
  make -C sdk clean >/dev/null 2>&1 || true
  make -C sdk -j"$(nproc)" ENABLESEC=1 GIT_VERSION="$GIT_VERSION" >/dev/null
  make -C sdk "$PKG_TYPE" ENABLESEC=1 GIT_VERSION="$GIT_VERSION" >/dev/null
  local artifacts=()
  local f
  shopt -s nullglob
  for f in sdk/*."$PKG_TYPE"; do
    artifacts+=("$f")
  done
  shopt -u nullglob
  if [ "${#artifacts[@]}" -ne 1 ]; then
    echo "✗ expected exactly 1 .$PKG_TYPE under sdk/, found ${#artifacts[@]}" >&2
    exit 1
  fi
  cp "${artifacts[0]}" "$dest"
}

log "Build 1/2 ($PKG_TYPE on $DISTRO_ID, GIT_VERSION=$GIT_VERSION, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
build_once "$WORK/first.$PKG_TYPE"

log "Build 2/2 (same commit, same inputs)"
build_once "$WORK/second.$PKG_TYPE"

log "Comparing sha256"
sha256sum "$WORK/first.$PKG_TYPE" "$WORK/second.$PKG_TYPE"
sum1="$(sha256sum "$WORK/first.$PKG_TYPE" | awk '{print $1}')"
sum2="$(sha256sum "$WORK/second.$PKG_TYPE" | awk '{print $1}')"
if [ "$sum1" != "$sum2" ]; then
  echo "✗ NOT reproducible: two builds of the same commit differ" >&2
  echo "  first differing bytes (cmp -l, octal, first 20):" >&2
  cmp -l "$WORK/first.$PKG_TYPE" "$WORK/second.$PKG_TYPE" 2>/dev/null | head -20 >&2 || true
  exit 1
fi
log "OK — byte-identical .$PKG_TYPE across two builds ($sum1)"
