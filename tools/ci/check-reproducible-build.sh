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

# One full build cycle: clean tree -> compile SDK -> assemble packages ->
# stash the artifacts in <dest>/. `make clean` between cycles removes objects
# AND the previous packages, so the second build starts from the same state a
# fresh checkout would. An ENABLESEC=1 build yields two packages, mmt-dpi and
# mmt-dpi-security (issue #497); each must be byte-identical across builds.
EXPECTED_ARTIFACTS=2
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
  if [ "${#artifacts[@]}" -ne "$EXPECTED_ARTIFACTS" ]; then
    echo "✗ expected exactly $EXPECTED_ARTIFACTS .$PKG_TYPE under sdk/, found ${#artifacts[@]}" >&2
    exit 1
  fi
  mkdir -p "$dest"
  cp "${artifacts[@]}" "$dest/"
}

log "Build 1/2 ($PKG_TYPE on $DISTRO_ID, GIT_VERSION=$GIT_VERSION, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
build_once "$WORK/first"

log "Build 2/2 (same commit, same inputs)"
build_once "$WORK/second"

log "Comparing sha256"
(cd "$WORK/first" && sha256sum -- *) | LC_ALL=C sort -k2 > "$WORK/first.sums"
(cd "$WORK/second" && sha256sum -- *) | LC_ALL=C sort -k2 > "$WORK/second.sums"
cat "$WORK/first.sums"
if ! diff -u "$WORK/first.sums" "$WORK/second.sums" >&2; then
  echo "✗ NOT reproducible: two builds of the same commit differ" >&2
  for f in "$WORK"/first/*; do
    name="$(basename "$f")"
    if ! cmp -s "$f" "$WORK/second/$name"; then
      echo "  $name — first differing bytes (cmp -l, octal, first 20):" >&2
      cmp -l "$f" "$WORK/second/$name" 2>/dev/null | head -20 >&2 || true
    fi
  done
  exit 1
fi
log "OK — byte-identical .$PKG_TYPE packages across two builds ($(wc -l < "$WORK/first.sums") packages)"
