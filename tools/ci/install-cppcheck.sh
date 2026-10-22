#!/usr/bin/env bash
#
# install-cppcheck.sh — build the pinned cppcheck release from source
# (issue #518, F-DEP-306).
#
# The findings ratchet of tools/ci/run-cppcheck.sh is only comparable under
# the cppcheck release it was measured with (issue #345). No distribution
# package carries the pinned release, and a distribution package would move
# under the ratchet on the next archive refresh anyway, so the lint job builds
# it from the upstream source tarball inside the digest-pinned ubuntu:24.04
# container (.github/workflows/c-cpp.yml, `lint` job). The tarball is pinned
# by sha256: a retagged or tampered archive fails here instead of silently
# changing the analyser. CPPCHECK_VERSION must keep the major.minor of
# CPPCHECK_PINNED_VERSION in run-cppcheck.sh — tools/ci/tests/
# test-cppcheck-version.sh fails when the two disagree.
#
# Build prerequisites: g++, make, python3 (the match compiler), curl,
# ca-certificates, tar/gzip. The script installs nothing else.
#
# Usage: bash tools/ci/install-cppcheck.sh [PREFIX]
#   PREFIX  install prefix (default /usr/local): the binary lands in
#           PREFIX/bin, the library configuration in PREFIX/share/cppcheck.
#   CPPCHECK_TARBALL=<file>  use an already-downloaded tarball (still
#           checksum-verified) instead of fetching it.
#
# Exit codes: 0 = installed and `cppcheck --version` reports the pin,
# 1 = checksum mismatch or the built binary reports another version,
# 2 = the helper itself is broken (download or build failure, bad usage).

set -euo pipefail

CPPCHECK_VERSION="2.22.0"
CPPCHECK_SHA256="d74945deb2d50393430e07596b766f8a779512c7f60dac2a30ea64e059ece57b"
CPPCHECK_URL="https://github.com/cppcheck-opensource/cppcheck/archive/refs/tags/${CPPCHECK_VERSION}.tar.gz"

PREFIX="${1:-/usr/local}"
case "$PREFIX" in
    /*) ;;
    *) echo "✗ install prefix must be absolute: $PREFIX" >&2; exit 2 ;;
esac
JOBS="$(nproc 2>/dev/null || echo 2)"

for tool in g++ make python3 tar sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "✗ $tool is required to build cppcheck" >&2
        exit 2
    }
done

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

tarball="${CPPCHECK_TARBALL:-}"
if [ -z "$tarball" ]; then
    command -v curl >/dev/null 2>&1 || { echo "✗ curl is required to fetch cppcheck" >&2; exit 2; }
    tarball="$WORK/cppcheck-${CPPCHECK_VERSION}.tar.gz"
    curl -fsSL --retry 5 --retry-delay 10 -o "$tarball" "$CPPCHECK_URL" || {
        echo "✗ cannot download $CPPCHECK_URL" >&2
        exit 2
    }
fi

actual="$(sha256sum "$tarball" | cut -d' ' -f1)"
if [ "$actual" != "$CPPCHECK_SHA256" ]; then
    echo "✗ cppcheck $CPPCHECK_VERSION tarball checksum mismatch" >&2
    echo "    expected $CPPCHECK_SHA256" >&2
    echo "    got      $actual" >&2
    exit 1
fi

tar -xzf "$tarball" -C "$WORK"
src="$WORK/cppcheck-${CPPCHECK_VERSION}"
[ -f "$src/Makefile" ] || { echo "✗ unexpected tarball layout (no $src/Makefile)" >&2; exit 2; }

# MATCHCOMPILER=yes is upstream's release-build optimisation (it does not
# change which findings are reported); an empty CPPCHK_GLIBCXX_DEBUG drops
# the libstdc++ debug containers the Makefile enables on Linux by default,
# which only slow the scan down.
make -C "$src" -j"$JOBS" \
    MATCHCOMPILER=yes CPPCHK_GLIBCXX_DEBUG= CXXFLAGS="-O2 -w" \
    FILESDIR="$PREFIX/share/cppcheck" PREFIX="$PREFIX" \
    install >/dev/null || { echo "✗ cppcheck $CPPCHECK_VERSION build failed" >&2; exit 2; }

reported="$("$PREFIX/bin/cppcheck" --version 2>/dev/null || true)"
if [ "$reported" != "Cppcheck $CPPCHECK_VERSION" ]; then
    echo "✗ installed cppcheck reports '${reported:-<nothing>}', expected Cppcheck $CPPCHECK_VERSION" >&2
    exit 1
fi
echo "✓ $reported installed in $PREFIX"
