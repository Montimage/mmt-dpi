#!/bin/sh
#
# shlib-deps.sh — derive package dependency declarations from the shared
# objects a package actually ships (issue #219, F-DEP-203/204/206).
#
# The .deb Depends: and .rpm Requires: lines used to be hand-maintained
# lists that drifted from the build: they named libpcap and libnghttp2,
# which nothing in the payload links against, and omitted libxml2, which
# the ENABLESEC engines do link. This helper reads the NEEDED entries of
# the shipped .so files (objdump -p) and maps each soname to the package
# that provides it, so the declaration can never diverge from the payload.
#
# Usage:
#   shlib-deps.sh sonames <dir> [<dir> ...]   sorted unique NEEDED sonames
#   shlib-deps.sh deb     <dir> [<dir> ...]   Debian Depends entries
#   shlib-deps.sh rpm     <dir> [<dir> ...]   RPM Requires entries
#
# <dir> is a directory containing the shared objects to scan (e.g. the
# package staging dir's lib/ and plugins/ folders, or sdk/lib). Symlinks
# and .a archives are ignored. POSIX sh — the Makefile invokes it via `sh`.
#
# The glibc/libstdc++ floors are read from rules/common.mk
# (MMT_GLIBC_MIN / MMT_LIBSTDCXX_MIN, issue #218) so the package
# declaration always matches the enforced toolchain contract.
#
# An unmapped soname exits 2 — better to break the package build loudly
# than to ship a declaration that does not cover the payload. The CI gate
# (check-package-deps.sh --verify-package) double-checks the result.
#
# Exit codes: 0 = ok, 2 = helper error (missing tool/dir, unmapped soname).

set -eu
# -f (noglob): sonames are word-split below; no glob may ever expand.
set -f

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

MODE="${1:-}"
case "$MODE" in
    sonames|deb|rpm) ;;
    *) echo "usage: $0 <sonames|deb|rpm> <dir> [<dir> ...]" >&2; exit 2 ;;
esac
shift
[ "$#" -ge 1 ] || { echo "✗ $0: at least one directory is required" >&2; exit 2; }
command -v objdump >/dev/null 2>&1 \
    || { echo "✗ $0: objdump (binutils) is required" >&2; exit 2; }

# Read the toolchain floors once from their single source of truth.
mk="$ROOT/rules/common.mk"
GLIBC_MIN="$(sed -n 's/^MMT_GLIBC_MIN[[:space:]]*:=[[:space:]]*//p' "$mk" | head -1)"
STDCXX_MIN="$(sed -n 's/^MMT_LIBSTDCXX_MIN[[:space:]]*:=[[:space:]]*//p' "$mk" | head -1)"
# MMT_LIBSTDCXX_MIN is defined as $(MMT_GCC_MIN) — resolve the indirection.
if [ "$STDCXX_MIN" = '$(MMT_GCC_MIN)' ]; then
    STDCXX_MIN="$(sed -n 's/^MMT_GCC_MIN[[:space:]]*:=[[:space:]]*//p' "$mk" | head -1)"
fi
[ -n "$GLIBC_MIN" ] && [ -n "$STDCXX_MIN" ] \
    || { echo "✗ $0: could not read MMT_GLIBC_MIN/MMT_LIBSTDCXX_MIN from rules/common.mk" >&2; exit 2; }

# Collect the sorted unique NEEDED sonames across every shipped .so.
sonames="$(
    for dir in "$@"; do
        [ -d "$dir" ] || { echo "✗ $0: not a directory: $dir" >&2; exit 2; }
        find "$dir" -type f -name '*.so*' -print0
    done | xargs -0 -r objdump -p 2>/dev/null | awk '/NEEDED/ { print $2 }' | sort -u
)"
[ -n "$sonames" ] || { echo "✗ $0: no NEEDED entries found under: $*" >&2; exit 2; }

if [ "$MODE" = "sonames" ]; then
    printf '%s\n' "$sonames"
    exit 0
fi

# Map one soname to the package that provides it. Echoes nothing and
# returns 1 for MMT's own libraries (internal — provided by this package
# itself) and for the vDSO; returns 2 for an unmapped soname.
deb_pkg() {
    case "$1" in
        # The dynamic loader appears in NEEDED on aarch64 toolchains.
        ld-linux*.so.*|ld64.so.*|ld-musl-*.so.*|\
        libc.so.*|libm.so.*|libmvec.so.*|libdl.so.*|libpthread.so.*|\
        librt.so.*|libresolv.so.*|libnsl.so.*|libutil.so.*)
            echo "libc6 (>= $GLIBC_MIN)" ;;
        libstdc++.so.*)  echo "libstdc++6 (>= $STDCXX_MIN)" ;;
        libgcc_s.so.*)   echo "libgcc-s1" ;;
        libxml2.so.*)    echo "libxml2" ;;
        libnghttp2.so.*) echo "libnghttp2-14" ;;
        libpcap.so.*)    echo "libpcap0.8 | libpcap0.8t64" ;;
        libz.so.*)       echo "zlib1g" ;;
        libmmt_*.so*|linux-vdso.so.*) return 1 ;;
        *) return 2 ;;
    esac
}

rpm_pkg() {
    case "$1" in
        ld-linux*.so.*|ld64.so.*|ld-musl-*.so.*|\
        libc.so.*|libm.so.*|libmvec.so.*|libdl.so.*|libpthread.so.*|\
        librt.so.*|libresolv.so.*|libnsl.so.*|libutil.so.*)
            echo "glibc >= $GLIBC_MIN" ;;
        libstdc++.so.*)  echo "libstdc++ >= $STDCXX_MIN" ;;
        libgcc_s.so.*)   echo "libgcc" ;;
        libxml2.so.*)    echo "libxml2" ;;
        libnghttp2.so.*) echo "libnghttp2" ;;
        libpcap.so.*)    echo "libpcap" ;;
        libz.so.*)       echo "zlib" ;;
        libmmt_*.so*|linux-vdso.so.*) return 1 ;;
        *) return 2 ;;
    esac
}

NL='
'
deps=""
for so in $sonames; do
    rc=0
    if [ "$MODE" = "deb" ]; then
        entry="$(deb_pkg "$so")" || rc=$?
    else
        entry="$(rpm_pkg "$so")" || rc=$?
    fi
    if [ "$rc" -eq 2 ]; then
        echo "✗ $0: unmapped soname '$so' — extend the mapping in $0" >&2
        exit 2
    fi
    if [ "$rc" -eq 0 ] && [ -n "$entry" ]; then
        deps="${deps:+$deps$NL}$entry"
    fi
done

printf '%s\n' "$deps" | sort -u | paste -sd, - | sed 's/,/, /g'
