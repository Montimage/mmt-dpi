#!/usr/bin/env bash
#
# build-api-reference.sh — generate the C API reference of the public headers
# with the pinned doxygen and fail on any warning (issue #582, F-DOCS-008).
#
# The Doxyfile at the repository root scopes the run to
# src/mmt_core/public_include and turns on every completeness warning:
# undocumented functions, variables, typedefs, macros, structs and enum
# values, documentation errors and incomplete parameter lists. A run that
# writes any warning fails, so a new MMTAPI declaration, struct, enum or macro
# without a doc comment fails the docs build. tools/ci/build-docs-site.sh
# calls this after the Jekyll build and publishes OUTDIR as <site>/api/ in
# the one Pages artifact (issue #386: no second renderer, no second deploy).
#
# The pin: doxygen DOXYGEN_PINNED_VERSION, installed by --install from the
# Ubuntu 24.04 (noble) release pocket at the exact package version
# DOXYGEN_DEB_VERSION. The release pocket never replaces a version, so the
# install is the same on every run; upstream publishes no arm64 binary, and
# the package exists for both runner architectures. Another doxygen release
# reports a different warning set on the same headers, so under CI=true a
# different version fails (exit 2); locally it warns and the warning gate is
# advisory.
#
# Usage: bash tools/ci/build-api-reference.sh OUTDIR
#          OUTDIR must not exist; it receives the HTML (OUTDIR/index.html).
#        bash tools/ci/build-api-reference.sh --install
#          apt-get installs the pinned package (sudo when not root).
#        bash tools/ci/build-api-reference.sh --version
#          prints the pinned doxygen version.
#
# Exit codes: 0 = reference built with no warning (or installed), 1 = doxygen
# reported warnings (they are printed), 2 = helper broken (doxygen missing or
# another version under CI, bad usage, doxygen failed).

set -euo pipefail

DOXYGEN_PINNED_VERSION="1.9.8"
DOXYGEN_DEB_VERSION="1.9.8+ds-2build5"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

usage() { echo "Usage: $0 OUTDIR | --install | --version" >&2; exit 2; }
[ $# -eq 1 ] || usage

case "$1" in
    --version)
        echo "$DOXYGEN_PINNED_VERSION"
        exit 0
        ;;
    --install)
        sudo_cmd=()
        [ "$(id -u)" -eq 0 ] || sudo_cmd=(sudo)
        # env after sudo: sudo's env_reset would drop a prefixed variable.
        # --allow-downgrades: noble-updates carries a later 1.9.8 build, which
        # an image may already have installed.
        "${sudo_cmd[@]}" apt-get update -q
        "${sudo_cmd[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
            --no-install-recommends --allow-downgrades "doxygen=$DOXYGEN_DEB_VERSION"
        got="$(doxygen --version 2>/dev/null | awk '{print $1}')"
        [ "$got" = "$DOXYGEN_PINNED_VERSION" ] || {
            echo "✗ installed doxygen reports '$got', pinned $DOXYGEN_PINNED_VERSION" >&2
            exit 2
        }
        echo "✓ doxygen $got installed (package $DOXYGEN_DEB_VERSION)"
        exit 0
        ;;
    -*) usage ;;
esac

OUT="$1"
if [ -e "$OUT" ]; then
    echo "✗ $OUT already exists — remove it first" >&2
    exit 2
fi

command -v doxygen >/dev/null 2>&1 || {
    echo "✗ doxygen is required to build the API reference" >&2
    echo "To fix:  bash tools/ci/build-api-reference.sh --install   (Ubuntu 24.04)" >&2
    exit 2
}
version="$(doxygen --version | awk '{print $1}')"
strict=1
if [ "$version" != "$DOXYGEN_PINNED_VERSION" ]; then
    if [ "${CI:-}" = "true" ]; then
        echo "✗ doxygen $version found, the warning gate is pinned to $DOXYGEN_PINNED_VERSION" >&2
        echo "To fix:  bash tools/ci/build-api-reference.sh --install" >&2
        exit 2
    fi
    echo "⚠ doxygen $version is not the pinned $DOXYGEN_PINNED_VERSION — warnings are advisory" >&2
    strict=0
fi

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

# Doxygen reads a config from stdin with `-`; later keys override earlier
# ones, so the output and the warning log land in the scratch directory.
{
    cat Doxyfile
    printf 'OUTPUT_DIRECTORY = %s\nWARN_LOGFILE = %s\n' "$work/out" "$work/warnings.log"
} | doxygen - || { echo "✗ doxygen failed" >&2; exit 2; }

[ -f "$work/out/html/index.html" ] || { echo "✗ doxygen wrote no html/index.html" >&2; exit 2; }

# Doxygen reports the undocumented functions and macros of a documented file
# only, so a header without a @file doc block would pass unseen: each header
# must have its file page (doxygen escapes `_` as `__` and `.` as `_8`).
nofile=0
for h in src/mmt_core/public_include/*.h; do
    b="$(basename "$h")"
    b="${b//_/__}"
    if [ ! -f "$work/out/html/${b//./_8}.html" ]; then
        echo "✗ $h has no doxygen file page — give it a /** @file */ doc block" >&2
        nofile=$((nofile + 1))
    fi
done
[ "$nofile" -eq 0 ] || exit 1

warnings=0
[ -s "$work/warnings.log" ] && warnings="$(grep -c 'warning:' "$work/warnings.log" || true)"
if [ -s "$work/warnings.log" ]; then
    sed "s|$ROOT/||" "$work/warnings.log" | sed 's/^/    /'
fi

mkdir -p "$(dirname "$OUT")"
cp -R "$work/out/html" "$OUT"

if [ -s "$work/warnings.log" ]; then
    echo "✗ doxygen $version reported $warnings warning(s) over src/mmt_core/public_include" >&2
    echo "To fix:  give each reported member a doc comment (Doxyfile, issue #582)" >&2
    [ "$strict" -eq 1 ] && exit 1
    exit 0
fi
echo "✓ API reference built by doxygen $version with 0 warnings → $OUT"
