#!/usr/bin/env bash
# validate-arm-cross-compile.sh — Check-only validation for Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md.
# Usage: ./validate-arm-cross-compile.sh [--check] [--run-destructive]
# shellcheck disable=SC2015
#  The A && B || C idiom below is used exclusively as
#  `check && echo "  ✓ ..." || { echo "  ✗ ..."; ERRORS+=1; }`, where the
#  middle command is a plain echo that cannot fail — the hazard SC2015
#  warns about (C running when A is true) cannot occur here. Scoped to
#  this file rather than .shellcheckrc (issue #189, F-CI-019).

set -euo pipefail

MODE="${1:---check}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ERRORS=0

check() {
    local desc="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo "  ✓ $desc"
    else
        echo "  ✗ $desc"
        ERRORS=$((ERRORS + 1))
    fi
}

if [ "$MODE" = "--run-destructive" ]; then
    echo "Running in destructive mode (not implemented for this script)."
    exit 0
fi

if [ "$MODE" != "--check" ]; then
    echo "Usage: $0 [--check] [--run-destructive]"
    exit 1
fi

echo "=== ARM cross-compile doc validation ==="

# Check 1: Available ARCH targets
shopt -s nullglob
arch_files=("$ROOT/rules/arch-"*.mk)
shopt -u nullglob
if [ "${#arch_files[@]}" -gt 0 ]; then
    echo "  ✓ ${#arch_files[@]} arch-*.mk files found"
    echo "     Available targets: $(for f in "${arch_files[@]}"; do basename "$f"; done | sed 's/arch-//;s/.mk//')"
else
    echo "  ✗ No arch-*.mk files found"
    ERRORS=$((ERRORS + 1))
fi

# Check 2: green-arm target does NOT exist (doc should note this)
if [ -f "$ROOT/rules/arch-green-arm.mk" ]; then
    echo "  ✗ arch-green-arm.mk exists but doc says it doesn't"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ arch-green-arm.mk does not exist (doc correctly notes this is outdated)"
fi

# Check 3: the default target (ARCH=linux) exists
check "rules/arch-linux.mk exists" "test -f $ROOT/rules/arch-linux.mk"

# Check 4: sdk/Makefile supports ARCH variable
grep -q 'ARCH' "$ROOT/sdk/Makefile" && echo "  ✓ ARCH variable used in sdk/Makefile" || { echo "  ✗ ARCH variable missing"; ERRORS=$((ERRORS + 1)); }

# Check 5: CC variable override support
grep -q 'CC' "$ROOT/rules/common.mk" && echo "  ✓ CC variable in rules/common.mk" || { echo "  ✗ CC variable missing"; ERRORS=$((ERRORS + 1)); }

# Checks 6-9 (issue #583, F-DOCS-016/018): native arm64 is the supported ARM
# path; cross-compilation is neither supported nor tested. No build is run.
GUIDE="$ROOT/docs/Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md"

# Check 6: no entry-point doc claims cross-compilation as supported. Each
# sentence (split at ". ") that names it must also say "not"; the guide's
# file name, which keeps its historical "cross-compiler" for the links, is
# ignored.
for doc in README.md docs/index.html docs/ARCHITECTURE.md; do
    claims=$(sed 's/Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler//g; s/\. /.\n/g' "$ROOT/$doc" \
        | grep -iE 'cross[- ]?compil' | grep -viwE 'not' || true)
    if [ -z "$claims" ]; then
        echo "  ✓ $doc does not claim cross-compilation support"
    else
        echo "  ✗ $doc claims cross-compilation support: $claims"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check 7: the guide states the actual status.
if grep -qiF 'native arm64 builds are supported' "$GUIDE" \
    && grep -qiF 'cross-compilation is not' "$GUIDE"; then
    echo "  ✓ the ARM guide states native arm64 is supported and cross-compilation is not"
else
    echo "  ✗ the ARM guide does not state 'native arm64 builds are supported' and 'cross-compilation is not'"
    ERRORS=$((ERRORS + 1))
fi

# Check 8: every target the guide lists (ARCH=<x>, or a `<x>` row of its
# targets table) has a rules/arch-<x>.mk, and no osx/win32/win64 is named.
targets=$( { grep -oE 'ARCH=[a-z0-9-]+' "$GUIDE" | sed 's/^ARCH=//'
             sed -nE "s/^\\| \`([a-z0-9-]+)\`.*/\\1/p" "$GUIDE"; } | sort -u || true)
if [ -z "$targets" ]; then
    echo "  ✗ the ARM guide lists no build target"
    ERRORS=$((ERRORS + 1))
fi
for t in $targets; do
    if [ -f "$ROOT/rules/arch-$t.mk" ]; then
        echo "  ✓ listed target $t has rules/arch-$t.mk"
    else
        echo "  ✗ the ARM guide lists target $t, but rules/arch-$t.mk does not exist"
        ERRORS=$((ERRORS + 1))
    fi
done
if grep -qwE 'osx|win32|win64' "$GUIDE"; then
    echo "  ✗ the ARM guide names an osx/win32/win64 target"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ the ARM guide names no osx/win32/win64 target"
fi

# Check 9: the CI anchor of the arm64 claim — the unit-tests-arm job of
# c-cpp.yml runs on the native ubuntu-24.04-arm runner.
arm_job=$(awk '/^  unit-tests-arm:/ { in_job = 1; next }
               in_job && /^  [A-Za-z0-9_-]+:/ { exit }
               in_job' "$ROOT/.github/workflows/c-cpp.yml")
if printf '%s\n' "$arm_job" | grep -qE '^ +runs-on: *ubuntu-24\.04-arm *$'; then
    echo "  ✓ c-cpp.yml unit-tests-arm runs on ubuntu-24.04-arm"
else
    echo "  ✗ c-cpp.yml has no unit-tests-arm job on ubuntu-24.04-arm"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
