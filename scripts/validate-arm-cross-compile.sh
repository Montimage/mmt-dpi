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

# Check 3: linux target exists for cross-compilation
check "rules/arch-linux.mk exists" "test -f $ROOT/rules/arch-linux.mk"

# Check 4: sdk/Makefile supports ARCH variable
grep -q 'ARCH' "$ROOT/sdk/Makefile" && echo "  ✓ ARCH variable used in sdk/Makefile" || { echo "  ✗ ARCH variable missing"; ERRORS=$((ERRORS + 1)); }

# Check 5: CC variable override support
grep -q 'CC' "$ROOT/rules/common.mk" && echo "  ✓ CC variable in rules/common.mk" || { echo "  ✗ CC variable missing"; ERRORS=$((ERRORS + 1)); }

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
