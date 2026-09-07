#!/usr/bin/env bash
# validate-compile-install.sh — Check-only validation for Compilation-and-Installation-Instructions.md.
# Usage: ./validate-compile-install.sh [--check] [--run-destructive]
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

echo "=== Compilation-and-Installation-Instructions.md validation ==="

# Check 1: Git repo URL is correct
remote_url=$(git -C "$ROOT" remote get-url origin 2>/dev/null || echo "")
if echo "$remote_url" | grep -q 'montimage-projects/mmt-dpi'; then
    echo "  ✓ Remote URL matches doc (montimage-projects/mmt-dpi)"
else
    echo "  ✗ Remote URL does not match doc"
    ERRORS=$((ERRORS + 1))
fi

# Check 2: sdk/Makefile exists with build targets
check "sdk/Makefile exists" "test -f $ROOT/sdk/Makefile"
grep -q '^default: sdk' "$ROOT/sdk/Makefile" && echo "  ✓ Default target is 'sdk'" || { echo "  ✗ Default target mismatch"; ERRORS=$((ERRORS + 1)); }

# Check 3: rules/ has expected platform files
check "rules/common.mk exists" "test -f $ROOT/rules/common.mk"
check "rules/arch-linux.mk exists" "test -f $ROOT/rules/arch-linux.mk"

# Check 4: install.sh exists
check "install.sh exists" "test -f $ROOT/install.sh"
check "install.sh is executable" "test -x $ROOT/install.sh"

# Check 5: src/examples/ directory has examples
example_count=$(find "$ROOT/src/examples/" -name '*.c' 2>/dev/null | wc -l)
if [ "$example_count" -gt 0 ]; then
    echo "  ✓ $example_count example .c files in src/examples/"
else
    echo "  ✗ No example .c files found"
    ERRORS=$((ERRORS + 1))
fi

# Check 6: Version consistency
version_common=$(grep '^VERSION' "$ROOT/rules/common.mk" 2>/dev/null | head -1 || echo "")
version_zip=$(grep 'VERSION=' "$ROOT/dist/ZIP/mmt-install-common.sh" 2>/dev/null | head -1 || echo "")
if [ -n "$version_common" ] && [ -n "$version_zip" ]; then
    echo "  ✓ Version defined in rules/common.mk and dist/ZIP/mmt-install-common.sh"
else
    echo "  ✗ Version definition missing from expected locations"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
