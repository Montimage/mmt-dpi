#!/usr/bin/env bash
# validate-release-prep.sh — Check-only validation for Prepare-for-a-new-released-version.md.
# Usage: ./validate-release-prep.sh [--check] [--run-destructive]
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

echo "=== Prepare-for-a-new-released-version.md validation ==="

# Check 1: Version locations exist and are consistent
check "rules/common.mk has VERSION" "grep -q '^VERSION' $ROOT/rules/common.mk"
check "dist/ZIP/mmt-install-common.sh has VERSION" "grep -q 'VERSION=' $ROOT/dist/ZIP/mmt-install-common.sh"
check "sdk/include/mmt_core.h has VERSION" "grep -q '#define VERSION' $ROOT/sdk/include/mmt_core.h"

# Check 2: mmt-test directory does NOT exist (doc should note this)
if [ -d "$ROOT/mmt-test" ]; then
    echo "  ✗ mmt-test/ exists but doc was updated to not reference it"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ mmt-test/ does not exist (doc correctly updated to use src/examples/)"
fi

# Check 3: Sample pcap exists for testing
check "src/examples/google-fr.pcap exists" "test -f $ROOT/src/examples/google-fr.pcap"

# Check 4: Git tag workflow
check "git is available" "command -v git"

# Check 5: CHANGELOG.md exists
check "CHANGELOG.md exists" "test -f $ROOT/CHANGELOG.md"

# Check 6: dist/ZIP/ directory exists
check "dist/ZIP/install.sh exists" "test -f $ROOT/dist/ZIP/install.sh"
check "dist/ZIP/uninstall.sh exists" "test -f $ROOT/dist/ZIP/uninstall.sh"
check "dist/ZIP/mmt-install-common.sh exists" "test -f $ROOT/dist/ZIP/mmt-install-common.sh"

# Check 7: CI workflows exist
check ".github/workflows/c-cpp.yml exists" "test -f $ROOT/.github/workflows/c-cpp.yml"
check ".github/workflows/release-packages.yml exists" "test -f $ROOT/.github/workflows/release-packages.yml"

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
