#!/usr/bin/env bash
# validate-deployment.sh — Check-only validation for DEPLOYMENT.md install/linking steps.
# Usage: ./validate-deployment.sh [--check] [--run-destructive]
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

echo "=== DEPLOYMENT.md validation ==="

# Check 1: Build and install targets exist
check "sdk/Makefile has 'install' target" "grep -q '^install:' $ROOT/sdk/Makefile"
check "sdk/Makefile has 'deb' target" "grep -q '^deb:' $ROOT/sdk/Makefile"
check "sdk/Makefile has 'dist-clean' target" "grep -q '^dist-clean:' $ROOT/sdk/Makefile"

# Check 2: Install paths match code
grep -q 'MMT_DPI' "$ROOT/rules/common.mk" && echo "  ✓ MMT_DPI path defined" || { echo "  ✗ MMT_DPI path mismatch"; ERRORS=$((ERRORS + 1)); }
grep -q 'MMT_LIB' "$ROOT/rules/common.mk" && echo "  ✓ MMT_LIB path defined" || { echo "  ✗ MMT_LIB path mismatch"; ERRORS=$((ERRORS + 1)); }
grep -q 'MMT_INC' "$ROOT/rules/common.mk" && echo "  ✓ MMT_INC path defined" || { echo "  ✗ MMT_INC path mismatch"; ERRORS=$((ERRORS + 1)); }
grep -q 'MMT_PLUGINS' "$ROOT/rules/common.mk" && echo "  ✓ MMT_PLUGINS path defined" || { echo "  ✗ MMT_PLUGINS path mismatch"; ERRORS=$((ERRORS + 1)); }

# Check 3: ldconfig file name
grep -q 'mmt-dpi.conf' "$ROOT/sdk/Makefile" && echo "  ✓ ldconfig file is mmt-dpi.conf" || { echo "  ✗ ldconfig file name mismatch"; ERRORS=$((ERRORS + 1)); }

# Check 4: Plugin path compiled in
grep -q 'PLUGINS_REPOSITORY_OPT' "$ROOT/rules/common.mk" && echo "  ✓ PLUGINS_REPOSITORY_OPT defined" || { echo "  ✗ PLUGINS_REPOSITORY_OPT missing"; ERRORS=$((ERRORS + 1)); }

# Check 5: Shared libraries exist in sdk/lib/
for lib in libmmt_core libmmt_tcpip; do
    if ls "$ROOT/sdk/lib/$lib"* >/dev/null 2>&1; then
        echo "  ✓ sdk/lib/$lib (or versioned) exists"
    else
        echo "  ✗ sdk/lib/$lib missing"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check 6: Headers exist
check "sdk/include/mmt_core.h exists" "test -f $ROOT/sdk/include/mmt_core.h"

# Check 7: No MMT_SEC_DTLS_CIPHER_ALLOWLIST in code (doc should not list it)
count=$(grep -r 'MMT_SEC_DTLS_CIPHER_ALLOWLIST' "$ROOT/sdk/" "$ROOT/src/" 2>/dev/null | wc -l || true)
if [ "$count" -eq 0 ]; then
    echo "  ✓ MMT_SEC_DTLS_CIPHER_ALLOWLIST not in code (doc correctly flags as unverified)"
else
    echo "  ✗ MMT_SEC_DTLS_CIPHER_ALLOWLIST found in code but doc flagged as unverified"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
