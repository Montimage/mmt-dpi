#!/usr/bin/env bash
# validate-user-guide.sh — Check-only validation for USER_GUIDE.md install steps.
# Usage: ./validate-user-guide.sh [--check] [--run-destructive]
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

echo "=== USER_GUIDE.md validation ==="

# Check 1: install.sh exists and is executable
check "install.sh exists" "test -f $ROOT/install.sh"
check "install.sh is executable" "test -x $ROOT/install.sh"

# Check 2: install.sh has expected env vars
grep -q 'MMT_BASE=' "$ROOT/install.sh" && echo "  ✓ MMT_BASE env var in install.sh" || { echo "  ✗ MMT_BASE env var missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'BRANCH=' "$ROOT/install.sh" && echo "  ✓ BRANCH env var in install.sh" || { echo "  ✗ BRANCH env var missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'SKIP_DEPS=' "$ROOT/install.sh" && echo "  ✓ SKIP_DEPS env var in install.sh" || { echo "  ✗ SKIP_DEPS env var missing"; ERRORS=$((ERRORS + 1)); }

# Check 3: sdk/Makefile exists with expected targets
check "sdk/Makefile exists" "test -f $ROOT/sdk/Makefile"
grep -q 'install:' "$ROOT/sdk/Makefile" && echo "  ✓ 'make install' target exists" || { echo "  ✗ 'make install' target missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'dist-clean:' "$ROOT/sdk/Makefile" && echo "  ✓ 'make dist-clean' target exists" || { echo "  ✗ 'make dist-clean' target missing"; ERRORS=$((ERRORS + 1)); }

# Check 4: examples exist in src/examples/
for f in extract_all.c packet_handler.c proto_attributes_iterator.c simple_traffic_reporting.c; do
    check "src/examples/$f exists" "test -f $ROOT/src/examples/$f"
done

# Check 5: sample pcap exists
check "src/examples/google-fr.pcap exists" "test -f $ROOT/src/examples/google-fr.pcap"

# Check 6: ldconfig file name matches code
grep -q 'mmt-dpi.conf' "$ROOT/sdk/Makefile" && echo "  ✓ ldconfig file is mmt-dpi.conf" || { echo "  ✗ ldconfig file name mismatch"; ERRORS=$((ERRORS + 1)); }

# Check 7: mmt_core.h has expected API functions
grep -q 'mmt_init_handler' "$ROOT/sdk/include/mmt_core.h" && echo "  ✓ mmt_init_handler() declared" || { echo "  ✗ mmt_init_handler() missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'mmt_close_handler' "$ROOT/sdk/include/mmt_core.h" && echo "  ✓ mmt_close_handler() declared" || { echo "  ✗ mmt_close_handler() missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'init_extraction' "$ROOT/sdk/include/mmt_core.h" && echo "  ✓ init_extraction() declared" || { echo "  ✗ init_extraction() missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'close_extraction' "$ROOT/sdk/include/mmt_core.h" && echo "  ✓ close_extraction() declared" || { echo "  ✗ close_extraction() missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'packet_process' "$ROOT/sdk/include/mmt_core.h" && echo "  ✓ packet_process() declared" || { echo "  ✗ packet_process() missing"; ERRORS=$((ERRORS + 1)); }

# Check 8: rules/common.mk has expected build options
grep -q 'DEBUG' "$ROOT/rules/common.mk" && echo "  ✓ DEBUG build option" || { echo "  ✗ DEBUG build option missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'NDEBUG' "$ROOT/rules/common.mk" && echo "  ✓ NDEBUG build option" || { echo "  ✗ NDEBUG build option missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'SHOWLOG' "$ROOT/rules/common.mk" && echo "  ✓ SHOWLOG build option" || { echo "  ✗ SHOWLOG build option missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'VALGRIND' "$ROOT/rules/common.mk" && echo "  ✓ VALGRIND build option" || { echo "  ✗ VALGRIND build option missing"; ERRORS=$((ERRORS + 1)); }

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
