#!/usr/bin/env bash
# validate-dev-setup.sh — Check-only validation for DEVELOPMENT.md setup steps.
# Usage: ./validate-dev-setup.sh [--check] [--run-destructive]
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

echo "=== DEVELOPMENT.md validation ==="

# Check 1: Build tools exist
check "gcc available" "command -v gcc"
check "make available" "command -v make"

# Check 2: No cmake dependency in codebase
cmake_count=$(grep -r 'cmake\|CMAKE' "$ROOT/sdk/" "$ROOT/rules/" --include='Makefile' --include='*.mk' 2>/dev/null | wc -l || true)
if [ "$cmake_count" -eq 0 ]; then
    echo "  ✓ No cmake dependency in build system (doc correctly removed cmake)"
else
    echo "  ✗ cmake found in build system but doc says it's not needed"
    ERRORS=$((ERRORS + 1))
fi

# Check 3: Build options match code
grep -q 'ifdef DEBUG' "$ROOT/rules/common.mk" && echo "  ✓ DEBUG=1 option exists" || { echo "  ✗ DEBUG=1 option missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'ifdef NDEBUG' "$ROOT/rules/common.mk" && echo "  ✓ NDEBUG=1 option exists" || { echo "  ✗ NDEBUG=1 option missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'ifdef SHOWLOG' "$ROOT/rules/common.mk" && echo "  ✓ SHOWLOG=1 option exists" || { echo "  ✗ SHOWLOG=1 option missing"; ERRORS=$((ERRORS + 1)); }
grep -q 'ifdef VALGRIND' "$ROOT/rules/common.mk" && echo "  ✓ VALGRIND=1 option exists" || { echo "  ✗ VALGRIND=1 option missing"; ERRORS=$((ERRORS + 1)); }

# Check 4: No TCP_SEGMENT or STATIC_LINK in code
tcp_seg=$(grep -r 'TCP_SEGMENT' "$ROOT/sdk/" "$ROOT/rules/" --include='Makefile' --include='*.mk' 2>/dev/null | wc -l || true)
static_link=$(grep -r 'STATIC_LINK' "$ROOT/sdk/" "$ROOT/rules/" --include='Makefile' --include='*.mk' 2>/dev/null | wc -l || true)
if [ "$tcp_seg" -eq 0 ] && [ "$static_link" -eq 0 ]; then
    echo "  ✓ TCP_SEGMENT and STATIC_LINK not in build system (doc correctly flags as unverified)"
else
    echo "  ✗ TCP_SEGMENT or STATIC_LINK found but doc says they don't exist"
    ERRORS=$((ERRORS + 1))
fi

# Check 5: DEVELOPMENT.md does not document 'make zip' as a dev build option
# (the sdk/Makefile 'zip:' target still exists for release packaging — see
# Prepare-for-a-new-released-version.md — but is intentionally not part of
# the day-to-day dev build options this doc covers)
zip_doc_count=$(grep -c 'make zip' "$ROOT/docs/DEVELOPMENT.md" 2>/dev/null || true)
if [ "$zip_doc_count" -eq 0 ]; then
    echo "  ✓ DEVELOPMENT.md does not document 'make zip' as a dev build option (doc correctly removed)"
else
    echo "  ✗ DEVELOPMENT.md documents 'make zip' as a dev build option, which this doc does not cover"
    ERRORS=$((ERRORS + 1))
fi

# Check 6: Public headers path — DEVELOPMENT.md points at the tracked source
# directory src/mmt_core/public_include/; sdk/include/ is a gitignored build
# copy that does not exist on a clean checkout (issue #187 — the
# doc-validators CI job runs on a clean checkout).
check "src/mmt_core/public_include/ has headers" "test -d $ROOT/src/mmt_core/public_include"
check "src/mmt_core/public_include/mmt_core.h exists" "test -f $ROOT/src/mmt_core/public_include/mmt_core.h"

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
