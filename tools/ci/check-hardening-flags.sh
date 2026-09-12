#!/usr/bin/env bash
#
# check-hardening-flags.sh — the shipped build carries the hardening flag set
# (issue #214, F-SEC-010; helper committed under issue #190).
#
# The release build must apply control-flow protection, the stronger
# _FORTIFY_SOURCE level behind a compiler-capability check, and PIE for the
# installed examples — and emit a build warning when hardening is switched
# off (DEBUG/sanitizer builds), so the tested configuration and the shipped
# configuration cannot silently diverge.
#
# Checked against rules/*.mk (the single home of every build flag):
#   - -fcf-protection present in the hardening flag set
#   - -D_FORTIFY_SOURCE=3 (the stronger level) behind a capability check
#   - examples built with -fPIE and linked -pie
#   - a $(warning …) fires when the hardening block is disabled
#
# Exit codes: 0 = all flags present, 1 = a flag is missing, 2 = helper broken.
#
# Usage: bash tools/ci/check-hardening-flags.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ERRORS=0

check() {
    local desc="$1" pattern="$2"
    if grep -rE -- "$pattern" rules/*.mk >/dev/null 2>&1; then
        echo "  ✓ $desc"
    else
        echo "  ✗ $desc"
        ERRORS=$((ERRORS + 1))
    fi
}

ls rules/*.mk >/dev/null 2>&1 || { echo "✗ no rules/*.mk found" >&2; exit 2; }

check "control-flow protection (-fcf-protection)"            '-fcf-protection'
check "strong fortification (-D_FORTIFY_SOURCE=3)"           '-D_FORTIFY_SOURCE=3'
check "fortification behind a compiler-capability check"     'FORTIFY.*(cc-option|compiler|__GNUC__|GNUC|filter)|filter.*FORTIFY'
check "stack protector (-fstack-protector-strong)"           '-fstack-protector'
check "examples built as PIE (-fPIE / -pie)"                 '-fPIE|[^a-z]-pie'
check "full RELRO (-Wl,-z,relro + -z,now)"                   '-z,relro.*-z,now|-z,now.*-z,relro'
check "non-executable stack (-Wl,-z,noexecstack)"            '-z,noexecstack'
check "build warning when hardening is disabled"             '\$\(warning'

if [ "$ERRORS" -ne 0 ]; then
    echo "✗ $ERRORS hardening flag(s) missing from rules/*.mk" >&2
    echo "To fix:  add the flag set to the release-hardening block" >&2
    echo "         (issue #214)" >&2
    exit 1
fi
echo "✓ hardening flag set complete"
