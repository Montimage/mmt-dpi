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
# With --built the script additionally inspects the shared objects already
# built under sdk/lib/ and asserts the flags actually landed on the shipped
# binaries (this is the CI-side proof the makefile greps cannot give):
#   - GNU_STACK program header without the E flag (non-executable stack)
#   - GNU_RELRO segment + BIND_NOW dynamic flags (full RELRO)
#   - a control-flow GNU property: IBT/SHSTK on x86, BTI/PAC on AArch64
#     (whatever the MMT_CF_PROTECTION probe selected for this target)
#
# Exit codes: 0 = all flags present, 1 = a flag is missing, 2 = helper broken.
#
# Usage: bash tools/ci/check-hardening-flags.sh [--built]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ERRORS=0
BUILT=0
[ "${1:-}" = "--built" ] && BUILT=1

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

if [ "$BUILT" -eq 0 ]; then
    exit 0
fi

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# --built: the flags above must be visible in the built shared objects, not
# just in the makefile. Needs binutils (readelf); the phase0/CI images have it.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

command -v readelf >/dev/null 2>&1 || { echo "✗ readelf not found" >&2; exit 2; }

shopt -s nullglob
sos=(sdk/lib/*.so.*)
[ "${#sos[@]}" -gt 0 ] || { echo "✗ no sdk/lib/*.so.* — build the SDK first" >&2; exit 2; }

check_so() {
    local desc="$1" file="$2" pattern="$3" opt="$4"
    if readelf "$opt" "$file" 2>/dev/null | grep -qE -- "$pattern"; then
        echo "  ✓ $desc: $(basename "$file")"
    else
        echo "  ✗ $desc: $(basename "$file")"
        ERRORS=$((ERRORS + 1))
    fi
}

# The control-flow property note is only assertable where the toolchain can
# merge one: on x86 (-fcf-protection/CET) every input including the crt stubs
# carries IBT/SHSTK, so the .so must show it. On AArch64 the crti/crtn stubs
# ship without the note and the AND-merge drops it — stamping it anyway with
# -z force-bti SIGILLs under a BTI-enforcing loader (the stubs have no landing
# pads). Re-run the same probe the makefile uses and gate the check on it.
CF_PROBE_OK=0
if printf 'int main(void){return 0;}\n' | "${CC:-cc}" -x c -fcf-protection -Werror - -o /dev/null >/dev/null 2>&1; then
    CF_PROBE_OK=1
fi

for so in "${sos[@]}"; do
    # Non-executable stack: the GNU_STACK header line must not carry E.
    if readelf -lW "$so" | awk '/GNU_STACK/ {print $7}' | grep -qE '^RW$'; then
        echo "  ✓ non-executable stack: $(basename "$so")"
    else
        echo "  ✗ non-executable stack: $(basename "$so")"
        ERRORS=$((ERRORS + 1))
    fi
    check_so "RELRO segment"          "$so" 'GNU_RELRO'           "-lW"
    check_so "BIND_NOW (full RELRO)"  "$so" 'BIND_NOW|FLAGS.*NOW' "-dW"
    # Control-flow property note: IBT/SHSTK (x86 CET) or BTI/PAC (AArch64).
    if [ "$CF_PROBE_OK" -eq 1 ]; then
        check_so "control-flow property"  "$so" 'IBT|SHSTK|BTI|PAC'   "-nW"
    else
        echo "  · control-flow property note not assertable on this target (see rules/common-linux.mk)"
    fi
done

if [ "$ERRORS" -ne 0 ]; then
    echo "✗ $ERRORS hardening assertion(s) failed on built .so files" >&2
    exit 1
fi
echo "✓ built shared objects carry the hardening set"
