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
# With --built the script additionally inspects built shared objects and
# asserts the flags actually landed on the shipped binaries (this is the
# CI-side proof the makefile greps cannot give). Without DIR it checks the
# host build under sdk/lib/; with DIRs it checks the regular *.so / *.so.*
# files in them (symlinks skipped) — release-packages.yml passes the
# directories an installed package populated, so the check covers the
# libraries that ship, not only an unshipped host build (issue #508):
#   - GNU_STACK program header without the E flag (non-executable stack)
#   - GNU_RELRO segment + BIND_NOW dynamic flags (full RELRO) — the
#     discriminator between a hardened build and one whose hardening block
#     was skipped (distribution compilers do not add BIND_NOW to a .so)
#   - a control-flow GNU property: IBT/SHSTK on x86, BTI/PAC on AArch64
#     (whatever the MMT_CF_PROTECTION probe selected for this target)
#   - a _FORTIFY_SOURCE floor: the checked set imports at least one
#     fortified libc entry point (__<name>_chk, __stack_chk_* excluded).
#     Necessary, not sufficient: a compiler that fortifies by default (Ubuntu
#     GCC) passes it even without the hardening block; a library with no
#     fortifiable call site legitimately imports none, so per-file counts are
#     informational. The makefile side of FORTIFY is pinned by
#     tools/ci/tests/test-hardening-identity.sh.
#
# Exit codes: 0 = all flags present, 1 = a flag is missing, 2 = helper broken.
#
# Usage: bash tools/ci/check-hardening-flags.sh [--built [DIR...]]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ERRORS=0
BUILT=0
SO_DIRS=()
if [ "${1:-}" = "--built" ]; then
    BUILT=1
    shift
    SO_DIRS=("$@")
fi

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
sos=()
if [ "${#SO_DIRS[@]}" -eq 0 ]; then
    sos=(sdk/lib/*.so.*)
    [ "${#sos[@]}" -gt 0 ] || { echo "✗ no sdk/lib/*.so.* — build the SDK first" >&2; exit 2; }
else
    for dir in "${SO_DIRS[@]}"; do
        [ -d "$dir" ] || { echo "✗ not a directory: $dir" >&2; exit 2; }
        for f in "$dir"/*.so "$dir"/*.so.*; do
            [ -f "$f" ] && [ ! -L "$f" ] && sos+=("$f")
        done
    done
    [ "${#sos[@]}" -gt 0 ] || { echo "✗ no shared objects under: ${SO_DIRS[*]}" >&2; exit 2; }
fi

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
# merge one into a shared object: the linker AND-merges the GNU property of
# every input, including the crt startup stubs, so one stub without the note
# drops it from the .so however the MMT objects were compiled. On AArch64 the
# crti/crtn stubs ship without the note — stamping it anyway with -z force-bti
# SIGILLs under a BTI-enforcing loader (the stubs have no landing pads). On
# x86, Debian 12's crt objects carry no IBT/SHSTK property either, although
# -fcf-protection compiles. So a compile probe is not enough: link a trivial
# -shared -fcf-protection object the way the libraries are linked and assert
# the note on the checked objects only when that probe carries it.
CF_PROBE_OK=0
CF_PROBE_DIR="$(mktemp -d)"
trap 'rm -rf "$CF_PROBE_DIR"' EXIT
printf 'int mmt_cf_probe(int x){return x + 1;}\n' >"$CF_PROBE_DIR/probe.c"
if "${CC:-cc}" -shared -fPIC -fcf-protection -Werror -o "$CF_PROBE_DIR/libprobe.so" \
        "$CF_PROBE_DIR/probe.c" >/dev/null 2>&1 \
   && readelf -nW "$CF_PROBE_DIR/libprobe.so" 2>/dev/null | grep -qE 'IBT|SHSTK|BTI|PAC'; then
    CF_PROBE_OK=1
fi
rm -rf "$CF_PROBE_DIR"

FORTIFIED=0
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
        echo "  · control-flow property note not assertable on this toolchain (see rules/common-linux.mk)"
    fi
    # Fortified libc imports (__memcpy_chk, __snprintf_chk, ...): counted for
    # the set-level floor below; __stack_chk_fail/__stack_chk_guard are the
    # stack protector's, not FORTIFY's.
    n="$(readelf -W --dyn-syms "$so" 2>/dev/null | awk '{print $8}' \
        | grep -E '^__[A-Za-z0-9_]+_chk(@|$)' | grep -cvE '^__stack_chk_' || true)"
    echo "  · fortified libc imports: $(basename "$so"): $n"
    FORTIFIED=$((FORTIFIED + n))
done

if [ "$FORTIFIED" -gt 0 ]; then
    echo "  ✓ _FORTIFY_SOURCE floor: $FORTIFIED fortified libc import(s) across ${#sos[@]} object(s)"
else
    echo "  ✗ _FORTIFY_SOURCE floor: no fortified libc import (__*_chk) in any checked object"
    ERRORS=$((ERRORS + 1))
fi

if [ "$ERRORS" -ne 0 ]; then
    echo "✗ $ERRORS hardening assertion(s) failed on built .so files" >&2
    exit 1
fi
echo "✓ built shared objects carry the hardening set"
