#!/usr/bin/env bash
#
# test-shape-ratchet.sh — self-test for the src/-wide ratchet mode of
# tools/ci/report-function-shape.sh and tools/ci/report-param-count.sh
# (issue #547, F-CLEAN-008/F-CLEAN-018).
#
# It copies the REAL scripts and tools/ci/vendor-paths-lib.sh into a throwaway
# git repository whose src/ holds fixture C files (one over-long function,
# one 7-parameter function, a generated asn1c file and a vendored file), so
# each scenario runs in milliseconds without scanning the real tree.
#
# Scenario -> expected exit:
#   no FILE: offender recorded in the ratchet              -> 0
#   no FILE: offender missing from the ratchet             -> 1
#   no FILE: offender grew past its ratchet row            -> 1
#   no FILE: stale row (function gone or within limits)    -> 1
#   no FILE: offender shrank but still over the limits     -> 1 (tighten)
#   no FILE: ratchet missing                               -> 2
#   no FILE: malformed ratchet row                         -> 2
#   asn1c and vendored sources are outside the default scope
#   --emit-ratchet prints exactly the offender rows
#   explicit FILE without --ratchet keeps the plain gate  -> 1
#
# Usage: bash tools/ci/tests/test-shape-ratchet.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
SHAPE="${REPO_ROOT}/tools/ci/report-function-shape.sh"
PARAMS="${REPO_ROOT}/tools/ci/report-param-count.sh"
LIB="${REPO_ROOT}/tools/ci/vendor-paths-lib.sh"
for f in "${SHAPE}" "${PARAMS}" "${LIB}"; do
    [ -f "${f}" ] || { echo "✗ missing ${f}" >&2; exit 2; }
done
command -v git >/dev/null 2>&1 || { echo "✗ git is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
FIX="${WORK}/repo"
mkdir -p "${FIX}/tools/ci" "${FIX}/src/lib" "${FIX}/src/mmt_mobile/asn1c"
cp "${SHAPE}" "${PARAMS}" "${LIB}" "${FIX}/tools/ci/"

# long_fn(): LONG lines of body; wide_fn(): 7 parameters; short_fn(): fine.
write_fixture() {
    local long="$1" i
    {
        echo "int long_fn(int x)"
        echo "{"
        for ((i = 0; i < long; i++)); do echo "    x++;"; done
        echo "    return x;"
        echo "}"
        echo "int wide_fn(int a, int b, int c, int d, int e, int f, int g)"
        echo "{"
        echo "    return a + b + c + d + e + f + g;"
        echo "}"
        echo "int short_fn(int x) { return x; }"
    } > "${FIX}/src/a.c"
}
write_fixture 210
# The same shapes in a generated asn1c file and in a vendored file: both are
# outside the default scope, so neither needs a ratchet row.
cp "${FIX}/src/a.c" "${FIX}/src/mmt_mobile/asn1c/gen.c"
cp "${FIX}/src/a.c" "${FIX}/src/lib/vendored.c"
printf '# fixture vendored-source list\nsrc/lib/vendored.c\n' \
    > "${FIX}/tools/ci/vendor-paths.txt"
git -C "${FIX}" init -q
git -C "${FIX}" add -A

pass=0
fail=0

# check NAME EXPECTED_RC OUTPUT_ERE CMD... — runs CMD in the fixture repo.
check() {
    local name="$1" want="$2" pattern="$3" rc=0
    shift 3
    (cd "${FIX}" && "$@") > "${WORK}/out.log" 2>&1 || rc=$?
    if [ "${rc}" -ne "${want}" ]; then
        echo "  ✗ ${name}: expected exit ${want}, got ${rc}"
        sed 's/^/      /' "${WORK}/out.log"
        fail=$((fail + 1))
    elif [ -n "${pattern}" ] && ! grep -Eq -- "${pattern}" "${WORK}/out.log"; then
        echo "  ✗ ${name}: output does not match /${pattern}/"
        sed 's/^/      /' "${WORK}/out.log"
        fail=$((fail + 1))
    else
        echo "  ✓ ${name} (exit ${rc})"
        pass=$((pass + 1))
    fi
}

shape_ratchet() { printf '# fixture\n%s\n' "$@" > "${WORK}/shape.txt"; }
param_ratchet() { printf '# fixture\n%s\n' "$@" > "${WORK}/params.txt"; }
export FUNCTION_SHAPE_RATCHET="${WORK}/shape.txt"
export PARAM_COUNT_RATCHET="${WORK}/params.txt"

echo "── report-function-shape.sh ratchet ──"
# long_fn spans 213 lines (opening through closing brace).
check "--emit-ratchet lists only the in-scope offender" 0 '^src/a\.c long_fn 213 1$' \
    bash tools/ci/report-function-shape.sh --emit-ratchet
check "asn1c and vendored sources are outside the default scope" 0 '' \
    bash -c '! bash tools/ci/report-function-shape.sh --emit-ratchet | grep -Eq "asn1c|vendored"'
shape_ratchet "src/a.c long_fn 213 1"
check "recorded offender passes"                         0 'long_fn .*\(ratcheted\)' \
    bash tools/ci/report-function-shape.sh
check "the pass names the ratchet"                       0 'within the ratchet .*\(1 rows\)' \
    bash tools/ci/report-function-shape.sh
shape_ratchet "# nothing recorded"
check "unrecorded offender fails"                        1 'long_fn .*<-- exceeds limits' \
    bash tools/ci/report-function-shape.sh
shape_ratchet "src/a.c long_fn 212 1"
check "offender grown past its row fails"                1 'beyond the ratchet' \
    bash tools/ci/report-function-shape.sh
shape_ratchet "src/a.c long_fn 213 1" "src/a.c short_fn 300 9"
check "row of a function within the limits is stale"     1 'stale ratchet row: src/a\.c short_fn' \
    bash tools/ci/report-function-shape.sh
shape_ratchet "src/a.c long_fn 213 1" "src/gone.c old_fn 300 9"
check "row of a deleted file is stale"                   1 'stale ratchet row: src/gone\.c old_fn' \
    bash tools/ci/report-function-shape.sh
shape_ratchet "src/a.c long_fn 220 1"
check "shrunk offender's loose row fails"                1 'loose ratchet row: src/a\.c long_fn shrank to 213 lines' \
    bash tools/ci/report-function-shape.sh
shape_ratchet "src/a.c long_fn 213"
check "malformed ratchet row is a broken helper"         2 'malformed ratchet row' \
    bash tools/ci/report-function-shape.sh
rm -f "${WORK}/shape.txt"
check "missing ratchet is a broken helper"               2 'ratchet not found' \
    bash tools/ci/report-function-shape.sh
check "--report-only needs no ratchet"                   0 'long_fn' \
    bash tools/ci/report-function-shape.sh --report-only
check "explicit FILE keeps the plain gate"               1 'exceed the shape limits' \
    bash tools/ci/report-function-shape.sh src/a.c

echo "── report-param-count.sh ratchet ──"
check "--emit-ratchet lists only the in-scope offender" 0 '^src/a\.c wide_fn 7$' \
    bash tools/ci/report-param-count.sh --emit-ratchet
param_ratchet "src/a.c wide_fn 7"
check "recorded offender passes"                         0 'wide_fn .*\(ratcheted\)' \
    bash tools/ci/report-param-count.sh
param_ratchet "# nothing recorded"
check "unrecorded offender fails"                        1 'wide_fn .*<-- exceeds limit' \
    bash tools/ci/report-param-count.sh
param_ratchet "src/a.c wide_fn 6"
check "offender grown past its row fails"                1 'beyond the ratchet' \
    bash tools/ci/report-param-count.sh
param_ratchet "src/a.c wide_fn 7" "src/a.c short_fn 8"
check "row of a function within --max is stale"          1 'stale ratchet row: src/a\.c short_fn' \
    bash tools/ci/report-param-count.sh
param_ratchet "src/a.c wide_fn 9"
check "narrowed offender's loose row fails"              1 'loose ratchet row: src/a\.c wide_fn dropped to 7' \
    bash tools/ci/report-param-count.sh
param_ratchet "src/a.c wide_fn"
check "malformed ratchet row is a broken helper"         2 'malformed ratchet row' \
    bash tools/ci/report-param-count.sh
rm -f "${WORK}/params.txt"
check "missing ratchet is a broken helper"               2 'ratchet not found' \
    bash tools/ci/report-param-count.sh
check "explicit FILE without --max only reports"         0 'wide_fn +7 params' \
    bash tools/ci/report-param-count.sh src/a.c

echo "shape ratchets: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
