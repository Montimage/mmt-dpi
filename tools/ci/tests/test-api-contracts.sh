#!/usr/bin/env bash
#
# test-api-contracts.sh — self-test for tools/ci/check-api-contracts.sh and
# the compile-time name check of tests/core_engine/api_contract.h
# (issue #525).
#
# Runs the REAL checker on small fixture lists; builds nothing but one
# `gcc -fsyntax-only` probe. Runs in well under a second.
#
# Scenario -> expected checker exit:
#   complete table, waivers listed                      -> 0 and "0 untested"
#   a declared name without an entry                    -> 1, names it
#   an entry naming no declared function (stale)        -> 1, names it
#   the same name entered twice                         -> 1, names it
#   a NO_ERROR_PATH entry missing from the waiver file  -> 1, names it
#   a waiver-file name with no NO_ERROR_PATH entry      -> 1, names it
#   empty declaration list                              -> 2
#   unreadable contract list                            -> 2
#   malformed contract line                             -> 2
# Plus: CONTRACT() on an undeclared name fails to compile, on a declared one
# compiles, check-public-decls.sh --list prints the real declared set, and
# --list on a scratch header with `MMTAPI` but no `MMTCALL` exits 2, naming it.
#
# Usage: bash tools/ci/tests/test-api-contracts.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
CHECKER="${REPO_ROOT}/tools/ci/check-api-contracts.sh"
DECLS_HELPER="${REPO_ROOT}/tools/ci/check-public-decls.sh"
CONTRACT_H="${REPO_ROOT}/tests/core_engine/api_contract.h"
for f in "${CHECKER}" "${DECLS_HELPER}" "${CONTRACT_H}"; do
    [ -f "${f}" ] || { echo "✗ missing ${f}" >&2; exit 2; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

printf '%s\n' alpha beta gamma delta > "${WORK}/decls"
good_contracts() {
    printf '%s\n' "CONTRACT alpha" "NO_ERROR_PATH beta" "CONTRACT gamma" "NO_ERROR_PATH delta"
}
good_contracts > "${WORK}/contracts"
printf '%s\n' "# ratchet" "" "beta" "delta  # trailing comment" > "${WORK}/waivers"

FAILED=0
expect() {
    # expect RC DESC DECLS CONTRACTS WAIVERS [NEEDLE] — exit RC, and NEEDLE
    # (when given) somewhere in the output.
    local want="$1" desc="$2" decls="$3" contracts="$4" waivers="$5" needle="${6:-}" rc=0
    bash "${CHECKER}" --decls "${decls}" --contracts "${contracts}" --waivers "${waivers}" \
        >"${WORK}/out" 2>&1 || rc=$?
    if [ "${rc}" -ne "${want}" ]; then
        echo "✗ ${desc}: exit ${rc}, expected ${want}"
        sed 's/^/      /' "${WORK}/out"
        FAILED=1
    elif [ -n "${needle}" ] && ! grep -qF -- "${needle}" "${WORK}/out"; then
        echo "✗ ${desc}: output does not mention '${needle}'"
        sed 's/^/      /' "${WORK}/out"
        FAILED=1
    else
        echo "✓ ${desc}"
    fi
}

expect 0 "complete table passes" "${WORK}/decls" "${WORK}/contracts" "${WORK}/waivers" \
    "4 MMTAPI functions, 0 untested, 2 error-path waivers"

good_contracts | grep -v ' gamma$' > "${WORK}/c-missing"
expect 1 "declared function without an entry fails" "${WORK}/decls" "${WORK}/c-missing" "${WORK}/waivers" \
    "gamma"

{ good_contracts; echo "CONTRACT epsilon"; } > "${WORK}/c-stale"
expect 1 "stale entry fails" "${WORK}/decls" "${WORK}/c-stale" "${WORK}/waivers" "epsilon"

{ good_contracts; echo "NO_ERROR_PATH alpha"; } > "${WORK}/c-dup"
expect 1 "duplicate entry fails" "${WORK}/decls" "${WORK}/c-dup" "${WORK}/waivers" \
    "more than one contract entry"

good_contracts | sed 's/^CONTRACT gamma$/NO_ERROR_PATH gamma/' > "${WORK}/c-unlisted"
expect 1 "waiver missing from the waiver file fails" "${WORK}/decls" "${WORK}/c-unlisted" "${WORK}/waivers" \
    "gamma"

{ cat "${WORK}/waivers"; echo "alpha"; } > "${WORK}/w-over"
expect 1 "waiver file over-listing fails (ratchet)" "${WORK}/decls" "${WORK}/contracts" "${WORK}/w-over" \
    "waivers only ratchet down"

: > "${WORK}/empty"
expect 2 "empty declaration list is a broken input" "${WORK}/empty" "${WORK}/contracts" "${WORK}/waivers"
expect 2 "unreadable contract list is a broken input" "${WORK}/decls" "${WORK}/no-such-file" "${WORK}/waivers"
{ good_contracts; echo "TESTED zeta"; } > "${WORK}/c-bad"
expect 2 "malformed contract line is a broken input" "${WORK}/decls" "${WORK}/c-bad" "${WORK}/waivers" \
    "TESTED zeta"

# The table references each function by address: a name nobody declared
# must not compile into a silently untested entry.
if ! command -v gcc >/dev/null 2>&1; then
    echo "✗ gcc is required for the compile-time probe" >&2
    exit 2
fi
cat > "${WORK}/declared.c" <<'EOF'
#include "api_contract.h"
int a_declared_function(int x);
static void b(void) {}
static void e(void) {}
static const api_contract_t t[] = {
    CONTRACT(a_declared_function, b, e),
    NO_ERROR_PATH(a_declared_function, b, "reason"),
};
const api_contract_t *table(void) { return t; }
EOF
sed 's/CONTRACT(a_declared_function/CONTRACT(not_a_real_fn/' "${WORK}/declared.c" > "${WORK}/undeclared.c"
if gcc -fsyntax-only -Wall -Wextra -Werror -I"$(dirname "${CONTRACT_H}")" "${WORK}/declared.c" \
        >"${WORK}/out" 2>&1; then
    echo "✓ CONTRACT on a declared function compiles warning-free"
else
    echo "✗ CONTRACT on a declared function does not compile:"
    sed 's/^/      /' "${WORK}/out"
    FAILED=1
fi
if gcc -fsyntax-only -I"$(dirname "${CONTRACT_H}")" "${WORK}/undeclared.c" >"${WORK}/out" 2>&1; then
    echo "✗ CONTRACT on an undeclared name compiled"
    FAILED=1
elif grep -q "not_a_real_fn" "${WORK}/out"; then
    echo "✓ CONTRACT on an undeclared name is a compile error"
else
    echo "✗ compile failed, but not on the undeclared name:"
    sed 's/^/      /' "${WORK}/out"
    FAILED=1
fi

n="$(bash "${DECLS_HELPER}" --list | wc -l | tr -d ' ')"
if [ "${n}" -gt 0 ] && bash "${DECLS_HELPER}" --list | grep -qx "mmt_init_handler"; then
    echo "✓ check-public-decls.sh --list prints the declared set (${n} names)"
else
    echo "✗ check-public-decls.sh --list printed ${n} names, mmt_init_handler missing"
    FAILED=1
fi

# MMTCALL is defined empty, so an export without it compiles: --list must
# refuse it rather than silently leave it out of the declared set. The helper
# reads the headers relative to its own location, so run a copy in a scratch
# tree holding one such header.
mkdir -p "${WORK}/tree/tools/ci" "${WORK}/tree/src/mmt_core/public_include"
cp "${DECLS_HELPER}" "${WORK}/tree/tools/ci/"
cat > "${WORK}/tree/src/mmt_core/public_include/probe.h" <<'EOF'
#define MMTAPI extern
#define MMTCALL
MMTAPI int MMTCALL probe_with_mmtcall(void);
MMTAPI int probe_no_mmtcall(void);
EOF
rc=0
bash "${WORK}/tree/tools/ci/check-public-decls.sh" --list >"${WORK}/out" 2>&1 || rc=$?
if [ "${rc}" -eq 2 ] && grep -q "without MMTCALL: probe_no_mmtcall" "${WORK}/out"; then
    echo "✓ --list exits 2 on an MMTAPI declaration without MMTCALL"
else
    echo "✗ --list on an MMTAPI declaration without MMTCALL: exit ${rc}, expected 2 naming probe_no_mmtcall"
    sed 's/^/      /' "${WORK}/out"
    FAILED=1
fi

# Issue #546: the default pass refuses an unsigned public function that
# returns -1, literally or through a local initialised to -1, and accepts a
# named sentinel, a signed function's -1 and a signed caller returning -1
# from a block opened by a call to an unsigned function. --libs pointing at an empty
# directory is not given, so no nm pass runs (no sdk/lib in the scratch tree).
mkdir -p "${WORK}/tree/src/lib"
cat > "${WORK}/tree/src/mmt_core/public_include/probe.h" <<'EOF'
#define MMTAPI extern
#define MMTCALL
MMTAPI unsigned MMTCALL probe_literal(int x);
MMTAPI uint64_t MMTCALL probe_local(int x);
MMTAPI uint32_t MMTCALL probe_sentinel(int x);
MMTAPI int MMTCALL probe_signed(int x);
EOF
cat > "${WORK}/tree/src/lib/probe.c" <<'EOF'
unsigned probe_literal(int x) { if (x) return -1; return 0; }
uint64_t probe_local(int x) { int r = -1; if (x) r = x; return r; }
uint32_t probe_sentinel(int x) { if (x) return UINT32_MAX; return 0; } /* return -1; */
int probe_signed(int x) { return x ? -1 : 0; }
int probe_caller(int x) {
    if (probe_sentinel(x)) { return -1; }
    return 0;
}
EOF
rc=0
(cd "${WORK}/tree" && MMT_BASE="${WORK}/none" bash tools/ci/check-public-decls.sh) >"${WORK}/out" 2>&1 || rc=$?
if [ "${rc}" -eq 1 ] && grep -q "probe_literal (unsigned)" "${WORK}/out" \
        && grep -q "probe_local (uint64_t)" "${WORK}/out" \
        && ! grep -q "probe_sentinel\|probe_signed\|probe_caller" "${WORK}/out"; then
    echo "✓ an unsigned public function returning -1 exits 1, naming only the offenders"
else
    echo "✗ unsigned -1 return scan: exit ${rc}, expected 1 naming probe_literal and probe_local only"
    sed 's/^/      /' "${WORK}/out"
    FAILED=1
fi
sed -i 's/return -1; return 0; }/return UINT_MAX; return 0; }/; s/int r = -1;/uint64_t r = UINT64_MAX;/' \
    "${WORK}/tree/src/lib/probe.c"
rc=0
(cd "${WORK}/tree" && MMT_BASE="${WORK}/none" bash tools/ci/check-public-decls.sh) >"${WORK}/out" 2>&1 || rc=$?
if [ "${rc}" -eq 0 ] && grep -q "no public function with an unsigned return type returns -1" "${WORK}/out"; then
    echo "✓ named sentinels pass the unsigned -1 return scan"
else
    echo "✗ unsigned -1 return scan on fixed sources: exit ${rc}, expected 0"
    sed 's/^/      /' "${WORK}/out"
    FAILED=1
fi

exit "${FAILED}"
