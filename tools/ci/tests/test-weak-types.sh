#!/usr/bin/env bash
#
# test-weak-types.sh — self-test for the `opaque` metric of the weak-type
# ratchet in tools/ci/count-weak-types.sh (issue #539).
#
# The real public headers name only allowlisted opaque roles, so the metric
# reads 0 there by construction; this self-test proves it can fail. It copies
# the REAL counter into a throwaway tree whose src/mmt_core/public_include
# holds fixture headers, with a fixture baseline, so each scenario runs in
# milliseconds without touching the real tree.
#
# Scenario -> expected counter exit:
#   only allowlisted opaque roles (incl. multi-line, const, comments)  -> 0
#   a named, non-allowlisted mmt_opaque_t parameter                    -> 1 (--strict)
#   the same, in baseline mode with `opaque 0`                         -> 1
#   an unnamed mmt_const_opaque_t parameter                            -> 1 (--strict)
#   a non-allowlisted name inside a comment or a struct field          -> 0
#   the real tree (src/mmt_core/public_include)                        -> 0 (--strict)
#
# Usage: bash tools/ci/tests/test-weak-types.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
COUNTER="${REPO_ROOT}/tools/ci/count-weak-types.sh"
[ -f "${COUNTER}" ] || { echo "✗ missing ${COUNTER}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
FIX="${WORK}/repo"
HDR="${FIX}/src/mmt_core/public_include"
mkdir -p "${FIX}/tools/ci" "${HDR}"
cp "${COUNTER}" "${FIX}/tools/ci/"
printf 'proto_id  0\nvoid_star 0\nopaque    0\nint_bool  0\n' >"${FIX}/tools/ci/weak-types-baseline.txt"

checks=0
failures=0
pass() { checks=$((checks + 1)); echo "  ✓ $1"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); echo "  ✗ $1" >&2; }

# write_header CONTENT — the fixture tree's only public header.
write_header() {
    rm -f "${HDR}"/*.h
    printf '%s\n' "$1" >"${HDR}/fixture.h"
}

# expect_exit DESC WANT [ARGS...] — runs the copied counter in the fixture tree.
expect_exit() {
    local desc="$1" want="$2"; shift 2
    local got=0 out
    out="$(bash "${FIX}/tools/ci/count-weak-types.sh" "$@" 2>&1)" || got=$?
    if [ "${got}" -eq "${want}" ]; then pass "${desc}"
    else fail "${desc} (exit ${got}, want ${want})"; printf '%s\n' "${out}" | sed 's/^/      /' >&2; fi
    LAST_OUT="${out}"
}

# The two int-return lines are allowlisted int_bool names: the counter's
# int_bool greps run under pipefail and need a match to exist.
ALLOWED='MMTAPI int MMTCALL hex2int(char c);
int char2int(char c);
typedef void *mmt_opaque_t;
typedef const void *mmt_const_opaque_t;
typedef void (*cb)(mmt_opaque_t key, mmt_opaque_t value, mmt_opaque_t args);
void f(
    int n,
    mmt_opaque_t user_data   /* a mmt_opaque_t bogus in a comment */
);
bool g(mmt_const_opaque_t x, mmt_opaque_t const y, mmt_opaque_t *user);
struct s { mmt_opaque_t bogus_field; };
/* void h(mmt_opaque_t bogus); */'

echo "-- allowlisted roles pass --"
write_header "${ALLOWED}"
expect_exit "only allowlisted opaque roles: --strict passes" 0 --strict
expect_exit "only allowlisted opaque roles: baseline mode passes" 0

echo "-- an unjustified opaque parameter fails --"
write_header "${ALLOWED}
void bad(int a, mmt_opaque_t session_ctx);"
expect_exit "a named non-allowlisted parameter fails --strict" 1 --strict
if grep -q 'fixture.h:13: mmt_opaque_t session_ctx' <<<"${LAST_OUT}"; then
    pass "the offender is named with file:line"
else
    fail "the offender is named with file:line"; printf '%s\n' "${LAST_OUT}" | sed 's/^/      /' >&2
fi
expect_exit "a named non-allowlisted parameter rises above the baseline" 1

echo "-- an unnamed opaque parameter fails --"
write_header "${ALLOWED}
typedef int (*bad_cb)(mmt_const_opaque_t, int);"
expect_exit "an unnamed opaque parameter fails --strict" 1 --strict
if grep -q '<unnamed>' <<<"${LAST_OUT}"; then pass "an unnamed parameter is reported as such"
else fail "an unnamed parameter is reported as such"; fi

echo "-- the real public headers --"
real_rc=0
bash "${COUNTER}" --strict >/dev/null 2>&1 || real_rc=$?
if [ "${real_rc}" -eq 0 ]; then pass "src/mmt_core/public_include passes --strict"
else fail "src/mmt_core/public_include passes --strict (exit ${real_rc})"; fi

echo "weak-types self-test: $((checks - failures))/${checks} passed"
[ "${failures}" -eq 0 ]
