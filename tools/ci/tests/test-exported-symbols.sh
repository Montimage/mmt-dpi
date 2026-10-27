#!/usr/bin/env bash
#
# test-exported-symbols.sh — self-test for the protocol-plugin export gate of
# scripts/validate-exported-symbols.sh (issue #534).
#
# Drives the REAL validator on a fixture: a tiny shared object built with
# -fvisibility=hidden and installed as libmmt_tcpip.so.9.9.9 in a scratch
# library directory, and a fixture document with a `## libmmt_tcpip` table.
# MMT_EXPORTS_LIB_DIR / MMT_EXPORTS_DOC / MMT_EXPORTS_LIBS=tcpip point the
# validator at them, so it builds no SDK and reads no file of the checkout
# but its own source.
#
# Scenario -> expected validator exit:
#   the table lists exactly the exports                      -> 0
#   the library exports a symbol the table does not list     -> 1, names it
#   the table lists a symbol the library no longer exports   -> 1, names it
#   the document has no libmmt_tcpip section                 -> 1
#   --write records a changed export set, then --check       -> 0, 0
#   the library is missing from the overridden directory     -> 2
#   MMT_EXPORTS_LIBS names an unknown library                -> 2
#
# Usage: bash tools/ci/tests/test-exported-symbols.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
VALIDATOR="${REPO_ROOT}/scripts/validate-exported-symbols.sh"
[ -f "${VALIDATOR}" ] || { echo "✗ missing ${VALIDATOR}" >&2; exit 2; }
CC="${CC:-gcc}"
command -v "${CC}" >/dev/null 2>&1 || { echo "✗ ${CC} is required" >&2; exit 2; }
command -v nm >/dev/null 2>&1 || { echo "✗ nm is required (binutils)" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

pass=0
fail=0
ok()  { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

# build_lib DIR SYMBOL... — a libmmt_tcpip.so.9.9.9 in DIR exporting exactly
# the SYMBOLs, plus a hidden helper that must never be reported.
build_lib() {
    local dir="$1" sym
    shift
    mkdir -p "${dir}"
    {
        echo 'int fixture_hidden_helper(void) { return 7; }'
        for sym in "$@"; do
            echo "__attribute__((visibility(\"default\"))) int ${sym}(void) { return fixture_hidden_helper(); }"
        done
    } > "${dir}/fixture.c"
    "${CC}" -shared -fPIC -fvisibility=hidden -o "${dir}/libmmt_tcpip.so.9.9.9" "${dir}/fixture.c" \
        || { echo "✗ could not build the fixture library" >&2; exit 2; }
    rm -f "${dir}/fixture.c"
}

# write_doc FILE SYMBOL... — a fixture document whose libmmt_tcpip table
# lists the SYMBOLs, between a preamble and a later section.
write_doc() {
    local file="$1" sym
    shift
    {
        printf '%s\n' '---' 'title: "fixture"' '---' '' '## libmmt_tcpip' '' \
            'Prose that --write keeps.' '' '| symbol |' '|:-|'
        for sym in "$@"; do printf '|%s%s%s|\n' '`' "${sym}" '`'; done
        printf '%s\n' '' '## Later section' '' 'Kept as is.'
    } > "${file}"
}

# run_validator LIBDIR DOC [ARGS...] — sets RC and OUT (stdout + stderr).
run_validator() {
    local libdir="$1" doc="$2"
    shift 2
    OUT="$(MMT_EXPORTS_LIB_DIR="${libdir}" MMT_EXPORTS_DOC="${doc}" \
           MMT_EXPORTS_LIBS="${MMT_EXPORTS_LIBS:-tcpip}" \
           bash "${VALIDATOR}" "$@" 2>&1)"
    RC=$?
}

# expect LABEL WANT_RC [PATTERN] — checks RC, and that OUT matches PATTERN.
expect() {
    local label="$1" want="$2" pattern="${3:-}"
    if [ "${RC}" -ne "${want}" ]; then
        bad "${label}: exit ${RC}, want ${want}"
        printf '%s\n' "${OUT}" | sed 's/^/      | /'
        return
    fi
    if [ -n "${pattern}" ] && ! grep -qE -- "${pattern}" <<<"${OUT}"; then
        bad "${label}: output lacks /${pattern}/"
        printf '%s\n' "${OUT}" | sed 's/^/      | /'
        return
    fi
    ok "${label}"
}

BASE="${WORK}/base"
build_lib "${BASE}" init_proto cleanup_proto
EXTRA="${WORK}/extra"
build_lib "${EXTRA}" init_proto cleanup_proto fixture_leaked_internal

DOC="${WORK}/doc.md"
write_doc "${DOC}" cleanup_proto init_proto

echo "=== validate-exported-symbols.sh plugin gate (issue #534) ==="

run_validator "${BASE}" "${DOC}"
expect "exports match the table" 0 'libmmt_tcpip: 2 exports, as recorded'

run_validator "${EXTRA}" "${DOC}"
expect "an unrecorded export fails" 1 '\+ fixture_leaked_internal'
if grep -q fixture_hidden_helper <<<"${OUT}"; then
    bad "a hidden symbol is reported"
else
    ok "a hidden symbol is not reported"
fi

STALE="${WORK}/stale.md"
write_doc "${STALE}" cleanup_proto init_proto fixture_removed_export
run_validator "${BASE}" "${STALE}"
expect "a recorded symbol no longer exported fails" 1 '\- fixture_removed_export'

NOSEC="${WORK}/nosection.md"
printf '%s\n' '# fixture' '' 'No plugin section.' > "${NOSEC}"
run_validator "${BASE}" "${NOSEC}"
expect "a missing section fails" 1 'no .## libmmt_tcpip. section'

WRITE="${WORK}/write.md"
write_doc "${WRITE}" cleanup_proto init_proto
run_validator "${EXTRA}" "${WRITE}" --write
expect "--write records the changed export set" 0 '\+ fixture_leaked_internal'
run_validator "${EXTRA}" "${WRITE}"
expect "the check passes after --write" 0 'libmmt_tcpip: 3 exports, as recorded'
if grep -q 'Prose that --write keeps.' "${WRITE}" && grep -q '^## Later section' "${WRITE}"; then
    ok "--write keeps the prose and the later section"
else
    bad "--write dropped the prose or the later section"
fi

mkdir -p "${WORK}/empty"
run_validator "${WORK}/empty" "${DOC}"
expect "a missing library is a broken run" 2 'library not found'

MMT_EXPORTS_LIBS=nosuchlib run_validator "${BASE}" "${DOC}"
expect "an unknown library name is a broken run" 2 'unknown library'

echo "=== ${pass} passed, ${fail} failed ==="
[ "${fail}" -eq 0 ]
