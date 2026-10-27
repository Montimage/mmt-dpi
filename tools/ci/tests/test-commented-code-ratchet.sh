#!/usr/bin/env bash
#
# test-commented-code-ratchet.sh — self-test for the commented-out code
# ratchet in tools/ci/lint-commented-code.sh (issue #529).
#
# It copies the REAL lint and tools/ci/vendor-paths-lib.sh into a throwaway
# git repository whose src/ holds fixture C files, a fixture vendored-source
# list and a fixture baseline, so each scenario runs in milliseconds without
# scanning the real tree.
#
# Scenario -> expected lint exit:
#   2-line commented-out run counted, 1-line run not  -> blocks == 1
#   blocks == baseline                                -> 0
#   blocks >  baseline (one run above)                -> 1
#   blocks <  baseline                                -> 0 + "tighten" note
#   ratchet baseline missing                          -> 2
#   run inside a vendored path                        -> not counted
#   vendored-source list missing                      -> 2
#
# Usage: bash tools/ci/tests/test-commented-code-ratchet.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
LINT="${REPO_ROOT}/tools/ci/lint-commented-code.sh"
LIB="${REPO_ROOT}/tools/ci/vendor-paths-lib.sh"
for f in "${LINT}" "${LIB}"; do
    [ -f "${f}" ] || { echo "✗ missing ${f}" >&2; exit 2; }
done
command -v git >/dev/null 2>&1 || { echo "✗ git is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
FIX="${WORK}/repo"
mkdir -p "${FIX}/tools/ci" "${FIX}/src/lib"
cp "${LINT}" "${LIB}" "${FIX}/tools/ci/"

# One 2-line run (counted), one 1-line run (not counted).
cat > "${FIX}/src/a.c" <<'EOF'
int f(int x)
{
    // x = x + 1;
    // return x;
    int y = x;
    // y++;
    return y;
}
EOF
# A 3-line run inside a vendored file: excluded through the list.
cat > "${FIX}/src/lib/vendored.c" <<'EOF'
/* upstream code
x = 1;
y = 2;
z = 3;
*/
int g(void) { return 0; }
EOF
printf '# fixture vendored-source list\n\nsrc/lib/vendored.c\n' \
    > "${FIX}/tools/ci/vendor-paths.txt"
git -C "${FIX}" init -q
git -C "${FIX}" add -A

pass=0
fail=0

# run_case NAME EXPECTED_RC BASELINE [OUTPUT_ERE] — BASELINE "-" = no file.
run_case() {
    local name="$1" want="$2" base="$3" pattern="${4:-}" rc=0
    rm -f "${WORK}/ratchet.txt"
    [ "${base}" = "-" ] || printf '# fixture baseline\n%s\n' "${base}" > "${WORK}/ratchet.txt"
    COMMENTED_CODE_RATCHET="${WORK}/ratchet.txt" \
        bash "${FIX}/tools/ci/lint-commented-code.sh" > "${WORK}/out.log" 2>&1 || rc=$?
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

echo "── lint-commented-code.sh ratchet ──"
run_case "2-line run counted, 1-line run and vendored run not" 0 1 \
    'blocks of ≥2 lines: 1 \(2 lines'
run_case "the counted run is the 2-line one"                   0 1 'src/a\.c:3  2 commented'
run_case "blocks at the baseline pass"                         0 1 'within the ratchet \(1 ≤ 1\)'
run_case "one block above the baseline fails"                  1 0 'rose above the ratchet: 1 > 0'
run_case "blocks below the baseline ask to tighten it"         0 2 'note: .*dropped below the baseline \(1 < 2\)'
run_case "missing ratchet baseline is a broken helper"         2 - 'ratchet baseline not found'
run_case "non-numeric baseline is a broken helper"             2 'many' 'ratchet baseline unreadable'

# Without the vendored-source list the lint cannot tell vendored code apart.
mv "${FIX}/tools/ci/vendor-paths.txt" "${WORK}/vendor-paths.txt"
run_case "missing vendored-source list is a broken helper"     2 1 \
    'vendored-source list not found: tools/ci/vendor-paths.txt'
# An empty list drops the exclusion: the vendored 3-line run is counted.
: > "${FIX}/tools/ci/vendor-paths.txt"
run_case "vendored run counted once the list no longer names it" 1 1 \
    'src/lib/vendored\.c:2  3 commented'

echo "commented-code ratchet: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
