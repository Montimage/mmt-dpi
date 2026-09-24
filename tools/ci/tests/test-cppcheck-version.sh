#!/usr/bin/env bash
#
# test-cppcheck-version.sh — self-test for the cppcheck version pin in
# tools/ci/run-cppcheck.sh (issue #345).
#
# It drives the REAL gate script with a PATH stub `cppcheck` whose version
# string, pass-1 finding count and pass-2 exit code come from environment
# variables, so each scenario runs in milliseconds without scanning src/.
# The ratchet baseline and the report go to a scratch directory.
#
# Scenario -> expected gate exit:
#   pinned version, findings <= baseline            -> 0
#   pinned version, findings >  baseline            -> 1 (ratchet trips)
#   other version locally, findings > baseline      -> 0 (ratchet advisory)
#   other version locally, error-severity finding   -> 1 (error gate stays)
#   other version with CI=true                      -> 2 (pin drifted in CI)
#   unparseable version string                      -> 2 (helper broken)
#
# Usage: bash tools/ci/tests/test-cppcheck-version.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
GATE="${REPO_ROOT}/tools/ci/run-cppcheck.sh"
[ -f "${GATE}" ] || { echo "✗ missing ${GATE}" >&2; exit 2; }

pinned="$(sed -n 's/^CPPCHECK_PINNED_VERSION="\([0-9.]*\)".*/\1/p' "${GATE}")"
[ -n "${pinned}" ] || { echo "✗ CPPCHECK_PINNED_VERSION not found in ${GATE}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/bin"

cat > "${WORK}/bin/cppcheck" <<'STUB'
#!/usr/bin/env bash
# Stub: --version prints $STUB_VERSION; the --xml pass writes $STUB_FINDINGS
# <error> entries to stderr; the error-gate pass exits $STUB_ERROR_RC.
for a in "$@"; do
    case "$a" in
        --version) printf '%s\n' "${STUB_VERSION}"; exit 0 ;;
        --xml) {
                   echo '<?xml version="1.0" encoding="UTF-8"?>'
                   echo '<results version="2"><errors>'
                   for _ in $(seq 1 "${STUB_FINDINGS}"); do
                       echo '<error id="x" severity="warning" msg="m"/>'
                   done
                   echo '</errors></results>'
               } >&2
               exit 0 ;;
    esac
done
exit "${STUB_ERROR_RC}"
STUB
chmod +x "${WORK}/bin/cppcheck"
printf '# test baseline\n10\n' > "${WORK}/ratchet.txt"

pass=0
fail=0

# run_case NAME EXPECTED_RC VERSION FINDINGS ERROR_RC CI_VALUE
run_case() {
    local name="$1" want="$2" rc=0
    env PATH="${WORK}/bin:${PATH}" CI="$6" \
        STUB_VERSION="$3" STUB_FINDINGS="$4" STUB_ERROR_RC="$5" \
        CPPCHECK_RATCHET="${WORK}/ratchet.txt" \
        CPPCHECK_REPORT="${WORK}/report.xml" CPPCHECK_JOBS=1 \
        bash "${GATE}" > "${WORK}/out.log" 2>&1 || rc=$?
    if [ "${rc}" -eq "${want}" ]; then
        echo "  ✓ ${name} (exit ${rc})"
        pass=$((pass + 1))
    else
        echo "  ✗ ${name}: expected exit ${want}, got ${rc}"
        sed 's/^/      /' "${WORK}/out.log"
        fail=$((fail + 1))
    fi
}

other="9.99"
echo "── run-cppcheck.sh version pin (pinned: ${pinned}) ──"
run_case "pinned version, within ratchet"          0 "Cppcheck ${pinned}.0" 10 0 ""
run_case "pinned version, ratchet exceeded"        1 "Cppcheck ${pinned}.0" 11 0 ""
run_case "other version locally, ratchet advisory" 0 "Cppcheck ${other}.0"  35 0 ""
run_case "other version locally, error gate trips" 1 "Cppcheck ${other}.0"  5  1 ""
run_case "other version in CI fails loudly"        2 "Cppcheck ${other}.0"  5  0 "true"
run_case "pinned version in CI, within ratchet"    0 "Cppcheck ${pinned}.1" 10 0 "true"
run_case "unparseable version string"              2 "Cppcheck dev"         0  0 ""

echo "cppcheck version pin: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
