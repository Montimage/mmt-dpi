#!/usr/bin/env bash
#
# test-cppcheck-version.sh — self-test for the cppcheck version pin in
# tools/ci/run-cppcheck.sh (issue #345).
#
# It drives the REAL gate script with a PATH stub `cppcheck` whose version
# string, finding count and error-severity count come from environment
# variables, so each scenario runs in milliseconds without scanning src/.
# The ratchet baseline and the report go to a scratch directory.
#
# Scenario -> expected gate exit:
#   pinned version, findings <= baseline            -> 0
#   pinned version, findings >  baseline            -> 1 (ratchet trips)
#   pinned version, error-severity finding          -> 1 (error gate)
#   other version locally, findings > baseline      -> 0 (ratchet advisory)
#   other version locally, error-severity finding   -> 1 (error gate stays)
#   other version with CI=true                      -> 2 (pin drifted in CI)
#   unparseable version string                      -> 2 (helper broken)
#
# Both checks read one scan (issue #552): the stub logs every invocation, and
# a run that scans the tree more than once fails, as does a
# $CPPCHECK_BUILD_DIR that does not reach cppcheck as --cppcheck-build-dir.
#
# It also checks where the pinned release comes from (issue #518): the
# major.minor of CPPCHECK_VERSION in tools/ci/install-cppcheck.sh must equal
# the pin, its checksum must be a sha256, and the `lint` job of
# .github/workflows/c-cpp.yml must run in a digest-pinned container, mark its
# checkout as a safe git directory (the container runs as root, so git
# ls-files would otherwise hand shellcheck no files) and build cppcheck with
# that installer — so the pin, the installer and the CI image
# cannot drift apart silently — and must restore its --cppcheck-build-dir
# with actions/cache (issue #552).
#
# Usage: bash tools/ci/tests/test-cppcheck-version.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
GATE="${REPO_ROOT}/tools/ci/run-cppcheck.sh"
[ -f "${GATE}" ] || { echo "✗ missing ${GATE}" >&2; exit 2; }

INSTALLER="${REPO_ROOT}/tools/ci/install-cppcheck.sh"
WORKFLOW="${REPO_ROOT}/.github/workflows/c-cpp.yml"
[ -f "${INSTALLER}" ] || { echo "✗ missing ${INSTALLER}" >&2; exit 2; }
[ -f "${WORKFLOW}" ] || { echo "✗ missing ${WORKFLOW}" >&2; exit 2; }

pinned="$(sed -n 's/^CPPCHECK_PINNED_VERSION="\([0-9.]*\)".*/\1/p' "${GATE}")"
[ -n "${pinned}" ] || { echo "✗ CPPCHECK_PINNED_VERSION not found in ${GATE}" >&2; exit 2; }
installed="$(sed -n 's/^CPPCHECK_VERSION="\([0-9.]*\)".*/\1/p' "${INSTALLER}")"
[ -n "${installed}" ] || { echo "✗ CPPCHECK_VERSION not found in ${INSTALLER}" >&2; exit 2; }
checksum="$(sed -n 's/^CPPCHECK_SHA256="\([^"]*\)".*/\1/p' "${INSTALLER}")"
# The lint job's block: from its `  lint:` key to the next job key.
lint_job="$(awk '/^  lint:$/ {in_job=1; print; next}
                 in_job && /^  [A-Za-z0-9_-]+:$/ {exit}
                 in_job {print}' "${WORKFLOW}")"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
# Only the case that sets it passes a build dir to the gate.
unset CPPCHECK_BUILD_DIR
mkdir -p "${WORK}/bin"

cat > "${WORK}/bin/cppcheck" <<'STUB'
#!/usr/bin/env bash
# Stub: --version prints $STUB_VERSION; any other invocation is a scan,
# logged to $STUB_LOG with its arguments; the --xml scan writes
# $STUB_FINDINGS <error> entries to stderr, the first $STUB_ERRORS of them
# error-severity.
for a in "$@"; do
    [ "$a" = --version ] && { printf '%s\n' "${STUB_VERSION}"; exit 0; }
done
printf '%s\n' "$*" >> "${STUB_LOG}"
for a in "$@"; do
    if [ "$a" = --xml ]; then
        {
            echo '<?xml version="1.0" encoding="UTF-8"?>'
            echo '<results version="2"><errors>'
            for i in $(seq 1 "${STUB_FINDINGS}"); do
                sev=warning
                [ "$i" -le "${STUB_ERRORS}" ] && sev=error
                echo "<error id=\"x\" severity=\"${sev}\" msg=\"m\"/>"
            done
            echo '</errors></results>'
        } >&2
        exit 0
    fi
done
exit 0
STUB
chmod +x "${WORK}/bin/cppcheck"
printf '# test baseline\n10\n' > "${WORK}/ratchet.txt"

pass=0
fail=0

# run_case NAME EXPECTED_RC VERSION FINDINGS ERRORS CI_VALUE
run_case() {
    local name="$1" want="$2" rc=0
    : > "${WORK}/scans.log"
    env PATH="${WORK}/bin:${PATH}" CI="$6" \
        STUB_VERSION="$3" STUB_FINDINGS="$4" STUB_ERRORS="$5" \
        STUB_LOG="${WORK}/scans.log" \
        CPPCHECK_RATCHET="${WORK}/ratchet.txt" \
        CPPCHECK_REPORT="${WORK}/report.xml" CPPCHECK_JOBS=1 \
        ${CPPCHECK_BUILD_DIR:+CPPCHECK_BUILD_DIR="${CPPCHECK_BUILD_DIR}"} \
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

not_grep() { ! grep -q "$@"; }

# check NAME CONDITION... — a static assertion on the pin's provenance.
check() {
    local name="$1"; shift
    if "$@"; then
        echo "  ✓ ${name}"
        pass=$((pass + 1))
    else
        echo "  ✗ ${name}"
        fail=$((fail + 1))
    fi
}

echo "── cppcheck pin provenance (installer: ${installed}) ──"
check "installer release ${installed} matches the pin ${pinned}" \
    test "${installed%.*}" = "${pinned}"
check "installer tarball is pinned by a sha256" \
    grep -Eq '^[0-9a-f]{64}$' <<< "${checksum}"
check "lint job runs in a digest-pinned container" \
    grep -Eq '^      image: "?[^" ]+@sha256:[0-9a-f]{64}"?$' <<< "${lint_job}"
# shellcheck disable=SC2016 # the workflow's literal $GITHUB_WORKSPACE
check "lint job marks the root-container checkout safe for git" \
    grep -qF 'safe.directory "$GITHUB_WORKSPACE"' <<< "${lint_job}"
check "lint job builds cppcheck with install-cppcheck.sh" \
    grep -q 'bash tools/ci/install-cppcheck.sh' <<< "${lint_job}"
# Backslash continuations joined, so a package on a continuation line of
# an apt-get install command is still seen.
lint_joined="$(sed -e ':a' -e '/\\$/{N;s/\\\n//;ba' -e '}' <<< "${lint_job}")"
no_distro_cppcheck() {
    ! grep -Eq '(apt-get install|extra-packages:).*[[:space:]]cppcheck([[:space:]]|$)' <<< "${lint_joined}"
}
check "lint job installs no distribution cppcheck" no_distro_cppcheck
check "lint job hands run-cppcheck.sh a build dir" \
    grep -q 'CPPCHECK_BUILD_DIR: .cppcheck-build' <<< "${lint_job}"
check "lint job restores the build dir with actions/cache" \
    grep -Eq '^        path: \.cppcheck-build$' <<< "${lint_job}"

other="9.99"
echo "── run-cppcheck.sh version pin (pinned: ${pinned}) ──"
run_case "pinned version, within ratchet"          0 "Cppcheck ${pinned}.0" 10 0 ""
run_case "pinned version, ratchet exceeded"        1 "Cppcheck ${pinned}.0" 11 0 ""
run_case "pinned version, error gate trips"        1 "Cppcheck ${pinned}.0" 10 1 ""
run_case "other version locally, ratchet advisory" 0 "Cppcheck ${other}.0"  35 0 ""
run_case "other version locally, error gate trips" 1 "Cppcheck ${other}.0"  5  1 ""
run_case "other version in CI fails loudly"        2 "Cppcheck ${other}.0"  5  0 "true"
run_case "pinned version in CI, within ratchet"    0 "Cppcheck ${pinned}.1" 10 0 "true"
run_case "unparseable version string"              2 "Cppcheck dev"         0  0 ""

echo "── run-cppcheck.sh scans once (issue #552) ──"
run_case "error-severity finding, single scan"     1 "Cppcheck ${pinned}.0" 3  1 ""
scans="$(wc -l < "${WORK}/scans.log")"
check "both checks read one scan (${scans} cppcheck scan(s))" \
    test "${scans}" -eq 1
check "no build dir without CPPCHECK_BUILD_DIR" \
    not_grep -- '--cppcheck-build-dir' "${WORK}/scans.log"
CPPCHECK_BUILD_DIR="${WORK}/cpb" \
    run_case "with CPPCHECK_BUILD_DIR, within ratchet" 0 "Cppcheck ${pinned}.0" 10 0 ""
check "CPPCHECK_BUILD_DIR reaches cppcheck as --cppcheck-build-dir" \
    grep -qF -- "--cppcheck-build-dir=${WORK}/cpb" "${WORK}/scans.log"
check "the build dir is created" test -d "${WORK}/cpb"

echo "cppcheck version pin: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
