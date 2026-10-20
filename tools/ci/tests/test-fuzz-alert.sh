#!/usr/bin/env bash
#
# test-fuzz-alert.sh — self-test for tools/ci/fuzz-alert.sh (issue #486):
# a failed scheduled fuzz run opens an issue carrying the reproducer, or
# comments on the open one instead of filing a duplicate.
#
# A PATH stub `gh` records each invocation and the body it was given; the
# FUZZ_STUB_OPEN_ISSUE variable is the number `gh issue list` reports (empty
# = no open issue).
#
# Usage: bash tools/ci/tests/test-fuzz-alert.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
ALERT="${REPO_ROOT}/tools/ci/fuzz-alert.sh"
[ -f "${ALERT}" ] || { echo "✗ missing ${ALERT}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/stubs" "${WORK}/art"

cat > "${WORK}/stubs/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FUZZ_STUB_CALLS}"
if [ "$1 $2" = "issue list" ]; then
    printf '%s' "${FUZZ_STUB_OPEN_ISSUE:-}"; exit 0
fi
while [ $# -gt 0 ]; do
    [ "$1" = "--body-file" ] && cp "$2" "${FUZZ_STUB_BODY}"
    shift
done
exit 0
STUB
chmod +x "${WORK}/stubs/gh"

# One reproducer exactly as run-fuzz.sh records it.
cat > "${WORK}/art/crash-pcap-ftp_multiple_session.pcap-seed36412723701.log" <<'LOG'
driver   : phase0_classify /x/crash-pcap-ftp_multiple_session.pcap-seed36412723701
seed file: tools/phase0/ci/pcaps/ftp_multiple_session.pcap
mutant   : mutate.py --seed 36412723701 (repro: python3 tools/ci/fuzz/mutate.py "tools/phase0/ci/pcaps/ftp_multiple_session.pcap" out --seed 36412723701)
exit code: 134 (signal/crash)
--- stderr ---
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x5040000abed0
LOG
printf 'run-fuzz summary\nfindings: 1\n' > "${WORK}/art/SUMMARY.txt"

PASS=0; FAIL=0
check() {
    # $1 = name, rest = command that must succeed
    local name="$1"; shift
    if "$@"; then PASS=$((PASS + 1)); printf '  ✓ %s\n' "${name}"
    else FAIL=$((FAIL + 1)); printf '  ✗ %s\n' "${name}"; fi
}
alert() {
    : > "${WORK}/calls"; rm -f "${WORK}/body"
    env PATH="${WORK}/stubs:${PATH}" FUZZ_STUB_CALLS="${WORK}/calls" \
        FUZZ_STUB_BODY="${WORK}/body" FUZZ_STUB_OPEN_ISSUE="${OPEN:-}" \
        bash "${ALERT}" "$1" https://example.invalid/run/1 >"${WORK}/out" 2>&1
}

echo "fuzz-alert.sh self-test (issue #486)"
OPEN=""
check "no open issue -> exits 0" alert "${WORK}/art"
check "  ... opens a new issue" grep -q '^issue create --title Scheduled fuzz run failed' "${WORK}/calls"
check "  ... body carries the mutate.py reproducer" grep -q 'mutate.py --seed 36412723701' "${WORK}/body"
check "  ... body carries the sanitizer report" grep -q 'heap-use-after-free' "${WORK}/body"
check "  ... body links the run" grep -q 'https://example.invalid/run/1' "${WORK}/body"

OPEN="501"
check "open issue -> exits 0" alert "${WORK}/art"
check "  ... comments on it" grep -q '^issue comment 501 ' "${WORK}/calls"
check "  ... files no duplicate" bash -c "! grep -q '^issue create' '${WORK}/calls'"

OPEN=""; mkdir -p "${WORK}/empty"
check "no reproducer (build break) -> still opens an issue" alert "${WORK}/empty"
check "  ... saying no reproducer was recorded" grep -q 'No reproducer was recorded' "${WORK}/body"

mkdir -p "${WORK}/many"
for i in $(seq 1 10); do
    for _ in $(seq 1 40); do printf '%0300d\n' "${i}"; done > "${WORK}/many/crash-${i}.log"
done
for _ in $(seq 1 400); do printf '%0300d\n' 0; done > "${WORK}/many/SUMMARY.txt"
check "10 large reproducer logs -> still opens an issue" alert "${WORK}/many"
check "  ... body stays under GitHub's 65,536-char limit" bash -c "[ \$(wc -c < '${WORK}/body') -lt 65536 ]"

check "missing arguments -> exit 2" bash -c "bash '${ALERT}' >/dev/null 2>&1; [ \$? -eq 2 ]"

echo ""
echo "fuzz-alert self-test: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
