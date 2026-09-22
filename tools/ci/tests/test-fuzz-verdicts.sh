#!/usr/bin/env bash
#
# test-fuzz-verdicts.sh — self-test for tools/ci/run-fuzz.sh verdict
# handling (issue #370, F-TEST-001).
#
# It drives the REAL wrapper end-to-end with two PATH stubs so every run
# exercises the actual verdict logic without the ASan SDK build:
#
#   - a stub `gcc` "compiles" shell-script drivers whose exit code and
#     stderr come from ${FUZZ_STUB_DIR}/{rc,stderr}; it also answers
#     `-print-file-name=libasan.so`;
#   - a stub `python3` stands in for mutate.py (writes the mutant file, or
#     fails on demand via FUZZ_STUB_MUTATE_RC);
#   - a fake --prefix carrying dpi/lib/libmmt_fuzz.so skips the SDK build;
#   - --iterations 1 bounds each invocation to a single driver run, so a
#     scenario costs well under a second.
#
# Scenario -> expected wrapper exit:
#   clean exit 0                          -> 0 (PASS)
#   expected parser rejection (rc 1/2)    -> 0 (benign, counted as refusal)
#   UBSan "runtime error" report at rc 1  -> 1 (sanitizer finding)
#   ASan report at rc 1                   -> 1 (sanitizer finding)
#   timeout (rc 124)                      -> 1 (finding: hang/timeout)
#   killed child (rc >= 128)              -> 1 (finding: signal/crash)
#   driver not executable/missing (125-127) -> 2 (harness breakage)
#   infrastructure failure (mutate dies)  -> 2 (harness breakage)
#
# Usage: bash tools/ci/tests/test-fuzz-verdicts.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
RUN_FUZZ="${REPO_ROOT}/tools/ci/run-fuzz.sh"
[ -f "${RUN_FUZZ}" ] || { echo "✗ missing ${RUN_FUZZ}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

STUBS="${WORK}/stubs"
CONTROL="${WORK}/control"
ARTIFACTS="${WORK}/artifacts"
PREFIX="${WORK}/prefix"
mkdir -p "${STUBS}" "${CONTROL}" "${ARTIFACTS}" "${PREFIX}/dpi/lib" "${PREFIX}/dpi/include"
: > "${PREFIX}/dpi/lib/libmmt_fuzz.so"

# A real shared object for LD_PRELOAD when a compiler is reachable so the
# per-run logs stay quiet; otherwise an empty file — the resulting ld.so
# warning is noise ("cannot be preloaded"), never a sanitizer banner, and
# cannot collide with the marker regex.
if command -v gcc >/dev/null 2>&1; then
    printf 'void __fuzz_stub_noop(void){}\n' \
        | gcc -x c -shared -fPIC -o "${STUBS}/libasan.so" - 2>/dev/null \
        || : > "${STUBS}/libasan.so"
else
    : > "${STUBS}/libasan.so"
fi

# --- stub: gcc ---------------------------------------------------------------
# Understands "-print-file-name=libasan.so" and "-o OUT" compiles. A compile
# writes a shell driver that replays ${FUZZ_STUB_DIR}/{rc,stderr} — a signal
# band rc makes the driver kill itself so `timeout` observes 128+SIG exactly
# like a genuine crash. FUZZ_STUB_NO_DRIVER=1 exits 0 without writing a
# binary, simulating a compile that leaves no executable behind.
cat > "${STUBS}/gcc" <<'EOF'
#!/usr/bin/env bash
STUB_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for a in "$@"; do
    case "${a}" in
        -print-file-name=*) printf '%s\n' "${STUB_HOME}/libasan.so"; exit 0 ;;
    esac
done
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *)  shift ;;
    esac
done
[ -n "${out}" ] || { echo "stub gcc: no -o in invocation" >&2; exit 1; }
if [ "${FUZZ_STUB_NO_DRIVER:-0}" = "1" ]; then
    exit 0   # compile "succeeded" but produced no binary
fi
cat > "${out}" <<'EOD'
#!/usr/bin/env bash
rc=0
[ -f "${FUZZ_STUB_DIR}/rc" ] && rc="$(cat "${FUZZ_STUB_DIR}/rc")"
[ -f "${FUZZ_STUB_DIR}/stderr" ] && cat "${FUZZ_STUB_DIR}/stderr" >&2
case "${rc}" in
    129|1[3-9][0-9])
        # Die by the real signal so timeout reports 128+SIG like a crash.
        sig=$((rc - 128)); kill -"${sig}" $$ 2>/dev/null || exit "${rc}"
        ;;
esac
exit "${rc}"
EOD
chmod +x "${out}"
exit 0
EOF
chmod +x "${STUBS}/gcc"

# --- stub: python3 -----------------------------------------------------------
# run-fuzz.sh calls python3 only for mutate.py: <mutate> <seed> <out> --seed N.
cat > "${STUBS}/python3" <<'EOF'
#!/usr/bin/env bash
if [ "${FUZZ_STUB_MUTATE_RC:-0}" != "0" ]; then
    echo "stub mutate.py failing (rc=${FUZZ_STUB_MUTATE_RC})" >&2
    exit "${FUZZ_STUB_MUTATE_RC}"
fi
printf 'stub-mutant\n' > "$3"
exit 0
EOF
chmod +x "${STUBS}/python3"

# --- harness -----------------------------------------------------------------
PASS=0
FAIL=0
TESTED=0

run_gate() {
    # Runs the REAL wrapper against the stubs; prints its exit code.
    local got
    set +e
    env PATH="${STUBS}:${PATH}" \
        FUZZ_STUB_DIR="${CONTROL}" \
        FUZZ_STUB_NO_DRIVER="${STUB_NO_DRIVER:-0}" \
        FUZZ_STUB_MUTATE_RC="${STUB_MUTATE_RC:-0}" \
        bash "${RUN_FUZZ}" --seconds 5 --iterations 1 \
             --artifacts "${ARTIFACTS}" --prefix "${PREFIX}" \
        >"${WORK}/out.log" 2>&1
    got=$?
    set -e
    printf '%s' "${got}"
}

set_control() {
    # $1 = driver exit code, $2 = optional driver stderr, $3 = no-driver flag,
    # $4 = mutate failure rc. Resets per-scenario artifacts.
    printf '%s\n' "$1" > "${CONTROL}/rc"
    if [ $# -ge 2 ] && [ -n "$2" ]; then
        printf '%s\n' "$2" > "${CONTROL}/stderr"
    else
        rm -f "${CONTROL}/stderr"
    fi
    STUB_NO_DRIVER="${3:-0}"
    STUB_MUTATE_RC="${4:-0}"
    rm -rf "${ARTIFACTS}"; mkdir -p "${ARTIFACTS}"
}

expect_rc() {
    # $1 = scenario name, $2 = expected wrapper exit code.
    local name="$1" want="$2" got
    TESTED=$((TESTED + 1))
    got="$(run_gate)"
    if [ "${got}" = "${want}" ]; then
        PASS=$((PASS + 1)); printf '  ✓ %-52s exit %s\n' "${name}" "${got}"
    else
        FAIL=$((FAIL + 1)); printf '  ✗ %-52s expected exit %s, got %s\n' "${name}" "${want}" "${got}"
        sed 's/^/      | /' "${WORK}/out.log" | tail -25
    fi
}

expect_grep() {
    # $1 = check name, $2 = extended-regex expected in the last run's output.
    local name="$1" pat="$2"
    TESTED=$((TESTED + 1))
    if grep -qE "${pat}" "${WORK}/out.log"; then
        PASS=$((PASS + 1)); printf '  ✓ %-52s output matches /%s/\n' "${name}" "${pat}"
    else
        FAIL=$((FAIL + 1)); printf '  ✗ %-52s output missing /%s/\n' "${name}" "${pat}"
        sed 's/^/      | /' "${WORK}/out.log" | tail -25
    fi
}

echo "run-fuzz.sh verdict self-test (issue #370, F-TEST-001)"
echo ""

# --- clean pass --------------------------------------------------------------
set_control 0
expect_rc "exit 0 (clean run) -> gate PASS" 0
expect_grep "PASS banner" "fuzz gate PASS"
expect_grep "clean run is not a refusal" "0 parser refusal"

# --- expected parser rejection: rc 1, refusal text, no sanitizer banner ------
set_control 1 'pcap_open: truncated dump file; tried to read 4-byte header'
expect_rc "exit 1 parser rejection -> gate PASS (benign refusal)" 0
expect_grep "refusal separately identifiable" "[1-9] parser refusal"

# --- UBSan report at rc 1: the F-TEST-001 reproducer --------------------------
set_control 1 'src/mmt_core/x.c:12:7: runtime error: signed integer overflow
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/mmt_core/x.c:12:7'
expect_rc "UBSan report at exit 1 -> gate FAIL" 1
expect_grep "classified sanitizer-error" "sanitizer-error"

# --- ASan report at rc 1 ------------------------------------------------------
set_control 1 '==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010'
expect_rc "ASan report at exit 1 -> gate FAIL" 1
expect_grep "classified sanitizer-error" "sanitizer-error"

# --- sanitizer banner even at rc 0 (halt_on_error=0 style) --------------------
set_control 0 '==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x604000000020'
expect_rc "ASan report at exit 0 -> gate FAIL" 1
expect_grep "classified sanitizer-error" "sanitizer-error"

# --- timeout: driver burned the per-input budget ------------------------------
set_control 124
expect_rc "timeout (rc 124) -> gate FAIL" 1
expect_grep "classified hang/timeout" "hang/timeout"

# --- killed child: driver dies by SIGABRT (rc 134) ----------------------------
set_control 134
expect_rc "killed child (SIGABRT, rc 134) -> gate FAIL" 1
expect_grep "classified signal/crash" "signal/crash"

# --- missing executable: compile leaves no driver -----------------------------
set_control 0 "" 1
expect_rc "driver missing (exec rc 126/127) -> harness exit 2" 2

# --- infrastructure failure: mutate.py dies ------------------------------------
set_control 0 "" 0 2
expect_rc "mutate.py failure -> harness exit 2" 2

echo ""
echo "verdict self-test: ${PASS} passed, ${FAIL} failed (${TESTED} checks)"
[ "${FAIL}" -eq 0 ]
