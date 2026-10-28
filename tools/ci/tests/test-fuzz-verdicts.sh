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
# Regression replay (issue #486) — the committed reproducers in
# tools/ci/fuzz/regressions run before the mutation loop:
#   --replay-only, clean replay           -> 0
#   --replay-only, replay crashes (ASan)  -> 1 (finding + artifact log)
#   default run replays before fuzzing    -> "replayed N regression(s)"
#   digest drift / unlisted / missing file / empty manifest -> 2
#
# libFuzzer mode (issue #530) — --fuzzer points at a stub packet_fuzzer, so
# nothing is built; it logs its argv and replays ${FUZZ_STUB_DIR}/lf-* for
# the phase named in lf-phase (replay | fuzz | corpus):
#   clean replay + fuzz + merge           -> 0
#   fuzz rc 1 + crash-* artifact (a real ASan exit) -> 1, <artifact>.log/.pcap
#   fuzz rc 1 + sanitizer banner, no artifact -> 1
#   fuzz rc 77 (-error_exitcode)          -> 1
#   fuzz rc 78 + timeout-* artifact       -> 1
#   fuzz rc 1, no artifact, no banner     -> 2 (harness breakage)
#   fuzz rc 126                           -> 2
#   replay of a committed input crashes   -> 1 (names the input)
#   seeds drift from gen_seeds.py         -> 2
#   a seed no longer reaches its dissector -> 2
#   --replay-only: files only, no -max_len, no fuzzing; an explicit
#     --corpus is replayed with -runs=0
#   --corpus without --libfuzzer, --prefix with it, a missing --fuzzer
#     binary                              -> 2
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
# Dispatches on the script: gen_seeds.py --check exits FUZZ_STUB_SEEDS_RC and
# --list names one family; to_pcap.py copies; anything else is mutate.py:
# <mutate> <seed> <out> --seed N.
cat > "${STUBS}/python3" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    */gen_seeds.py)
        case " $* " in
            *" --list "*) echo "smb smb"; exit 0 ;;
            *) exit "${FUZZ_STUB_SEEDS_RC:-0}" ;;
        esac ;;
    */to_pcap.py) cp "$2" "$3"; exit 0 ;;
esac
if [ "${FUZZ_STUB_MUTATE_RC:-0}" != "0" ]; then
    echo "stub mutate.py failing (rc=${FUZZ_STUB_MUTATE_RC})" >&2
    exit "${FUZZ_STUB_MUTATE_RC}"
fi
printf 'stub-mutant\n' > "$3"
exit 0
EOF
chmod +x "${STUBS}/python3"

# --- stub: packet_fuzzer (libFuzzer mode) -----------------------------------
# Logs its argv to lf-argv. MMT_FUZZ_PRINT_PATHS prints lf-paths (the seed
# classification check); -merge=1 succeeds. Otherwise the phase — fuzz when
# -max_total_time is given, corpus for -runs=0, else replay — is compared
# with lf-phase, and on a match the stub prints lf-stderr, creates
# <artifact_prefix><lf-artifact> and exits lf-rc.
cat > "${STUBS}/packet_fuzzer" <<'EOF'
#!/usr/bin/env bash
c="${FUZZ_STUB_DIR}"
printf '%s\n' "$*" >> "${c}/lf-argv"
if [ -n "${MMT_FUZZ_PRINT_PATHS:-}" ]; then cat "${c}/lf-paths"; exit 0; fi
phase=replay prefix=""
for a in "$@"; do
    case "${a}" in
        -merge=1) exit 0 ;;
        -max_total_time=*) phase=fuzz ;;
        -runs=0) phase=corpus ;;
        -artifact_prefix=*) prefix="${a#*=}" ;;
    esac
done
[ "${phase}" = "$(cat "${c}/lf-phase")" ] || exit 0
echo "Running: /stub/input-${phase}" >&2
[ -f "${c}/lf-stderr" ] && cat "${c}/lf-stderr" >&2
[ -f "${c}/lf-artifact" ] && printf 'x' > "${prefix}$(cat "${c}/lf-artifact")"
exit "$(cat "${c}/lf-rc")"
EOF
chmod +x "${STUBS}/packet_fuzzer"

# --- harness -----------------------------------------------------------------
PASS=0
FAIL=0
TESTED=0
EXTRA_ARGS=()

run_gate() {
    # Runs the REAL wrapper against the stubs; prints its exit code.
    local got
    set +e
    env PATH="${STUBS}:${PATH}" \
        FUZZ_STUB_DIR="${CONTROL}" \
        FUZZ_STUB_NO_DRIVER="${STUB_NO_DRIVER:-0}" \
        FUZZ_STUB_MUTATE_RC="${STUB_MUTATE_RC:-0}" \
        bash "${RUN_FUZZ}" --seconds 5 --iterations 1 \
             --artifacts "${ARTIFACTS}" --prefix "${PREFIX}" "${EXTRA_ARGS[@]}" \
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

# --- regression replay (issue #486) ------------------------------------------
REAL_REGRESSIONS="${REPO_ROOT}/tools/ci/fuzz/regressions"
nreg="$(grep -cE '^[0-9a-f]{64}  ' "${REAL_REGRESSIONS}/manifest.txt")"

set_control 0
EXTRA_ARGS=( --replay-only )
expect_rc "--replay-only, committed reproducers clean -> 0" 0
expect_grep "replay PASS banner" "regression replay PASS — ${nreg} committed"

set_control 1 '==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x5040000abed0
    #0 0x1 in ftp_session_data_analysis proto_ftp.c:3222'
expect_rc "--replay-only, reproducer crashes again -> 1" 1
expect_grep "replay FAIL banner" "regression replay FAIL"
TESTED=$((TESTED + 1))
if ls "${ARTIFACTS}"/regression-*.log >/dev/null 2>&1 \
        && grep -q 'heap-use-after-free' "${ARTIFACTS}"/regression-*.log; then
    PASS=$((PASS + 1)); printf '  ✓ %-52s\n' "replay finding carries reproducer + stderr log"
else
    FAIL=$((FAIL + 1)); printf '  ✗ %-52s\n' "replay finding carries reproducer + stderr log"
fi

set_control 0
EXTRA_ARGS=()
expect_rc "default run replays regressions, then fuzzes -> 0" 0
expect_grep "replay ran before the loop" "replayed ${nreg} regression"

# Corpus integrity: each broken manifest is harness breakage (exit 2).
REG="${WORK}/regressions"
reset_reg() { rm -rf "${REG}"; cp -r "${REAL_REGRESSIONS}" "${REG}"; }
EXTRA_ARGS=( --replay-only --regressions "${REG}" )

reset_reg; reg_pcaps=( "${REG}"/*.pcap ); printf 'x' >> "${reg_pcaps[0]}"
expect_rc "reproducer drifted from its sha256 -> exit 2" 2
expect_grep "digest mismatch reported" "sha256 .* != manifest"

reset_reg; printf 'stray\n' > "${REG}/stray.pcap"
expect_rc "file not listed in the manifest -> exit 2" 2

reset_reg; rm -f "${REG}"/*.pcap
expect_rc "listed reproducer missing -> exit 2" 2

# A relative --regressions path is resolved before the drivers run from
# inside the prefix, so the replay reads the files it just verified.
reset_reg; EXTRA_ARGS=( --replay-only --regressions "${REG##*/}" )
cd "${REG%/*}"
expect_rc "relative --regressions path -> replayed, 0" 0
expect_grep "relative path resolved to absolute" "committed reproducer\(s\) in ${REG}\$"
cd - >/dev/null
EXTRA_ARGS=( --replay-only --regressions "${REG}" )

reset_reg; rm -f "${REG}"/*.pcap; grep -v '^[0-9a-f]' "${REAL_REGRESSIONS}/manifest.txt" > "${REG}/manifest.txt"
expect_rc "--replay-only with an empty manifest -> exit 2" 2
EXTRA_ARGS=()

# --- libFuzzer mode (issue #530) ----------------------------------------------
LF_CORPUS="${WORK}/corpus"
LF_ARGS=()
STUB_SEEDS_RC=0

run_lf() {
    # Runs the REAL wrapper in libFuzzer mode against the stub target.
    local got
    set +e
    env PATH="${STUBS}:${PATH}" FUZZ_STUB_DIR="${CONTROL}" \
        FUZZ_STUB_SEEDS_RC="${STUB_SEEDS_RC}" \
        bash "${RUN_FUZZ}" --libfuzzer --seconds 5 --artifacts "${ARTIFACTS}" \
             "${LF_ARGS[@]}" >"${WORK}/out.log" 2>&1
    got=$?
    set -e
    printf '%s' "${got}"
}

lf_control() {
    # $1 = phase, $2 = rc, $3 = artifact name ("" = none), $4 = stderr.
    printf '%s\n' "$1" > "${CONTROL}/lf-phase"
    printf '%s\n' "$2" > "${CONTROL}/lf-rc"
    if [ -n "${3:-}" ]; then printf '%s' "$3" > "${CONTROL}/lf-artifact"; else rm -f "${CONTROL}/lf-artifact"; fi
    if [ -n "${4:-}" ]; then printf '%s\n' "$4" > "${CONTROL}/lf-stderr"; else rm -f "${CONTROL}/lf-stderr"; fi
    printf 'meta.ethernet.ip.tcp.smb\n' > "${CONTROL}/lf-paths"
    : > "${CONTROL}/lf-argv"
    STUB_SEEDS_RC=0
    rm -rf "${ARTIFACTS}" "${LF_CORPUS}"; mkdir -p "${ARTIFACTS}"
    LF_ARGS=( --fuzzer "${STUBS}/packet_fuzzer" --corpus "${LF_CORPUS}" )
}

expect_lf() {
    # $1 = scenario name, $2 = expected wrapper exit code.
    local name="$1" want="$2" got
    TESTED=$((TESTED + 1))
    got="$(run_lf)"
    if [ "${got}" = "${want}" ]; then
        PASS=$((PASS + 1)); printf '  ✓ %-52s exit %s\n' "${name}" "${got}"
    else
        FAIL=$((FAIL + 1)); printf '  ✗ %-52s expected exit %s, got %s\n' "${name}" "${want}" "${got}"
        sed 's/^/      | /' "${WORK}/out.log" | tail -25
    fi
}

expect_file() {
    # $1 = check name, $2 = path that must exist.
    TESTED=$((TESTED + 1))
    if [ -e "$2" ]; then
        PASS=$((PASS + 1)); printf '  ✓ %-52s\n' "$1"
    else
        FAIL=$((FAIL + 1)); printf '  ✗ %-52s missing %s\n' "$1" "$2"
    fi
}

expect_argv() {
    # $1 = check name, $2 = ERE that must match a libFuzzer invocation of the
    # last run — or, with $3 = "!", must match none of them.
    local hit=0
    TESTED=$((TESTED + 1))
    grep -qE -- "$2" "${CONTROL}/lf-argv" && hit=1
    if { [ "${3:-}" != "!" ] && [ "${hit}" -eq 1 ]; } || { [ "${3:-}" = "!" ] && [ "${hit}" -eq 0 ]; }; then
        PASS=$((PASS + 1)); printf '  ✓ %-52s\n' "$1"
    else
        FAIL=$((FAIL + 1)); printf '  ✗ %-52s argv %s/%s/\n' "$1" "${3:-}" "$2"
        sed 's/^/      | /' "${CONTROL}/lf-argv"
    fi
}

echo ""
echo "libFuzzer mode (issue #530)"
lf_control fuzz 0
expect_lf "--libfuzzer clean replay + fuzz -> 0" 0
expect_grep "libFuzzer PASS banner" "libFuzzer PASS"
expect_argv "fuzz run bounds input size, writes the corpus" "-max_len=65536 .*-max_total_time=5 .*${LF_CORPUS} "
expect_argv "replay reads seeds whole (no -max_len)" "^-error_exitcode=77 -timeout_exitcode=78 -timeout=20 -rss_limit_mb=2560 -artifact_prefix=[^ ]+ [^-][^ ]*/seeds/"
expect_argv "corpus minimised after fuzzing" "^-merge=1 "

lf_control fuzz 1 crash-0123abcd '==7==ERROR: AddressSanitizer: heap-buffer-overflow'
expect_lf "fuzz rc 1 + crash artifact (real ASan exit) -> 1" 1
expect_file "finding log written" "${ARTIFACTS}/libfuzzer-crash-0123abcd.log"
expect_file "finding wrapped as a pcap" "${ARTIFACTS}/libfuzzer-crash-0123abcd.pcap"
expect_grep "FAIL banner" "libFuzzer FAIL"

lf_control fuzz 1 "" 'src/x.c:3:1: runtime error: index 255 out of bounds'
expect_lf "fuzz rc 1 + UBSan banner, no artifact -> 1" 1

lf_control fuzz 77
expect_lf "fuzz rc 77 (-error_exitcode) -> 1" 1

lf_control fuzz 78 timeout-4567
expect_lf "fuzz rc 78 + timeout artifact -> 1" 1
expect_file "timeout log written" "${ARTIFACTS}/libfuzzer-timeout-4567.log"

lf_control fuzz 1
expect_lf "fuzz rc 1, no artifact, no banner -> harness exit 2" 2

lf_control fuzz 126
expect_lf "fuzz rc 126 -> harness exit 2" 2

lf_control replay 1 "" '==9==ERROR: AddressSanitizer: heap-buffer-overflow'
expect_lf "replay of a committed input crashes -> 1" 1
expect_grep "replay finding names the input" "rc=1\) -> /stub/input-replay"
expect_argv "no fuzzing after a replay failure" "-max_total_time" "!"

lf_control fuzz 0; STUB_SEEDS_RC=1
expect_lf "seeds drifted from gen_seeds.py -> exit 2" 2

lf_control fuzz 0; printf 'meta.ethernet.ip.tcp.unknown\n' > "${CONTROL}/lf-paths"
expect_lf "seed no longer reaches its dissector -> exit 2" 2
expect_grep "classification failure named" "no longer classified as smb"

lf_control fuzz 0; LF_ARGS=( --fuzzer "${STUBS}/packet_fuzzer" --replay-only )
expect_lf "--libfuzzer --replay-only -> 0" 0
expect_argv "--replay-only does not fuzz" "-max_total_time|-max_len" "!"
expect_grep "replay PASS banner" "libFuzzer replay PASS"

lf_control corpus 1 crash-89ab '==9==ERROR: AddressSanitizer: SEGV'
mkdir -p "${LF_CORPUS}"; printf 'x' > "${LF_CORPUS}/input"
LF_ARGS=( --fuzzer "${STUBS}/packet_fuzzer" --corpus "${LF_CORPUS}" --replay-only )
expect_lf "--replay-only --corpus replays it, finding -> 1" 1
expect_argv "corpus replayed with -runs=0" "-runs=0 ${LF_CORPUS}\$"

lf_control fuzz 0; LF_ARGS=( --fuzzer "${WORK}/no-such-fuzzer" )
expect_lf "--fuzzer binary missing -> exit 2" 2

lf_control fuzz 0; LF_ARGS=( --prefix "${PREFIX}" )
expect_lf "--libfuzzer with --prefix -> exit 2" 2

set_control 0
EXTRA_ARGS=( --corpus "${LF_CORPUS}" )
expect_rc "--corpus without --libfuzzer -> exit 2" 2
EXTRA_ARGS=()

echo ""
echo "verdict self-test: ${PASS} passed, ${FAIL} failed (${TESTED} checks)"
[ "${FAIL}" -eq 0 ]
