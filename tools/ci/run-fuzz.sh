#!/usr/bin/env bash
#
# run-fuzz.sh — bounded mutation-fuzz gate for the CI fuzz job (issue #224,
# F-SEC-009).
#
# What it does:
#   1. Builds + installs the SDK with BUILD=asan and ENABLESEC=1 into an
#      isolated prefix — ASan/UBSan is the crash oracle; ENABLESEC also
#      produces libmmt_fuzz, the shipped fuzz engine that was previously
#      only compiled, never run.
#   2. Compiles two drivers against the prefix:
#      - tools/phase0/phase0_classify.c  (packet-classification surface:
#        pcap -> packet_process, the library's hostile-input entry point)
#      - tools/ci/fuzz/qe_xml_driver.c   (fuzz-engine surface: file ->
#        application_quality_estimation_xml_parser, so the fuzz run
#        exercises libmmt_fuzz rather than only linking it)
#   3. Until the wall-clock budget runs out, generates one deterministic
#      mutant per iteration — tools/ci/fuzz/mutate.py — seeded from the
#      vendored golden captures (tools/phase0/ci/pcaps/*.pcap) and the QE
#      model seed (tools/ci/fuzz/seed_qe.xml), and runs the matching driver
#      on it under a per-input timeout.
#
# Finding rule: an exit code >= 128 (signal — ASan/UBSan aborts with
# abort_on_error=1 and -fno-sanitize-recover=all, plus genuine SIGSEGV /
# SIGABRT) or 124 (per-input timeout — a hang on hostile input is a
# robustness finding) is a crash. So is a sanitizer report on the driver's
# stderr at any lower exit code: a sanitizer runtime that did not abort the
# process (UBSan without abort_on_error, ASan with halt_on_error=0 or a
# non-fatal report) prints its "runtime error" / "*Sanitizer" banner and
# still exits 0/1/2, which the exit code alone would silently pass (issue
# #370, F-TEST-001). Ordinary refusals (rc 1/2 — libpcap or libxml2 cleanly
# rejecting the mutant) carry no sanitizer banner, are not findings and are
# counted separately so a refusal never reads as a crash. The QE target runs
# with LeakSanitizer on (detect_leaks=1, issue #470) — its driver frees every
# parsed model, so a LeakSanitizer report is a finding too; the pcap target
# keeps detect_leaks=0. An exit code of
# 125/126/127 means the driver (or timeout itself) could not be executed —
# harness breakage, never a finding. On a finding the
# reproducer file and the driver's stderr are copied into the artifacts
# directory and the run continues so one CI failure can carry several
# distinct reproducers (capped); the script exits 1 at the end when any
# finding was recorded. Exit 2 is reserved for the harness itself breaking
# (build/compile failure, missing corpus, unexecutable driver) so a broken
# gate can never read as a clean fuzz run.
#
# Suppressions: tools/ci/fuzz/suppressions.txt lists already-reported
# deterministic mutants as "<seed-file-basename>:<seed>" pairs, one per
# line, each carrying a trailing comment naming the tracking issue. A
# suppressed mutant is skipped at generation time — the gate stays strict
# for every input NOT on the list, and the list only ever grows a line when
# a finding has a filed issue to point at. The mechanism exists because the
# deterministic PR seed makes the same latent bugs fire on every pull
# request; suppressions keep a pre-existing bug tracked-and-visible without
# making CI permanently red.
#
# Regression replay (issue #486): before the mutation loop, every input
# listed in tools/ci/fuzz/regressions/manifest.txt — committed reproducers
# of past findings — is replayed through its driver (*.pcap through
# phase0_classify, *.xml through the QE driver) under the same finding rule.
# A regression that crashes again is a finding like any other, so a fixed
# bug cannot come back silently and a scheduled-run crash, once committed
# there, is gated on every pull request whatever seed the run uses. Each
# entry carries its sha256: a file that drifts from its digest, a file in
# the directory the manifest does not list, or a listed file that is
# missing is harness breakage (exit 2), never a silent skip.
#
# libFuzzer mode (issue #530, F-TEST-013) — --libfuzzer swaps the mutation
# loop for the coverage-guided target tools/ci/fuzz/packet_fuzzer.c:
#   1. Checks the committed seeds (tools/ci/fuzz/seeds, one capture per
#      F-TEST-013 family) against tools/ci/fuzz/gen_seeds.py byte for byte.
#   2. Builds only libmmt_core.a and libmmt_tcpip.a with clang
#      (ARCH=linux-clang BUILD=asan plus -fsanitize=fuzzer-no-link and
#      tools/ci/fuzz/ubsan-ignorelist.txt) and links the target statically.
#      The rest of the SDK does not build with clang, and the TCP/IP archive
#      holds every F-TEST-013 dissector. The sdk/ tree is cleaned on exit.
#   3. Replays every seed and every *.pcap regression as an individual file
#      (read whole — no -max_len), then checks that each seed is still
#      classified as its family (gen_seeds.py --list). A seed that no longer
#      reaches its dissector is harness breakage (exit 2).
#   4. Without --replay-only: fuzzes for --seconds from the --corpus
#      directory (new inputs are written there), the seeds and copies of the
#      golden captures, then minimises the corpus in place (-merge=1).
#      With --replay-only and an explicit --corpus: replays that corpus.
#   Finding rule: a new libfuzzer-{crash,leak,timeout,oom,slow-unit}-*
#   artifact, exit code 77/78 (-error_exitcode/-timeout_exitcode) or a
#   sanitizer banner in the log. Each finding gets <artifact>.log (output
#   and repro commands) and <artifact>.pcap (tools/ci/fuzz/to_pcap.py — the
#   form to commit to tools/ci/fuzz/regressions). Exit 0 otherwise only when
#   libFuzzer exited 0; any other exit code is harness breakage (2).
#
# Usage:
#   bash tools/ci/run-fuzz.sh [--seconds N] [--seed N] [--artifacts DIR]
#                             [--iterations N] [--prefix DIR]
#                             [--replay-only] [--regressions DIR]
#   bash tools/ci/run-fuzz.sh --libfuzzer [--seconds N] [--seed N]
#                             [--iterations N] [--artifacts DIR]
#                             [--corpus DIR] [--fuzzer BIN]
#                             [--keep-fuzzer FILE]
#                             [--replay-only] [--regressions DIR]
#
#   --seconds N      fuzzing wall-clock budget AFTER the build (default 300)
#   --seed N         base seed for mutate.py (default 224 — deterministic)
#   --iterations N   stop after N loop iterations even if budget remains
#                    (default 0 = wall-clock only). The PR job passes a cap so
#                    the explored mutant set is identical on every runner —
#                    without it a faster machine would reach uncharacterized
#                    mutants and could flake on an unreported hang.
#   --artifacts D    reproducer output dir (default ./fuzz-artifacts)
#   --prefix D       reuse an existing BUILD=asan+ENABLESEC install prefix
#                    instead of building (local iteration helper)
#   --replay-only    replay the committed regressions, then stop (no
#                    mutation loop); exit 1 when any of them is a finding
#   --regressions D  regression directory (default tools/ci/fuzz/regressions)
#   --libfuzzer      run the libFuzzer mode described above
#   --corpus D       libFuzzer working corpus (default ./fuzz-corpus; the CI
#                    job keeps it in the Actions cache between runs)
#   --fuzzer BIN     reuse a packet_fuzzer built earlier instead of building
#   --keep-fuzzer F  copy the packet_fuzzer this run builds to F
#   With --libfuzzer, --iterations N caps the fuzzing at N inputs (-runs=N).
#
# Used by .github/workflows/c-cpp.yml (fuzz job). Runnable locally too.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CORPUS_DIR="${REPO_ROOT}/tools/phase0/ci/pcaps"
QE_SEED="${SCRIPT_DIR}/fuzz/seed_qe.xml"
MUTATE="${SCRIPT_DIR}/fuzz/mutate.py"
SUPPRESSIONS="${SCRIPT_DIR}/fuzz/suppressions.txt"
REGRESSIONS="${SCRIPT_DIR}/fuzz/regressions"
REPLAY_ONLY=0
LIBFUZZER=0
LF_CORPUS=""
LF_FUZZER=""
LF_KEEP=""
LF_SRC="${SCRIPT_DIR}/fuzz/packet_fuzzer.c"
LF_IGNORELIST="${SCRIPT_DIR}/fuzz/ubsan-ignorelist.txt"
LF_SEEDS="${SCRIPT_DIR}/fuzz/seeds"
LF_GEN_SEEDS="${SCRIPT_DIR}/fuzz/gen_seeds.py"
LF_TO_PCAP="${SCRIPT_DIR}/fuzz/to_pcap.py"
QE_DRIVER_SRC="${SCRIPT_DIR}/fuzz/qe_xml_driver.c"
CLASSIFY_SRC="${REPO_ROOT}/tools/phase0/phase0_classify.c"

BUDGET=300
SEED=224
MAX_ITER=0
ARTIFACTS="${REPO_ROOT}/fuzz-artifacts"
PREFIX=""
PER_INPUT_TIMEOUT=20
MAX_FINDINGS=10

while [ $# -gt 0 ]; do
    case "$1" in
        --seconds)    BUDGET="$2"; shift 2 ;;
        --seed)       SEED="$2"; shift 2 ;;
        --iterations) MAX_ITER="$2"; shift 2 ;;
        --artifacts)  ARTIFACTS="$2"; shift 2 ;;
        --prefix)     PREFIX="$2"; shift 2 ;;
        --replay-only) REPLAY_ONLY=1; shift ;;
        --regressions) REGRESSIONS="$2"; shift 2 ;;
        --libfuzzer)  LIBFUZZER=1; shift ;;
        --corpus)     LF_CORPUS="$2"; shift 2 ;;
        --fuzzer)     LF_FUZZER="$2"; shift 2 ;;
        --keep-fuzzer) LF_KEEP="$2"; shift 2 ;;
        -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

# A non-numeric bound would silently truncate the loop and read as a pass.
for pair in "BUDGET:--seconds" "SEED:--seed" "MAX_ITER:--iterations"; do
    v="${pair%%:*}"
    case "${!v}" in
        ''|*[!0-9]*) echo "✗ ${pair##*:} must be a non-negative integer, got '${!v}'" >&2; exit 2 ;;
    esac
done

if [ "${LIBFUZZER}" -eq 1 ]; then
    [ -z "${PREFIX}" ] || { echo "✗ --prefix applies to the mutation mode; use --fuzzer with --libfuzzer" >&2; exit 2; }
    COMPONENTS=( "${LF_SRC}" "${LF_IGNORELIST}" "${LF_GEN_SEEDS}" "${LF_TO_PCAP}" )
    COMMANDS=( python3 sha256sum )
    [ -n "${LF_FUZZER}" ] || COMMANDS+=( clang clang++ make )
else
    for pair in "LF_CORPUS:--corpus" "LF_FUZZER:--fuzzer" "LF_KEEP:--keep-fuzzer"; do
        v="${pair%%:*}"
        [ -z "${!v}" ] || { echo "✗ ${pair##*:} needs --libfuzzer" >&2; exit 2; }
    done
    COMPONENTS=( "${MUTATE}" "${QE_DRIVER_SRC}" "${CLASSIFY_SRC}" "${QE_SEED}" )
    COMMANDS=( python3 timeout gcc make sha256sum )
fi
for f in "${COMPONENTS[@]}"; do
    [ -f "$f" ] || { echo "✗ missing fuzz component: $f" >&2; exit 2; }
done
for cmd in "${COMMANDS[@]}"; do
    command -v "${cmd}" >/dev/null 2>&1 || { echo "✗ ${cmd} not found" >&2; exit 2; }
done

shopt -s nullglob
PCAPS=( "${CORPUS_DIR}"/*.pcap )
if [ "${#PCAPS[@]}" -eq 0 ]; then
    echo "✗ golden corpus empty: ${CORPUS_DIR}" >&2
    exit 2
fi

# Absolute, like --artifacts: the drivers run from inside the prefix, so a
# relative path would pass the manifest checks here, then fail to open in
# the driver and read as a parser refusal — a silent false PASS.
[ -d "${REGRESSIONS}" ] || { echo "✗ regression directory missing: ${REGRESSIONS}" >&2; exit 2; }
REGRESSIONS="$(cd "${REGRESSIONS}" && pwd)"

# The regression manifest is checked before the (minutes-long) SDK build so
# a broken corpus fails fast. Format: "<sha256>  <file>" per line, '#'
# comments allowed; every file in the directory must be listed.
MANIFEST="${REGRESSIONS}/manifest.txt"
[ -f "${MANIFEST}" ] || { echo "✗ regression manifest missing: ${MANIFEST}" >&2; exit 2; }
REG_FILES=()
declare -A REG_LISTED=()
while IFS= read -r line; do
    line="${line%%#*}"
    read -r want name rest <<<"${line}" || true
    [ -z "${want:-}" ] && continue
    if [ -z "${name:-}" ] || [ -n "${rest:-}" ] || ! [[ "${want}" =~ ^[0-9a-f]{64}$ ]]; then
        echo "✗ malformed regression manifest line: ${line}" >&2; exit 2
    fi
    f="${REGRESSIONS}/${name}"
    [ -f "${f}" ] || { echo "✗ regression listed but missing: ${f}" >&2; exit 2; }
    got="$(sha256sum "${f}")"; got="${got%% *}"
    if [ "${got}" != "${want}" ]; then
        echo "✗ regression ${name}: sha256 ${got} != manifest ${want}" >&2; exit 2
    fi
    case "${name}" in
        *.pcap|*.xml) ;;
        *) echo "✗ regression ${name}: no driver for this extension (.pcap/.xml)" >&2; exit 2 ;;
    esac
    REG_FILES+=( "${f}" )
    REG_LISTED["${name}"]=1
done < "${MANIFEST}"
for f in "${REGRESSIONS}"/*; do
    b="${f##*/}"
    [ "${b}" = "manifest.txt" ] && continue
    [ -n "${REG_LISTED["${b}"]:-}" ] || { echo "✗ regression ${b} is not in ${MANIFEST}" >&2; exit 2; }
done
if [ "${REPLAY_ONLY}" -eq 1 ] && [ "${#REG_FILES[@]}" -eq 0 ]; then
    echo "✗ --replay-only with an empty regression manifest: ${MANIFEST}" >&2
    exit 2
fi

# A sanitizer report on stderr is a finding even when the process exits
# cleanly (see the finding rule in the header). Match the runtime banners,
# never a bare "error" substring, so an expected parser refusal cannot
# collide with them.
SANITIZER_MARKERS='runtime error:|ERROR: (Address|UndefinedBehavior|Leak|Memory|Thread)Sanitizer|SUMMARY: (Address|UndefinedBehavior|Leak|Memory|Thread)Sanitizer'

# --- libFuzzer mode (issue #530) — see the header --------------------------
if [ "${LIBFUZZER}" -eq 1 ]; then
    say() { printf '  %s\n' "$*"; }
    LF_REGS=()
    for f in "${REG_FILES[@]}"; do
        case "${f}" in *.pcap) LF_REGS+=( "${f}" ) ;; esac
    done
    WORK="$(mktemp -d)"
    LF_BUILT=0
    # The clang objects stay in the source tree after the build; clean them
    # so a later gcc build never links them (docs/AGENT_ENVIRONMENT.md §5).
    trap 'rm -rf "${WORK}"; [ "${LF_BUILT}" -eq 0 ] || make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true' EXIT
    RUN_DIR="${WORK}/run"     # cwd of every run: holds no plugins/ directory
    mkdir -p "${RUN_DIR}" "${ARTIFACTS}"
    ARTIFACTS="$(cd "${ARTIFACTS}" && pwd)"
    if [ -n "${LF_CORPUS}" ] || [ "${REPLAY_ONLY}" -eq 0 ]; then
        LF_CORPUS="${LF_CORPUS:-${REPO_ROOT}/fuzz-corpus}"
        mkdir -p "${LF_CORPUS}"
        LF_CORPUS="$(cd "${LF_CORPUS}" && pwd)"
    fi
    LF_PREFIX="${ARTIFACTS}/libfuzzer-"
    LF_OPTS=( -error_exitcode=77 -timeout_exitcode=78 "-timeout=${PER_INPUT_TIMEOUT}"
              -rss_limit_mb=2560 "-artifact_prefix=${LF_PREFIX}" )
    lf_findings=0

    say "libFuzzer mode : tools/ci/fuzz/packet_fuzzer.c"
    say "seeds          : ${LF_SEEDS}"
    say "regressions    : ${#LF_REGS[@]} committed pcap reproducer(s) in ${REGRESSIONS}"
    say "corpus         : ${LF_CORPUS:-(not replayed)}"
    say "artifacts      : ${ARTIFACTS}"

    # --- 1. seeds match their generator -----------------------------------
    say "[1/4] checking the seeds against ${LF_GEN_SEEDS##*/} ..."
    if ! python3 "${LF_GEN_SEEDS}" --check --out-dir "${LF_SEEDS}"; then
        echo "✗ committed seeds differ from ${LF_GEN_SEEDS}" >&2; exit 2
    fi
    LF_SEED_FILES=( "${LF_SEEDS}"/*.pcap )
    [ "${#LF_SEED_FILES[@]}" -gt 0 ] || { echo "✗ no seeds in ${LF_SEEDS}" >&2; exit 2; }

    # --- 2. build the target ----------------------------------------------
    if [ -n "${LF_FUZZER}" ]; then
        [ -x "${LF_FUZZER}" ] || { echo "✗ --fuzzer ${LF_FUZZER} is not an executable" >&2; exit 2; }
        FUZZER="$(cd "$(dirname "${LF_FUZZER}")" && pwd)/$(basename "${LF_FUZZER}")"
        say "[2/4] reusing ${FUZZER}"
    else
        say "[2/4] building libmmt_core.a + libmmt_tcpip.a with clang, linking the target ..."
        LF_BUILT=1
        BUILD_LOG="${WORK}/build.log"
        SDK_LIB="$(cd "${REPO_ROOT}" && pwd -P)/sdk/lib"
        LF_SAN=( -fsanitize=fuzzer-no-link "-fsanitize-ignorelist=${LF_IGNORELIST}" )
        make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
        if ! make -C "${REPO_ROOT}/sdk" ARCH=linux-clang BUILD=asan \
                CC="clang ${LF_SAN[*]}" CXX="clang++ ${LF_SAN[*]}" \
                MMT_BASE="${WORK}/prefix" -j"$(nproc 2>/dev/null || echo 2)" \
                "${SDK_LIB}/libmmt_core.a" "${SDK_LIB}/libmmt_tcpip.a" includes \
                >"${BUILD_LOG}" 2>&1; then
            echo "✗ clang SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 2
        fi
        FUZZER="${WORK}/packet_fuzzer"
        if ! clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
                "-fsanitize-ignorelist=${LF_IGNORELIST}" \
                -I "${REPO_ROOT}/sdk/include" -o "${FUZZER}" "${LF_SRC}" \
                -Wl,--whole-archive "${SDK_LIB}/libmmt_tcpip.a" "${SDK_LIB}/libmmt_core.a" \
                -Wl,--no-whole-archive -lstdc++ -ldl -lpthread -lm \
                >>"${BUILD_LOG}" 2>&1; then
            echo "✗ fuzz target link failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 2
        fi
        [ -x "${FUZZER}" ] || { echo "✗ fuzz target not produced: ${FUZZER}" >&2; exit 2; }
        if [ -n "${LF_KEEP}" ]; then
            cp "${FUZZER}" "${LF_KEEP}" || { echo "✗ cannot copy the target to ${LF_KEEP}" >&2; exit 2; }
        fi
    fi

    lf_run() {
        # $1 = log file, then the fuzzer arguments. Runs from RUN_DIR.
        local log="$1"; shift
        set +e
        ( cd "${RUN_DIR}" && \
          ASAN_OPTIONS="detect_leaks=0:detect_odr_violation=0" \
          UBSAN_OPTIONS="print_stacktrace=1" \
          "${FUZZER}" "$@" ) >"${log}" 2>&1
        rc=$?
        set -e
        return 0
    }

    lf_artifacts() {
        # Lists the libFuzzer artifacts (not the .log/.pcap written for them).
        local f
        for f in "${LF_PREFIX}"*; do
            case "${f}" in *.log|*.pcap) ;; *) printf '%s\n' "${f}" ;; esac
        done
    }

    # lf_verdict <phase> <rc> <log> <artifacts listed before the run>
    # Returns 0 on a finding (after recording it), 1 on a clean run; exits 2
    # on harness breakage.
    lf_verdict() {
        local phase="$1" rc="$2" log="$3" before="$4" new a kind input
        new="$(comm -13 <(printf '%s' "${before}" | sort) <(lf_artifacts | sort))"
        if [ -z "${new}" ] && [ "${rc}" -ne 77 ] && [ "${rc}" -ne 78 ] \
                && ! grep -qE "${SANITIZER_MARKERS}" "${log}"; then
            [ "${rc}" -eq 0 ] && return 1
            echo "✗ libFuzzer ${phase} exited ${rc} without a finding — harness breakage; last lines:" >&2
            tail -20 "${log}" >&2
            exit 2
        fi
        if [ -z "${new}" ]; then
            # Files named on the command line (the replay) leave no artifact:
            # the input is the one libFuzzer was running when it died.
            input="$(sed -n 's/^Running: //p' "${log}" | tail -1)"
            new="${LF_PREFIX}${phase}"
        else
            input=""
        fi
        while IFS= read -r a; do
            kind="${a#"${LF_PREFIX}"}"; kind="${kind%%-*}"
            [ -z "${input}" ] || kind="sanitizer report"
            lf_findings=$((lf_findings + 1))
            [ ! -f "${a}" ] || python3 "${LF_TO_PCAP}" "${a}" "${a}.pcap" || true
            {
                echo "driver   : ${FUZZER} (tools/ci/fuzz/packet_fuzzer.c)"
                echo "phase    : libFuzzer ${phase}"
                echo "finding  : ${kind} (exit code ${rc})"
                if [ -n "${input}" ]; then
                    echo "input    : ${input}"
                    echo "reproduce: <packet_fuzzer> ${input}"
                else
                    echo "reproduce: <packet_fuzzer> ${a##*/}"
                    echo "regression: commit ${a##*/}.pcap to tools/ci/fuzz/regressions with its sha256 in manifest.txt"
                fi
                echo "           (build <packet_fuzzer>: bash tools/ci/run-fuzz.sh --libfuzzer --replay-only --keep-fuzzer ./packet_fuzzer)"
                echo "--- libFuzzer output (last 80 lines) ---"
                tail -80 "${log}"
            } > "${a}.log"
            say "  ✗ finding #${lf_findings}: ${phase} (${kind}, rc=${rc}) -> ${input:-${a}}"
        done <<<"${new}"
        return 0
    }

    lf_summary() {
        {
            echo "libFuzzer (tools/ci/fuzz/packet_fuzzer.c): $1"
            echo "seeds: ${#LF_SEED_FILES[@]}  regressions replayed: ${#LF_REGS[@]}  findings: ${lf_findings}"
        } >> "${ARTIFACTS}/SUMMARY.txt"
    }

    # --- 3. replay seeds + regressions, check seed classification ---------
    say "[3/4] replaying ${#LF_SEED_FILES[@]} seed(s) + ${#LF_REGS[@]} regression(s) ..."
    before="$(lf_artifacts)"
    lf_run "${WORK}/replay.log" "${LF_OPTS[@]}" "${LF_SEED_FILES[@]}" ${LF_REGS[@]+"${LF_REGS[@]}"}
    if lf_verdict replay "${rc}" "${WORK}/replay.log" "${before}"; then
        lf_summary "committed-input replay FAIL"
        echo "✗ libFuzzer replay FAIL — a committed seed or regression crashes; logs in ${ARTIFACTS}" >&2
        exit 1
    fi
    while read -r family proto; do
        [ -n "${family}" ] || continue
        set +e
        paths="$(cd "${RUN_DIR}" && MMT_FUZZ_PRINT_PATHS=1 ASAN_OPTIONS=detect_leaks=0 \
                 "${FUZZER}" "${LF_SEEDS}/${family}.pcap" 2>/dev/null)"
        set -e
        if ! grep -qE "(^|\.)${proto}(\.|\$)" <<<"${paths}"; then
            echo "✗ seed ${family}.pcap is no longer classified as ${proto} — regenerate it or fix ${LF_GEN_SEEDS##*/}" >&2
            exit 2
        fi
    done < <(python3 "${LF_GEN_SEEDS}" --list)
    say "      replay clean; every seed reaches its dissector"

    if [ "${REPLAY_ONLY}" -eq 1 ]; then
        if [ -n "${LF_CORPUS}" ] && [ -n "$(ls -A "${LF_CORPUS}")" ]; then
            say "[4/4] replaying the corpus ${LF_CORPUS} ..."
            before="$(lf_artifacts)"
            lf_run "${WORK}/corpus.log" "${LF_OPTS[@]}" -runs=0 "${LF_CORPUS}"
            if lf_verdict corpus-replay "${rc}" "${WORK}/corpus.log" "${before}"; then
                lf_summary "corpus replay FAIL"
                echo "✗ libFuzzer corpus replay FAIL — logs in ${ARTIFACTS}" >&2
                exit 1
            fi
        else
            say "[4/4] no corpus to replay"
        fi
        lf_summary "replay PASS"
        echo "✓ libFuzzer replay PASS — ${#LF_SEED_FILES[@]} seed(s) + ${#LF_REGS[@]} regression(s) clean"
        exit 0
    fi

    # --- 4. fuzz, then minimise the corpus ---------------------------------
    mkdir -p "${WORK}/golden"
    cp "${PCAPS[@]}" "${WORK}/golden/"
    LF_FUZZ_OPTS=( -max_len=65536 "-seed=${SEED}" "-max_total_time=${BUDGET}" -print_final_stats=1 )
    [ "${MAX_ITER}" -eq 0 ] || LF_FUZZ_OPTS+=( "-runs=${MAX_ITER}" )
    say "[4/4] fuzzing for up to ${BUDGET}s (seed ${SEED}, per-input timeout ${PER_INPUT_TIMEOUT}s) ..."
    before="$(lf_artifacts)"
    lf_run "${WORK}/fuzz.log" "${LF_OPTS[@]}" "${LF_FUZZ_OPTS[@]}" \
        "${LF_CORPUS}" "${LF_SEEDS}" "${WORK}/golden"
    if lf_verdict fuzz "${rc}" "${WORK}/fuzz.log" "${before}"; then
        lf_summary "fuzz FAIL"
        echo "✗ libFuzzer FAIL — ${lf_findings} finding(s); reproducers in ${ARTIFACTS}" >&2
        exit 1
    fi
    grep -E '^(#[0-9]+[[:space:]]+DONE|stat::number_of_executed_units)' "${WORK}/fuzz.log" | sed 's/^/      /' || true
    mkdir -p "${WORK}/merged"
    lf_run "${WORK}/merge.log" -merge=1 -max_len=65536 "-timeout=${PER_INPUT_TIMEOUT}" \
        -rss_limit_mb=2560 "${WORK}/merged" "${LF_CORPUS}"
    if [ "${rc}" -ne 0 ]; then
        echo "✗ corpus minimisation (-merge=1) failed (rc=${rc}) — last lines:" >&2
        tail -20 "${WORK}/merge.log" >&2
        exit 2
    fi
    find "${LF_CORPUS}" -mindepth 1 -maxdepth 1 -type f -delete
    find "${WORK}/merged" -mindepth 1 -maxdepth 1 -type f -exec mv -t "${LF_CORPUS}" {} +
    say "      corpus minimised to $(find "${LF_CORPUS}" -type f | wc -l) input(s)"
    lf_summary "fuzz PASS (${BUDGET}s)"
    echo "✓ libFuzzer PASS — no findings in ${BUDGET}s"
    exit 0
fi

WORK="$(mktemp -d)"
PREFIX_CREATED=0
if [ -z "${PREFIX}" ]; then
    PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/mmt-fuzz.XXXXXX")"
    PREFIX_CREATED=1
fi
trap 'rm -rf "${WORK}"; [ "${PREFIX_CREATED}" -eq 0 ] || rm -rf "${PREFIX}"' EXIT

JOBS="$(nproc 2>/dev/null || echo 2)"
INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"
mkdir -p "${ARTIFACTS}"
ARTIFACTS="$(cd "${ARTIFACTS}" && pwd)"

say() { printf '  %s\n' "$*"; }

say "repo root      : ${REPO_ROOT}"
say "install prefix : ${PREFIX}"
say "corpus         : ${#PCAPS[@]} golden pcaps + 1 QE model seed"
say "budget         : ${BUDGET}s fuzzing (seed base ${SEED}, iteration cap ${MAX_ITER:-0})"
say "regressions    : ${#REG_FILES[@]} committed reproducer(s) in ${REGRESSIONS}"
say "artifacts      : ${ARTIFACTS}"

# --- 1. build + install the SDK (asan + security/fuzz engines) --------------
if [ "${PREFIX_CREATED}" -eq 1 ]; then
    say "[1/4] building + installing SDK (BUILD=asan ENABLESEC=1) ..."
    BUILD_LOG="${WORK}/build.log"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
    if ! make -C "${REPO_ROOT}/sdk" BUILD=asan ENABLESEC=1 -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
        echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 2
    fi
    if ! make -C "${REPO_ROOT}/sdk" BUILD=asan ENABLESEC=1 MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
        echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 2
    fi
else
    say "[1/4] reusing existing prefix ${PREFIX}"
fi

# The fuzz engine must actually be present — this gate exists because it was
# only ever compiled, never run.
if ! ls "${LIB}"/libmmt_fuzz.so* >/dev/null 2>&1; then
    echo "✗ libmmt_fuzz not produced by the ENABLESEC build (${LIB})" >&2
    exit 2
fi

# --- 2. compile the drivers (ASan/UBSan instrumented) ------------------------
say "[2/4] compiling fuzz drivers (ASan/UBSan) ..."
CLASSIFY_BIN="${WORK}/phase0_classify"
QE_BIN="${WORK}/qe_xml_driver"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${CLASSIFY_BIN}" "${CLASSIFY_SRC}" \
    -I "${INC}" -L "${LIB}" -lmmt_core -ldl -lpcap
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${QE_BIN}" "${QE_DRIVER_SRC}" \
    -I "${INC}" -L "${LIB}" \
    -lmmt_fuzz -lmmt_security -lmmt_core -lmmt_tcpip -lmmt_tmobile -lxml2 -lm -ldl

ASAN_RT="$(gcc -print-file-name=libasan.so)"

# --- 3+4. mutation loop under the wall-clock budget --------------------------
say "[3/4] fuzzing for up to ${BUDGET}s (per-input timeout ${PER_INPUT_TIMEOUT}s) ..."

# Load already-reported mutants to skip — "<basename>:<seed>" per line,
# '#'-comments allowed. Entries are only added with a filed tracking issue.
declare -A SUPPRESSED=()
suppressed_count=0
if [ -f "${SUPPRESSIONS}" ]; then
    while IFS= read -r line; do
        line="${line%%#*}"                       # strip trailing comment
        line="$(printf '%s' "${line}" | tr -d '[:space:]')"
        [ -z "${line}" ] && continue
        SUPPRESSED["${line}"]=1
    done < "${SUPPRESSIONS}"
    say "      loaded ${#SUPPRESSED[@]} suppression(s) from ${SUPPRESSIONS}"
fi

deadline=$(( $(date +%s) + BUDGET ))
iter=0
findings=0
runs=0
refusals=0

run_driver() {
    # $1 = binary, $2 = mutant file, $3 = per-run stderr log,
    # $4 = detect_leaks (0/1)
    # cwd is the install prefix because mmt_init_handler loads plugins
    # (plugins/libmmt_tcpip.so) relative to the working directory.
    set +e
    ( cd "${PREFIX}" && \
      LD_PRELOAD="${ASAN_RT}" \
      ASAN_OPTIONS="abort_on_error=1:detect_leaks=$4:detect_odr_violation=0" \
      UBSAN_OPTIONS="print_stacktrace=1" \
      LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
      timeout -k 5 "${PER_INPUT_TIMEOUT}" "$1" "$2" ) > /dev/null 2>"$3"
    rc=$?
    set -e
    return "${rc}"
}

# record_verdict <tag> <name> <input> <rc> <seed-file> <repro-hint>
# Classifies one driver run (see the finding rule in the header) and, on a
# finding, copies the input and its stderr into the artifacts directory.
# Returns 0 when the run was a finding, 1 otherwise.
record_verdict() {
    local tag="$1" name="$2" input="$3" rc="$4" from="$5" hint="$6" kind repro
    # The driver failing to execute at all — or timeout itself failing —
    # (timeout reports 125/126/127) is the harness breaking, never a finding
    # on hostile input: a missing binary must not masquerade as a crash.
    if [ "${rc}" -eq 125 ] || [ "${rc}" -eq 126 ] || [ "${rc}" -eq 127 ]; then
        echo "✗ fuzz driver could not be executed: ${bin} (rc=${rc})" >&2
        cat "${log}" >&2 || true
        exit 2
    fi

    # Classify the outcome. rc >= 124 stays a finding (124 = per-input
    # timeout/hang, >= 128 = signal/crash). Below that band the run is
    # normally an expected parser refusal — except when the log carries a
    # sanitizer banner, which is a real memory/UB finding the exit code
    # alone would have passed (issue #370, F-TEST-001). rc 0 is a tested-
    # clean run, counted via `runs`, never a refusal.
    if [ "${rc}" -ge 124 ]; then
        if [ "${rc}" -eq 124 ]; then kind="hang/timeout"; else kind="signal/crash"; fi
    elif grep -qE "${SANITIZER_MARKERS}" "${log}"; then
        kind="sanitizer-error"
    elif [ "${rc}" -gt 0 ]; then
        # Expected parser refusal — counted so it stays separately
        # identifiable from both a tested-clean run and a finding.
        refusals=$((refusals + 1))
        return 1
    else
        return 1
    fi

    findings=$((findings + 1))
    repro="${ARTIFACTS}/${name}"
    [ "${input}" = "${repro}" ] || cp "${input}" "${repro}"
    {
        echo "driver   : $(basename "${bin}") ${repro}"
        echo "seed file: ${from}"
        echo "mutant   : ${hint}"
        echo "exit code: ${rc} (${kind})"
        echo "--- stderr ---"
        cat "${log}"
    } > "${repro}.log"
    say "  ✗ finding #${findings}: ${tag} (rc=${rc}, ${kind}) -> ${repro}"
    return 0
}

# Replay the committed regressions first: they gate every run, whatever the
# seed, and do not consume the mutation budget.
reg_findings=0
for f in "${REG_FILES[@]}"; do
    case "${f}" in
        *.pcap) bin="${CLASSIFY_BIN}"; leaks=0 ;;
        *.xml)  bin="${QE_BIN}";       leaks=1 ;;
    esac
    log="${WORK}/run.log"
    run_driver "${bin}" "${f}" "${log}" "${leaks}" && rc=0 || rc=$?
    if record_verdict "regression ${f##*/}" "regression-${f##*/}" "${f}" "${rc}" "${f}" \
            "committed regression (bash tools/ci/run-fuzz.sh --replay-only)"; then
        reg_findings=$((reg_findings + 1))
    fi
done
say "      replayed ${#REG_FILES[@]} regression(s): ${reg_findings} finding(s)"
if [ "${REPLAY_ONLY}" -eq 1 ]; then
    if [ "${findings}" -gt 0 ]; then
        echo "✗ regression replay FAIL — ${findings} committed reproducer(s) still crash; logs in ${ARTIFACTS}" >&2
        exit 1
    fi
    echo "✓ regression replay PASS — ${#REG_FILES[@]} committed reproducer(s) clean"
    exit 0
fi

# The mutation budget starts after the replay.
deadline=$(( $(date +%s) + BUDGET ))
while [ "$(date +%s)" -lt "${deadline}" ] && [ "${findings}" -lt "${MAX_FINDINGS}" ] \
      && { [ "${MAX_ITER}" -eq 0 ] || [ "${iter}" -lt "${MAX_ITER}" ]; }; do
    iter=$((iter + 1))
    # Alternate surfaces: odd iterations fuzz a golden pcap through
    # phase0_classify, even iterations fuzz the QE model through libmmt_fuzz.
    if [ $((iter % 2)) -eq 1 ]; then
        seed_file="${PCAPS[$(( (iter / 2) % ${#PCAPS[@]} ))]}"
        bin="${CLASSIFY_BIN}"
        tag="pcap"
        leaks=0
    else
        seed_file="${QE_SEED}"
        bin="${QE_BIN}"
        tag="qexml"
        # LeakSanitizer is on for the QE target only (issue #470): the driver
        # frees every model it parses, so a leak there is a parser ownership
        # regression — reported through the LeakSanitizer banner below. The
        # pcap target keeps the project's detect_leaks=0 policy (leaks are
        # the Valgrind leak gate's job, tools/phase0/tests).
        leaks=1
    fi
    mutant="${WORK}/mutant.${tag}"
    mseed=$((SEED + iter))
    seed_base="${seed_file##*/}"
    if [ -n "${SUPPRESSED["${seed_base}:${mseed}"]:-}" ]; then
        suppressed_count=$((suppressed_count + 1))
        continue
    fi
    if ! python3 "${MUTATE}" "${seed_file}" "${mutant}" --seed "${mseed}"; then
        echo "✗ mutate.py failed on ${seed_file}" >&2
        exit 2
    fi

    log="${WORK}/run.log"
    run_driver "${bin}" "${mutant}" "${log}" "${leaks}" && rc=0 || rc=$?
    runs=$((runs + 1))
    record_verdict "${tag} mutant of ${seed_base} (seed ${mseed})" \
        "crash-${tag}-${seed_base}-seed${mseed}" "${mutant}" "${rc}" "${seed_file}" \
        "mutate.py --seed ${mseed} (repro: python3 ${MUTATE} \"${seed_file}\" out --seed ${mseed})" || true
done

elapsed=$(( $(date +%s) - (deadline - BUDGET) ))
{
    echo "run-fuzz summary"
    echo "iterations: ${iter}  driver runs: ${runs}  suppressed: ${suppressed_count}  refusals: ${refusals}  elapsed: ${elapsed}s  findings: ${findings}"
    echo "seed base: ${SEED}  corpus: ${#PCAPS[@]} pcaps + seed_qe.xml"
    echo "regressions replayed: ${#REG_FILES[@]}  regression findings: ${reg_findings}"
} > "${ARTIFACTS}/SUMMARY.txt"

say "[4/4] ${runs} mutated inputs in ${elapsed}s (+ ${#REG_FILES[@]} regression replay(s)), ${findings} finding(s), ${refusals} parser refusal(s), ${suppressed_count} suppressed"
if [ "${findings}" -gt 0 ]; then
    echo "✗ fuzz gate FAIL — ${findings} crash(es); reproducers in ${ARTIFACTS}" >&2
    exit 1
fi
echo "✓ fuzz gate PASS — no crashes in ${runs} mutated inputs (${elapsed}s)"
exit 0
