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
# counted separately so a refusal never reads as a crash. An exit code of
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
# Usage:
#   bash tools/ci/run-fuzz.sh [--seconds N] [--seed N] [--artifacts DIR]
#                             [--iterations N] [--prefix DIR]
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
#
# Used by .github/workflows/c-cpp.yml (fuzz job). Runnable locally too.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CORPUS_DIR="${REPO_ROOT}/tools/phase0/ci/pcaps"
QE_SEED="${SCRIPT_DIR}/fuzz/seed_qe.xml"
MUTATE="${SCRIPT_DIR}/fuzz/mutate.py"
SUPPRESSIONS="${SCRIPT_DIR}/fuzz/suppressions.txt"
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

for f in "${MUTATE}" "${QE_DRIVER_SRC}" "${CLASSIFY_SRC}" "${QE_SEED}"; do
    [ -f "$f" ] || { echo "✗ missing fuzz component: $f" >&2; exit 2; }
done
for cmd in python3 timeout gcc make; do
    command -v "${cmd}" >/dev/null 2>&1 || { echo "✗ ${cmd} not found" >&2; exit 2; }
done

shopt -s nullglob
PCAPS=( "${CORPUS_DIR}"/*.pcap )
if [ "${#PCAPS[@]}" -eq 0 ]; then
    echo "✗ golden corpus empty: ${CORPUS_DIR}" >&2
    exit 2
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

# A sanitizer report on stderr is a finding even when the process exits
# cleanly (see the finding rule in the header). Match the runtime banners,
# never a bare "error" substring, so an expected parser refusal cannot
# collide with them.
SANITIZER_MARKERS='runtime error:|ERROR: (Address|UndefinedBehavior|Leak|Memory|Thread)Sanitizer|SUMMARY: (Address|UndefinedBehavior|Leak|Memory|Thread)Sanitizer'

run_driver() {
    # $1 = binary, $2 = mutant file, $3 = per-run stderr log
    # cwd is the install prefix because mmt_init_handler loads plugins
    # (plugins/libmmt_tcpip.so) relative to the working directory.
    set +e
    ( cd "${PREFIX}" && \
      LD_PRELOAD="${ASAN_RT}" \
      ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:detect_odr_violation=0" \
      UBSAN_OPTIONS="print_stacktrace=1" \
      LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
      timeout -k 5 "${PER_INPUT_TIMEOUT}" "$1" "$2" ) > /dev/null 2>"$3"
    rc=$?
    set -e
    return "${rc}"
}

while [ "$(date +%s)" -lt "${deadline}" ] && [ "${findings}" -lt "${MAX_FINDINGS}" ] \
      && { [ "${MAX_ITER}" -eq 0 ] || [ "${iter}" -lt "${MAX_ITER}" ]; }; do
    iter=$((iter + 1))
    # Alternate surfaces: odd iterations fuzz a golden pcap through
    # phase0_classify, even iterations fuzz the QE model through libmmt_fuzz.
    if [ $((iter % 2)) -eq 1 ]; then
        seed_file="${PCAPS[$(( (iter / 2) % ${#PCAPS[@]} ))]}"
        bin="${CLASSIFY_BIN}"
        tag="pcap"
    else
        seed_file="${QE_SEED}"
        bin="${QE_BIN}"
        tag="qexml"
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
    run_driver "${bin}" "${mutant}" "${log}" && rc=0 || rc=$?
    runs=$((runs + 1))

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
        continue
    else
        continue
    fi

    findings=$((findings + 1))
    repro="${ARTIFACTS}/crash-${tag}-${seed_base}-seed${mseed}"
    cp "${mutant}" "${repro}"
    {
        echo "driver   : $(basename "${bin}") ${repro}"
        echo "seed file: ${seed_file}"
        echo "mutant   : mutate.py --seed ${mseed} (repro: python3 ${MUTATE} \"${seed_file}\" out --seed ${mseed})"
        echo "exit code: ${rc} (${kind})"
        echo "--- stderr ---"
        cat "${log}"
    } > "${repro}.log"
    say "  ✗ finding #${findings}: ${tag} mutant of ${seed_base} (seed ${mseed}, rc=${rc}, ${kind}) -> ${repro}"
done

elapsed=$(( $(date +%s) - (deadline - BUDGET) ))
{
    echo "run-fuzz summary"
    echo "iterations: ${iter}  driver runs: ${runs}  suppressed: ${suppressed_count}  refusals: ${refusals}  elapsed: ${elapsed}s  findings: ${findings}"
    echo "seed base: ${SEED}  corpus: ${#PCAPS[@]} pcaps + seed_qe.xml"
} > "${ARTIFACTS}/SUMMARY.txt"

say "[4/4] ${runs} mutated inputs in ${elapsed}s, ${findings} finding(s), ${refusals} parser refusal(s), ${suppressed_count} suppressed"
if [ "${findings}" -gt 0 ]; then
    echo "✗ fuzz gate FAIL — ${findings} crash(es); reproducers in ${ARTIFACTS}" >&2
    exit 1
fi
echo "✓ fuzz gate PASS — no crashes in ${runs} mutated inputs (${elapsed}s)"
exit 0
