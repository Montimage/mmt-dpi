#!/usr/bin/env bash
#
# check_instructions.sh — CI gate for the attribute/handler-path instruction
# counts (issue #555).
#
# Wall-clock pps is too noisy on shared runners to gate, so this gate counts
# instructions instead: Valgrind's callgrind runs tools/phase0/phase0_throughput
# once per vendored CI pcap (ci/golden_pcaps.txt, the classification gate's
# input) in each mode — bare, attrs8 and fetch-all (`all`) — with collection
# limited to the replay (the driver brackets it with CALLGRIND_TOGGLE_COLLECT,
# so init_extraction(), handler setup and teardown and attribute registration
# are excluded; it needs <valgrind/callgrind.h>, shipped by the valgrind
# package, at compile time).
# The per-mode totals, as instructions per packet, are compared with the
# committed baseline ci/baseline/instructions.txt:
#
#   - more than INSTR_TOLERANCE_PCT (default 2) percent above it   -> FAIL
#   - more than INSTR_TOLERANCE_PCT percent below it               -> PASS, with
#     a notice: ratchet the baseline in the same PR (see below)
#   - a mode or the packet count differing from the baseline       -> FAIL
#   - a baseline recorded on another architecture                  -> exit 2
#
# Counts repeat within a few tens of instructions per pcap for one binary and
# input (MMT_DETERMINISTIC_SEED=1 pins the hash seeds, issue #551; the residue
# moves with the environment and paths, through stack alignment), so the gate
# relies on its tolerance, never on exact equality. They depend on the
# architecture and the toolchain: the baseline is measured on aarch64 / Ubuntu 24.04 / GCC 13, the
# toolchain of the `instruction-gate` job's ubuntu-24.04-arm runner
# (.github/workflows/phase0-baseline.yml). A GCC or Valgrind other than the
# baseline's is reported as a warning; the tolerance absorbs patch-level drift.
#
# Regenerating the baseline (an intentional change, or a perf PR that lowers
# the counts): run the gate on a matching host — it writes
# ci/baseline/instructions.actual.txt, which the CI job also uploads as the
# `phase0-instructions-actual` artifact — then
#   cp tools/phase0/ci/baseline/instructions.actual.txt \
#      tools/phase0/ci/baseline/instructions.txt
# (or run with --update) and give the before/after per-mode figures in the PR
# body.
#
# Usage:
#   tools/phase0/ci/check_instructions.sh            # build, measure, compare
#   tools/phase0/ci/check_instructions.sh --update   # ... and refresh the baseline
#   tools/phase0/ci/check_instructions.sh --compare BASELINE ACTUAL
#                                                    # compare two files only
#   tools/phase0/ci/check_instructions.sh --self-test
#                                                    # the comparator on fixtures
# Environment:
#   MMT_PREFIX           install prefix (default: a private mktemp dir, removed)
#   MMT_SDK_PREBUILT=1   reuse the SDK already installed under MMT_PREFIX
#   INSTR_TOLERANCE_PCT  regression tolerance in percent (default 2)
#   INSTR_MODES          modes to measure (default "bare attrs8 all")
#
# Exit: 0 pass, 1 regression or mismatch, 2 bad usage, missing tool or
# architecture mismatch.
set -euo pipefail
export LC_ALL=C
# Issue #551: fixed hash seeds, so a pass's count repeats within a few tens
# of instructions (see the header).
export MMT_DETERMINISTIC_SEED=1

CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${CI_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
BASELINE="${CI_DIR}/baseline/instructions.txt"
ACTUAL="${CI_DIR}/baseline/instructions.actual.txt"
PCAP_DIR="${CI_DIR}/pcaps"
PCAP_LIST="${CI_DIR}/golden_pcaps.txt"
TOL="${INSTR_TOLERANCE_PCT:-2}"
MODES="${INSTR_MODES:-bare attrs8 all}"

case "${TOL}" in
    ''|*[!0-9.]*) echo "✗ INSTR_TOLERANCE_PCT must be a number (got '${TOL}')" >&2; exit 2 ;;
esac

# compare_files BASELINE ACTUAL — the gate's verdict on two instruction files.
# Prints one line per baseline mode; returns 0 pass, 1 fail, 2 arch mismatch.
compare_files() {
    local base="$1" act="$2"
    [ -f "${base}" ] || { echo "✗ baseline missing: ${base}" >&2; return 1; }
    [ -f "${act}" ]  || { echo "✗ measurement missing: ${act}" >&2; return 1; }
    local barch aarch
    barch="$(sed -n 's/^# arch: //p' "${base}" | head -n 1)"
    aarch="$(sed -n 's/^# arch: //p' "${act}" | head -n 1)"
    if [ -z "${barch}" ] || [ "${barch}" != "${aarch}" ]; then
        echo "✗ baseline architecture '${barch:-none}' differs from this run's '${aarch:-none}':" >&2
        echo "  instruction counts are per architecture — run on a ${barch:-matching} host" >&2
        return 2
    fi
    local key
    for key in gcc valgrind; do
        local bv av
        bv="$(sed -n "s/^# ${key}: //p" "${base}" | head -n 1)"
        av="$(sed -n "s/^# ${key}: //p" "${act}" | head -n 1)"
        [ "${bv}" = "${av}" ] || echo "⚠ ${key} differs from the baseline's (${bv:-?} -> ${av:-?}); the ${TOL}% tolerance absorbs patch-level drift"
    done
    awk -F'\t' -v tol="${TOL}" '
        FNR == 1 { file++ }
        $1 == "total" && file == 1 { bp[$2] = $3; bi[$2] = $5; order[++n] = $2 }
        $1 == "total" && file == 2 { ap[$2] = $3; ai[$2] = $5; seen[$2] = 1 }
        END {
            rc = 0
            if (n == 0) { print "✗ baseline has no total rows"; exit 1 }
            for (k = 1; k <= n; k++) {
                m = order[k]
                if (!(m in seen)) { printf "✗ %-7s missing from this run\n", m; rc = 1; continue }
                if (bp[m] != ap[m]) {
                    printf "✗ %-7s packet count %s differs from the baseline %s (input changed: regenerate)\n", m, ap[m], bp[m]
                    rc = 1; continue
                }
                d = (bi[m] > 0) ? (ai[m] - bi[m]) * 100.0 / bi[m] : 0
                if (d > tol) {
                    printf "✗ %-7s %.1f Ir/pkt vs baseline %.1f (%+.2f%%, over +%s%%): REGRESSION\n", m, ai[m], bi[m], d, tol
                    rc = 1
                } else if (d < -tol) {
                    printf "✓ %-7s %.1f Ir/pkt vs baseline %.1f (%+.2f%%): improved past the tolerance - ratchet the baseline\n", m, ai[m], bi[m], d
                } else {
                    printf "✓ %-7s %.1f Ir/pkt vs baseline %.1f (%+.2f%%)\n", m, ai[m], bi[m], d
                }
            }
            for (m in seen) if (!(m in bi)) printf "⚠ %-7s measured but not in the baseline (not gated)\n", m
            exit rc
        }' "${base}" "${act}"
}

self_test() {
    local dir fails=0
    TOL=2   # the fixtures below are written against the default tolerance
    dir="$(mktemp -d)"
    # fixture <file> <arch> <bare Ir/pkt> <all Ir/pkt> [packets]
    fixture() {
        local pk="${5:-100}"
        {
            printf '# arch: %s\n# gcc: 13.3.0\n# valgrind: valgrind-3.22.0\n' "$2"
            printf 'total\tbare\t%s\t%s\t%s\n' "${pk}" "$(awk -v v="$3" -v p="${pk}" 'BEGIN{printf "%d", v*p}')" "$3"
            if [ -n "$4" ]; then
                printf 'total\tall\t%s\t%s\t%s\n' "${pk}" "$(awk -v v="$4" -v p="${pk}" 'BEGIN{printf "%d", v*p}')" "$4"
            fi
        } > "$1"
    }
    expect() {
        local want="$1" name="$2" got
        set +e; compare_files "${dir}/base" "${dir}/act" >"${dir}/out" 2>&1; got=$?; set -e
        if [ "${got}" -eq "${want}" ]; then
            echo "  ✓ ${name} (exit ${got})"
        else
            echo "  ✗ ${name}: exit ${got}, expected ${want}"; sed 's/^/      /' "${dir}/out"
            fails=$((fails + 1))
        fi
    }
    fixture "${dir}/base" aarch64 1000 5000
    fixture "${dir}/act" aarch64 1000 5000;      expect 0 "identical counts pass"
    fixture "${dir}/act" aarch64 1015 5090;      expect 0 "drift inside the tolerance passes"
    fixture "${dir}/act" aarch64 1000 5200;      expect 1 "a fetch-all regression past the tolerance fails"
    fixture "${dir}/act" aarch64 1030 5000;      expect 1 "a bare regression past the tolerance fails"
    fixture "${dir}/act" aarch64 700 2500;       expect 0 "an improvement passes"
    grep -q 'ratchet the baseline' "${dir}/out" || { echo "  ✗ an improvement does not ask for a ratchet"; fails=$((fails + 1)); }
    fixture "${dir}/act" aarch64 1000 "";        expect 1 "a mode missing from the run fails"
    fixture "${dir}/act" aarch64 1000 5000 99;   expect 1 "a changed packet count fails"
    fixture "${dir}/act" x86_64 1000 5000;       expect 2 "another architecture is refused"
    rm -rf "${dir}"
    if [ "${fails}" -eq 0 ]; then echo "✓ check_instructions self-test: PASS"; return 0; fi
    echo "✗ check_instructions self-test: ${fails} case(s) failed"; return 1
}

UPDATE=0
case "${1:-}" in
    --self-test) self_test; exit $? ;;
    --compare)
        [ $# -eq 3 ] || { echo "usage: $0 --compare BASELINE ACTUAL" >&2; exit 2; }
        compare_files "$2" "$3"; exit $? ;;
    --update) UPDATE=1 ;;
    '') ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: $0 [--update | --compare BASELINE ACTUAL | --self-test]" >&2; exit 2 ;;
esac

command -v valgrind >/dev/null 2>&1 || { echo "✗ valgrind is required (apt-get install valgrind)" >&2; exit 2; }
echo '#include <valgrind/callgrind.h>' | gcc -E -x c - >/dev/null 2>&1 \
    || { echo "✗ <valgrind/callgrind.h> not found (it ships with the valgrind package)" >&2; exit 2; }
[ -f "${PCAP_LIST}" ] || { echo "✗ pcap list missing: ${PCAP_LIST}" >&2; exit 2; }

WORK="$(mktemp -d)"
if [ -n "${MMT_PREFIX:-}" ]; then
    PREFIX="${MMT_PREFIX}"
    trap 'rm -rf "${WORK}"' EXIT
else
    PREFIX="$(mktemp -d /tmp/mmt-phase0.XXXXXX)"
    trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT
fi

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing the SDK installed at ${PREFIX} (MMT_SDK_PREBUILT=1)"
    [ -f "${PREFIX}/dpi/include/mmt_core.h" ] || { echo "✗ no installed SDK under ${PREFIX}" >&2; exit 2; }
else
    echo "[1/3] building + installing the default-profile SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
    if ! make -C "${REPO_ROOT}/sdk" -j"$(nproc)" MMT_BASE="${PREFIX}" >"${WORK}/build.log" 2>&1 \
       || ! make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >>"${WORK}/build.log" 2>&1; then
        echo "✗ SDK build/install failed — last lines:" >&2; tail -20 "${WORK}/build.log" >&2; exit 1
    fi
fi

echo "[2/3] compiling phase0_throughput"
BIN="${WORK}/phase0_throughput"
gcc -O2 -Wall -o "${BIN}" "${PHASE0_DIR}/phase0_throughput.c" \
    -I "${PREFIX}/dpi/include" -L "${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap

mapfile -t PCAPS < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "${PCAP_LIST}")
[ "${#PCAPS[@]}" -gt 0 ] || { echo "✗ ${PCAP_LIST} lists no pcap" >&2; exit 2; }

echo "[3/3] counting replay instructions (callgrind) over ${#PCAPS[@]} pcaps, modes: ${MODES}"
{
    printf '# Instruction-count baseline of the phase0_throughput replay (issue #555).\n'
    printf '# callgrind Ir of the replay pass, 1 iteration per pcap, over\n'
    printf '# tools/phase0/ci/golden_pcaps.txt; gated per mode on Ir per packet by\n'
    printf '# tools/phase0/ci/check_instructions.sh. Regenerate on a matching host,\n'
    printf '# never by hand (see the script header).\n'
    printf '# arch: %s\n' "$(uname -m)"
    printf '# gcc: %s\n' "$(gcc -dumpfullversion)"
    printf '# valgrind: %s\n' "$(valgrind --version)"
    printf '# os: %s\n' "$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown)"
    printf '#\n# pcap\t<mode>\t<pcap>\t<packets>\t<instructions>\n'
    printf '# total\t<mode>\t<packets>\t<instructions>\t<instructions_per_packet>\n'
} > "${WORK}/actual.txt"

failed=0
for mode in ${MODES}; do
    tot_pk=0; tot_ir=0
    for rel in "${PCAPS[@]}"; do
        pcap="${PCAP_DIR}/${rel}"
        if [ ! -f "${pcap}" ]; then
            echo "    ✗ ${mode} ${rel}: listed pcap is missing" >&2; failed=1; continue
        fi
        # Neutral working dir; prefix-bound plugin loading (issue #503).
        if ! ( cd "${WORK}" && PHASE0_MODE="${mode}" \
               LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
               valgrind --tool=callgrind --collect-atstart=no \
                   --callgrind-out-file=/dev/null \
                   "${BIN}" "${pcap}" 1 >"${WORK}/run.out" 2>"${WORK}/run.err" ); then
            echo "    ✗ ${mode} ${rel}: phase0_throughput failed under callgrind:" >&2
            tail -5 "${WORK}/run.err" | sed 's/^/      /' >&2; failed=1; continue
        fi
        ir="$(sed -n 's/^==[0-9]*== Collected : \([0-9]*\)$/\1/p' "${WORK}/run.err" | tail -n 1)"
        pk="$(cut -f1 "${WORK}/run.out")"
        # Zero means the driver was built without the callgrind bracket.
        case "${ir}:${pk}" in
            *[!0-9:]*|:*|*:|0:*) echo "    ✗ ${mode} ${rel}: no count (Ir='${ir}', packets='${pk}')" >&2; failed=1; continue ;;
        esac
        printf 'pcap\t%s\t%s\t%s\t%s\n' "${mode}" "${rel}" "${pk}" "${ir}" >> "${WORK}/actual.txt"
        tot_pk=$((tot_pk + pk)); tot_ir=$((tot_ir + ir))
    done
    if [ "${tot_pk}" -gt 0 ]; then
        per="$(awk -v i="${tot_ir}" -v p="${tot_pk}" 'BEGIN { printf "%.1f", i / p }')"
        printf 'total\t%s\t%s\t%s\t%s\n' "${mode}" "${tot_pk}" "${tot_ir}" "${per}" >> "${WORK}/actual.txt"
        printf '    %-7s %8s packets %14s Ir  %10s Ir/pkt\n' "${mode}" "${tot_pk}" "${tot_ir}" "${per}"
    fi
done
cp "${WORK}/actual.txt" "${ACTUAL}"
[ "${failed}" -eq 0 ] || { echo "✗ instruction gate: a measurement failed (see above)" >&2; exit 1; }

if [ "${UPDATE}" -eq 1 ]; then
    cp "${ACTUAL}" "${BASELINE}"
    echo "✓ baseline refreshed: ${BASELINE#"${REPO_ROOT}/"} (commit it with the reason in the PR body)"
    exit 0
fi

echo
set +e
compare_files "${BASELINE}" "${ACTUAL}"
rc=$?
set -e
case "${rc}" in
    0) echo "✓ instruction-count gate: PASS (tolerance ${TOL}%)" ;;
    1) echo "✗ instruction-count gate: FAIL"
       echo "  If the change is intentional, refresh the baseline in the same PR:"
       echo "    cp ${ACTUAL#"${REPO_ROOT}/"} ${BASELINE#"${REPO_ROOT}/"}" ;;
esac
exit "${rc}"
