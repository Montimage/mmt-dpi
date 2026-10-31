#!/usr/bin/env bash
#
# capture_perf.sh — capture the same-machine perf reference
# tools/phase0/baseline/perf/throughput.txt (issues #251, #555).
#
# Builds the default-profile SDK (-O3, the release build) into an isolated
# prefix, compiles tools/phase0/phase0_throughput.c against it and replays each
# pcap of throughput_pcaps.txt (bigFlows, smallFlows — from the mmt-test
# data-sets) in each attribute mode:
#   bare    no attribute, no handler (the classifier hot path)
#   attrs8  the driver's fixed 8-attribute set, fetched by a packet handler
#   all     fetch-all: every protocol attribute registered, and every one the
#           packet's protocol path carries fetched on every packet
# One row per (pcap, mode). Wall-clock figures are host-dependent: compare
# them on the same host (the header records it) — CI gates instruction
# counts instead (tools/phase0/ci/check_instructions.sh).
#
# Usage:
#   tools/phase0/capture_perf.sh [--iterations N] [--modes "bare attrs8 all"]
#                                [--out FILE] [--datasets DIR] [--jobs N]
#
#   --iterations N  passes per (pcap, mode) (default 200)
#   --modes LIST    modes to capture (default "bare attrs8 all")
#   --out FILE      output (default tools/phase0/baseline/perf/throughput.txt)
#   --datasets DIR  pcap dataset root (default $MMT_TEST_DATASETS, else
#                   <repo>/../mmt-test/data-sets)
# Environment:
#   MMT_PREFIX          install prefix (default: a private mktemp dir, removed)
#   MMT_SDK_PREBUILT=1  reuse the SDK already installed under MMT_PREFIX
#
# The build runs `make -C sdk clean` first, so it discards an in-tree build.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ITERATIONS=200
MODES="bare attrs8 all"
OUT="${SCRIPT_DIR}/baseline/perf/throughput.txt"
DATASETS_OPT=""
JOBS="$(nproc 2>/dev/null || echo 4)"
LIST="${SCRIPT_DIR}/throughput_pcaps.txt"

while [ $# -gt 0 ]; do
    case "$1" in
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --modes)      MODES="$2"; shift 2 ;;
        --out)        OUT="$2"; shift 2 ;;
        --datasets)   DATASETS_OPT="$2"; shift 2 ;;
        --jobs)       JOBS="$2"; shift 2 ;;
        -h|--help)    sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "${ITERATIONS}" in ''|*[!0-9]*|0) echo "✗ --iterations takes a positive integer" >&2; exit 2 ;; esac

DATASETS="${DATASETS_OPT:-${MMT_TEST_DATASETS:-${REPO_ROOT}/../mmt-test/data-sets}}"
[ -d "${DATASETS}" ] || { echo "✗ mmt-test data-sets not found at: ${DATASETS} (set MMT_TEST_DATASETS)" >&2; exit 1; }
DATASETS="$(cd "${DATASETS}" && pwd)"
mkdir -p "$(dirname "${OUT}")"
OUT="$(cd "$(dirname "${OUT}")" && pwd)/$(basename "${OUT}")"

WORK="$(mktemp -d)"
if [ -n "${MMT_PREFIX:-}" ]; then
    PREFIX="${MMT_PREFIX}"
    trap 'rm -rf "${WORK}"' EXIT
else
    PREFIX="$(mktemp -d /tmp/mmt-perf.XXXXXX)"
    trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT
fi

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing the SDK installed at ${PREFIX} (MMT_SDK_PREBUILT=1)"
    [ -f "${PREFIX}/dpi/include/mmt_core.h" ] || { echo "✗ no installed SDK under ${PREFIX}" >&2; exit 2; }
else
    echo "[1/3] building + installing the default-profile SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
    if ! make -C "${REPO_ROOT}/sdk" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${WORK}/build.log" 2>&1 \
       || ! make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >>"${WORK}/build.log" 2>&1; then
        echo "✗ SDK build/install failed — last lines:" >&2; tail -20 "${WORK}/build.log" >&2; exit 1
    fi
fi

echo "[2/3] compiling phase0_throughput"
BIN="${WORK}/phase0_throughput"
gcc -O2 -Wall -o "${BIN}" "${SCRIPT_DIR}/phase0_throughput.c" \
    -I "${PREFIX}/dpi/include" -L "${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap
export LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}"

mapfile -t PCAPS < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "${LIST}")
echo "[3/3] replaying ${#PCAPS[@]} pcap(s) x modes '${MODES}', ${ITERATIONS} iterations each"
{
    printf '# Phase 0 perf reference — in-memory replay, default (-O3) build (issues #251, #555).\n'
    printf '# Same-host figures: compare deltas on the host below, never across hosts.\n'
    printf '# Captured by tools/phase0/capture_perf.sh. Modes (PHASE0_MODE): bare = no\n'
    printf '# attribute or handler; attrs8 = 8 attributes fetched by a packet handler;\n'
    printf '# all = fetch-all, every attribute the packet carries fetched per packet.\n'
    printf '# ns_per_pkt = 1e9 / pps. RSS columns (issue #251): harness_rss_kib is the\n'
    printf '# trace-preload share, library_rss_kib the SDK share on top of it.\n'
    printf '# library_rss_kib is the peak over all iterations, so it rises with --iterations.\n'
    printf '# M4 budget reference (audit host, issues #555/#584): bigFlows bare\n'
    printf '# 3,106,798 pps and library_rss_kib 21,428; fetch-all 1,704 ns/pkt.\n'
    printf '# host: %s | cpu: %s | gcc: %s | os: %s | commit: %s\n' \
        "$(uname -m)" "$(nproc 2>/dev/null || echo '?')" "$(gcc -dumpfullversion)" \
        "$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown)" \
        "$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    printf '#\n# pcap\tmode\tattrs\tpackets\titerations\telapsed_s\tpps\tharness_rss_kib\tlibrary_rss_kib\tpeak_rss_kib\tns_per_pkt\n'
} > "${WORK}/perf.txt"
for rel in "${PCAPS[@]}"; do
    pcap="${DATASETS}/${rel}"
    [ -f "${pcap}" ] || { echo "✗ missing pcap: ${pcap}" >&2; exit 1; }
    for mode in ${MODES}; do
        if ! line="$(cd "${WORK}" && PHASE0_MODE="${mode}" "${BIN}" "${pcap}" "${ITERATIONS}" 2>"${WORK}/err")"; then
            echo "✗ ${rel} ${mode}: phase0_throughput failed: $(tail -n 2 "${WORK}/err")" >&2; exit 1
        fi
        attrs="$(sed -n 's/^mode\t[a-z0-9]*\t\([0-9]*\)$/\1/p' "${WORK}/err" | head -n 1)"
        printf '%s\t%s\t%s\t%s\n' "${rel}" "${mode}" "${attrs:-?}" "${line}" >> "${WORK}/perf.txt"
        printf '    %-16s %-7s %s\n' "${rel}" "${mode}" "${line}"
    done
done
cp "${WORK}/perf.txt" "${OUT}"
echo "✓ wrote ${OUT#"${REPO_ROOT}/"}"
