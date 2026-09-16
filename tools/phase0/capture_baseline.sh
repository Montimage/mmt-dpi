#!/usr/bin/env bash
#
# capture_baseline.sh — capture the Phase 0 classification + throughput baseline.
#
# Part of the MMT-DPI Master Improvement Plan, Phase 0 (baseline harness).
# See tools/phase0/README.md.
#
# What it does:
#   1. Builds the library at -O3 and installs it to an isolated prefix.
#   2. Compiles the phase0_classify and phase0_throughput drivers against it.
#   3. Runs phase0_classify over the golden pcap set -> classification fingerprints.
#   4. Runs phase0_throughput over the golden set -> a pps throughput baseline.
#   5. Runs Valgrind --leak-check on one pcap if valgrind is installed, else
#      records a SKIPPED note with the exact command to run elsewhere.
#
# Re-run it after each phase and `git diff tools/phase0/baseline/` — any change
# to the classification fingerprints is a regression to investigate. The
# throughput / valgrind numbers are environment-dependent and are diffed by
# eye, not asserted.
#
# Usage:
#   tools/phase0/capture_baseline.sh [--prefix DIR] [--iterations N] [--jobs N]
#                                    [--golden FILE] [--out DIR] [--datasets DIR]
#
#   --golden FILE   golden pcap manifest (default: tools/phase0/golden_pcaps.txt)
#   --out DIR       output directory for the baseline (default: tools/phase0/baseline)
#   --datasets DIR  pcap dataset root (overrides $MMT_TEST_DATASETS)
#
# Environment overrides:
#   MMT_TEST_DATASETS  path to mmt-test data-sets (default: <repo>/../mmt-test/data-sets)
#
# The CI gate (.github/workflows/phase0-baseline.yml) reuses this script with a
# small self-contained pcap subset under tools/phase0/ci/.
#
set -euo pipefail

# --- locate ourselves / the repo -------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PREFIX="/tmp/mmt"
ITERATIONS=200
JOBS="$(nproc 2>/dev/null || echo 4)"
GOLDEN_LIST="${SCRIPT_DIR}/golden_pcaps.txt"
OUT_DIR="${SCRIPT_DIR}/baseline"
DATASETS_OPT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)     PREFIX="$2"; shift 2 ;;
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --jobs)       JOBS="$2"; shift 2 ;;
        --golden)     GOLDEN_LIST="$2"; shift 2 ;;
        --out)        OUT_DIR="$2"; shift 2 ;;
        --datasets)   DATASETS_OPT="$2"; shift 2 ;;
        -h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Dataset root precedence: --datasets > $MMT_TEST_DATASETS > sibling mmt-test.
DATASETS="${DATASETS_OPT:-${MMT_TEST_DATASETS:-${REPO_ROOT}/../mmt-test/data-sets}}"
# Resolve to an absolute path: the SDK loads its protocol plugins from a
# CWD-relative "plugins/" directory first (plugins_engine.c), falling back to
# the compiled-in prefix only when CWD has no "plugins/" dir. We therefore run
# the drivers from the neutral build dir and must reference pcaps absolutely.
DATASETS="$(cd "${DATASETS}" 2>/dev/null && pwd || echo "${DATASETS}")"
# Make the output dir and golden list absolute too: the drivers run from a
# neutral build dir (see above), so any relative path would resolve there.
mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
case "${GOLDEN_LIST}" in
    /*) : ;;
    *)  GOLDEN_LIST="$(cd "$(dirname "${GOLDEN_LIST}")" && pwd)/$(basename "${GOLDEN_LIST}")" ;;
esac
CLASS_DIR="${OUT_DIR}/classification"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

say() { printf '  %s\n' "$*"; }

say "repo root      : ${REPO_ROOT}"
say "install prefix : ${PREFIX}"
say "data-sets      : ${DATASETS}"

if [ ! -d "${DATASETS}" ]; then
    echo "✗ mmt-test data-sets not found at: ${DATASETS}" >&2
    echo "  Set MMT_TEST_DATASETS to the correct path and re-run." >&2
    exit 1
fi

mkdir -p "${CLASS_DIR}"

# --- 1. build + install the library at -O3 ---------------------------------
say "[1/5] building + installing library at -O3 ..."
BUILD_LOG="${BUILD_DIR}/build.log"
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ library build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ library install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
say "      installed to ${PREFIX}/dpi/lib"

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"
export LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}"

# --- 2. compile the drivers ------------------------------------------------
say "[2/5] compiling phase0 drivers ..."
gcc -O2 -Wall -o "${BUILD_DIR}/phase0_classify" \
    "${SCRIPT_DIR}/phase0_classify.c" -I "${INC}" -L "${LIB}" -lmmt_core -ldl -lpcap
gcc -O2 -Wall -o "${BUILD_DIR}/phase0_throughput" \
    "${SCRIPT_DIR}/phase0_throughput.c" -I "${INC}" -L "${LIB}" -lmmt_core -ldl -lpcap

# --- read the golden pcap list ---------------------------------------------
mapfile -t PCAPS < <(grep -vE '^\s*(#|$)' "${GOLDEN_LIST}")
if [ "${#PCAPS[@]}" -eq 0 ]; then
    echo "✗ golden pcap list is empty: ${GOLDEN_LIST}" >&2
    exit 1
fi
say "      golden set: ${#PCAPS[@]} pcaps"

# Run the drivers from the neutral build dir so the SDK's CWD-relative
# "plugins/" lookup misses and falls back to ${PREFIX}/plugins (see note above).
cd "${BUILD_DIR}"

# --- 3. classification fingerprints ----------------------------------------
say "[3/5] capturing classification fingerprints ..."
COMBINED="${OUT_DIR}/classification.txt"
: > "${COMBINED}"
missing=0
for rel in "${PCAPS[@]}"; do
    pcap="${DATASETS}/${rel}"
    safe="$(printf '%s' "${rel}" | tr '/' '_')"
    if [ ! -f "${pcap}" ]; then
        say "      ⚠ missing: ${rel}"
        missing=$((missing + 1))
        continue
    fi
    # A driver failure (e.g. a pcap whose link-type mmt_init_handler does not
    # support) is recorded as a stable marker, not a fatal error — that keeps
    # the fingerprint complete and would flag a future change in DLT support.
    if ! "${BUILD_DIR}/phase0_classify" "${pcap}" \
            > "${CLASS_DIR}/${safe}.txt" 2>"${BUILD_DIR}/cls.err"; then
        # Normalize away the host-specific dataset path so the marker (and the
        # committed fingerprint) stays identical across machines.
        reason="$(tr '\n' ' ' < "${BUILD_DIR}/cls.err" \
                  | sed "s#${DATASETS}/##g;s/  */ /g;s/ *$//")"
        printf '<unclassified: %s>\n' "${reason:-driver error}" > "${CLASS_DIR}/${safe}.txt"
    fi
    {
        printf '### %s\n' "${rel}"
        cat "${CLASS_DIR}/${safe}.txt"
        printf '\n'
    } >> "${COMBINED}"
done
say "      wrote ${CLASS_DIR}/ and ${COMBINED}"
[ "${missing}" -gt 0 ] && say "      (${missing} pcap(s) missing — see warnings above)"

# --- 4. throughput baseline ------------------------------------------------
say "[4/5] capturing throughput baseline (${ITERATIONS} iterations/pcap) ..."
THRU="${OUT_DIR}/throughput.txt"
{
    printf '# Phase 0 throughput baseline — packets/second, in-memory replay.\n'
    printf '# Environment-dependent: compare relative deltas, not absolute pps.\n'
    printf '# RSS columns (issue #251): the trace is preloaded, not streamed —\n'
    printf '# harness_rss_kib is the preload cost subtracted explicitly, and\n'
    printf '# library_rss_kib is the RSS delta attributable to the SDK on top of it.\n'
    printf '# host: %s | cpu: %s | iterations: %s\n' \
        "$(uname -m)" "$(nproc 2>/dev/null || echo '?')" "${ITERATIONS}"
    printf '#\n# pcap\tpackets\titerations\telapsed_s\tpps\tharness_rss_kib\tlibrary_rss_kib\tpeak_rss_kib\n'
} > "${THRU}"
for rel in "${PCAPS[@]}"; do
    pcap="${DATASETS}/${rel}"
    [ -f "${pcap}" ] || continue
    if line="$("${BUILD_DIR}/phase0_throughput" "${pcap}" "${ITERATIONS}" 2>/dev/null)"; then
        printf '%s\t%s\n' "${rel}" "${line}" >> "${THRU}"
    else
        printf '%s\tn/a\tn/a\tn/a\tn/a\tn/a\tn/a\t<unsupported link-type>\n' "${rel}" >> "${THRU}"
    fi
done
say "      wrote ${THRU}"

# --- 5. valgrind leak baseline ---------------------------------------------
say "[5/5] valgrind leak baseline ..."
VG="${OUT_DIR}/valgrind.txt"
VG_PCAP="${DATASETS}/ftp/ftp_multiple_session.pcap"
[ -f "${VG_PCAP}" ] || VG_PCAP="${DATASETS}/${PCAPS[0]}"
if command -v valgrind >/dev/null 2>&1; then
    say "      running valgrind on $(basename "${VG_PCAP}") ..."
    valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=0 \
        "${BUILD_DIR}/phase0_classify" "${VG_PCAP}" >/dev/null 2>"${VG}" || true
    say "      wrote ${VG}"
else
    {
        printf '# Valgrind leak baseline — SKIPPED: valgrind not installed on this host.\n'
        printf '#\n# To capture on a host with valgrind:\n'
        printf '#   make -C sdk clean && make -C sdk MMT_BASE=%s && make -C sdk MMT_BASE=%s install\n' "${PREFIX}" "${PREFIX}"
        printf '#   gcc -O2 -o phase0_classify tools/phase0/phase0_classify.c \\\n'
        printf '#       -I %s/dpi/include -L %s/dpi/lib -lmmt_core -ldl -lpcap\n' "${PREFIX}" "${PREFIX}"
        printf '#   LD_LIBRARY_PATH=%s/dpi/lib valgrind --leak-check=full \\\n' "${PREFIX}"
        printf '#       --show-leak-kinds=all ./phase0_classify %s\n' "${VG_PCAP}"
    } > "${VG}"
    say "      ⚠ valgrind not found — wrote SKIPPED note to ${VG}"
fi

echo
say "✓ Phase 0 baseline captured under ${OUT_DIR}"
say "  Re-run after each phase and: git diff ${OUT_DIR}/classification.txt"
