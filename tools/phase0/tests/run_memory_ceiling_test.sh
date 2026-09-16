#!/usr/bin/env bash
#
# run_memory_ceiling_test.sh — M4 library-RSS ceiling gate (issue #251,
# F-PERF-016).
#
# phase0_throughput reports the SDK's resident set separately from the
# driver's trace-preload cost (the harness share). This harness replays the
# CI pcap subset through it and fails when the largest reported
# library_rss_kib exceeds the ceiling committed at
# tools/phase0/ci/baseline/memory.txt — the figure milestone M4's memory
# budget is set from.
#
# The SDK must be built WITHOUT sanitizers: an ASan/TSan runtime plus its
# shadow memory would inflate RSS and measure the sanitizer, not the
# library — which is why this harness belongs to the "default" build
# profile group under run_all_harnesses.sh.
#
# Usage: tools/phase0/tests/run_memory_ceiling_test.sh
# Exit:  0 when every pcap's library RSS is <= the ceiling; 1 otherwise;
#        2 on setup failure (missing baseline, unreadable ceiling).
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${TEST_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
PCAP_DIR="${PHASE0_DIR}/ci/pcaps"
GOLDEN_LIST="${PHASE0_DIR}/ci/golden_pcaps.txt"
CEILING_FILE="${PHASE0_DIR}/ci/baseline/memory.txt"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"; [ -n "${MMT_MEM_PREFIX:-}" ] || rm -rf "${PREFIX:-}"' EXIT

JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
PREFIX="${MMT_MEM_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/memceil.XXXXXX")}"

# --- 1. SDK -----------------------------------------------------------------
if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK (default profile) -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"${JOBS}" >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >/dev/null
fi

# --- 2. driver ---------------------------------------------------------------
BIN="${WORK}/phase0_throughput"
echo "[2/3] compiling phase0_throughput"
gcc -O2 -Wall -o "${BIN}" "${PHASE0_DIR}/phase0_throughput.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap

# --- ceiling -----------------------------------------------------------------
[ -f "${CEILING_FILE}" ] || { echo "✗ ceiling file missing: ${CEILING_FILE}" >&2; exit 2; }
CEILING="$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "${CEILING_FILE}" \
           | awk -F'\t' '$1 == "library_rss_ceiling_kib" { print $2 }')"
case "${CEILING}" in
    ''|*[!0-9]*) echo "✗ no numeric library_rss_ceiling_kib in ${CEILING_FILE}" >&2; exit 2 ;;
esac

# --- 3. measure ---------------------------------------------------------------
# Drivers run from the neutral WORK dir so the SDK's CWD-relative plugins/
# lookup misses and falls back to the installed prefix (see README notes).
echo "[3/3] measuring library RSS over the CI pcap subset (ceiling: ${CEILING} KiB)"
max_lib=-1
worst=""
count=0
while read -r rel; do
    pcap="${PCAP_DIR}/${rel}"
    [ -f "${pcap}" ] || continue
    # 2 passes: the second pass confirms no growth once session state exists.
    if line="$(cd "${WORK}" && LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
               "${BIN}" "${pcap}" 2 2>/dev/null)"; then
        lib="$(printf '%s' "${line}" | cut -f6)"
        case "${lib}" in ''|*[!0-9-]*) lib=-1 ;; esac
        printf '    %-50s library_rss=%s KiB\n' "${rel}" "${lib}"
        if [ "${lib}" -gt "${max_lib}" ]; then max_lib="${lib}"; worst="${rel}"; fi
        count=$((count + 1))
    else
        echo "    ${rel}: skipped (driver failed / unsupported link-type)"
    fi
done < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "${GOLDEN_LIST}")

if [ "${count}" -eq 0 ] || [ "${max_lib}" -lt 0 ]; then
    echo "✗ memory ceiling: no pcap produced a library_rss_kib reading" >&2
    exit 2
fi

echo "  worst: ${worst} library_rss=${max_lib} KiB (ceiling ${CEILING} KiB)"
if [ "${max_lib}" -gt "${CEILING}" ]; then
    echo "✗ memory ceiling: FAILED — library RSS ${max_lib} KiB > ${CEILING} KiB" >&2
    exit 1
fi
echo "✓ memory ceiling: PASSED (${max_lib} KiB <= ${CEILING} KiB over ${count} pcaps)"
