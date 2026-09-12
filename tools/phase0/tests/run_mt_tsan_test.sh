#!/usr/bin/env bash
#
# run_mt_tsan_test.sh — build the multi-threaded thread-safety harness against a
# ThreadSanitizer-instrumented build of the SDK and run it (issue #65).
#
# This mechanically verifies the Phase 6 thread-safety work that was previously
# "verified by construction" only:
#   - #22  global registry mutexes (packet_processing.c / plugins_engine.c)
#   - #23  per-session RADIUS parser state (proto_radius.c)
#   - #67  handler bookkeeping map mutex (packet_processing.c)
#
# TSan only finds races in code built with -fsanitize=thread, and the race-prone
# code lives INSIDE the SDK libraries. So, mirroring run_redis_resp_test.sh, we:
#   1. Build + install the SDK with BUILD=tsan into an isolated prefix. The
#      install step also copies the freshly built (TSan) libmmt_tcpip.so into the
#      prefix's plugins dir, so the dlopen'd protocol plugin is TSan-instrumented
#      too (the core was compiled to look there via PLUGINS_REPOSITORY_OPT).
#   2. Synthesize a multi-flow RADIUS pcap (pure stdlib generator).
#   3. Compile tools/phase0/tests/mt_tsan_harness.c with -fsanitize=thread and
#      link it against the installed TSan libraries.
#   4. Run the harness under TSan in replay, registry-stress and handler-churn
#      modes over the RADIUS pcap and an existing TCP pcap. With
#      -fno-sanitize-recover=all a data race aborts the process; fingerprint
#      mismatches exit non-zero too.
#
# Usage: tools/phase0/tests/run_mt_tsan_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${TEST_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
PREFIX="${MMT_TSAN_PREFIX:-/tmp/mmt-tsan-mt}"
WORK="$(mktemp -d)"
BIN="${WORK}/mt_tsan_harness"
RADIUS_PCAP="${WORK}/radius.pcap"
SUPP="${TEST_DIR}/mt_tsan_suppressions.txt"
NUM_THREADS="${MT_TSAN_THREADS:-8}"

trap 'rm -rf "${WORK}"; [ "${MMT_SDK_PREBUILT:-0}" = "1" ] || rm -rf "${PREFIX}"' EXIT

CC="${CC:-gcc}"

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/4] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/4] building + installing SDK with BUILD=tsan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" BUILD=tsan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=tsan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/4] generating multi-flow RADIUS pcap"
python3 "${PHASE0_DIR}/gen_radius_pcap.py" "${RADIUS_PCAP}"

echo "[3/4] compiling mt_tsan_harness (ThreadSanitizer)"
"${CC}" -g -O1 -fsanitize=thread -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/mt_tsan_harness.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap -lpthread -lm

export LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}"
export TSAN_OPTIONS="halt_on_error=1 second_deadlock_stack=1 suppressions=${SUPP}"

TCP_PCAP="${PHASE0_DIR}/ci/pcaps/tcp_ecn_sample.pcap"

# Newer Linux kernels randomise mmap with enough entropy that the TSan runtime
# aborts with "unexpected memory mapping". Running with ASLR disabled
# (setarch -R) sidesteps it; harmless where it is not needed. Fall back to a
# direct run if setarch is unavailable.
RUNNER=()
if command -v setarch >/dev/null 2>&1 && setarch -R true >/dev/null 2>&1; then
    RUNNER=(setarch -R)
fi

echo "[4/4] running mt_tsan_harness under ThreadSanitizer"
rc=0

run_case() {
    local desc="$1"; shift
    echo "  -> ${desc}"
    # Run from the temp dir: the core looks for a relative "plugins/" first
    # (PLUGINS_REPOSITORY) and only falls back to the installed absolute path
    # (PLUGINS_REPOSITORY_OPT) when that is absent. The repo root has a stale
    # plugins/ symlink to the default (non-TSan) build, so executing elsewhere
    # guarantees the dlopen'd libmmt_tcpip.so is the just-installed TSan one.
    if ! ( cd "${WORK}" && "${RUNNER[@]}" "${BIN}" "$@" ); then
        echo "    FAIL: ${desc}"
        rc=1
    fi
}

run_case "replay RADIUS pcap (per-session RADIUS state, #23)" \
    replay "${RADIUS_PCAP}" "${NUM_THREADS}"
run_case "replay TCP pcap" \
    replay "${TCP_PCAP}" "${NUM_THREADS}"
run_case "registry mutex stress (#22)" \
    registry-stress "${NUM_THREADS}" 200
run_case "concurrent handler create/destroy (#67)" \
    handler-churn "${NUM_THREADS}" 200

echo
if [ "${rc}" -eq 0 ]; then
    echo "✓ Multi-threaded TSan harness: PASS (no data races, fingerprints match)"
else
    echo "✗ Multi-threaded TSan harness: FAIL"
fi
exit "${rc}"
