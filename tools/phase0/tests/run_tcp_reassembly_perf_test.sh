#!/usr/bin/env bash
#
# run_tcp_reassembly_perf_test.sh — build + run the issue #245 bounded
# TCP-reassembly harness (F-PERF-003/004/005/006, F-BUG-038) against a plain
# build of the SDK.
#
# Steps:
#   1. Build + install the SDK into an isolated prefix.
#   2. Compile tools/phase0/tests/tcp_reassembly_perf_test.c against that
#      library. Internal headers (packet_processing.h — the reassembly stat
#      accessors) are pulled from the source tree; they are not installed.
#   3. Run it. The harness streams synthetic TCP flows through
#      process_packet_with_reassembly() and asserts: zero list walks for
#      in-order/reversed arrivals, zero steady-state packet allocations,
#      exactly-once byte flattening, duplicate/overlap handling, 32-bit
#      sequence wraparound, the per-flow ceiling, and a clean teardown.
#
# The build stays non-sanitized so the ns/packet timing is meaningful (the
# aggregate runner groups this script with the default profile). For ASan
# coverage compile the same source with -fsanitize=address against a
# BUILD=asan SDK prefix (MMT_SDK_PREBUILT=1 + MMT_REASM_PREFIX).
#
# Usage: tools/phase0/tests/run_tcp_reassembly_perf_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_REASM_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/reasm.XXXXXX")}"
BIN="$(mktemp -d)/tcp_reassembly_perf_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_REASM_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling tcp_reassembly_perf_test"
gcc -g -O1 -o "${BIN}" "${TEST_DIR}/tcp_reassembly_perf_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running tcp_reassembly_perf_test"
# Run from the install prefix so the SDK's CWD-relative "plugins/" lookup
# finds the freshly installed protocol plugins.
set +e
( cd "${PREFIX}" && \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}" )
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ TCP reassembly perf test: PASS"
else
    echo "✗ TCP reassembly perf test: FAIL (rc=${rc})"
fi
exit "${rc}"
