#!/usr/bin/env bash
#
# run_tcp_doff_min_test.sh — build the TCP data-offset (doff) minimum-length
# validation test against an ASan/UBSan-instrumented build of the SDK and run it
# (issue #25, M6).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/tcp_doff_min_test.c against that library,
#      itself instrumented with -fsanitize=address,undefined.
#   3. Run it. With -fno-sanitize-recover=all, any out-of-bounds read aborts
#      with non-zero status; all assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_tcp_doff_min_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-/tmp/mmt-asan-tcp-doff}"
BIN="$(mktemp -d)/tcp_doff_min_test"
trap 'rm -rf "$(dirname "${BIN}")"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling tcp_doff_min_test (ASan/UBSan)"
# The internal packet/session structs (mmt_tcpip_internal_packet_struct,
# mmt_internal_tcpip_session_struct) are not part of the installed public
# headers, so add the in-tree plugin include paths. The layout matches the
# compiled library byte-for-byte (same header).
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/tcp_doff_min_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running tcp_doff_min_test under ASan/UBSan"
ASAN_OPTIONS="detect_leaks=0" \
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}"
rc=$?

if [ "${rc}" -eq 0 ]; then
    echo "✓ TCP data-offset minimum validation test: PASS"
else
    echo "✗ TCP data-offset minimum validation test: FAIL (rc=${rc})"
fi
exit "${rc}"
