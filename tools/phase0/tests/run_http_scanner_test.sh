#!/usr/bin/env bash
#
# run_http_scanner_test.sh — build the bounded HTTP scanner / ctype hardening
# test against an ASan/UBSan-instrumented build of the SDK and run it
# (issue #7, H4 + H5).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/http_scanner_test.c against that library,
#      itself instrumented with -fsanitize=address,undefined. The internal
#      packet struct header is pulled from the source tree (it is not part of
#      the installed public include set).
#   3. Run it. With -fno-sanitize-recover=all, any out-of-bounds read or
#      undefined ctype call aborts with non-zero status; all assertions must
#      also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_http_scanner_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-/tmp/mmt-asan-http-scanner}"
BIN="$(mktemp -d)/http_scanner_test"
trap 'rm -rf "$(dirname "${BIN}")"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling http_scanner_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/http_scanner_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running http_scanner_test under ASan/UBSan"
ASAN_OPTIONS="detect_leaks=0" \
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}"
rc=$?

if [ "${rc}" -eq 0 ]; then
    echo "✓ HTTP scanner hardening test: PASS"
else
    echo "✗ HTTP scanner hardening test: FAIL (rc=${rc})"
fi
exit "${rc}"
