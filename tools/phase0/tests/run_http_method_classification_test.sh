#!/usr/bin/env bash
#
# run_http_method_classification_test.sh — build the HTTP method-table
# regression test against an ASan/UBSan-instrumented build of the SDK and run
# it (issue #101, ACC-16: PATCH/MKCOL/LOCK method recognition).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/http_method_classification_test.c against
#      that library, itself instrumented with -fsanitize=address,undefined.
#   3. Run it. With -fno-sanitize-recover=all, any sanitizer hit aborts with
#      non-zero status; all assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_http_method_classification_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-/tmp/mmt-asan-http-method-classification}"
BIN="$(mktemp -d)/http_method_classification_test"
trap 'rm -rf "$(dirname "${BIN}")"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling http_method_classification_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/http_method_classification_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running http_method_classification_test under ASan/UBSan"
rc=0
ASAN_OPTIONS="detect_leaks=0" \
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}" || rc=$?

if [ "${rc}" -eq 0 ]; then
    echo "✓ HTTP method classification test: PASS"
else
    echo "✗ HTTP method classification test: FAIL (rc=${rc})"
fi
exit "${rc}"
