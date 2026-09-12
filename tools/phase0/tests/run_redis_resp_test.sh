#!/usr/bin/env bash
#
# run_redis_resp_test.sh — build the Redis RESP first-byte heuristic unit test
# against an ASan/UBSan-instrumented build of the SDK and run it (issue #60).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/redis_resp_test.c against that library,
#      itself instrumented with -fsanitize=address,undefined. The decision
#      helpers under test (redis_is_resp_opener / redis_resp_exchange_match) are
#      exported from proto_redis.c but not part of any installed public header,
#      so the test re-declares them and links libmmt_tcpip directly.
#   3. Run it. With -fno-sanitize-recover=all any sanitizer hit aborts; all
#      assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_redis_resp_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-/tmp/mmt-asan-redis-resp}"
BIN="$(mktemp -d)/redis_resp_test"
trap 'rm -rf "$(dirname "${BIN}")"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling redis_resp_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/redis_resp_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running redis_resp_test under ASan/UBSan"
ASAN_OPTIONS="detect_leaks=0" \
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}"
rc=$?

if [ "${rc}" -eq 0 ]; then
    echo "✓ Redis RESP heuristic test: PASS"
else
    echo "✗ Redis RESP heuristic test: FAIL (rc=${rc})"
fi
exit "${rc}"
