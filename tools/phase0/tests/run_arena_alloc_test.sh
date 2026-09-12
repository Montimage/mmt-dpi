#!/usr/bin/env bash
#
# run_arena_alloc_test.sh — build + run the per-flow arena allocator unit test
# (issue #20, Phase 5 P2). Verifies mmt_arena_create/alloc/reset/destroy hand
# out distinct, aligned, writable blocks, grow correctly, and are NULL-safe.
#
# The test is built with AddressSanitizer + UBSan so any out-of-bounds write
# inside an arena block (the blocks are real malloc()s, tracked by the ASan
# runtime in this executable) is caught even though the library itself need not
# be an ASan build. With -fno-sanitize-recover=all a sanitizer hit aborts.
#
# Usage: tools/phase0/tests/run_arena_alloc_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ARENA_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/arena.XXXXXX")}"
BIN="$(mktemp -d)/arena_alloc_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ARENA_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling arena_alloc_test (ASan + UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/arena_alloc_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpthread -lm

echo "[3/3] running arena_alloc_test"
set +e
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    ASAN_OPTIONS=detect_leaks=0 "${BIN}"
rc=$?
set -e
if [ "${rc}" -ne 0 ]; then
    echo "✗ arena allocator test: FAIL (rc=${rc})"
    exit "${rc}"
fi

echo "✓ arena allocator test: PASS"
exit 0
