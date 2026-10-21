#!/usr/bin/env bash
#
# run_tunnel_parent_lifetime_test.sh — build the issue #499 regression test
# against an ASan/UBSan-instrumented build of the SDK and run it.
#
# Issue #499 (F-BUG-001): a tunnel child session kept a raw pointer to its
# parent (outer) session that nothing reference-counted; when the outer
# session expired first, the next tunnel packet dereferenced freed memory.
# The harness expires the outer session's own timeout first and requires a
# clean run under ASan/UBSan.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/tunnel_parent_lifetime_test.c against it,
#      itself instrumented with -fsanitize=address,undefined.
#   3. Run it. With -fno-sanitize-recover=all any sanitizer finding aborts
#      with non-zero status; all assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_tunnel_parent_lifetime_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/tunnel_parent_lifetime_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling tunnel_parent_lifetime_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/tunnel_parent_lifetime_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap

echo "[3/3] running tunnel_parent_lifetime_test under ASan/UBSan"
# Preload the ASan runtime: the SDK is pulled in via dlopen, so the runtime
# cannot be resolved from the executable alone (see tools/phase0/README.md).
# Run from the install prefix so the SDK's CWD-relative "plugins/" lookup
# resolves to this BUILD=asan plugin set.
set +e
( cd "${PREFIX}" && \
  LD_PRELOAD="$(gcc -print-file-name=libasan.so)" \
  ASAN_OPTIONS="detect_leaks=0" \
  UBSAN_OPTIONS="print_stacktrace=1" \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
      "${BIN}" )
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ tunnel parent lifetime (issue #499) test: PASS"
else
    echo "✗ tunnel parent lifetime (issue #499) test: FAIL (rc=${rc})"
fi
exit "${rc}"
