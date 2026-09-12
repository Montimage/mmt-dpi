#!/usr/bin/env bash
#
# run_port_confirm_test.sh — build the payload-confirmed port-only demotion
# predicate unit test against an ASan/UBSan-instrumented build of the SDK and
# run it (issue #75, M9 round 3).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/port_confirm_test.c against that library,
#      itself instrumented with -fsanitize=address,undefined. The predicate
#      under test (mmt_payload_confirms_proto) is exported from libmmt_tcpip but
#      not part of any installed public header, so the test re-declares it and
#      links libmmt_tcpip directly.
#   3. Run it. With -fno-sanitize-recover=all any sanitizer hit aborts; all
#      assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_port_confirm_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/port_confirm_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling port_confirm_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/port_confirm_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm -lpcap

echo "[3/3] running port_confirm_test under ASan/UBSan"
set +e
( LD_PRELOAD="$(gcc -print-file-name=libasan.so)" \
  ASAN_OPTIONS="detect_leaks=0" \
  UBSAN_OPTIONS="print_stacktrace=1" \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
      "${BIN}" )
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ port-confirm predicate test: PASS"
else
    echo "✗ port-confirm predicate test: FAIL (rc=${rc})"
fi
exit "${rc}"
