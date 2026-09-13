#!/usr/bin/env bash
#
# run_http_session_test.sh — build the HTTP session-lifetime regression
# harness against an ASan/UBSan-instrumented SDK build and run it with
# LeakSanitizer enabled (issue #204: F-BUG-048, F-BUG-053, F-BUG-056,
# F-BUG-058).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/http_session_test.c against that library,
#      itself instrumented with -fsanitize=address,undefined. Internal headers
#      (mmt_tcpip_plugin_structs.h, packet_processing.h, http_parser*.h,
#      protocols/http.h) are pulled from the source tree — they are not part
#      of the installed public include set.
#   3. Run it with ASAN_OPTIONS=detect_leaks=1. The harness replays 10,000
#      HTTP requests through http_session_data_analysis() on one session and
#      then invokes the registered cleanup; any allocation the library forgot
#      to free is reported by LeakSanitizer at exit. Exit 0 + all checks ==
#      clean.
#
# Usage: tools/phase0/tests/run_http_session_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/http_session_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling http_session_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/http_session_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running http_session_test under ASan/UBSan + LeakSanitizer"
# Run from the install prefix so the SDK's CWD-relative "plugins/" lookup
# finds the freshly installed protocol plugins (same convention as
# run_caplen_clamp_test.sh).
( cd "${PREFIX}" && \
  ASAN_OPTIONS="detect_leaks=1" \
  LSAN_OPTIONS="suppressions=${TEST_DIR}/http_session_lsan_suppressions.txt" \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}" )
rc=$?

if [ "${rc}" -eq 0 ]; then
    echo "✓ HTTP session lifetime test: PASS (10,000 requests, zero leaks)"
else
    echo "✗ HTTP session lifetime test: FAIL (rc=${rc})"
fi
exit "${rc}"
