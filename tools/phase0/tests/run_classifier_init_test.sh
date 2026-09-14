#!/usr/bin/env bash
#
# run_classifier_init_test.sh — build the classifier-wiring / hostname-table
# regression harness (issue #212: F-BUG-041 checked registration, F-BUG-026
# reverse-matcher bounds, F-BUG-030 hostname-trie guards) against an
# ASan/UBSan-instrumented SDK and run it.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/classifier_init_test.c against that library,
#      itself instrumented with -fsanitize=address,undefined. The entry points
#      under test (mmt_register_classifier, the reverse-matcher wrapper,
#      get_proto_id_by_hostname) are exported from libmmt_tcpip but not part
#      of the installed public headers, so they are declared in
#      internal_decls.h and the test links libmmt_tcpip directly.
#   3. Run it. With -fno-sanitize-recover=all any sanitizer hit aborts; all
#      assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_classifier_init_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/classifier_init_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling classifier_init_test (ASan/UBSan)"
# packet_processing.h (private) supplies the mmt_session_struct layout the
# harness fills; mmt_tcpip_protocols.h supplies the PROTO_* ids.
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/classifier_init_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/include" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm -lpcap

echo "[3/3] running classifier_init_test under ASan/UBSan"
# Preload the ASan runtime (the SDK is also pulled in via dlopen) and run from
# the install prefix so the SDK's CWD-relative "plugins/" lookup resolves.
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
    echo "✓ classifier init / hostname-table test: PASS"
else
    echo "✗ classifier init / hostname-table test: FAIL (rc=${rc})"
fi
exit "${rc}"
