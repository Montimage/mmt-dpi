#!/usr/bin/env bash
#
# run_position_unknown_guard_test.sh — build + run the POSITION_NOT_KNOWN
# central-caplen-guard test against an ASan/UBSan-instrumented build of the
# SDK (issue #193, F-BUG-032).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix. The
#      sanitizer build also arms the mmt_caplen_guard_* tripwire counters in
#      packet_processing.c (they compile under MMT_BUILD_ASAN), so the corpus
#      leg can assert that 0 attributes reached an extractor with no caplen
#      validation — and every extractor the golden pcaps exercise runs under
#      ASan/UBSan on top.
#   2. Compile tools/phase0/tests/position_unknown_guard_test.c against that
#      library, itself instrumented. The test pulls attribute_internal_struct
#      and mmt_handler_struct from the in-tree private header
#      src/mmt_core/private_include/packet_processing.h and the internal
#      entry points from internal_decls.h (issue #186 convention).
#   3. Run it from the install prefix (CWD-relative "plugins/" lookup) over
#      the vendored golden pcap subset tools/phase0/ci/pcaps/.
#      With -fno-sanitize-recover=all any sanitizer hit aborts; all
#      assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_position_unknown_guard_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/position_unknown_guard_test"
PCAP_DIR="${REPO_ROOT}/tools/phase0/ci/pcaps"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling position_unknown_guard_test (ASan/UBSan)"
# The attribute_internal_struct / mmt_handler_struct layouts come from the
# in-tree private header, identical to what the library was compiled with.
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/position_unknown_guard_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm -lpcap

echo "[3/3] running position_unknown_guard_test under ASan/UBSan over ${PCAP_DIR}"
# Preload the ASan runtime (the SDK is also pulled in via dlopen) and run from
# the install prefix so the SDK's CWD-relative "plugins/" lookup resolves.
set +e
( cd "${PREFIX}" && \
  LD_PRELOAD="$(gcc -print-file-name=libasan.so)" \
  ASAN_OPTIONS="detect_leaks=0" \
  UBSAN_OPTIONS="print_stacktrace=1" \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
      "${BIN}" "${PCAP_DIR}" )
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ POSITION_NOT_KNOWN caplen-guard test: PASS"
else
    echo "✗ POSITION_NOT_KNOWN caplen-guard test: FAIL (rc=${rc})"
fi
exit "${rc}"
