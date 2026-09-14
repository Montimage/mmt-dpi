#!/usr/bin/env bash
#
# run_dicom_test.sh — build + run the DICOM truncated-PDU /
# out-of-capture-offset test against an ASan/UBSan-instrumented build of
# the SDK (issue #210, F-BUG-099).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/dicom_test.c against that library, itself
#      instrumented. The test #includes src/mmt_dicom/dicom.c so the static
#      _extraction_att() entry point is reachable and instrumented too —
#      pre-fix, the out-of-caplen offsets below read past the end of the
#      captured buffer and abort the run; post-fix they must return 0.
#   3. Run it. With -fno-sanitize-recover=all any sanitizer hit aborts;
#      all assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_dicom_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_DICOM_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/dicom_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_DICOM_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling dicom_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/dicom_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm -lpcap

echo "[3/3] running dicom_test under ASan/UBSan"
set +e
LD_PRELOAD="$(gcc -print-file-name=libasan.so)" \
ASAN_OPTIONS="detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1" \
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}"
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ DICOM caplen-guard test: PASS"
else
    echo "✗ DICOM caplen-guard test: FAIL (rc=${rc})"
fi
exit "${rc}"
