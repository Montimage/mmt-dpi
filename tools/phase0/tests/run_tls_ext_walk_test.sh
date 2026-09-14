#!/usr/bin/env bash
#
# run_tls_ext_walk_test.sh — build the TLS extension-walk / extractor-offset
# regression test against an ASan/UBSan-instrumented build of the SDK and run
# it (issue #203: F-BUG-064 + F-BUG-073).
#
#   F-BUG-064  getServerNameFromClientHello() walked the ClientHello extension
#              list with a uint16_t cursor; a declared extension length of
#              0xFFFC wrapped the cursor (6 + 65532 -> 2) and the loop
#              re-read the same header forever. The harness bounds this with
#              alarm(): a wrap is a loud failure, not a stalled test.
#   F-BUG-073  the tls_{content_type,version,length}_extraction() functions
#              trusted get_packet_offset_at_index() results that can be -1
#              and read the TLS record header at wild offsets.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/tls_ext_walk_test.c against that library,
#      itself instrumented with -fsanitize=address,undefined.
#   3. Run it. With -fno-sanitize-recover=all, any out-of-bounds read aborts
#      with non-zero status; all assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_tls_ext_walk_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/tls_ext_walk_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling tls_ext_walk_test (ASan/UBSan)"
# The internal packet struct is not part of the installed public headers, so
# add the in-tree plugin include paths (layout matches the compiled library).
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/tls_ext_walk_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_tcpip/include" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running tls_ext_walk_test under ASan/UBSan"
rc=0
ASAN_OPTIONS="detect_leaks=0" \
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}" || rc=$?

if [ "${rc}" -eq 0 ]; then
    echo "✓ TLS extension-walk / extractor-offset test: PASS"
else
    echo "✗ TLS extension-walk / extractor-offset test: FAIL (rc=${rc})"
fi
exit "${rc}"
