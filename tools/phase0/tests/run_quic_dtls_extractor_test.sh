#!/usr/bin/env bash
#
# run_quic_dtls_extractor_test.sh — build the QUIC-IETF / DTLS extractor
# regression test against an ASan/UBSan-instrumented build of the SDK and run
# it (issue #203: F-BUG-063 + F-BUG-070 + F-BUG-071).
#
#   F-BUG-063  _extraction_quic_ietf_att() overlaid a packed struct with
#              pointer members on the packet bytes (corrupting the capture)
#              and walked a caplen-blind cursor.
#   F-BUG-071  the connection-id extractor wrote into the attribute_t and
#              %-printed raw packet bytes.
#   F-BUG-070  _dtls_client_hello_extract_attribute() published a cipher-suite
#              array length larger than the fixed BINARY_64DATA_LEN capacity.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/quic_dtls_extractor_test.c against that
#      library, itself instrumented with -fsanitize=address,undefined.
#   3. Run it. With -fno-sanitize-recover=all, any out-of-bounds read/write
#      aborts with non-zero status; all assertions must pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_quic_dtls_extractor_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/quic_dtls_extractor_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling quic_dtls_extractor_test (ASan/UBSan)"
# mmt_session_struct lives in the core private headers; the tcpip plugin
# structs, attribute ids and the quic protocol header are in-tree only.
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/quic_dtls_extractor_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_tcpip/include" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running quic_dtls_extractor_test under ASan/UBSan"
rc=0
ASAN_OPTIONS="detect_leaks=0" \
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}" || rc=$?

if [ "${rc}" -eq 0 ]; then
    echo "✓ QUIC/DTLS extractor test: PASS"
else
    echo "✗ QUIC/DTLS extractor test: FAIL (rc=${rc})"
fi
exit "${rc}"
