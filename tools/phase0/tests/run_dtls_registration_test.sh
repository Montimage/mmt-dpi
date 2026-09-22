#!/usr/bin/env bash
#
# run_dtls_registration_test.sh — build the DTLS plugin-registration
# end-to-end test against an ASan/UBSan-instrumented build of the SDK and run
# it (issue #262).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/dtls_registration_test.c against that
#      library, itself instrumented with -fsanitize=address,undefined.
#   3. Generate the synthetic DTLS pcap via gen_tcpip_pcap.py.
#   4. Run the test from a scratch directory so the SDK's CWD-relative
#      plugins/ lookup misses and plugin loading falls back to the ASan
#      prefix (same convention as run_tcpip_pcap_harness_test.sh).
#
# Usage: tools/phase0/tests/run_dtls_registration_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${TEST_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
WORK="$(mktemp -d)"
BIN="${WORK}/dtls_registration_test"
trap 'rm -rf "${WORK}"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/4] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/4] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/4] compiling dtls_registration_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/dtls_registration_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap -lpthread -lm

echo "[3/4] generating synthetic DTLS pcap"
python3 "${PHASE0_DIR}/gen_tcpip_pcap.py" --out-dir "${WORK}" --pcap dtls >/dev/null

echo "[4/4] running dtls_registration_test under ASan/UBSan"
rc=0
# Run from WORK so the CWD-relative plugins/ lookup misses and the plugin is
# dlopened from ${PREFIX}/plugins (the repo root has a plugins/ symlink to the
# non-ASan in-tree build).
(cd "${WORK}" && \
    ASAN_OPTIONS="detect_leaks=0" \
    LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
        "${BIN}" "${WORK}/dtls.pcap") || rc=$?

if [ "${rc}" -eq 0 ]; then
    echo "✓ DTLS registration test: PASS"
else
    echo "✗ DTLS registration test: FAIL (rc=${rc})"
fi
exit "${rc}"
