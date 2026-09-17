#!/usr/bin/env bash
#
# run_session_scale_test.sh — build + run the issue #254 session-scale harness
# (F-PERF-011/012/013) against a plain build of the SDK.
#
# Steps:
#   1. Build + install the SDK into an isolated prefix.
#   2. Compile tools/phase0/tests/session_scale_test.c against that library.
#      Internal headers (packet_processing.h, hash_utils.h) are pulled from
#      the source tree — they are not part of the installed public include set.
#   3. Run it. The harness bursts 100k sessions through packet_process(),
#      asserts the timeout index performs zero allocations across a >400k-op
#      milestone churn (interposed malloc/calloc counter), then idles the
#      clock so the whole burst expires and checks resident memory is back
#      within 20% of pre-burst.
#
# The build must stay non-sanitized: ASan owns malloc and quarantines freed
# blocks, which defeats both the allocation counter and the RSS check.
#
# Usage: tools/phase0/tests/run_session_scale_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_SCALE_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/scale.XXXXXX")}"
BIN="$(mktemp -d)/session_scale_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_SCALE_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling session_scale_test"
gcc -g -O1 -o "${BIN}" "${TEST_DIR}/session_scale_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running session_scale_test"
# Run from the install prefix so the SDK's CWD-relative "plugins/" lookup
# finds the freshly installed protocol plugins (same convention as
# run_caplen_clamp_test.sh).
set +e
( cd "${PREFIX}" && \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    "${BIN}" )
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ session-scale test: PASS"
else
    echo "✗ session-scale test: FAIL (rc=${rc})"
fi
exit "${rc}"
