#!/usr/bin/env bash
#
# run_caplen_clamp_test.sh — build the issue #192 regression test against an
# ASan/UBSan-instrumented build of the SDK and run it.
#
# Issue #192 (F-BUG-016): proto_ip.c derived l4_packet_len from the
# attacker-controlled IPv4 tot_len and clamped to the captured length only on
# the reassembly branch, so a 60-byte frame declaring tot_len=65535 produced a
# ~65495-byte payload_packet_len that downstream dissectors trusted as a bound.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/caplen_clamp_test.c against it, itself
#      instrumented with -fsanitize=address,undefined. The internal packet
#      struct header is pulled from the source tree (it is not part of the
#      installed public include set).
#   3. Run it. The library loads its protocol plugins from the compiled-in
#      prefix ($PREFIX/plugins). With -fno-sanitize-recover=all any
#      out-of-bounds read aborts with non-zero status; all assertions must
#      also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_caplen_clamp_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/caplen_clamp_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling caplen_clamp_test (ASan/UBSan)"
# Link only mmt_core (+ libpcap for DLT_EN10MB); the protocol plugins,
# including libmmt_tcpip, are loaded at run time via dlopen — matching
# phase0_classify.
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/caplen_clamp_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap

echo "[3/3] running caplen_clamp_test under ASan/UBSan"
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
    echo "✓ caplen clamp (issue #192) test: PASS"
else
    echo "✗ caplen clamp (issue #192) test: FAIL (rc=${rc})"
fi
exit "${rc}"
