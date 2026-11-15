#!/usr/bin/env bash
#
# run_ip_reassembled_l4_len_test.sh — build the issue #84 regression test
# against an ASan/UBSan-instrumented build of the SDK and run it.
#
# Issue #84: since the issue #192 clamp, proto_ip.c bounded the L4 length of
# a datagram rebuilt from IPv4 fragments by the tot_len of the fragment that
# completed it, so a reassembled TCP/UDP payload was cut to the size of the
# last fragment (tcp.payload_len 0 on a fragmented TCP SYN carrying data).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/ip_reassembled_l4_len_test.c against it, itself
#      instrumented with -fsanitize=address,undefined. The internal packet
#      struct header is pulled from the source tree (it is not part of the
#      installed public include set).
#   3. Run it. The library loads its protocol plugins from the compiled-in
#      prefix ($PREFIX/plugins). With -fno-sanitize-recover=all any
#      out-of-bounds read aborts with non-zero status; all assertions must
#      also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_ip_reassembled_l4_len_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/ip_reassembled_l4_len_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling ip_reassembled_l4_len_test (ASan/UBSan)"
# Link only mmt_core (+ libpcap for DLT_EN10MB); the protocol plugins,
# including libmmt_tcpip, are loaded at run time via dlopen — matching
# phase0_classify.
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/ip_reassembled_l4_len_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap

echo "[3/3] running ip_reassembled_l4_len_test under ASan/UBSan"
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
    echo "✓ ip reassembled l4 len (issue #84) test: PASS"
else
    echo "✗ ip reassembled l4 len (issue #84) test: FAIL (rc=${rc})"
fi
exit "${rc}"
