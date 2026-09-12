#!/usr/bin/env bash
#
# run_ip_unaligned_header_test.sh — build the issue #57 regression test against
# an ASan/UBSan-instrumented build of the SDK and run it.
#
# Issue #57: the IP/L4 classification path cast "&ipacket->data[offset]" (a
# byte-aligned capture buffer) to struct iphdr/tcphdr/udphdr and dereferenced
# multi-byte fields directly. When a header does not land on its natural
# boundary that is a misaligned access — UB that aborts under
# -fsanitize=alignment. The SDK copies each packet into a 16-byte-aligned
# buffer, so a 14-byte Ethernet header puts the IPv4 header at a 2-byte-aligned
# (not 4-byte-aligned) address, making the bug deterministic.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/ip_unaligned_header_test.c against it,
#      itself instrumented with -fsanitize=address,undefined.
#   3. Run it. The library loads its protocol plugins from the compiled-in
#      prefix ($PREFIX/plugins). With -fno-sanitize-recover=all any misaligned
#      access aborts with non-zero status; all assertions must also pass.
#      Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_ip_unaligned_header_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-/tmp/mmt-asan-ip-unaligned-header}"
BIN="$(mktemp -d)/ip_unaligned_header_test"
trap 'rm -rf "$(dirname "${BIN}")"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling ip_unaligned_header_test (ASan/UBSan)"
# Link only mmt_core (+ libpcap for DLT_EN10MB); the protocol plugins, including
# libmmt_tcpip, are loaded at run time via dlopen — matching phase0_classify.
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/ip_unaligned_header_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap

echo "[3/3] running ip_unaligned_header_test under ASan/UBSan"
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
    echo "✓ IP/L4 unaligned-header (issue #57) test: PASS"
else
    echo "✗ IP/L4 unaligned-header (issue #57) test: FAIL (rc=${rc})"
fi
exit "${rc}"
