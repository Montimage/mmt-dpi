#!/usr/bin/env bash
#
# run_ip_frag_bounds_test.sh — build the issue #201 regression test against
# an ASan/UBSan-instrumented build of the SDK and run it.
#
# Issue #201 ("2.3: IP, fragment, SCTP, GRE and TCP-segment bounds"):
# IPv4/IPv6 fragment reassembly trusted attacker-controlled ihl/tot_len /
# payload_len / ext-header lengths, the ip_streams fragment map grew without
# bound for the handler lifetime, and the SCTP/GRE/GTP/VLAN classifiers plus
# ICMP data extraction, mmt_bytestream_to_number and the TCP-segment helpers
# all had reads or copies not bounded by the captured length / allocator.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/ip_frag_bounds_test.c against it, itself
#      instrumented with -fsanitize=address,undefined. Internal headers are
#      pulled from the source tree (not part of the installed include set).
#   3. Run it. With -fno-sanitize-recover=all any out-of-bounds or
#      allocator-mismatch aborts with non-zero status; all assertions must
#      also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_ip_frag_bounds_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/ip_frag_bounds_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling ip_frag_bounds_test (ASan/UBSan)"
# Link mmt_core (+ libpcap for DLT_EN10MB). libmmt_tcpip is also linked
# directly (not just dlopen'd): the test reaches internal helpers —
# tcp_seg_*, mmt_bytestream_to_number, the dgram structs — whose symbols
# live in that plugin.
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/ip_frag_bounds_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib/protocols" \
    -I"${REPO_ROOT}/src/mmt_tcpip/include" \
    -I"${REPO_ROOT}/src/mmt_fuzz_engine" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpcap

echo "[3/3] running ip_frag_bounds_test under ASan/UBSan"
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
    echo "✓ ip frag bounds (issue #201) test: PASS"
else
    echo "✗ ip frag bounds (issue #201) test: FAIL (rc=${rc})"
fi
exit "${rc}"
