#!/usr/bin/env bash
#
# run_classified_flow_fastpath_test.sh — build the issue #252 (F-PERF-002)
# regression test against an ASan/UBSan-instrumented build of the SDK and run
# it over a classified-flow pcap.
#
# Issue #252 (F-PERF-002): proto_packet_classify_next walked every registered
# checker on every packet — ~99 under TCP, ~67 under UDP — even after the flow
# had converged, because standard checkers return 4 (bits 0-1 unset) and the
# walk only stops on MMT_CLASSIFY_MATCHED_MASK. The harness asserts the
# acceptance criterion directly: a packet on an already-classified session
# invokes 0 checkers on its own chain (IP/TCP/UDP).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix (the
#      debug counters are armed only in assert-enabled/sanitizer builds).
#   2. Compile tools/phase0/tests/classified_flow_fastpath_test.c against it.
#   3. Run it over a classified-flow pcap (default: the ftp_multiple_session
#      golden capture — several TCP sessions that converge to FTP).
#
# Usage:
#   tools/phase0/tests/run_classified_flow_fastpath_test.sh [pcap-path]
#   MMT_SDK_PREBUILT=1 MMT_ASAN_PREFIX=<prefix> ... — reuse an existing build
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
# Default to the vendored golden pcap subset (tools/phase0/ci/pcaps/) — the
# harness CI job checks out only this repo, so the mmt-test data-sets tree is
# not reachable there; MMT_TEST_DATASETS or a positional arg overrides it.
DATASETS="${MMT_TEST_DATASETS:-${REPO_ROOT}/tools/phase0/ci/pcaps}"
PCAP="${1:-${DATASETS}/ftp_multiple_session.pcap}"
if [ ! -f "${PCAP}" ] && [ -f "${DATASETS}/ftp/ftp_multiple_session.pcap" ]; then
    # mmt-test data-sets keeps pcaps under a per-protocol subdirectory
    PCAP="${DATASETS}/ftp/ftp_multiple_session.pcap"
fi
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/classified_flow_fastpath_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling classified_flow_fastpath_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/classified_flow_fastpath_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap

echo "[3/3] replaying ${PCAP} under ASan/UBSan"
if [ ! -f "${PCAP}" ]; then
    echo "✗ pcap not found: ${PCAP} (set MMT_TEST_DATASETS or pass a path)" >&2
    exit 2
fi
# Preload the ASan runtime: the SDK is pulled in via dlopen, so the runtime
# cannot be resolved from the executable alone (see tools/phase0/README.md).
# Run from the install prefix so the SDK's CWD-relative "plugins/" lookup
# resolves to this BUILD=asan plugin set.
set +e
( cd "${PREFIX}" && \
  LD_PRELOAD="$(gcc -print-file-name=libasan.so)" \
  ASAN_OPTIONS="allocator_may_return_null=1:detect_leaks=0" \
  UBSAN_OPTIONS="print_stacktrace=1" \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
      "${BIN}" "${PCAP}" )
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ classified-flow fast path (issue #252) test: PASS"
else
    echo "✗ classified-flow fast path (issue #252) test: FAIL (rc=${rc})"
fi
exit "${rc}"
