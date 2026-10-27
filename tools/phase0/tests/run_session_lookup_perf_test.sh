#!/usr/bin/env bash
#
# run_session_lookup_perf_test.sh — build + run the issue #253 (F-PERF-008)
# acceptance harness for the per-packet session lookup.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix (the
#      mmt_oa_equal_calls/mmt_oa_comp_calls tripwire counters are armed only
#      in assert-enabled/sanitizer builds — same contract as the #252
#      classify counters).
#   2. Compile + run tools/phase0/tests/session_lookup_perf_test.c — asserts
#      the shipped ipv4_session_hash / ipv6_session_hash return pinned
#      golden values for fixed keys and differ from the FNV-1a byte loops
#      they replaced (issue #526: this executed check replaced a source-side
#      count of multiply ops, which a renamed function would have passed);
#      that the probes resolve through the one-call equality predicate with
#      zero ordering-comparator calls; and reports the equal-vs-fallback A/B
#      ns/lookup microbenchmark.
#
# Usage:
#   tools/phase0/tests/run_session_lookup_perf_test.sh
#   MMT_SDK_PREBUILT=1 MMT_SESSLOOK_PREFIX=<prefix> ... — reuse an existing build
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_SESSLOOK_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/sesslook.XXXXXX")}"
BIN="$(mktemp -d)/session_lookup_perf_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_SESSLOOK_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

# Issue #533: this test calls libmmt_core internals the shared library hides,
# so it links the static archive instead (never -lmmt_core as well).
# shellcheck source=tools/phase0/tests/static_core_link.sh
. "${TEST_DIR}/static_core_link.sh"
mmt_static_core_link "${PREFIX}/dpi/lib" || exit 2
echo "[2/3] compiling session_lookup_perf_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/session_lookup_perf_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib/protocols" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip "${MMT_STATIC_CORE_LDFLAGS[@]}" -ldl -lpthread -lm

echo "[3/3] running session_lookup_perf_test under ASan/UBSan"
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
      "${BIN}" )
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ session lookup perf (issue #253) test: PASS"
else
    echo "✗ session lookup perf (issue #253) test: FAIL (rc=${rc})"
fi
exit "${rc}"
