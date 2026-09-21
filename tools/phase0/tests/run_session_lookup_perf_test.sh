#!/usr/bin/env bash
#
# run_session_lookup_perf_test.sh — build + run the issue #253 (F-PERF-008)
# acceptance harness for the per-packet session lookup, plus the source-side
# dependent-multiply assertion the issue asks for.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix (the
#      mmt_oa_equal_calls/mmt_oa_comp_calls tripwire counters are armed only
#      in assert-enabled/sanitizer builds — same contract as the #252
#      classify counters).
#   2. Statically assert the dependent-multiply budget inside
#      ipv4_session_hash / ipv6_session_hash: the FNV-1a byte loops ran 13 /
#      37 serially-dependent multiplies; the word-parallel replacement keeps
#      <= 4 / <= 6 multiply ops (independent terms + one finalizer).
#   3. Compile + run tools/phase0/tests/session_lookup_perf_test.c — asserts
#      the probes resolve through the one-call equality predicate with zero
#      ordering-comparator calls, and reports the equal-vs-fallback A/B
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
    echo "[1/4] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/4] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

# --- dependent-multiply budget (issue #253 acceptance text) -----------------
# Counts multiply ops of the form `expr * 0xHEX` / `h *= 0xHEX` inside each
# session-key hash body — the documented budget is part of the fix.
count_muls() {
    awk -v fn="$1" '
        $0 ~ ("^uint64_t " fn "\\(void \\* ?key\\)") { in_fn=1; next }
        in_fn && /^}/ { in_fn=0 }
        in_fn { n += gsub(/\*=? *0x[0-9A-Fa-f]+/, "&") }
        END { print n+0 }
    ' "$2"
}

echo "[2/4] asserting dependent-multiply budget in session-key hashes"
mul4="$(count_muls ipv4_session_hash "${REPO_ROOT}/src/mmt_tcpip/lib/protocols/proto_ip.c")"
mul6="$(count_muls ipv6_session_hash "${REPO_ROOT}/src/mmt_tcpip/lib/protocols/proto_ipv6.c")"
echo "    ipv4_session_hash: ${mul4} multiply ops (budget <= 4; was 13 FNV-1a)"
echo "    ipv6_session_hash: ${mul6} multiply ops (budget <= 6; was 37 FNV-1a)"
if [ "${mul4}" -gt 4 ] || [ "${mul6}" -gt 6 ]; then
    echo "✗ session-key hash multiply budget exceeded" >&2
    exit 1
fi

echo "[3/4] compiling session_lookup_perf_test (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/session_lookup_perf_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib/protocols" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[4/4] running session_lookup_perf_test under ASan/UBSan"
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
