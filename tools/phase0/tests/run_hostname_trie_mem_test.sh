#!/usr/bin/env bash
#
# run_hostname_trie_mem_test.sh — build + run the issue #253 (F-PERF-007)
# acceptance harness for the sparse, lazily-built hostname trie.
#
# Steps:
#   1. Build + install the SDK with the DEFAULT profile into an isolated
#      prefix — RSS figures must come from a non-sanitized library (same
#      requirement as run_memory_ceiling_test.sh: an ASan/TSan runtime plus
#      its shadow memory would measure the sanitizer, not the trie).
#   2. Compile tools/phase0/tests/hostname_trie_mem_test.c against it.
#   3. Run it: asserts the trie is unbuilt at load (lazy), accounts under
#      4 MiB once built, and the VmRSS delta across the build stays under
#      4 MiB (sampled via /proc/self/status — the corrected harness
#      mechanism of issue #251).
#
# Usage: tools/phase0/tests/run_hostname_trie_mem_test.sh
#   MMT_SDK_PREBUILT=1 MMT_TRIE_PREFIX=<prefix> ... — reuse an existing build
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_TRIE_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/trie.XXXXXX")}"
BIN="$(mktemp -d)/hostname_trie_mem_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_TRIE_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK (default profile) -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling hostname_trie_mem_test"
gcc -g -O2 -o "${BIN}" "${TEST_DIR}/hostname_trie_mem_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${REPO_ROOT}/src/mmt_core/private_include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/include" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running hostname_trie_mem_test"
# Run from a neutral directory — the test links libmmt_tcpip directly and
# needs no plugin set (direct get_proto_id_by_hostname calls only).
set +e
( cd "$(dirname "${BIN}")" && \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
      "${BIN}" )
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ hostname trie memory (issue #253) test: PASS"
else
    echo "✗ hostname trie memory (issue #253) test: FAIL (rc=${rc})"
fi
exit "${rc}"
