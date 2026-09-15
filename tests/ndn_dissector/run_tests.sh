#!/usr/bin/env bash
# run_tests.sh — crafted-input coverage for the NDN dissector
# (src/mmt_tcpip/lib/protocols/ndn.c), issue #215.
#
# The dissector source is compiled into the test binary so every exercised
# line is attributed to the real file in the coverage tracefile; the mmt_core
# packet/attribute helpers it calls are stubbed inside the test. The real
# memory.c and mmt_utils.c are linked so mmt_malloc()/str_* behaviour (size
# headers, strlen-based substring) is identical to the library.
#
# Usage: tests/ndn_dissector/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SRC="${REPO_ROOT}/src/mmt_tcpip/lib/protocols/ndn.c"
TEST_SRC="${SCRIPT_DIR}/test_ndn_dissector.c"
TEST_BIN="${SCRIPT_DIR}/test_ndn_dissector"

echo "  repo root : ${REPO_ROOT}"
echo "  source    : ${SRC#"$REPO_ROOT"/}"

read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC:-gcc} "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 \
    -I "${REPO_ROOT}/src/mmt_core/public_include" \
    -I "${REPO_ROOT}/src/mmt_core/private_include" \
    -I "${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I "${REPO_ROOT}/src/mmt_tcpip/include" \
    -I "${REPO_ROOT}/src/mmt_tcpip/lib/protocols" \
    -I "${REPO_ROOT}/src/mmt_fuzz_engine" \
    -o "${TEST_BIN}" \
    "${TEST_SRC}" \
    "${REPO_ROOT}/src/mmt_core/src/mmt_utils.c" \
    "${REPO_ROOT}/src/mmt_core/src/memory.c" \
    -lm

echo "  running test_ndn_dissector ..."
if "${TEST_BIN}"; then
    echo
    echo "✓ NDN dissector crafted-input tests passed (issue #215)"
else
    echo "✗ NDN dissector crafted-input tests failed" >&2
    exit 1
fi
