#!/usr/bin/env bash
# run_tests.sh — crafted-input coverage for the DICOM dissector
# (src/mmt_dicom/dicom.c), issue #215.
#
# The dissector source is compiled into the test binary so every exercised
# line is attributed to the real file in the coverage tracefile; the mmt_core
# registration/packet helpers it calls are stubbed inside the test.
#
# Usage: tests/dicom_dissector/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SRC="${REPO_ROOT}/src/mmt_dicom/dicom.c"
TEST_SRC="${SCRIPT_DIR}/test_dicom_dissector.c"
TEST_BIN="${SCRIPT_DIR}/test_dicom_dissector"

echo "  repo root : ${REPO_ROOT}"
echo "  source    : ${SRC#"$REPO_ROOT"/}"

read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC:-gcc} "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 \
    -o "${TEST_BIN}" "${TEST_SRC}"

echo "  running test_dicom_dissector ..."
if "${TEST_BIN}"; then
    echo
    echo "✓ DICOM dissector crafted-input tests passed (issue #215)"
else
    echo "✗ DICOM dissector crafted-input tests failed" >&2
    exit 1
fi
