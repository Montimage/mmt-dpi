#!/usr/bin/env bash
# run_tests.sh — coverage for the business-app plugin
# (src/mmt_business_app/mmt_business_app.c + proto_ips_data.c), issue #243.
#
# The plugin sources are compiled into the test binary so every exercised
# line is attributed to the real files in the coverage tracefile; the mmt_core
# registration/packet helpers they call are stubbed inside the test (same
# convention as tests/dicom_dissector, issue #215).
#
# Usage: tests/business_app/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_SRC="${SCRIPT_DIR}/test_business_app.c"
TEST_BIN="${SCRIPT_DIR}/test_business_app"

echo "  repo root : ${REPO_ROOT}"
echo "  source    : src/mmt_business_app/{mmt_business_app,proto_ips_data}.c"

read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC:-gcc} "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 \
    -o "${TEST_BIN}" "${TEST_SRC}"

echo "  running test_business_app ..."
if "${TEST_BIN}"; then
    echo
    echo "✓ business-app plugin tests passed (issue #243)"
else
    echo "✗ business-app plugin tests failed" >&2
    exit 1
fi
