#!/usr/bin/env bash
# run_tests.sh — crafted-input regression tests for three 1.8.0 classifier
# fixes (issue #243, F-TEST-014): the syslog RFC 3164/5424 format split
# (#80), the PTP-over-UDP classifier, and the DCERPC packet-type offset +
# payload-threshold fix (#86). Each test pins the behaviour its fix added —
# reverting the fix fails the suite.
#
# Each proto source is compiled into its own test binary (the per-protocol
# file-scope classifier bitmasks must not alias), so every exercised line is
# attributed to the real file in the coverage tracefile; the mmt_core helpers
# the classifiers call are stubbed inside each test (same convention as
# tests/dicom_dissector, issue #215).
#
# Usage: tests/proto_classifiers/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CC="${CC:-gcc}"
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"

INCS=(
    -I"${REPO_ROOT}/src/mmt_core/public_include"
    -I"${REPO_ROOT}/src/mmt_core/private_include"
    -I"${REPO_ROOT}/src/mmt_tcpip/lib"
    -I"${REPO_ROOT}/src/mmt_tcpip/include"
    # mmt_common_internal_include.h pulls protocols/rtp.h, which needs the
    # fuzz-engine include dir for mmt_quality_estimation_utilities.h (same as
    # tests/core_engine).
    -I"${REPO_ROOT}/src/mmt_fuzz_engine"
)

echo "  repo root : ${REPO_ROOT}"

rc=0
for name in dcerpc_offset ptp_classify syslog_format; do
    src="${SCRIPT_DIR}/test_${name}.c"
    bin="${SCRIPT_DIR}/test_${name}"
    echo "  compiling test_${name} ..."
    "${CC}" "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 \
        "${INCS[@]}" -o "${bin}" "${src}"
    echo "  running test_${name} ..."
    if "${bin}"; then
        echo "  ✓ test_${name}: PASSED"
    else
        echo "  ✗ test_${name}: FAILED" >&2
        rc=1
    fi
    echo
done

if [ "${rc}" -ne 0 ]; then
    echo "✗ 1.8.0 classifier crafted-input tests failed" >&2
    exit 1
fi
echo "✓ 1.8.0 classifier crafted-input tests passed (issue #243)"
