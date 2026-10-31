#!/usr/bin/env bash
# run_tests.sh — crafted-input regression tests for three 1.8.0 classifier
# fixes (issue #243, F-TEST-014): the syslog RFC 3164/5424 format split
# (#80), the PTP-over-UDP classifier, and the DCERPC packet-type offset +
# payload-threshold fix (#86). test_diameter_flags pins the Diameter command
# flag decoding (issue #504). Each test pins the behaviour its fix added —
# reverting the fix fails the suite.
#
# test_ftp_dialogue (issue #563) drives the FTP dissector — parsing, session
# tuples, IPv4/IPv6 dialogues read back through the attribute extractors,
# classification and out-of-memory sweeps. FTP is five units (issue #544),
# so they and mmt_utils.c are compiled as objects beside the test with the
# fault-injecting allocator of ftp_alloc_fail.c (-Dmalloc=fda_malloc ...),
# objects in this directory so their .gcda outlive the script (issue #524).
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
    # test_diameter_flags includes src/mmt_mobile/proto_diameter.c (#504).
    -I"${REPO_ROOT}/src/mmt_mobile"
    -I"${REPO_ROOT}/src/mmt_mobile/include"
)

echo "  repo root : ${REPO_ROOT}"

build_ftp_dialogue() {
    local count=(-Dmalloc=fda_malloc -Dcalloc=fda_calloc
                 -Drealloc=fda_realloc -Dfree=fda_free)
    local objs=() src
    for src in proto_ftp proto_ftp_session proto_ftp_parse proto_ftp_addr proto_ftp_extract; do
        "${CC}" "${extra_cflags[@]}" -O1 -g -std=gnu11 -DNDEBUG "${count[@]}" "${INCS[@]}" \
            -c "${REPO_ROOT}/src/mmt_tcpip/lib/protocols/${src}.c" -o "${SCRIPT_DIR}/fd_${src}.o"
        objs+=("${SCRIPT_DIR}/fd_${src}.o")
    done
    "${CC}" "${extra_cflags[@]}" -O1 -g -std=gnu11 "${count[@]}" "${INCS[@]}" \
        -c "${REPO_ROOT}/src/mmt_core/src/mmt_utils.c" -o "${SCRIPT_DIR}/fd_mmt_utils.o"
    "${CC}" "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 "${count[@]}" "${INCS[@]}" \
        -c "${SCRIPT_DIR}/test_ftp_dialogue.c" -o "${SCRIPT_DIR}/test_ftp_dialogue.o"
    "${CC}" "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 \
        -c "${SCRIPT_DIR}/ftp_alloc_fail.c" -o "${SCRIPT_DIR}/fd_alloc_fail.o"
    "${CC}" "${extra_cflags[@]}" -o "${SCRIPT_DIR}/test_ftp_dialogue" \
        "${SCRIPT_DIR}/test_ftp_dialogue.o" "${objs[@]}" "${SCRIPT_DIR}/fd_mmt_utils.o" \
        "${SCRIPT_DIR}/fd_alloc_fail.o" -lm
}

rc=0
for name in dcerpc_offset ptp_classify syslog_format diameter_flags ftp_dialogue; do
    src="${SCRIPT_DIR}/test_${name}.c"
    bin="${SCRIPT_DIR}/test_${name}"
    echo "  compiling test_${name} ..."
    if [ "${name}" = ftp_dialogue ]; then
        build_ftp_dialogue
    else
        "${CC}" "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 \
            "${INCS[@]}" -o "${bin}" "${src}"
    fi
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
    echo "✗ classifier crafted-input tests failed" >&2
    exit 1
fi
echo "✓ classifier crafted-input tests passed (issues #243, #563)"
