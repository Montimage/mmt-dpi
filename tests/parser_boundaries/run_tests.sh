#!/usr/bin/env bash
# run_tests.sh — parser boundary tests.
#
# Issue #375 (F-BUG-002) adds the "udp" fixture:
# udp_pre_classification_function() must bound the UDP payload by
# the UDP header length field AND the enclosing IP payload (IPv4 tot_len /
# IPv6 payload_len, extension-header aware, jumbogram explicit).
#
#   test_udp_bounds_unit.c    — helper reproducer: proto_udp.c is included
#                               directly and udp_pre_classification_function()
#                               is driven over fabricated ipacket fixtures
#                               (no SDK build needed).
#   test_udp_payload_bounds.c — packet/API path: crafted Ethernet/IPv{4,6}/UDP
#                               frames are fed through mmt_init_handler +
#                               packet_process against the built SDK.
#
# Issue #376 (F-BUG-001 follow-up) adds the "dtls" fixture: the central
# wire-extent guard in internal_extract_attribute() must separate the bytes
# an extractor may read on the wire from data_len, the attribute's output
# capacity — a 67-byte DTLS ClientHello must extract its cipher despite the
# 132-byte mmt_u16_array_t result buffer.
#
#   test_dtls_wire_extent_unit.c — drives internal_extract_attribute() over
#                               crafted ipacket/attribute fixtures plus the
#                               real _dtls_extract_attribute() (linked SDK).
#   test_dtls_wire_extent_api.c  — packet/API path: crafted
#                               Ethernet/IPv4/UDP/DTLS frames through
#                               mmt_init_handler + packet_process with a
#                               registered attribute handler.
#
# Issue #377 (F-BUG-003) adds the "dns-soa" fixture: the SOA answer parser in
# proto_dns.c must advance by each name's consumed wire length — literal
# labels plus the root terminator, or the two bytes of a compression
# pointer — bounded by the declared rdata extent.
#
#   test_dns_soa_consumed_bytes.c — packet/API path: crafted
#                               Ethernet/IPv4/UDP/DNS responses through
#                               mmt_init_handler + packet_process, reading the
#                               DNS_ANSWERS attribute back via
#                               get_attribute_extracted_data().
#
# Issue #378 (F-BUG-004) adds the "dns-txt" fixture: every TXT
# <character-string> field — a length byte plus that many content bytes —
# must stay inside the record's declared RDATA extent (RDLENGTH clamped to
# captured bytes), so a string running past the record rejects instead of
# consuming the next record's bytes.
#
#   test_dns_txt_rdata_bounds.c — packet/API path: crafted
#                               Ethernet/IPv4/UDP/DNS responses through
#                               mmt_init_handler + packet_process, reading the
#                               DNS_ANSWERS attribute back via
#                               get_attribute_extracted_data().
#
# Usage: tests/parser_boundaries/run_tests.sh [fixture ...]
#   no arguments runs every fixture; "udp"/"dtls"/"dns-soa"/"dns-txt" select
#   a fixture family.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# --- fixture selection -----------------------------------------------------
FIXTURES=( "$@" )
[ "${#FIXTURES[@]}" -eq 0 ] && FIXTURES=(udp dtls dns-soa dns-txt)
UNIT_TESTS=()
API_TESTS=()
for f in "${FIXTURES[@]}"; do
    case "$f" in
        udp)
            UNIT_TESTS+=(udp_bounds_unit)
            API_TESTS+=(udp_payload_bounds)
            ;;
        dtls)
            API_TESTS+=(dtls_wire_extent_unit dtls_wire_extent_api)
            ;;
        dns-soa)
            API_TESTS+=(dns_soa_consumed_bytes)
            ;;
        dns-txt)
            API_TESTS+=(dns_txt_rdata_bounds)
            ;;
        *)
            echo "✗ unknown parser_boundaries fixture '$f' (known: udp dtls dns-soa dns-txt)" >&2
            exit 2
            ;;
    esac
done

CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"

if [ -z "${MMT_PREFIX:-}" ]; then
    PREFIX="$(mktemp -d)"
    PREFIX_CREATED=1
else
    PREFIX="${MMT_PREFIX}"
fi
WORK="$(mktemp -d)"
BUILD_LOG="${WORK}/build.log"
if [ -n "${PREFIX_CREATED:-}" ]; then
    trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT
else
    trap 'rm -rf "${WORK}"' EXIT
fi

if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    set -- "BUILD=${SDK_BUILD_PROFILE}"
else
    set --
fi

echo "  repo root      : ${REPO_ROOT}"
echo "  install prefix : ${PREFIX}"

# --- [1/3] SDK build+install (needed by the API-path tests) ----------------
echo "  [1/3] building + installing SDK ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "$@" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "$@" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"

UNIT_INCS=(
    -I"${REPO_ROOT}/src/mmt_core/public_include"
    -I"${REPO_ROOT}/src/mmt_core/private_include"
    -I"${REPO_ROOT}/src/mmt_tcpip/lib"
    -I"${REPO_ROOT}/src/mmt_tcpip/include"
    # mmt_common_internal_include.h pulls protocols/rtp.h, which needs the
    # fuzz-engine include dir for mmt_quality_estimation_utilities.h (same as
    # tests/proto_classifiers).
    -I"${REPO_ROOT}/src/mmt_fuzz_engine"
)

# --- [2/3] compile ----------------------------------------------------------
echo "  [2/3] compiling tests ..."
for name in "${UNIT_TESTS[@]}"; do
    "${CC}" "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 \
        "${UNIT_INCS[@]}" -o "${SCRIPT_DIR}/test_${name}" \
        "${SCRIPT_DIR}/test_${name}.c"
done
for name in "${API_TESTS[@]}"; do
    "${CC}" "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 \
        -o "${SCRIPT_DIR}/test_${name}" "${SCRIPT_DIR}/test_${name}.c" \
        -I"${INC}" -I"${REPO_ROOT}/src/mmt_tcpip/lib" "${UNIT_INCS[@]}" \
        -L"${LIB}" -lmmt_tcpip -lmmt_core -ldl -lpcap -lpthread -lm
done

# --- [3/3] run ---------------------------------------------------------------
# The protocol plugins are loaded at run time via dlopen, so under a
# sanitizer profile the runtime must be preloaded — it cannot be resolved
# from the executable alone (same contract as tools/phase0/tests/).
echo "  [3/3] running tests ..."
env_prefix=()
case "${SDK_BUILD_PROFILE:-}" in
    asan) env_prefix=(LD_PRELOAD="$( "${CC}" -print-file-name=libasan.so )") ;;
    tsan) env_prefix=(LD_PRELOAD="$( "${CC}" -print-file-name=libtsan.so )") ;;
esac

rc=0
run_one() {
    local name="$1"
    if ( cd "${PREFIX}" && \
        env "${env_prefix[@]}" \
            ASAN_OPTIONS="detect_leaks=0" \
            UBSAN_OPTIONS="print_stacktrace=1" \
            LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
            "${SCRIPT_DIR}/test_${name}" ); then
        echo "  ✓ test_${name}: PASSED"
    else
        echo "  ✗ test_${name}: FAILED" >&2
        rc=1
    fi
}

for name in "${UNIT_TESTS[@]}" "${API_TESTS[@]}"; do
    run_one "${name}"
    echo
done

if [ "${rc}" -ne 0 ]; then
    echo "✗ parser boundary tests failed" >&2
    exit 1
fi
echo "✓ parser boundary tests passed (issues #375, #376, #377, #378)"
