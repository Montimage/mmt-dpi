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
# Issue #409 adds the "dns-names" fixture: dns_extract_queries() and
# dns_extract_answers() must advance past an owner name by its consumed wire
# length — a mixed name (literal labels ending in a compression pointer) was
# counted one byte too long, misaligning every following field and record.
#
#   test_dns_mixed_name_length.c — packet/API path: crafted
#                               Ethernet/IPv4/UDP/DNS responses through
#                               mmt_init_handler + packet_process, reading the
#                               DNS_QUERIES / DNS_ANSWERS attributes back via
#                               get_attribute_extracted_data().
#
# Issue #407 adds the "nfs" fixture: the NFS extractors in proto_nfs.c must
# bound every fixed-offset u32 of the ONC-RPC call header (msg_type at +8,
# rpc_version/program/prog_version/procedure at +12/+16/+20/+24) with
# mmt_have_bytes(), so a truncated capture never reads past caplen.
#
#   test_nfs_rpc_header_bounds.c — calls the exported nfs_*_extraction()
#                               functions of the linked SDK over exactly
#                               caplen-sized heap captures.
#
# Issue #332 adds the "int" fixture: the INT dissector (proto_int.c) must
# detect INT from an IPv6 carrier's Traffic Class as well as the IPv4 TOS,
# size the layer after INT from the shim Length, survive a zero Hop ML and
# decode both LV2 port-ID layouts; the INT-report dissector
# (proto_int_report.c) must parse an IPv6 (or optioned IPv4) inner packet.
# Issue #453 extends it: DSCP 0x20 (CS4) alone is not INT — the payload must
# start with a valid INT v1.0 shim + metadata header, over UDP or TCP; the hop
# stride follows Hop ML; the INT-report inner packet rejects non-first IPv4
# fragments and invalid shims and exposes ip_src/ip_dst in network order.
#
#   test_int_ipv6_parser.c — packet/API path: crafted Ethernet/IPv{4,6}/UDP
#                               INT frames and INT reports through
#                               mmt_init_handler + packet_process, reading the
#                               INT/INT-report attributes back.
#
# Issue #331 adds the "tcp-options" and "radius-dns" fixtures: the appended
# tcp.mss / tcp.wscale / tcp.sack_permitted attributes and the 4-byte
# tcp.syn_received result, and the radius.dns_ipv6 extraction (first server
# of the 3GPP-IPv6-DNS-Servers vendor sub-attribute).
#
#   test_tcp_options_bounds.c  — calls the exported tcp_option_extraction()
#                               and tcp_syn_rcv_extraction() over exactly
#                               caplen-sized heap captures (every truncation,
#                               mis-sized and odd-offset options).
#   test_radius_dns_ipv6_api.c — packet/API path: crafted
#                               Ethernet/IPv4/UDP/RADIUS Accounting-Requests
#                               through mmt_init_handler + packet_process.
#
# Issue #333 adds the "quic" fixture: QUIC-IETF version 2 (RFC 9369), the
# short-header DCID length learned from the flow's long headers, and
# coalesced packets (RFC 9000 §12.2) classified as QUIC after QUIC, every
# Length/varint bounded by the captured bytes. Issue #458 extends it: a
# chained packet must carry the first packet's DCID, and the chained tail
# never outlives its datagram — also past the classification threshold.
#
#   test_quic_ietf_coalesced.c — packet/API path: crafted Ethernet/IPv4/UDP
#                               QUIC frames through mmt_init_handler +
#                               packet_process, reading the path and the
#                               QUIC attributes back per layer.
#
# Usage: tests/parser_boundaries/run_tests.sh [fixture ...]
#   no arguments runs every fixture; "udp"/"dtls"/"dns-soa"/"dns-txt"/"dns-names"/"nfs"/"int"/
#   "tcp-options"/"radius-dns"/"quic" select a fixture family.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# --- fixture selection -----------------------------------------------------
FIXTURES=( "$@" )
[ "${#FIXTURES[@]}" -eq 0 ] && FIXTURES=(udp dtls dns-soa dns-txt dns-names nfs int tcp-options radius-dns quic)
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
        dns-names)
            API_TESTS+=(dns_mixed_name_length)
            ;;
        nfs)
            API_TESTS+=(nfs_rpc_header_bounds)
            ;;
        int)
            API_TESTS+=(int_ipv6_parser)
            ;;
        tcp-options)
            API_TESTS+=(tcp_options_bounds)
            ;;
        radius-dns)
            API_TESTS+=(radius_dns_ipv6_api)
            ;;
        quic)
            API_TESTS+=(quic_ietf_coalesced)
            ;;
        *)
            echo "✗ unknown parser_boundaries fixture '$f' (known: udp dtls dns-soa dns-txt dns-names nfs int tcp-options radius-dns quic)" >&2
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
echo "✓ parser boundary tests passed (issues #331, #332, #333, #375, #376, #377, #378, #407, #409, #453)"
