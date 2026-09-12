/*
 * dtls_classify_guard_test — crafted-input regression test for the standard
 * selection/exclusion/detection bitmask guards added to the DTLS classifier,
 * and the removal of the undocumented DTLS version 0x0100 (issue #104).
 *
 * Before the fix, classify_dtls_from_udp() (src/mmt_tcpip/lib/protocols/
 * proto_dtls.c) had none of the standard classifier guards used by every
 * sibling classifier (see mmt_check_skype_udp() in proto_skype.c and
 * mmt_check_dhcp() in proto_dhcp.c):
 *
 *   - it never checked packet->detected_protocol_stack[0] != PROTO_UNKNOWN,
 *     so a UDP flow already classified as something else could still be
 *     re-classified as DTLS mid-stream on a later packet;
 *   - it never consulted the selection/exclusion/detection bitmasks at all
 *     (it only ever WROTE to excluded_protocol_bitmask on failure, never
 *     read it as a guard), so a flow already marked "not DTLS" could still
 *     be re-evaluated and (if the bytes happened to look right) accepted;
 *   - _is_dtls_version() accepted an undocumented version 0x0100 with no
 *     supporting spec reference, alongside the three real DTLS versions.
 *
 * The fix wraps the body of classify_dtls_from_udp() in the standard
 * compound guard (selection bitmask subset check + exclusion bitmask
 * disjointness check + detection bitmask overlap check), adds an explicit
 * "already classified" early return, and drops the 0x0100 branch from
 * _is_dtls_version().
 *
 * Each test drives classify_dtls_from_udp() directly (declared in the shared
 * internal_decls.h, since it is exported non-static but not declared in any
 * public header — same convention as quic_min_len_test.c /
 * ssl_tls12_version_test.c) with a
 * heap-allocated, exactly-sized datagram buffer, so AddressSanitizer brackets
 * it tightly. The runner (run_dtls_classify_guard_test.sh) builds the library
 * and this test with -fsanitize=address,undefined -fno-sanitize-recover=all.
 *
 * Test cases:
 *   1. test_already_classified_flow_not_reclassified (AC2) — a flow whose
 *      packet-level detected_protocol_stack[0] is already non-PROTO_UNKNOWN
 *      must not be re-classified as DTLS, even given an otherwise-genuine
 *      DTLS datagram.
 *   2. test_excluded_flow_not_reclassified (AC1, exclusion half) — a flow
 *      whose excluded_protocol_bitmask already excludes PROTO_DTLS must not
 *      be classified, even given an otherwise-genuine DTLS datagram.
 *   3. test_version_0x0100_rejected (AC3) — a datagram with version 0x0100
 *      must not be classified as DTLS.
 *   4. test_genuine_dtls_versions_classify (AC4) — genuine DTLS 1.0/1.2/1.3
 *      datagrams on a fresh, non-excluded flow are still classified
 *      correctly (no regression from the added guards).
 *
 * Build (see run_dtls_classify_guard_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -o dtls_classify_guard_test \
 *       dtls_classify_guard_test.c -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "mmt_core.h"
#include "mmt_tcpip_plugin_structs.h"
#include "mmt_tcpip_internal_defs_macros.h"

/*
 * classify_dtls_from_udp() and mmt_init_classify_me_dtls() are exported
 * (non-static) in src/mmt_tcpip/lib/protocols/proto_dtls.c but not declared
 * in any public header; they come from the shared internal header
 * (issue #186).
 */
#include "internal_decls.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do {                                         \
        g_checks++;                                                   \
        if (cond) {                                                   \
            printf("  PASS: %s\n", (msg));                            \
        } else {                                                      \
            printf("  FAIL: %s\n", (msg));                            \
            g_failures++;                                             \
        }                                                             \
    } while (0)

/* Allocate an exactly-sized buffer (ASan brackets it), zero-filled.
 * Caller frees. */
static uint8_t *make_buf(size_t len)
{
    uint8_t *b = (uint8_t *)malloc(len ? len : 1);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, len ? len : 1);
    return b;
}

/*
 * Build a `total_len`-byte datagram buffer (zero-filled) representing an
 * 8-byte UDP header followed by a DTLS record: content_type at byte 8,
 * big-endian version at bytes 9-10. classify_dtls_from_udp() computes
 * offset = get_packet_offset_at_index(...) + 8 (== 8, since
 * proto_path[0] == 0) and requires p_hdr->len - offset > sizeof(dtls_header_t)
 * (13), so total_len must be >= 22 for the record to be considered at all.
 * Caller frees.
 */
static uint8_t *build_dtls_datagram(uint8_t content_type, uint16_t version, int total_len)
{
    uint8_t *b = make_buf((size_t)total_len);
    b[8] = content_type;
    b[9] = (uint8_t)(version >> 8);
    b[10] = (uint8_t)(version & 0xFF);
    return b;
}

#define DATAGRAM_LEN 22

/*
 * Drive classify_dtls_from_udp() with `datagram` of exactly `len` bytes,
 * over a flow/packet wired up so:
 *   - the selection/detection compound guard is forced open regardless of
 *     the classifier's actual static bitmask values (all bits set on
 *     mmt_selection_packet and detection_bitmask);
 *   - flow->excluded_protocol_bitmask starts at whatever the caller-supplied
 *     `flow` already has (so exclusion tests can pre-mark PROTO_DTLS);
 *   - ip.detected_protocol_stack[0] is set to `pre_detected_protocol` (the
 *     packet-level snapshot the "already classified" guard reads).
 *
 * flow is a caller-supplied out-parameter so tests can inspect
 * flow->detected_protocol_stack[0] afterward — the observable proof of
 * whether mmt_internal_add_connection() actually fired.
 */
static int run_classify_dtls(struct mmt_internal_tcpip_session_struct *flow,
                              uint16_t pre_detected_protocol,
                              const uint8_t *datagram, int len)
{
    ipacket_t pkt;
    struct mmt_tcpip_internal_packet_struct ip;
    proto_hierarchy_t headers_offset;
    pkthdr_t p_hdr;

    memset(&pkt, 0, sizeof(pkt));
    memset(&ip, 0, sizeof(ip));
    memset(&headers_offset, 0, sizeof(headers_offset));
    memset(&p_hdr, 0, sizeof(p_hdr));

    headers_offset.proto_path[0] = 0;
    pkt.proto_headers_offset = &headers_offset;
    pkt.internal_cumulative_offset_valid = 0;

    p_hdr.len = (unsigned int)len;
    p_hdr.caplen = (unsigned int)len; /* the datagram buffer is exactly len bytes (#146 bounds by caplen) */
    pkt.p_hdr = &p_hdr;
    pkt.data = (const u_char *)datagram;

    ip.flow = flow;
    ip.mmt_selection_packet = (MMT_SELECTION_BITMASK_PROTOCOL_SIZE)~0u;
    memset(&ip.detection_bitmask, 0xFF, sizeof(ip.detection_bitmask));
    ip.detected_protocol_stack[0] = pre_detected_protocol;

    pkt.internal_packet = &ip;

    return classify_dtls_from_udp(&pkt, 0);
}

/* ---- an already-classified flow is not re-classified as DTLS (AC2) ---- */
static void test_already_classified_flow_not_reclassified(void)
{
    printf("[#104] already-classified UDP flow is not re-classified as DTLS mid-stream\n");

    struct mmt_internal_tcpip_session_struct flow;
    memset(&flow, 0, sizeof(flow));

    uint8_t *b = build_dtls_datagram(DTLS_CONTENT_TYPE_HANDSHAKE, DTLS_VERSION_1_2, DATAGRAM_LEN);
    int r = run_classify_dtls(&flow, PROTO_HTTP, b, DATAGRAM_LEN);

    CHECK(r == 0, "classify_dtls_from_udp returns 0 for an already-classified flow");
    CHECK(flow.detected_protocol_stack[0] == PROTO_UNKNOWN,
          "flow is not marked PROTO_DTLS (mmt_internal_add_connection did not fire)");
    free(b);
}

/* ---- a flow already excluded from DTLS is not (re-)classified (AC1) ---- */
static void test_excluded_flow_not_reclassified(void)
{
    printf("[#104] flow already excluded from DTLS is not classified\n");

    struct mmt_internal_tcpip_session_struct flow;
    memset(&flow, 0, sizeof(flow));
    MMT_ADD_PROTOCOL_TO_BITMASK(flow.excluded_protocol_bitmask, PROTO_DTLS)

    uint8_t *b = build_dtls_datagram(DTLS_CONTENT_TYPE_HANDSHAKE, DTLS_VERSION_1_2, DATAGRAM_LEN);
    int r = run_classify_dtls(&flow, PROTO_UNKNOWN, b, DATAGRAM_LEN);

    CHECK(r == 0, "classify_dtls_from_udp returns 0 for a flow excluded from DTLS");
    CHECK(flow.detected_protocol_stack[0] == PROTO_UNKNOWN,
          "excluded flow is not marked PROTO_DTLS");
    free(b);
}

/* ---- version 0x0100 is not classified as DTLS (AC3) ---- */
static void test_version_0x0100_rejected(void)
{
    printf("[#104] DTLS payload with version 0x0100 is not classified as DTLS\n");

    struct mmt_internal_tcpip_session_struct flow;
    memset(&flow, 0, sizeof(flow));

    uint8_t *b = build_dtls_datagram(DTLS_CONTENT_TYPE_HANDSHAKE, 0x0100, DATAGRAM_LEN);
    int r = run_classify_dtls(&flow, PROTO_UNKNOWN, b, DATAGRAM_LEN);

    CHECK(r == 0, "classify_dtls_from_udp returns 0 for version 0x0100");
    CHECK(flow.detected_protocol_stack[0] == PROTO_UNKNOWN,
          "version 0x0100 payload is not marked PROTO_DTLS");
    free(b);
}

/* ---- genuine DTLS traffic is still classified correctly (AC4) ---- */
static void test_genuine_dtls_versions_classify(void)
{
    printf("[#104] genuine DTLS 1.0/1.2/1.3 traffic is still classified correctly\n");

    const uint16_t versions[] = { DTLS_VERSION_1_0, DTLS_VERSION_1_2, DTLS_VERSION_1_3 };
    const char *names[] = { "DTLS_VERSION_1_0", "DTLS_VERSION_1_2", "DTLS_VERSION_1_3" };

    for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        struct mmt_internal_tcpip_session_struct flow;
        memset(&flow, 0, sizeof(flow));

        uint8_t *b = build_dtls_datagram(DTLS_CONTENT_TYPE_HANDSHAKE, versions[i], DATAGRAM_LEN);
        int r = run_classify_dtls(&flow, PROTO_UNKNOWN, b, DATAGRAM_LEN);

        char msg[96];
        snprintf(msg, sizeof(msg), "%s: classify_dtls_from_udp returns 1", names[i]);
        CHECK(r == 1, msg);
        snprintf(msg, sizeof(msg), "%s: flow marked PROTO_DTLS", names[i]);
        CHECK(flow.detected_protocol_stack[0] == PROTO_DTLS, msg);
        free(b);
    }
}

int main(void)
{
    printf("=== DTLS classifier guard test (issue #104) ===\n");
    mmt_init_classify_me_dtls();
    test_already_classified_flow_not_reclassified();
    test_excluded_flow_not_reclassified();
    test_version_0x0100_rejected();
    test_genuine_dtls_versions_classify();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
