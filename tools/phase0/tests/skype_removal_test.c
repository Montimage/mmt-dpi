/*
 * skype_removal_test — crafted-input regression test for the removal of the
 * Skype UDP/TCP false-positive classification heuristic (issue #102).
 *
 * Before the fix, mmt_check_skype_tcp() and mmt_check_skype_udp()
 * (src/mmt_tcpip/lib/protocols/proto_skype.c) classified a flow as Skype
 * based purely on coincidental packet shape, with zero validation of any
 * actual Skype protocol content:
 *
 *   - mmt_check_skype_tcp(): once the 3-way handshake had been observed
 *     (seen_syn && seen_syn_ack && seen_ack) and exactly 3 packets had been
 *     seen on the flow, a payload_len of 8 or 3 bytes alone was "Skype".
 *   - mmt_check_skype_udp(): within the first 5 packets of a flow to a
 *     non-1119 destination port, a 3-byte payload whose 3rd byte had a
 *     trailing nibble of 0x_d, OR a >=16-byte payload with byte[0] != 0x30
 *     and byte[2] == 0x02, alone was "Skype".
 *
 * These two classifiers were registered in configured_protocols.c ahead of
 * (lower weight than) the signature-based classifiers for STUN, RTP and
 * QUIC (mmt_check_stun_udp/mmt_check_rtp_udp at weight 50 vs.
 * mmt_check_skype_udp at weight 40), so any STUN/RTP/QUIC packet that
 * coincidentally satisfied Skype's loose shape check would be permanently
 * mislabeled Skype by proto_packet_classify_next() (which stops at the
 * first classifier match).
 *
 * The fix (this commit) neutralizes the coincidental match-condition logic
 * in both functions -- they can no longer return a positive Skype
 * classification -- while leaving the guard preamble (selection/exclusion/
 * detection bitmask gate, "already classified" early return, handshake /
 * packet-count bookkeeping) intact, and removes both classifiers'
 * registration calls from configured_protocols.c so the engine never
 * invokes them at all.
 *
 * Each test drives mmt_check_skype_tcp()/mmt_check_skype_udp() directly
 * (declared extern, since they are exported non-static but not declared in
 * any public header -- same convention as quic_min_len_test.c /
 * ssl_tls12_version_test.c / dtls_classify_guard_test.c) with a
 * heap-allocated, exactly-sized payload buffer, so AddressSanitizer
 * brackets it tightly. The runner (run_skype_removal_test.sh) builds the
 * library and this test with -fsanitize=address,undefined
 * -fno-sanitize-recover=all.
 *
 * Test cases:
 *   1. test_tcp_coincidental_shape_no_longer_classifies_skype (AC1/AC2) --
 *      a TCP flow with a completed 3-way handshake and a payload_len of
 *      exactly 8 or 3 bytes (the two lengths that used to satisfy the loose
 *      match) on packet #3 must not be classified as Skype.
 *   2. test_udp_coincidental_shape_no_longer_classifies_skype (AC1/AC2) --
 *      a UDP flow with a 3-byte payload with trailing nibble 0x0d, and
 *      separately a >=16-byte payload with byte[0] != 0x30 && byte[2] ==
 *      0x02 (the two byte-patterns that used to satisfy the loose match)
 *      must not be classified as Skype.
 *   3. test_tcp_already_classified_flow_not_reclassified (guard preamble
 *      preserved) -- a packet whose detected_protocol_stack[0] is already
 *      non-PROTO_UNKNOWN must not be (re-)classified as Skype, even given
 *      an otherwise-genuine crafted-shape match, and the classifier must
 *      return before touching any handshake/packet-count state.
 *   4. test_udp_already_classified_flow_not_reclassified (guard preamble
 *      preserved) -- same as #3 for the UDP classifier.
 *
 * Build (see run_skype_removal_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -o skype_removal_test \
 *       skype_removal_test.c -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "mmt_core.h"
/*
 * mmt_check_skype_tcp()/mmt_check_skype_udp() read
 * ipacket->internal_packet->{payload, payload_packet_len, tcp, udp, flow,
 * detected_protocol_stack, mmt_selection_packet, detection_bitmask}, and
 * flow->l4.{tcp,udp}.{skype_packet_id, seen_syn, seen_syn_ack, seen_ack}.
 * The internal packet and session structs are opaque in the installed
 * public headers, so pull in their full definitions from the (in-tree)
 * plugin header, same as quic_min_len_test.c / dtls_classify_guard_test.c.
 */
#include "mmt_tcpip_plugin_structs.h"
#include "mmt_tcpip_internal_defs_macros.h"

/*
 * mmt_check_skype_tcp(), mmt_check_skype_udp() and
 * mmt_init_classify_me_skype() are exported (non-static) in
 * src/mmt_tcpip/lib/protocols/proto_skype.c but not declared in any public
 * header; they come from the shared internal header (issue #186).
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

/* Allocate an exactly-sized buffer (ASan brackets it) and copy in `len`
 * bytes from src (rest zeroed). Caller frees. */
static uint8_t *make_buf(const uint8_t *src, size_t len)
{
    uint8_t *b = (uint8_t *)malloc(len ? len : 1);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, len ? len : 1);
    if (len && src) memcpy(b, src, len);
    return b;
}

/*
 * Drive mmt_check_skype_tcp() over a flow whose 3-way handshake / packet
 * count is set directly (bypassing the core engine, which would normally
 * set seen_syn/seen_syn_ack/seen_ack from real TCP flags), with the
 * selection/detection compound guard forced open regardless of the
 * classifier's actual static bitmask values (all bits set on
 * mmt_selection_packet and detection_bitmask). `flow` is a caller-supplied
 * out-parameter so tests can inspect flow->l4.tcp.skype_packet_id and
 * flow->detected_protocol_stack[0] afterward.
 */
static int run_check_skype_tcp(struct mmt_internal_tcpip_session_struct *flow,
                                uint8_t pre_skype_packet_id,
                                int seen_syn, int seen_syn_ack, int seen_ack,
                                uint16_t pre_detected_protocol,
                                uint32_t payload_len)
{
    ipacket_t pkt;
    struct mmt_tcpip_internal_packet_struct ip;
    struct tcphdr tcp;

    memset(&pkt, 0, sizeof(pkt));
    memset(&ip, 0, sizeof(ip));
    memset(&tcp, 0, sizeof(tcp));

    flow->l4.tcp.skype_packet_id = pre_skype_packet_id;
    flow->l4.tcp.seen_syn = seen_syn ? 1 : 0;
    flow->l4.tcp.seen_syn_ack = seen_syn_ack ? 1 : 0;
    flow->l4.tcp.seen_ack = seen_ack ? 1 : 0;

    ip.flow = flow;
    ip.tcp = &tcp;
    ip.payload_packet_len = (uint16_t)payload_len;
    ip.detected_protocol_stack[0] = pre_detected_protocol;

    /* Force the outer selection/exclusion/detection gate open. */
    ip.mmt_selection_packet = (MMT_SELECTION_BITMASK_PROTOCOL_SIZE)~0u;
    memset(&ip.detection_bitmask, 0xFF, sizeof(ip.detection_bitmask));

    pkt.internal_packet = &ip;
    return mmt_check_skype_tcp(&pkt, 0);
}

/* Same as run_check_skype_tcp(), for the UDP classifier. `payload` may be
 * NULL when payload_len is 0. */
static int run_check_skype_udp(struct mmt_internal_tcpip_session_struct *flow,
                                uint8_t pre_skype_packet_id,
                                uint16_t dest_port,
                                uint16_t pre_detected_protocol,
                                const uint8_t *payload, uint32_t payload_len)
{
    ipacket_t pkt;
    struct mmt_tcpip_internal_packet_struct ip;
    struct udphdr udp;

    memset(&pkt, 0, sizeof(pkt));
    memset(&ip, 0, sizeof(ip));
    memset(&udp, 0, sizeof(udp));

    flow->l4.udp.skype_packet_id = pre_skype_packet_id;
    udp.dest = htons(dest_port);

    ip.flow = flow;
    ip.udp = &udp;
    ip.payload = payload;
    ip.payload_packet_len = (uint16_t)payload_len;
    ip.detected_protocol_stack[0] = pre_detected_protocol;

    ip.mmt_selection_packet = (MMT_SELECTION_BITMASK_PROTOCOL_SIZE)~0u;
    memset(&ip.detection_bitmask, 0xFF, sizeof(ip.detection_bitmask));

    pkt.internal_packet = &ip;
    return mmt_check_skype_udp(&pkt, 0);
}

/* ---- TCP: the old payload_len == 8 || payload_len == 3 shape match no
 * longer classifies as Skype (AC1/AC2) ---- */
static void test_tcp_coincidental_shape_no_longer_classifies_skype(void)
{
    printf("[#102] TCP payload_len 8/3 on a completed handshake is not classified as Skype\n");

    const uint32_t lens[] = { 8, 3 };
    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        struct mmt_internal_tcpip_session_struct flow;
        memset(&flow, 0, sizeof(flow));

        /* pre_skype_packet_id = 2 -> becomes 3 after the classifier's own
         * increment, matching the "we have just seen the 3-way handshake"
         * branch. */
        int r = run_check_skype_tcp(&flow, 2, 1, 1, 1, PROTO_UNKNOWN, lens[i]);

        char msg[128];
        snprintf(msg, sizeof(msg), "payload_len %u: mmt_check_skype_tcp returns 0 (no match)", lens[i]);
        CHECK(r == 0, msg);
        snprintf(msg, sizeof(msg), "payload_len %u: flow not marked PROTO_SKYPE", lens[i]);
        CHECK(flow.detected_protocol_stack[0] != PROTO_SKYPE, msg);
    }
}

/* ---- UDP: the old 3-byte-trailing-nibble / >=16-byte-pattern shape match
 * no longer classifies as Skype (AC1/AC2) ---- */
static void test_udp_coincidental_shape_no_longer_classifies_skype(void)
{
    printf("[#102] UDP crafted shape/byte-pattern payloads are not classified as Skype\n");

    /* Case A: payload_len == 3, payload[2] & 0x0F == 0x0d. */
    {
        const uint8_t seed[3] = { 0x00, 0x00, 0x2D }; /* 0x2D & 0x0F == 0x0D */
        uint8_t *b = make_buf(seed, sizeof(seed));

        struct mmt_internal_tcpip_session_struct flow;
        memset(&flow, 0, sizeof(flow));

        int r = run_check_skype_udp(&flow, 0, 54321, PROTO_UNKNOWN, b, sizeof(seed));
        CHECK(r == 0, "3-byte payload with trailing nibble 0x0d: mmt_check_skype_udp returns 0 (no match)");
        CHECK(flow.detected_protocol_stack[0] != PROTO_SKYPE, "3-byte payload: flow not marked PROTO_SKYPE");
        free(b);
    }

    /* Case B: payload_len >= 16, payload[0] != 0x30, payload[2] == 0x02. */
    {
        uint8_t seed[16];
        memset(seed, 0, sizeof(seed));
        seed[0] = 0x01; /* != 0x30 */
        seed[2] = 0x02;
        uint8_t *b = make_buf(seed, sizeof(seed));

        struct mmt_internal_tcpip_session_struct flow;
        memset(&flow, 0, sizeof(flow));

        int r = run_check_skype_udp(&flow, 0, 54321, PROTO_UNKNOWN, b, sizeof(seed));
        CHECK(r == 0, ">=16-byte payload[0]!=0x30 && payload[2]==0x02: mmt_check_skype_udp returns 0 (no match)");
        CHECK(flow.detected_protocol_stack[0] != PROTO_SKYPE, ">=16-byte payload: flow not marked PROTO_SKYPE");
        free(b);
    }
}

/* ---- TCP guard preamble: an already-classified packet is not
 * re-classified as Skype, even given an otherwise crafted-match shape ---- */
static void test_tcp_already_classified_flow_not_reclassified(void)
{
    printf("[#102] already-classified TCP packet is not (re-)classified as Skype\n");

    struct mmt_internal_tcpip_session_struct flow;
    memset(&flow, 0, sizeof(flow));

    /* pre_detected_protocol = PROTO_HTTP (i.e. != PROTO_UNKNOWN) must make
     * the classifier return before it even increments skype_packet_id. */
    int r = run_check_skype_tcp(&flow, 2, 1, 1, 1, PROTO_HTTP, 8);

    CHECK(r == 0, "mmt_check_skype_tcp returns 0 for an already-classified packet");
    CHECK(flow.detected_protocol_stack[0] != PROTO_SKYPE, "flow not marked PROTO_SKYPE");
    CHECK(flow.l4.tcp.skype_packet_id == 2,
          "skype_packet_id left untouched (guard fires before any state mutation)");
}

/* ---- UDP guard preamble: same as above, for the UDP classifier ---- */
static void test_udp_already_classified_flow_not_reclassified(void)
{
    printf("[#102] already-classified UDP packet is not (re-)classified as Skype\n");

    const uint8_t seed[3] = { 0x00, 0x00, 0x2D };
    uint8_t *b = make_buf(seed, sizeof(seed));

    struct mmt_internal_tcpip_session_struct flow;
    memset(&flow, 0, sizeof(flow));

    int r = run_check_skype_udp(&flow, 0, 54321, PROTO_HTTP, b, sizeof(seed));

    CHECK(r == 0, "mmt_check_skype_udp returns 0 for an already-classified packet");
    CHECK(flow.detected_protocol_stack[0] != PROTO_SKYPE, "flow not marked PROTO_SKYPE");
    CHECK(flow.l4.udp.skype_packet_id == 0,
          "skype_packet_id left untouched (guard fires before any state mutation)");
    free(b);
}

int main(void)
{
    printf("=== Skype false-positive heuristic removal test (issue #102) ===\n");
    mmt_init_classify_me_skype();
    test_tcp_coincidental_shape_no_longer_classifies_skype();
    test_udp_coincidental_shape_no_longer_classifies_skype();
    test_tcp_already_classified_flow_not_reclassified();
    test_udp_already_classified_flow_not_reclassified();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
