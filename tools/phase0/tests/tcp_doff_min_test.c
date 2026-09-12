/*
 * tcp_doff_min_test — crafted-input regression test for the TCP data-offset
 * (doff) minimum-length validation.
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 7 (issue #25, M6).
 *
 * The TCP data offset (`doff`) is a 4-bit header field that, per RFC 793, must
 * be at least 5 — a 20-byte header with no options. Before the fix,
 * tcp_pre_classification_function() (and its reassembling twin) in
 * src/mmt_tcpip/lib/protocols/proto_tcp.c derived the header length straight
 * from doff:
 *
 *     uint16_t tcphdr_len = packet->tcp->doff * 4;
 *     if (packet->l4_packet_len < tcphdr_len) return 0;   // length sanity
 *     packet->payload = ((uint8_t *) packet->tcp) + tcphdr_len;
 *
 * A malformed doff of 0 produces tcphdr_len == 0, which slips past the
 * "l4_packet_len < tcphdr_len" check and leaves the parser treating the whole
 * segment (including the bytes that are actually part of the TCP header) as
 * payload. The fix rejects any segment whose doff is below 5 before deriving
 * offsets from it.
 *
 * This test drives tcp_pre_classification_function() directly with crafted TCP
 * headers. The function sets packet->payload only once it has accepted the
 * doff value and passed the subsequent length check, so packet->payload is a
 * clean observable for the gate:
 *
 *   - doff in 0..4 (malformed): rejected at the doff gate -> packet->payload
 *     stays NULL (the early return runs before the payload assignment).
 *   - doff in 5..15 (valid):    accepted past the doff gate -> packet->payload
 *     is set to (tcp header start + doff*4), i.e. non-NULL.
 *
 * The packet data buffer is heap-allocated and exactly sized so AddressSanitizer
 * brackets it tightly; the runner (run_tcp_doff_min_test.sh) builds the library
 * and this test with -fsanitize=address,undefined -fno-sanitize-recover=all, so
 * any out-of-bounds access while parsing a malformed header aborts. A clean
 * exit 0 with every assertion passing is the success condition.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#include "mmt_core.h"
/*
 * The internal packet / session structs are opaque in the installed public
 * headers, so pull in their full definitions from the in-tree plugin header
 * (the runner adds the matching -I paths). The layout is identical to the one
 * the library was compiled with, since both come from this same header.
 */
#include "mmt_tcpip_plugin_structs.h"
#include "mmt_tcpip_internal_defs_macros.h"

/*
 * Entry point under test. tcp_pre_classification_function() is exported but not
 * declared in any installed public header; it comes from the shared internal
 * header (issue #186).
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

/* TCP header bytes [12..13] carry the data offset (high nibble of byte 12) and
 * the flags. We craft the on-the-wire layout directly so the test is
 * independent of how the library's struct names the bitfields. */
#define TCP_DOFF_BYTE 12

/*
 * Build an exactly-`len`-byte (ASan-bracketed) packet buffer that looks like a
 * TCP segment whose data offset is `doff`, run it through
 * tcp_pre_classification_function() over a non-IPv6 flow with l4_packet_len set
 * to the full buffer, and report back whether packet->payload was set.
 *
 * Returns the function's return value; *payload_set is 1 iff packet->payload is
 * non-NULL after the call.
 */
static int run_tcp_pre(unsigned doff, size_t len, int *payload_set)
{
    ipacket_t pkt;
    struct mmt_tcpip_internal_packet_struct ip;
    proto_hierarchy_t headers_offset;

    memset(&pkt, 0, sizeof(pkt));
    memset(&ip, 0, sizeof(ip));
    memset(&headers_offset, 0, sizeof(headers_offset));

    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    if (!buf) { perror("malloc"); exit(2); }
    memset(buf, 0, len ? len : 1);
    /* data offset lives in the high nibble of header byte 12 */
    if (len > TCP_DOFF_BYTE)
        buf[TCP_DOFF_BYTE] = (uint8_t)((doff & 0x0F) << 4);

    /* proto_headers_offset[0] == 0 -> the L4 offset resolves to the start of
     * the buffer, so packet->tcp points at buf[0]. */
    headers_offset.proto_path[0] = 0;
    pkt.proto_headers_offset = &headers_offset;
    pkt.internal_cumulative_offset_valid = 0;
    pkt.data = (const u_char *)buf;
    pkt.session = NULL;
    pkt.p_hdr = NULL;
    pkt.internal_packet = (mmt_tcpip_internal_packet_t *)&ip;

    /* iphv6 == 0 -> the function keeps the l4_packet_len we set here. */
    ip.iphv6 = NULL;
    ip.flow = NULL;            /* NULL flow keeps the path simple + side-effect free */
    ip.l4_packet_len = (uint16_t)len;
    ip.payload = NULL;

    int rc = tcp_pre_classification_function(&pkt, 0);
    *payload_set = (ip.payload != NULL);
    free(buf);
    return rc;
}

/* ---- malformed data offsets (doff < 5) are rejected before use (AC #1) ---- */
static void test_doff_below_min_rejected(void)
{
    printf("[M6] TCP data offset below 5 is rejected (no offset derived from it)\n");
    for (unsigned doff = 0; doff <= 4; doff++) {
        int payload_set = -1;
        int rc = run_tcp_pre(doff, 60, &payload_set);
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "doff %u rejected: payload left unset (rc=%d)", doff, rc);
        /* The gate must short-circuit before packet->payload is assigned. */
        CHECK(payload_set == 0, msg);
    }
}

/* ---- valid data offsets (doff >= 5) pass the gate (AC #1, contrast) ---- */
static void test_doff_at_or_above_min_accepted(void)
{
    printf("[M6] TCP data offset >= 5 passes the validation gate\n");
    /* l4_packet_len = 60 is large enough for every legal doff (max 15 -> 60
     * bytes), so the post-gate length check passes and payload is assigned. */
    for (unsigned doff = 5; doff <= 15; doff++) {
        int payload_set = -1;
        run_tcp_pre(doff, 60, &payload_set);
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "doff %u accepted: payload assigned past the gate", doff);
        CHECK(payload_set == 1, msg);
    }
}

int main(void)
{
    printf("=== TCP data-offset minimum validation test (issue #25: M6) ===\n");
    test_doff_below_min_rejected();
    test_doff_at_or_above_min_accepted();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
