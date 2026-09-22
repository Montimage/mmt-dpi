/*
 * test_udp_payload_bounds — packet/API-path regression test for issue #375
 * (F-BUG-002): udp_pre_classification_function() must bound the UDP payload
 * by BOTH the UDP header length field and the enclosing IP payload:
 *
 *   - UDP length 8 with 32 captured L4 bytes exposes zero payload, and the
 *     trailing captured bytes cannot affect detection — a DNS-looking blob
 *     sitting past the declared datagram must not classify the packet DNS;
 *   - IPv4 and IPv6 behave identically, including IPv6 extension headers
 *     (payload_len counts them) and the IPv6 jumbo case (payload_len == 0,
 *     RFC 2675 — captured bound retained, UDP length 0 is legal there);
 *   - a forged UDP length above the IP payload, an oversized enclosing
 *     length and truncated captures all clamp to captured/declared bounds.
 *
 * The test drives the full public packet path (mmt_init_handler +
 * packet_process) and asserts inside the packet handler on
 * internal_packet->payload_packet_len, the payload pointer and the detected
 * protocol path. Built with sanitizers by run_tests.sh, so any residual
 * over-read by a dissector also aborts the run.
 *
 * Build (see run_tests.sh):
 *   gcc -g -O1 -o test_udp_payload_bounds test_udp_payload_bounds.c \
 *       -I<prefix>/dpi/include -I<repo>/src/mmt_tcpip/lib \
 *       -L<prefix>/dpi/lib -lmmt_core -ldl -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mmt_tcpip_plugin_structs.h"   /* struct mmt_tcpip_internal_packet_struct — from the source tree, not installed */

typedef unsigned char u_char;

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, msg) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: %s\n", (msg));                           \
        } else {                                                     \
            printf("  FAIL: %s\n", (msg));                           \
            g_failures++;                                            \
        }                                                            \
    } while (0)

/* Values observed in the packet handler for the last processed packet. */
static int      g_seen;
static uint32_t g_caplen;
static uint32_t g_payload_len;
static uint32_t g_l4_len;
static uint64_t g_data_byte_volume;
static const uint8_t *g_payload;
static const u_char    *g_data;
static int      g_dns_seen;

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (ipacket->internal_packet == NULL)
        return 0;
    g_seen        = 1;
    g_caplen      = ipacket->p_hdr->caplen;
    g_data        = ipacket->data;
    g_payload_len = ipacket->internal_packet->payload_packet_len;
    g_l4_len      = ipacket->internal_packet->l4_packet_len;
    g_payload     = ipacket->internal_packet->payload;
    g_data_byte_volume = ipacket->session != NULL
        ? get_session_data_byte_count(ipacket->session) : 0;
    g_dns_seen = 0;
    if (ipacket->proto_hierarchy != NULL) {
        int i;
        for (i = 0; i < ipacket->proto_hierarchy->len; i++) {
            if (ipacket->proto_hierarchy->proto_path[i] == PROTO_DNS)
                g_dns_seen = 1;
        }
    }
    return 0;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

/* Write a 14-byte Ethernet header. */
static int put_eth(uint8_t *b, uint16_t ethertype) {
    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(b, dst, 6);
    memcpy(b + 6, src, 6);
    put_be16(b + 12, ethertype);
    return 14;
}

/* Write a 20-byte IPv4 header (ihl=5) with the given tot_len. */
static int put_ip4(uint8_t *b, uint8_t proto, uint16_t tot_len) {
    memset(b, 0, 20);
    b[0]  = 0x45;
    put_be16(b + 2, tot_len);
    put_be16(b + 4, 0x1234);
    put_be16(b + 6, 0);
    b[8]  = 64;
    b[9]  = proto;
    b[12] = 10; b[13] = 0; b[14] = 0; b[15] = 1;
    b[16] = 10; b[17] = 0; b[18] = 0; b[19] = 2;
    return 20;
}

/* Write a 40-byte IPv6 header with the given payload_len and nexthdr. */
static int put_ip6(uint8_t *b, uint8_t nexthdr, uint16_t payload_len) {
    memset(b, 0, 40);
    b[0]  = 0x60;
    put_be16(b + 4, payload_len);
    b[6]  = nexthdr;
    b[7]  = 64;
    /* saddr 2001:db8::1, daddr 2001:db8::2 */
    b[8] = 0x20; b[9] = 0x01; b[10] = 0x0d; b[11] = 0xb8; b[23] = 1;
    b[24] = 0x20; b[25] = 0x01; b[26] = 0x0d; b[27] = 0xb8; b[39] = 2;
    return 40;
}

/* Write an 8-byte hop-by-hop extension header (next=UDP, len 0 -> 8 bytes). */
static int put_ip6_hbh(uint8_t *b) {
    memset(b, 0, 8);
    b[0] = 17;   /* next header: UDP */
    b[1] = 0;    /* hdr ext len: 0 -> 8 bytes total */
    b[2] = 1; b[3] = 0;   /* PadN option, len 0 */
    b[4] = 0;             /* Pad1 */
    b[5] = 0;
    return 8;
}

/* Write an 8-byte UDP header with the given len field. */
static int put_udp(uint8_t *b, uint16_t sport, uint16_t dport, uint16_t len) {
    put_be16(b, sport);
    put_be16(b + 2, dport);
    put_be16(b + 4, len);
    put_be16(b + 6, 0);
    return 8;
}

/* Write a minimal valid DNS query (passes dns_check_payload): ID, RD flag,
 * QDCOUNT=1, all other counts 0, then a 12-byte QNAME/QTYPE/QCLASS blob. */
static int put_dns_query(uint8_t *b) {
    memset(b, 0, 24);
    put_be16(b, 0x1234);      /* ID */
    put_be16(b + 2, 0x0100);  /* RD */
    put_be16(b + 4, 1);       /* QDCOUNT */
    b[12] = 1; b[13] = 'a';
    put_be16(b + 15, 1);      /* QTYPE A — position is illustrative only */
    put_be16(b + 17, 1);      /* QCLASS IN */
    return 24;
}

/* Feed one frame through the full classification path. */
static void run_packet(mmt_handler_t *h, const uint8_t *data, uint32_t caplen,
        uint32_t wire_len) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec  = 1;
    hdr.ts.tv_usec = 0;
    hdr.caplen     = caplen;
    hdr.len        = wire_len;
    g_seen = 0;
    packet_process(h, &hdr, data);
}

int main(void) {
    char errbuf[1024];
    mmt_handler_t *h;
    uint8_t pkt[160];
    int off;
    uint16_t sport = 40000;

    init_extraction();
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);

    printf("issue #375: UDP payload bounded by udp->len and the enclosing IP payload\n");

    /* ================= IPv4 ================= */

    /* 1. HEADLINE CASE: UDP length 8 (no declared payload) but 32 L4 bytes
     *    captured — the trailing 24 bytes are a valid-looking DNS query to
     *    dport 53. They must expose zero payload and must not classify the
     *    packet DNS nor count as session data volume. */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 17, 20 + 8 + 24);
    off += put_udp(pkt + off, sport++, 53, 8);
    off += put_dns_query(pkt + off);
    run_packet(h, pkt, off, off);
    CHECK(g_seen, "IPv4 udp_len=8/32: packet reached the handler");
    CHECK(g_payload_len == 0,
          "IPv4 udp_len=8 of 32 captured: zero payload");
    CHECK(!g_dns_seen,
          "IPv4 udp_len=8/32: trailing DNS blob cannot classify");
    CHECK(g_data_byte_volume == 0,
          "IPv4 udp_len=8/32: trailing bytes excluded from data volume");
    CHECK(g_payload + g_payload_len <= g_data + g_caplen,
          "IPv4 udp_len=8/32: payload end within the capture");

    /* 2. UDP length smaller than the captured L4 extent: declared wins. */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 17, 20 + 32);
    off += put_udp(pkt + off, sport++, 9999, 20);
    memset(pkt + off, 'A', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 12,
          "IPv4 udp_len=20 of 32 captured: payload == 12");
    CHECK(g_data_byte_volume == 12,
          "IPv4 udp_len=20/32: data volume counts 12 payload bytes only");

    /* 3. UDP length larger than the enclosing IP payload: enclosing wins. */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 17, 20 + 32);
    off += put_udp(pkt + off, sport++, 9999, 60);
    memset(pkt + off, 'B', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 24,
          "IPv4 udp_len=60 oversized vs l4=32: payload == 24");

    /* 4. UDP length 0 over IPv4 keeps the enclosing bound. */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 17, 20 + 32);
    off += put_udp(pkt + off, sport++, 9999, 0);
    memset(pkt + off, 'C', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 24,
          "IPv4 udp_len=0: payload == 24 (enclosing bound)");

    /* 5. UDP length below the header size: malformed, no payload. */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 17, 20 + 32);
    off += put_udp(pkt + off, sport++, 9999, 4);
    memset(pkt + off, 'D', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 0,
          "IPv4 udp_len=4 malformed: zero payload");

    /* 6. Oversized enclosing length: IPv4 tot_len=65535 over a 66-byte
     *    capture — payload clamps to what was captured, then to udp_len. */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 17, 65535);
    off += put_udp(pkt + off, sport++, 9999, 60);
    memset(pkt + off, 'E', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 24,
          "IPv4 tot_len=65535 oversized: payload == 24 (captured bound)");
    CHECK(g_payload + g_payload_len <= g_data + g_caplen,
          "IPv4 tot_len=65535: payload end within the capture");

    /* 7. Truncated capture: wire declares a 76-byte datagram but only 66
     *    were captured — the bound clamps to the capture. */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 17, 20 + 8 + 48);
    off += put_udp(pkt + off, sport++, 9999, 8 + 48);
    memset(pkt + off, 'F', 24); off += 24;
    run_packet(h, pkt, off, 14 + 20 + 8 + 48);
    CHECK(g_seen && g_payload_len == 24,
          "IPv4 truncated capture: payload == 24 (only captured bytes)");

    /* ================= IPv6 ================= */

    /* 8. IPv6 headline: UDP length 8, 32 captured L4 bytes — zero payload. */
    off  = put_eth(pkt, 0x86dd);
    off += put_ip6(pkt + off, 17, 32);
    off += put_udp(pkt + off, sport++, 9999, 8);
    memset(pkt + off, 'G', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 0,
          "IPv6 udp_len=8 of 32 captured: zero payload");

    /* 9. IPv6 payload_len smaller than the capture: the over-captured tail
     *    is excluded even though udp_len would allow it. */
    off  = put_eth(pkt, 0x86dd);
    off += put_ip6(pkt + off, 17, 20);
    off += put_udp(pkt + off, sport++, 9999, 20);
    memset(pkt + off, 'H', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 12,
          "IPv6 plen=20 over-captured 32: payload == 12");

    /* 10. IPv6 extension headers: an 8-byte hop-by-hop header sits between
     *     the base header and UDP; payload_len counts it too. */
    off  = put_eth(pkt, 0x86dd);
    off += put_ip6(pkt + off, 0 /*hbh*/, 8 + 40);
    off += put_ip6_hbh(pkt + off);
    off += put_udp(pkt + off, sport++, 9999, 40);
    memset(pkt + off, 'I', 32); off += 32;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 32,
          "IPv6 hbh+udp plen=48 udp_len=40: payload == 32");

    /* 11. IPv6 jumbogram: payload_len 0 (RFC 2675) and UDP length 0 keep
     *     the captured bound — the real length lives in the Jumbo Payload
     *     hop-by-hop option which is not consulted here. */
    off  = put_eth(pkt, 0x86dd);
    off += put_ip6(pkt + off, 17, 0);
    off += put_udp(pkt + off, sport++, 9999, 0);
    memset(pkt + off, 'J', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 24,
          "IPv6 jumbo plen=0 udp_len=0: payload == 24 (captured bound)");

    /* 12. A non-jumbo IPv6 packet declaring UDP length 0 is malformed:
     *     no payload is exposed. */
    off  = put_eth(pkt, 0x86dd);
    off += put_ip6(pkt + off, 17, 32);
    off += put_udp(pkt + off, sport++, 9999, 0);
    memset(pkt + off, 'K', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 0,
          "IPv6 non-jumbo udp_len=0 malformed: zero payload");

    /* 13. Oversized IPv6 payload_len vs captured bytes: captured bound
     *     wins, then udp_len applies inside it. */
    off  = put_eth(pkt, 0x86dd);
    off += put_ip6(pkt + off, 17, 100);
    off += put_udp(pkt + off, sport++, 9999, 24);
    memset(pkt + off, 'L', 24); off += 24;
    run_packet(h, pkt, off, off);
    CHECK(g_seen && g_payload_len == 16,
          "IPv6 plen=100 oversized vs 32 captured: payload == 16");

    mmt_close_handler(h);
    close_extraction();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
