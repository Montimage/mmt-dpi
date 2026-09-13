/*
 * caplen_clamp_test — regression test for issue #192 (F-BUG-016):
 * ip_post_classification_function() (proto_ip.c) derived l4_packet_len from
 * the attacker-controlled IPv4 tot_len and clamped to the captured length
 * only on the reassembly branch. A 60-byte frame declaring tot_len=65535
 * yielded l4_packet_len = 65515 — and payload_packet_len ~= 65495 in
 * proto_tcp.c — over a handful of actually captured payload bytes, so every
 * downstream dissector trusting it as a bound read far past the buffer.
 *
 * The fix computes usable = MIN(l3_packet_len, l3_captured_packet_len) before
 * subtracting the header length on every branch, so payload_packet_len can
 * never exceed what was captured.
 *
 * This test drives the full public packet path (mmt_init_handler +
 * packet_process) and asserts, inside the packet handler, that
 * internal_packet->payload_packet_len stays within the captured length.
 * The library is built with BUILD=asan by run_caplen_clamp_test.sh, so any
 * residual over-read by a dissector also aborts the run.
 *
 * Build (see run_caplen_clamp_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o caplen_clamp_test caplen_clamp_test.c \
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
static uint32_t g_l3_captured_len;
static const uint8_t *g_payload;
static const u_char    *g_data;

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (ipacket->internal_packet == NULL)
        return 0;
    g_seen            = 1;
    g_caplen          = ipacket->p_hdr->caplen;
    g_data            = ipacket->data;
    g_payload_len     = ipacket->internal_packet->payload_packet_len;
    g_l4_len          = ipacket->internal_packet->l4_packet_len;
    g_l3_captured_len = ipacket->internal_packet->l3_captured_packet_len;
    g_payload         = ipacket->internal_packet->payload;
    return 0;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

/* Write a 14-byte Ethernet header (ethertype IPv4). */
static int put_eth(uint8_t *b) {
    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(b, dst, 6);
    memcpy(b + 6, src, 6);
    put_be16(b + 12, 0x0800);
    return 14;
}

/* Write a 20-byte IPv4 header (ihl=5) with the given tot_len. */
static int put_ip4(uint8_t *b, uint8_t proto, uint16_t tot_len) {
    memset(b, 0, 20);
    b[0]  = 0x45;                 /* version 4, ihl 5 */
    b[1]  = 0x00;                 /* tos */
    put_be16(b + 2, tot_len);     /* total length — attacker-controlled */
    put_be16(b + 4, 0x1234);      /* id */
    put_be16(b + 6, 0);           /* flags + fragment offset: none */
    b[8]  = 64;                   /* ttl */
    b[9]  = proto;                /* protocol */
    /* checksum left 0 (MMT does not validate it) */
    b[12] = 10; b[13] = 0; b[14] = 0; b[15] = 1;   /* saddr 10.0.0.1 */
    b[16] = 10; b[17] = 0; b[18] = 0; b[19] = 2;   /* daddr 10.0.0.2 */
    return 20;
}

/* Write a 20-byte TCP header (doff=5, ACK+PSH). */
static int put_tcp(uint8_t *b) {
    put_be16(b, 12345);           /* sport */
    put_be16(b + 2, 80);          /* dport */
    memset(b + 4, 0, 8);          /* seq + ack */
    b[12] = 0x50;                 /* data offset 5 (<<4) */
    b[13] = 0x18;                 /* flags: PSH|ACK */
    put_be16(b + 14, 0xffff);     /* window */
    put_be16(b + 16, 0);          /* checksum */
    put_be16(b + 18, 0);          /* urg ptr */
    return 20;
}

/* Feed one frame through the full classification path. */
static void run_packet(mmt_handler_t *h, const uint8_t *data, uint32_t caplen) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec  = 1;
    hdr.ts.tv_usec = 0;
    hdr.caplen     = caplen;
    hdr.len        = caplen;
    g_seen = 0;
    packet_process(h, &hdr, data);
}

int main(void) {
    char errbuf[1024];
    mmt_handler_t *h;
    uint8_t pkt[128];
    int off;

    init_extraction();
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);

    printf("issue #192: l4/payload length clamped to the captured length\n");

    /* 1. THE BUG: a 60-byte frame (14 eth + 20 ip + 20 tcp + 6 payload)
     *    whose IPv4 header declares tot_len=65535. Before the fix
     *    l4_packet_len was 65515 and payload_packet_len 65495 — far beyond
     *    the 6 captured payload bytes. */
    off  = put_eth(pkt);
    off += put_ip4(pkt + off, 6 /*TCP*/, 65535);
    off += put_tcp(pkt + off);
    memset(pkt + off, 'A', 6); off += 6;
    CHECK(off == 60, "crafted frame is exactly 60 bytes");
    run_packet(h, pkt, off);
    CHECK(g_seen, "packet reached the handler");
    CHECK(g_payload_len <= g_caplen,
          "tot_len=65535: payload_packet_len <= caplen");
    CHECK(g_l4_len <= g_l3_captured_len,
          "tot_len=65535: l4_packet_len <= l3_captured_packet_len");
    CHECK(g_payload_len == 6,
          "tot_len=65535: payload_packet_len equals the 6 captured payload bytes");
    CHECK(g_payload + g_payload_len <= g_data + g_caplen,
          "tot_len=65535: payload end within the captured buffer");

    /* 2. Control: the same frame with an honest tot_len=46 must classify
     *    identically (payload_packet_len = 6). */
    off  = put_eth(pkt);
    off += put_ip4(pkt + off, 6 /*TCP*/, 20 + 20 + 6);
    off += put_tcp(pkt + off);
    memset(pkt + off, 'A', 6); off += 6;
    run_packet(h, pkt, off);
    CHECK(g_seen && g_payload_len == 6,
          "honest tot_len=46: payload_packet_len == 6 (unaffected)");

    /* 3. Truncated capture: wire declares a 100-byte IP datagram but only
     *    60 bytes were captured — the clamp must bound to the capture. */
    off  = put_eth(pkt);
    off += put_ip4(pkt + off, 6 /*TCP*/, 100);
    off += put_tcp(pkt + off);
    memset(pkt + off, 'B', 6); off += 6;
    run_packet(h, pkt, off);
    CHECK(g_seen && g_payload_len == 6,
          "truncated tot_len=100 over 60-byte capture: payload_packet_len == 6");

    /* 4. Ethernet padding: a 64-byte wire frame carrying an honest
     *    tot_len=46 — the clamp must NOT inflate the payload with padding. */
    off  = put_eth(pkt);
    off += put_ip4(pkt + off, 6 /*TCP*/, 20 + 20 + 6);
    off += put_tcp(pkt + off);
    memset(pkt + off, 'C', 6); off += 6;
    memset(pkt + off, 0, 4); off += 4;    /* 4 padding bytes to reach 64 */
    run_packet(h, pkt, off);
    CHECK(g_seen && g_payload_len == 6,
          "padded frame: payload_packet_len == 6 (padding excluded)");

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
