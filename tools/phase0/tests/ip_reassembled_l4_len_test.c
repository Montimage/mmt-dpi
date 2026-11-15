/*
 * ip_reassembled_l4_len_test — regression test for issue #84:
 * since issue #192 (F-BUG-016) ip_post_classification_function()
 * (proto_ip.c) bounded the L4 length by MIN(l3_packet_len,
 * l3_captured_packet_len) on every branch, including a datagram rebuilt
 * from fragments. Such a datagram keeps the IPv4 header of the fragment
 * that completed it, so l3_packet_len (its tot_len) is the size of that
 * last fragment, not of the rebuilt datagram, and the L4 length was cut
 * to it: a TCP SYN carrying 26 bytes whose last fragment holds 6 bytes got
 * l4_packet_len 6 (< the TCP header), proto_tcp.c skipped it and
 * tcp.payload_len was 0 (mmt-security "data in SYN" rule, 19.SQLI.pcap).
 *
 * The fix takes the length of the reassembled buffer for a reassembled
 * datagram and keeps the MIN for every other packet
 * (run_caplen_clamp_test.sh still covers that bound).
 *
 * This test drives the full public packet path (mmt_init_handler +
 * packet_process) with fragmented IPv4 TCP and UDP datagrams whose
 * reassembled payload is longer than the last fragment, and asserts, in the
 * packet handler of the completing fragment, that payload_packet_len and
 * tcp.payload_len equal the real payload length and stay inside the
 * reassembled buffer. The library is built with BUILD=asan by
 * run_ip_reassembled_l4_len_test.sh, so any over-read also aborts the run.
 *
 * Build (see run_ip_reassembled_l4_len_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o ip_reassembled_l4_len_test ip_reassembled_l4_len_test.c \
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
static int      g_has_tcp_attr;
static uint32_t g_tcp_attr_payload_len;
static const uint8_t *g_payload;
static const u_char  *g_data;
static uint8_t  g_payload_copy[256];

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (ipacket->internal_packet == NULL)
        return 0;
    g_seen         = 1;
    g_caplen       = ipacket->p_hdr->caplen;
    g_data         = ipacket->data;
    g_payload_len  = ipacket->internal_packet->payload_packet_len;
    g_l4_len       = ipacket->internal_packet->l4_packet_len;
    g_payload      = ipacket->internal_packet->payload;
    if (g_payload != NULL && g_payload_len <= sizeof(g_payload_copy)
        && g_payload >= g_data && g_payload + g_payload_len <= g_data + g_caplen)
        memcpy(g_payload_copy, g_payload, g_payload_len);
    else
        memset(g_payload_copy, 0, sizeof(g_payload_copy));

    const uint32_t *v = (const uint32_t *)
        get_attribute_extracted_data(ipacket, PROTO_TCP, TCP_PAYLOAD_LEN);
    g_has_tcp_attr         = (v != NULL);
    g_tcp_attr_payload_len = v ? *v : 0;
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

/* Write a 20-byte IPv4 header (ihl=5) for one fragment: offset in bytes
 * (multiple of 8), mf = more-fragments flag. */
static int put_ip4_frag(uint8_t *b, uint8_t proto, uint16_t id,
                        uint16_t tot_len, uint16_t frag_off_bytes, int mf,
                        uint8_t saddr_last) {
    memset(b, 0, 20);
    b[0]  = 0x45;                 /* version 4, ihl 5 */
    put_be16(b + 2, tot_len);
    put_be16(b + 4, id);
    put_be16(b + 6, (uint16_t) ((mf ? 0x2000 : 0) | (frag_off_bytes >> 3)));
    b[8]  = 64;                   /* ttl */
    b[9]  = proto;
    b[12] = 10; b[13] = 0; b[14] = 0; b[15] = saddr_last;  /* saddr 10.0.0.x */
    b[16] = 10; b[17] = 0; b[18] = 0; b[19] = 2;           /* daddr 10.0.0.2 */
    return 20;
}

/* Feed one frame through the full classification path. */
static void run_packet(mmt_handler_t *h, const uint8_t *data, uint32_t caplen,
                       uint32_t sec) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec  = sec;
    hdr.ts.tv_usec = 0;
    hdr.caplen     = caplen;
    hdr.len        = caplen;
    g_seen = 0;
    packet_process(h, &hdr, data);
}

/* Send the L4 datagram `l4` (l4_len bytes) as IPv4 fragments cut at the
 * byte offsets in cuts[] (each a multiple of 8, ascending, < l4_len). The
 * handler state left afterwards is that of the completing (last) fragment. */
static void send_fragmented(mmt_handler_t *h, uint8_t proto, uint16_t id,
                            uint8_t saddr_last, const uint8_t *l4,
                            uint16_t l4_len, const uint16_t *cuts,
                            int ncuts, uint32_t sec) {
    uint8_t frame[256];
    int i;
    for (i = 0; i <= ncuts; i++) {
        uint16_t start = (i == 0) ? 0 : cuts[i - 1];
        uint16_t end   = (i == ncuts) ? l4_len : cuts[i];
        uint16_t flen  = (uint16_t) (end - start);
        int off = put_eth(frame);
        off += put_ip4_frag(frame + off, proto, id, (uint16_t) (20 + flen),
                            start, i != ncuts, saddr_last);
        memcpy(frame + off, l4 + start, flen);
        off += flen;
        run_packet(h, frame, (uint32_t) off, sec);
    }
}

int main(void) {
    char errbuf[1024];
    mmt_handler_t *h;
    uint8_t l4[128];
    static const char tcp_data[] = "AAAAAAAA SELECT ZZZZZZZZZZ";   /* 26 bytes */
    static const char udp_data[] = "0123456789abcdefghijklmnopqrstuv"; /* 32 bytes */

    init_extraction();
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_extraction_attribute(h, PROTO_TCP, TCP_PAYLOAD_LEN);
    register_packet_handler(h, 1, packet_handler, NULL);

    printf("issue #84: L4 length of a reassembled IPv4 datagram\n");

    /* 1. THE BUG (shape of mmt-security 19.SQLI.pcap): a TCP SYN with 26
     *    bytes of data (46-byte L4) in two fragments, 40 + 6 bytes. The
     *    completing fragment declares tot_len = 26, so before the fix
     *    l4_packet_len was 6 (< the TCP header) and payload_len 0. */
    {
        const uint16_t l4_len = 20 + 26;
        const uint16_t cuts[] = { 40 };
        memset(l4, 0, sizeof(l4));
        put_be16(l4, 12345);          /* sport */
        put_be16(l4 + 2, 80);         /* dport */
        l4[7]  = 1;                   /* seq 1 */
        l4[12] = 0x50;                /* data offset 5 */
        l4[13] = 0x02;                /* SYN */
        put_be16(l4 + 14, 0xffff);    /* window */
        memcpy(l4 + 20, tcp_data, 26);
        send_fragmented(h, 6 /*TCP*/, 0x1001, 1, l4, l4_len, cuts, 1, 1);
        CHECK(g_seen, "TCP 40+6: reassembled packet reached the handler");
        CHECK(g_l4_len == l4_len,
              "TCP 40+6: l4_packet_len == 46 (reassembled TCP segment)");
        CHECK(g_payload_len == 26,
              "TCP 40+6: payload_packet_len == 26 (not 0)");
        CHECK(g_has_tcp_attr && g_tcp_attr_payload_len == 26,
              "TCP 40+6: tcp.payload_len attribute == 26");
        CHECK(memcmp(g_payload_copy, tcp_data, 26) == 0,
              "TCP 40+6: payload bytes are the reassembled data");
        CHECK(g_payload + g_payload_len <= g_data + g_caplen,
              "TCP 40+6: payload end within the reassembled buffer");
    }

    /* 2. Three fragments, out of order (last one first): the datagram is
     *    completed by the middle fragment, whose tot_len (20 + 16) again
     *    describes only itself. */
    {
        const uint16_t l4_len = 20 + 26;
        uint8_t frame[256];
        int off;
        memset(l4, 0, sizeof(l4));
        put_be16(l4, 23456);
        put_be16(l4 + 2, 80);
        l4[12] = 0x50;
        l4[13] = 0x02;
        put_be16(l4 + 14, 0xffff);
        memcpy(l4 + 20, tcp_data, 26);
        /* [0,24) [24,40) [40,46) sent as 3rd, 1st, 2nd */
        off  = put_eth(frame);
        off += put_ip4_frag(frame + off, 6, 0x1002, 20 + 6, 40, 0, 3);
        memcpy(frame + off, l4 + 40, 6); off += 6;
        run_packet(h, frame, (uint32_t) off, 2);
        off  = put_eth(frame);
        off += put_ip4_frag(frame + off, 6, 0x1002, 20 + 24, 0, 1, 3);
        memcpy(frame + off, l4, 24); off += 24;
        run_packet(h, frame, (uint32_t) off, 2);
        off  = put_eth(frame);
        off += put_ip4_frag(frame + off, 6, 0x1002, 20 + 16, 24, 1, 3);
        memcpy(frame + off, l4 + 24, 16); off += 16;
        run_packet(h, frame, (uint32_t) off, 2);
        CHECK(g_seen && g_payload_len == 26,
              "TCP 24+16+6 out of order: payload_packet_len == 26");
        CHECK(g_has_tcp_attr && g_tcp_attr_payload_len == 26,
              "TCP 24+16+6 out of order: tcp.payload_len attribute == 26");
        CHECK(g_payload + g_payload_len <= g_data + g_caplen,
              "TCP 24+16+6 out of order: payload end within the reassembled buffer");
    }

    /* 3. UDP: 8 + 32 bytes in two fragments, 24 + 16. Before the fix the
     *    L4 length was 16 and the payload 8 bytes instead of 32. */
    {
        const uint16_t l4_len = 8 + 32;
        const uint16_t cuts[] = { 24 };
        memset(l4, 0, sizeof(l4));
        put_be16(l4, 40000);          /* sport */
        put_be16(l4 + 2, 9999);       /* dport */
        put_be16(l4 + 4, l4_len);     /* udp length */
        memcpy(l4 + 8, udp_data, 32);
        send_fragmented(h, 17 /*UDP*/, 0x1003, 4, l4, l4_len, cuts, 1, 3);
        CHECK(g_seen, "UDP 24+16: reassembled packet reached the handler");
        CHECK(g_l4_len == l4_len,
              "UDP 24+16: l4_packet_len == 40 (reassembled UDP datagram)");
        CHECK(g_payload_len == 32,
              "UDP 24+16: payload_packet_len == 32 (not 8)");
        CHECK(memcmp(g_payload_copy, udp_data, 32) == 0,
              "UDP 24+16: payload bytes are the reassembled data");
        CHECK(g_payload + g_payload_len <= g_data + g_caplen,
              "UDP 24+16: payload end within the reassembled buffer");
    }

    /* 4. Control: the #192 bound still holds for an unfragmented packet —
     *    a 60-byte frame declaring tot_len=65535 exposes only the 6
     *    captured payload bytes. */
    {
        uint8_t frame[128];
        int off = put_eth(frame);
        off += put_ip4_frag(frame + off, 6, 0x1004, 65535, 0, 0, 5);
        memset(frame + off, 0, 20);
        put_be16(frame + off, 12345);
        put_be16(frame + off + 2, 80);
        frame[off + 12] = 0x50;
        frame[off + 13] = 0x18;       /* PSH|ACK */
        off += 20;
        memset(frame + off, 'A', 6); off += 6;
        run_packet(h, frame, (uint32_t) off, 4);
        CHECK(g_seen && g_payload_len == 6,
              "unfragmented tot_len=65535: payload_packet_len == 6 (still clamped)");
    }

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
