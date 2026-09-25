/*
 * test_int_ipv6_parser — packet/API-path regression test for issues #332
 * and #453: the INT (proto_int.c) and INT-report (proto_int_report.c)
 * dissectors.
 *
 *   - INT embedded in UDP or TCP is detected from the DSCP of an IPv4 or an
 *     IPv6 (Traffic Class) carrier; a non-INT DSCP is not;
 *   - the DSCP alone (0x20 is also the standard CS4 class) is not enough:
 *     the payload must start with a valid INT v1.0 shim (type 0/1, Length of
 *     at least 3 words fitting the payload) and metadata header (Ver 1);
 *   - the hop stride follows Hop ML when it covers the parsed fields;
 *   - the layer after INT starts at the shim's Length (4-byte words), not a
 *     fixed 56 bytes;
 *   - a Hop ML of 0 never divides by zero;
 *   - LV2 Ingress/Egress Port IDs decode as 16+16 bits in one word and, when
 *     Hop ML says so, as the spec's two 4-byte words;
 *   - an INT report whose inner packet is IPv6 is classified, exposes the
 *     IPv6 flow addresses (ip6_src/ip6_dst) and the ports, while the IPv4-only
 *     ip_src is absent; an inner IPv4 with options still yields its ports;
 *     truncated inner headers and non-first inner fragments are rejected,
 *     an inner packet without a valid shim carries no INT layer, and the
 *     inner IPv4 ip_src/ip_dst are in network byte order; an inner TCP header
 *     is skipped by its data offset (options included), and a data offset
 *     below 5 words is rejected.
 *
 * Frames are copied into exactly caplen-sized heap buffers, and run_tests.sh
 * builds with sanitizers under SANITIZE=asan, so any over-read or misaligned
 * load aborts the run.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mmt_tcpip_plugin_structs.h"          /* source tree, not installed */
#include "protocols/proto_int.h"               /* INT_* attribute ids */
#include "protocols/proto_int_report.h"        /* INT_REPORT_* attribute ids */

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

/* --- snapshot of the last processed packet ----------------------------- */
static struct {
    int      int_seen, report_seen;
    int      after_int_offset;       /* header offset of the layer after INT, -1 if none */
    int      has_num_hop;
    uint8_t  num_hop;
    int      has_lv2;
    uint32_t lv2_in[4], lv2_e[4];
    uint32_t lv2_len;
    int      has_ip6_src, has_ip6_dst, has_ip_src;
    uint8_t  ip6_src[16], ip6_dst[16];
    int      has_ports;
    uint16_t port_src, port_dst;
    int      has_sw_ids;
    uint32_t sw_ids[4], sw_len;
    int      has_ip_dst;
    uint8_t  ip_src[4], ip_dst[4];
} g;

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    memset(&g, 0, sizeof(g));
    g.after_int_offset = -1;
    if (ipacket->proto_hierarchy == NULL)
        return 0;
    for (int i = 0; i < ipacket->proto_hierarchy->len; i++) {
        uint32_t p = ipacket->proto_hierarchy->proto_path[i];
        if (p == PROTO_INT_REPORT)
            g.report_seen = 1;
        if (p == PROTO_INT) {
            g.int_seen = 1;
            if (i + 1 < ipacket->proto_hierarchy->len)
                g.after_int_offset = ipacket->proto_headers_offset->proto_path[i + 1];
        }
    }
    const uint8_t *u8 = get_attribute_extracted_data(ipacket, PROTO_INT, INT_NUM_HOP);
    if (u8 != NULL) { g.has_num_hop = 1; g.num_hop = *u8; }

    const mmt_u32_array_t *in = get_attribute_extracted_data(ipacket, PROTO_INT, INT_HOP_LV2_INGRESS_PORT_IDS);
    const mmt_u32_array_t *eg = get_attribute_extracted_data(ipacket, PROTO_INT, INT_HOP_LV2_EGRESS_PORT_IDS);
    if (in != NULL && eg != NULL) {
        g.has_lv2 = 1;
        g.lv2_len = in->len;
        for (uint32_t i = 0; i < in->len && i < 4; i++) {
            g.lv2_in[i] = in->data[i];
            g.lv2_e[i]  = eg->data[i];
        }
    }

    const uint8_t *a6 = get_attribute_extracted_data(ipacket, PROTO_INT_REPORT, INT_REPORT_FLOW_IP6_SRC);
    if (a6 != NULL) { g.has_ip6_src = 1; memcpy(g.ip6_src, a6, 16); }
    a6 = get_attribute_extracted_data(ipacket, PROTO_INT_REPORT, INT_REPORT_FLOW_IP6_DST);
    if (a6 != NULL) { g.has_ip6_dst = 1; memcpy(g.ip6_dst, a6, 16); }
    const mmt_u32_array_t *sw = get_attribute_extracted_data(ipacket, PROTO_INT, INT_HOP_SWITCH_IDS);
    if (sw != NULL) {
        g.has_sw_ids = 1;
        g.sw_len = sw->len;
        for (uint32_t i = 0; i < sw->len && i < 4; i++)
            g.sw_ids[i] = sw->data[i];
    }
    const uint8_t *a4 = get_attribute_extracted_data(ipacket, PROTO_INT_REPORT, INT_REPORT_FLOW_IP_SRC);
    if (a4 != NULL) { g.has_ip_src = 1; memcpy(g.ip_src, a4, 4); }
    a4 = get_attribute_extracted_data(ipacket, PROTO_INT_REPORT, INT_REPORT_FLOW_IP_DST);
    if (a4 != NULL) { g.has_ip_dst = 1; memcpy(g.ip_dst, a4, 4); }
    const uint16_t *ps = get_attribute_extracted_data(ipacket, PROTO_INT_REPORT, INT_REPORT_FLOW_PORT_SRC);
    const uint16_t *pd = get_attribute_extracted_data(ipacket, PROTO_INT_REPORT, INT_REPORT_FLOW_PORT_DST);
    if (ps != NULL && pd != NULL) { g.has_ports = 1; g.port_src = *ps; g.port_dst = *pd; }
    return 0;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

static const uint8_t SRC6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01};
static const uint8_t DST6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x02};

static size_t put_eth(uint8_t *b, uint16_t type) {
    static const uint8_t macs[12] = {0x00,0x11,0x22,0x33,0x44,0x55,
                                     0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(b, macs, 12);
    put_be16(b + 12, type);
    return 14;
}

/* IPv4 header (ihl words), protocol l4proto, TOS = dscp << 2 */
static size_t put_ip4(uint8_t *b, uint8_t dscp, unsigned ihl, size_t l4_len, uint8_t l4proto) {
    size_t hl = ihl * 4;
    memset(b, 0, hl);
    b[0] = 0x40 | (uint8_t) ihl;
    b[1] = (uint8_t)(dscp << 2);
    put_be16(b + 2, (uint16_t)(hl + l4_len));
    b[8] = 64; b[9] = l4proto;
    b[12] = 10; b[15] = 1; b[16] = 10; b[19] = 2;
    if (hl > 20) b[20] = 0x01; /* NOP options */
    return hl;
}

/* IPv6 header, next header l4proto, Traffic Class = dscp << 2 */
static size_t put_ip6(uint8_t *b, uint8_t dscp, size_t l4_len, uint8_t l4proto) {
    uint8_t tc = (uint8_t)(dscp << 2);
    memset(b, 0, 40);
    b[0] = 0x60 | (tc >> 4);
    b[1] = (uint8_t)(tc << 4);
    put_be16(b + 4, (uint16_t) l4_len);
    b[6] = l4proto; b[7] = 64;
    memcpy(b + 8, SRC6, 16);
    memcpy(b + 24, DST6, 16);
    return 40;
}

static size_t put_udp(uint8_t *b, uint16_t sport, uint16_t dport, size_t len) {
    put_be16(b, sport);
    put_be16(b + 2, dport);
    put_be16(b + 4, (uint16_t) len);
    put_be16(b + 6, 0);
    return 8;
}

/* TCP header without options (20 bytes) */
static size_t put_tcp(uint8_t *b, uint16_t sport, uint16_t dport, uint8_t flags) {
    memset(b, 0, 20);
    put_be16(b, sport);
    put_be16(b + 2, dport);
    put_be32(b + 4, 1000);
    b[12] = 5 << 4;
    b[13] = flags;
    put_be16(b + 14, 65535);
    return 20;
}

/* INT shim + hop-by-hop header + metadata stack of nb_words words.
 * ins: instruction bitmap. Stack words are 0xA0000000 + index. */
static size_t put_int(uint8_t *b, uint8_t hop_ml, uint16_t ins, unsigned nb_words) {
    b[0] = 1; b[1] = 0; b[2] = (uint8_t)(3 + nb_words); b[3] = 0;   /* shim */
    b[4] = 0x10; b[5] = 0; b[6] = hop_ml; b[7] = 8;                /* ver 1 */
    put_be16(b + 8, ins);
    put_be16(b + 10, 0);
    for (unsigned i = 0; i < nb_words; i++)
        put_be32(b + 12 + 4 * i, 0xA0000000u + i);
    return 12 + 4 * nb_words;
}

static void run(mmt_handler_t *h, const uint8_t *pkt, size_t len) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = 1;
    hdr.caplen = (uint32_t) len;
    hdr.len    = (uint32_t) len;
    memset(&g, 0, sizeof(g));
    uint8_t *cap = malloc(len);
    if (cap == NULL) { perror("malloc"); exit(2); }
    memcpy(cap, pkt, len);
    packet_process(h, &hdr, cap);
    free(cap);
}

/* Ethernet/IP(v4 with ihl words|v6)/UDP carrying INT + 8 opaque payload bytes. */
static size_t build_int_udp_ihl(uint8_t *pkt, int v6, unsigned ihl, uint8_t dscp, uint16_t sport,
        uint8_t hop_ml, uint16_t ins, unsigned nb_words) {
    size_t int_len = 12 + 4 * nb_words + 8;
    size_t o = put_eth(pkt, v6 ? 0x86DD : 0x0800);
    o += v6 ? put_ip6(pkt + o, dscp, 8 + int_len, 17) : put_ip4(pkt + o, dscp, ihl, 8 + int_len, 17);
    o += put_udp(pkt + o, sport, 40000, 8 + int_len);
    o += put_int(pkt + o, hop_ml, ins, nb_words);
    memset(pkt + o, 0x5a, 8);
    return o + 8;
}

static size_t build_int_udp(uint8_t *pkt, int v6, uint8_t dscp, uint16_t sport,
        uint8_t hop_ml, uint16_t ins, unsigned nb_words) {
    return build_int_udp_ihl(pkt, v6, 5, dscp, sport, hop_ml, ins, nb_words);
}

/* Ethernet/IP(v4|v6)/TCP (PSH|ACK, or SYN when len == 0) carrying payload. */
static size_t build_tcp_payload(uint8_t *pkt, int v6, uint8_t dscp, uint16_t sport,
        const uint8_t *payload, size_t len) {
    size_t o = put_eth(pkt, v6 ? 0x86DD : 0x0800);
    o += v6 ? put_ip6(pkt + o, dscp, 20 + len, 6) : put_ip4(pkt + o, dscp, 5, 20 + len, 6);
    o += put_tcp(pkt + o, sport, 40000, len == 0 ? 0x02 : 0x18);
    memcpy(pkt + o, payload, len);
    return o + len;
}

/* Ethernet/IP(v4|v6)/UDP carrying payload. */
static size_t build_udp_payload(uint8_t *pkt, int v6, uint8_t dscp, uint16_t sport,
        const uint8_t *payload, size_t len) {
    size_t o = put_eth(pkt, v6 ? 0x86DD : 0x0800);
    o += v6 ? put_ip6(pkt + o, dscp, 8 + len, 17) : put_ip4(pkt + o, dscp, 5, 8 + len, 17);
    o += put_udp(pkt + o, sport, 40000, 8 + len);
    memcpy(pkt + o, payload, len);
    return o + len;
}

/* Ethernet/IPv4/UDP:6000 INT report of an inner Ethernet/IP(v4|v6)/UDP/INT.
 * inner_frag: IPv4 flags + fragment offset of the inner packet;
 * inner_shim_type: type byte of the inner INT shim. */
static size_t build_report_ex(uint8_t *pkt, int inner_v6, unsigned inner_ihl,
        uint16_t sport, size_t truncate_to, uint16_t inner_frag, uint8_t inner_shim_type) {
    uint8_t in[256];
    size_t io = put_eth(in, inner_v6 ? 0x86DD : 0x0800);
    size_t inner_l4 = 8 + 12 + 4 + 8;
    if (inner_v6)
        io += put_ip6(in + io, 0x20, inner_l4, 17);
    else {
        put_ip4(in + io, 0x20, inner_ihl, inner_l4, 17);
        put_be16(in + io + 6, inner_frag);
        io += inner_ihl * 4;
    }
    io += put_udp(in + io, 1234, 5678, inner_l4);
    io += put_int(in + io, 1, 0x8000, 1);  /* one hop, switch id only */
    in[io - 16] = inner_shim_type;
    memset(in + io, 0x5a, 8); io += 8;
    if (truncate_to != 0 && truncate_to < io)
        io = truncate_to;

    size_t rep_len = 16 + io;
    size_t o = put_eth(pkt, 0x0800);
    o += put_ip4(pkt + o, 0, 5, 8 + rep_len, 17);
    o += put_udp(pkt + o, sport, 6000, 8 + rep_len);
    memset(pkt + o, 0, 16);
    pkt[o] = 0x10;                       /* version 1 */
    put_be32(pkt + o + 4, 7);            /* switch id */
    put_be32(pkt + o + 8, 42);           /* seq */
    o += 16;
    memcpy(pkt + o, in, io);
    return o + io;
}

static size_t build_report(uint8_t *pkt, int inner_v6, unsigned inner_ihl,
        uint16_t sport, size_t truncate_to) {
    return build_report_ex(pkt, inner_v6, inner_ihl, sport, truncate_to, 0, 1);
}

/* Ethernet/IPv4/UDP:6000 INT report of an inner Ethernet/IPv4/TCP/INT whose
 * TCP header has data offset doff (options are NOPs when doff > 5). */
static size_t build_report_tcp(uint8_t *pkt, uint16_t sport, unsigned doff) {
    uint8_t in[256];
    size_t tcp_len = doff > 5 ? doff * 4 : 20;
    size_t inner_l4 = tcp_len + 12 + 4 + 8;
    size_t io = put_eth(in, 0x0800);
    io += put_ip4(in + io, 0x20, 5, inner_l4, 6);
    put_tcp(in + io, 1234, 5678, 0x18);
    memset(in + io + 20, 0x01, tcp_len - 20);   /* NOP options */
    in[io + 12] = (uint8_t)(doff << 4);
    io += tcp_len;
    io += put_int(in + io, 1, 0x8000, 1);       /* one hop, switch id only */
    memset(in + io, 0x5a, 8); io += 8;

    size_t rep_len = 16 + io;
    size_t o = put_eth(pkt, 0x0800);
    o += put_ip4(pkt + o, 0, 5, 8 + rep_len, 17);
    o += put_udp(pkt + o, sport, 6000, 8 + rep_len);
    memset(pkt + o, 0, 16);
    pkt[o] = 0x10;                       /* version 1 */
    put_be32(pkt + o + 4, 7);            /* switch id */
    put_be32(pkt + o + 8, 42);           /* seq */
    o += 16;
    memcpy(pkt + o, in, io);
    return o + io;
}

/* offset of the INT shim in build_int_udp() frames */
#define INT_OFF4 (14 + 20 + 8)
#define INT_OFF6 (14 + 40 + 8)

int main(void) {
    char errbuf[1024];
    uint8_t pkt[512];

    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);
    const struct { uint32_t p, a; } atts[] = {
        {PROTO_INT, INT_NUM_HOP},
        {PROTO_INT, INT_HOP_LV2_INGRESS_PORT_IDS},
        {PROTO_INT, INT_HOP_LV2_EGRESS_PORT_IDS},
        {PROTO_INT, INT_HOP_SWITCH_IDS},
        {PROTO_INT_REPORT, INT_REPORT_FLOW_IP_SRC},
        {PROTO_INT_REPORT, INT_REPORT_FLOW_IP_DST},
        {PROTO_INT_REPORT, INT_REPORT_FLOW_IP6_SRC},
        {PROTO_INT_REPORT, INT_REPORT_FLOW_IP6_DST},
        {PROTO_INT_REPORT, INT_REPORT_FLOW_PORT_SRC},
        {PROTO_INT_REPORT, INT_REPORT_FLOW_PORT_DST},
    };
    for (size_t i = 0; i < sizeof(atts) / sizeof(atts[0]); i++) {
        if (register_extraction_attribute(h, atts[i].p, atts[i].a) != true) {
            fprintf(stderr, "register_extraction_attribute(%u,%u) failed\n", atts[i].p, atts[i].a);
            mmt_close_handler(h);
            close_extraction();
            return 2;
        }
    }

    printf("issue #332: INT over IPv4/IPv6 carriers\n");
    {
        size_t n = build_int_udp(pkt, 0, 0x20, 41001, 1, 0x8000, 2);
        run(h, pkt, n);
        CHECK(g.int_seen, "IPv4 DSCP 0x20: INT detected");
        CHECK(g.after_int_offset == 20, "IPv4: layer after INT starts at shim length (5 words = 20 bytes)");
        CHECK(g.has_num_hop && g.num_hop == 2, "IPv4: two hops of one word");

        n = build_int_udp(pkt, 1, 0x20, 41002, 1, 0x8000, 2);
        run(h, pkt, n);
        CHECK(g.int_seen, "IPv6 Traffic Class DSCP 0x20: INT detected");
        CHECK(g.has_num_hop && g.num_hop == 2, "IPv6: two hops of one word");
        CHECK(g.after_int_offset == 20, "IPv6: layer after INT starts at shim length");

        /* DSCP read at the carrier's own offset, not 20 bytes before UDP */
        n = build_int_udp_ihl(pkt, 0, 6, 0x20, 41008, 1, 0x8000, 2);
        run(h, pkt, n);
        CHECK(g.int_seen, "IPv4 with options, DSCP 0x20: INT detected");


        n = build_int_udp(pkt, 1, 0x0a, 41003, 1, 0x8000, 2);
        run(h, pkt, n);
        CHECK(!g.int_seen, "IPv6 other DSCP: INT not detected");

        /* the low Traffic Class nibble (IPv6 byte 1) is part of the DSCP */
        n = build_int_udp(pkt, 1, 0x21, 41010, 1, 0x8000, 2);
        run(h, pkt, n);
        CHECK(!g.int_seen, "IPv6 DSCP 0x21: INT not detected");

        /* ECN bits do not affect the DSCP: Traffic Class 0x83 */
        n = build_int_udp(pkt, 1, 0x20, 41011, 1, 0x8000, 2);
        pkt[14 + 1] |= 0x30;
        run(h, pkt, n);
        CHECK(g.int_seen, "IPv6 DSCP 0x20 with ECN bits set: INT detected");
    }

    printf("issue #332: INT hop metadata parsing\n");
    {
        /* Hop ML 0: the hop count must not divide by zero */
        size_t n = build_int_udp(pkt, 1, 0x20, 41004, 0, 0x8000, 2);
        run(h, pkt, n);
        CHECK(g.int_seen && g.has_num_hop && g.num_hop == 0, "Hop ML 0: zero hops, no division by zero");

        /* switch id (bit 15) + LV2 port ids (bit 9); Hop ML 2: 16+16 bits in one word */
        n = build_int_udp(pkt, 1, 0x20, 41005, 2, 0x8200, 4);
        run(h, pkt, n);
        CHECK(g.has_lv2 && g.lv2_len == 2, "LV2 16+16 layout: two hops");
        CHECK(g.has_lv2 && g.lv2_in[0] == 0xA000 && g.lv2_e[0] == 0x0001
              && g.lv2_in[1] == 0xA000 && g.lv2_e[1] == 0x0003,
              "LV2 16+16 layout: ingress/egress halves of one word");

        /* Hop ML 3: LV2 ingress and egress are 4 bytes each (spec 4.7) */
        n = build_int_udp(pkt, 1, 0x20, 41006, 3, 0x8200, 6);
        run(h, pkt, n);
        CHECK(g.has_lv2 && g.lv2_len == 2, "LV2 spec layout: two hops");
        CHECK(g.has_lv2 && g.lv2_in[0] == 0xA0000001u && g.lv2_e[0] == 0xA0000002u
              && g.lv2_in[1] == 0xA0000004u && g.lv2_e[1] == 0xA0000005u,
              "LV2 spec layout: 4-byte ingress then 4-byte egress");

        /* Hop ML 3, two hops announced, capture cut before the last egress word */
        n = build_int_udp(pkt, 1, 0x20, 41007, 3, 0x8200, 6) - 8 - 4;
        run(h, pkt, n);
        CHECK(!g.has_lv2, "LV2 spec layout truncated: no attribute, no over-read");
    }

    printf("issue #332: INT reports with an IPv6 inner packet\n");
    {
        size_t n = build_report(pkt, 1, 0, 42001, 0);
        run(h, pkt, n);
        CHECK(g.report_seen, "inner IPv6: INT report detected");
        CHECK(g.int_seen, "inner IPv6: INT classified after the report");
        CHECK(g.has_ip6_src && memcmp(g.ip6_src, SRC6, 16) == 0, "inner IPv6: ip6_src extracted");
        CHECK(g.has_ip6_dst && memcmp(g.ip6_dst, DST6, 16) == 0, "inner IPv6: ip6_dst extracted");
        CHECK(!g.has_ip_src, "inner IPv6: IPv4-only ip_src absent");
        CHECK(g.has_ports && g.port_src == 1234 && g.port_dst == 5678, "inner IPv6: ports extracted");

        n = build_report(pkt, 0, 6, 42002, 0);
        run(h, pkt, n);
        CHECK(g.report_seen && g.int_seen, "inner IPv4 with options: report and INT detected");
        CHECK(g.has_ip_src && !g.has_ip6_src, "inner IPv4: ip_src present, ip6_src absent");
        CHECK(g.has_ports && g.port_src == 1234 && g.port_dst == 5678, "inner IPv4 with options: ports past the options");

        n = build_report(pkt, 1, 0, 42003, 14 + 30);
        run(h, pkt, n);
        CHECK(!g.report_seen, "inner IPv6 truncated: INT report rejected");
    }

    printf("issue #453: DSCP 0x20 (CS4) without a valid INT shim is not INT\n");
    {
        uint8_t pl[64];
        memset(pl, 0x33, sizeof(pl));
        pl[0] = 0x40;                          /* opaque payload, not a shim */
        size_t n = build_udp_payload(pkt, 0, 0x20, 43001, pl, 16);
        run(h, pkt, n);
        CHECK(!g.int_seen, "CS4 IPv4 UDP, opaque payload: INT not detected");

        n = build_udp_payload(pkt, 1, 0x20, 43002, pl, 16);
        run(h, pkt, n);
        CHECK(!g.int_seen, "CS4 IPv6 UDP, opaque payload: INT not detected");

        n = build_udp_payload(pkt, 0, 0x20, 43003, pl, 0);
        run(h, pkt, n);
        CHECK(!g.int_seen, "CS4 IPv4 UDP, empty payload: INT not detected");

        n = build_tcp_payload(pkt, 0, 0x20, 43004, pl, 0);
        run(h, pkt, n);
        CHECK(!g.int_seen, "CS4 IPv4 TCP SYN, no payload: INT not detected");

        /* a valid shim + metadata header start, cut to 11 of their 12 bytes */
        build_int_udp(pkt, 0, 0x20, 43005, 1, 0x8000, 0);
        memcpy(pl, pkt + INT_OFF4, 11);
        n = build_udp_payload(pkt, 0, 0x20, 43005, pl, 11);
        run(h, pkt, n);
        CHECK(!g.int_seen, "CS4 UDP, 11-byte payload: INT not detected");

        n = build_int_udp(pkt, 0, 0x20, 43006, 1, 0x8000, 2);
        pkt[INT_OFF4] = 2;
        run(h, pkt, n);
        CHECK(!g.int_seen, "shim type 2: INT not detected");

        n = build_int_udp(pkt, 0, 0x20, 43007, 1, 0x8000, 2);
        pkt[INT_OFF4 + 4] = 0x00;
        run(h, pkt, n);
        CHECK(!g.int_seen, "metadata header Ver 0: INT not detected");

        n = build_int_udp(pkt, 1, 0x20, 43008, 1, 0x8000, 2);
        pkt[INT_OFF6 + 4] = 0x20;
        run(h, pkt, n);
        CHECK(!g.int_seen, "metadata header Ver 2: INT not detected");

        n = build_int_udp(pkt, 0, 0x20, 43009, 1, 0x8000, 2);
        pkt[INT_OFF4 + 2] = 2;
        run(h, pkt, n);
        CHECK(!g.int_seen, "shim length < 3 words: INT not detected");

        /* 20 + 8 payload bytes, the shim announces 8 words = 32 bytes */
        n = build_int_udp(pkt, 0, 0x20, 43010, 1, 0x8000, 2);
        pkt[INT_OFF4 + 2] = 8;
        run(h, pkt, n);
        CHECK(!g.int_seen, "shim length beyond the payload: INT not detected");
    }

    printf("issue #453: valid INT shims over TCP and UDP\n");
    {
        uint8_t shim[64];
        size_t n = build_int_udp(pkt, 0, 0x20, 44000, 1, 0x8000, 2);
        size_t int_len = n - INT_OFF4;         /* 20-byte INT stack + 8 bytes */
        memcpy(shim, pkt + INT_OFF4, int_len);

        n = build_tcp_payload(pkt, 0, 0x20, 44001, shim, int_len);
        run(h, pkt, n);
        CHECK(g.int_seen, "IPv4 TCP carrier with a valid shim: INT detected");
        CHECK(g.after_int_offset == 20, "IPv4 TCP: layer after INT starts at shim length");
        CHECK(g.has_num_hop && g.num_hop == 2, "IPv4 TCP: two hops of one word");

        n = build_tcp_payload(pkt, 1, 0x20, 44002, shim, int_len);
        run(h, pkt, n);
        CHECK(g.int_seen && g.after_int_offset == 20, "IPv6 TCP carrier with a valid shim: INT detected");

        n = build_int_udp(pkt, 0, 0x20, 44003, 1, 0x8000, 2);
        pkt[INT_OFF4] = 0;
        run(h, pkt, n);
        CHECK(g.int_seen && g.after_int_offset == 20, "shim type 0: INT still detected");
    }

    printf("issue #453: hop stride follows Hop ML\n");
    {
        /* switch id only (1 word parsed), Hop ML 2: one padding word per hop */
        size_t n = build_int_udp(pkt, 0, 0x20, 45001, 2, 0x8000, 4);
        put_be32(pkt + INT_OFF4 + 12, 0x11);
        put_be32(pkt + INT_OFF4 + 16, 0xEEEEEEEEu);
        put_be32(pkt + INT_OFF4 + 20, 0x22);
        put_be32(pkt + INT_OFF4 + 24, 0xEEEEEEEEu);
        run(h, pkt, n);
        CHECK(g.has_sw_ids && g.sw_len == 2 && g.sw_ids[0] == 0x11 && g.sw_ids[1] == 0x22,
              "Hop ML 2 over a 1-word hop: second hop read at hop_ml*4");

        /* switch id + hop latency (2 words parsed), Hop ML 1: the parsed
         * fields stay the stride, no re-sync backwards. The second hop
         * lies past the shim-declared stack, so only assert that it was
         * not read at hop_ml*4 (the first hop's latency word). */
        n = build_int_udp(pkt, 0, 0x20, 45002, 1, 0xA000, 2);
        run(h, pkt, n);
        CHECK(g.has_sw_ids && g.sw_len >= 1 && g.sw_ids[0] == 0xA0000000u
              && (g.sw_len < 2 || g.sw_ids[1] != 0xA0000001u),
              "Hop ML smaller than the parsed fields: stride unchanged");
    }

    printf("issue #453: INT-report inner packet checks\n");
    {
        /* non-first inner IPv4 fragment (offset 185 * 8 bytes) */
        size_t n = build_report_ex(pkt, 0, 5, 46001, 0, 185, 1);
        run(h, pkt, n);
        CHECK(!g.int_seen, "inner non-first IPv4 fragment: no INT layer");

        /* first fragment: More Fragments set, offset 0 */
        n = build_report_ex(pkt, 0, 5, 46002, 0, 0x2000, 1);
        run(h, pkt, n);
        CHECK(g.report_seen && g.int_seen, "inner first IPv4 fragment: INT still detected");

        n = build_report_ex(pkt, 0, 5, 46003, 0, 0, 2);
        run(h, pkt, n);
        CHECK(g.report_seen && !g.int_seen, "inner shim type 2: report detected, no INT layer");

        static const uint8_t src4[4] = {10, 0, 0, 1}, dst4[4] = {10, 0, 0, 2};
        n = build_report(pkt, 0, 5, 46004, 0);
        run(h, pkt, n);
        CHECK(g.has_ip_src && memcmp(g.ip_src, src4, 4) == 0, "inner IPv4: ip_src 10.0.0.1 in network order");
        CHECK(g.has_ip_dst && memcmp(g.ip_dst, dst4, 4) == 0, "inner IPv4: ip_dst 10.0.0.2 in network order");

        /* inner TCP without options, then with 12 option bytes (doff 8) */
        n = build_report_tcp(pkt, 46005, 5);
        run(h, pkt, n);
        CHECK(g.report_seen && g.int_seen, "inner TCP doff 5: report and INT detected");
        CHECK(g.has_ports && g.port_src == 1234 && g.port_dst == 5678, "inner TCP doff 5: ports extracted");

        n = build_report_tcp(pkt, 46006, 8);
        run(h, pkt, n);
        CHECK(g.report_seen && g.int_seen, "inner TCP with options (doff 8): INT found past the options");

        /* data offset below the 5-word minimum */
        n = build_report_tcp(pkt, 46007, 4);
        run(h, pkt, n);
        CHECK(!g.report_seen && !g.int_seen, "inner TCP doff 4: INT report rejected");
    }

    mmt_close_handler(h);
    close_extraction();
    printf("%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}
