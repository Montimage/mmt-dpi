/*
 * test_encap_walk_api.c — packet/API-path test for issue #572 (F-BUG-308):
 * MPLS, VXLAN, GENEVE and PPPoE are walked down to the inner flow.
 *
 *   - Ethernet and 802.1Q hand an MPLS label stack to proto_mpls.c, which
 *     steps over every entry to the bottom of stack and hands the payload to
 *     IPv4 / IPv6 (first nibble or explicit-null label) or, behind a
 *     pseudowire control word, to Ethernet;
 *   - UDP/4789 with the VXLAN I flag and UDP/6081 with a version-0 GENEVE
 *     header (options included) re-enter Ethernet or IP;
 *   - a PPPoE session packet is handed to PPP and PPP to IPv4 / IPv6;
 *   - the inner TCP flow is sessionized and classified (HTTP) beneath each.
 *
 * Negative and boundary cases: a stack without a bottom-of-stack entry
 * within the walker's bound, the G-ACh label, the VXLAN I flag clear, GENEVE
 * version 1 and a control packet, a PPPoE discovery packet, a PPP control
 * protocol, and every encapsulation header cut short of caplen — on a fresh
 * flow and on an established one — end the path at the encapsulation and
 * read nothing past caplen (every capture is an exactly-sized heap copy, so
 * ASan brackets it under SANITIZE=asan). A tunnel nested deeper than the
 * protocol path stops at PROTO_PATH_SIZE layers.
 *
 * Crafted frames are fed through mmt_init_handler + packet_process; each
 * case uses its own inner and outer host pairs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mmt_tcpip_attributes.h"      /* TCP_SRC_PORT */

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

/* --- the last packet's protocol path, and whether HTTP was ever seen ---- */
static int g_path[PROTO_PATH_SIZE];
static int g_path_len;
static int g_raw_len;       /* proto_hierarchy->len, unbounded */
static int g_http_seen;
static int g_tcp_sport;     /* tcp.src_port of the last packet, -1: none */

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    g_path_len = 0;
    if (ipacket->proto_hierarchy == NULL)
        return 0;
    g_raw_len = (int) ipacket->proto_hierarchy->len;
    const uint16_t *sport = get_attribute_extracted_data(ipacket, PROTO_TCP, TCP_SRC_PORT);
    g_tcp_sport = sport != NULL ? *sport : -1;
    for (int i = 0; i < ipacket->proto_hierarchy->len && i < PROTO_PATH_SIZE; i++) {
        g_path[g_path_len++] = (int) ipacket->proto_hierarchy->proto_path[i];
        if (ipacket->proto_hierarchy->proto_path[i] == PROTO_HTTP)
            g_http_seen = 1;
    }
    return 0;
}

/* The last path holds `want` in order (not necessarily contiguous). */
static int path_has(const int *want, int n) {
    int j = 0;
    for (int i = 0; i < g_path_len && j < n; i++)
        if (g_path[i] == want[j])
            j++;
    return j == n;
}
#define PATH_HAS(...) path_has((const int[]){ __VA_ARGS__ }, \
        (int) (sizeof((const int[]){ __VA_ARGS__ }) / sizeof(int)))

static int path_count(int proto) {
    int n = 0;
    for (int i = 0; i < g_path_len; i++)
        n += g_path[i] == proto;
    return n;
}

static int path_last(void) { return g_path_len ? g_path[g_path_len - 1] : -1; }

/* --- frame builders ------------------------------------------------------ */
static void be16(uint8_t *p, uint32_t v) { p[0] = (uint8_t) (v >> 8); p[1] = (uint8_t) v; }

static unsigned eth(uint8_t *p, uint32_t ethertype) {
    static const uint8_t mac[12] = {0x02,0,0,0,0,0x02, 0x02,0,0,0,0,0x01};
    memcpy(p, mac, 12);
    be16(p + 12, ethertype);
    return 14;
}

static unsigned mpls(uint8_t *p, uint32_t label, int bos) {
    p[0] = (uint8_t) (label >> 12);
    p[1] = (uint8_t) (label >> 4);
    p[2] = (uint8_t) (((label & 0x0f) << 4) | (bos ? 1 : 0));
    p[3] = 64;
    return 4;
}

static unsigned ipv4(uint8_t *p, uint8_t net, uint8_t host, int c2s, uint8_t proto, unsigned l4len) {
    memset(p, 0, 20);
    p[0] = 0x45;
    be16(p + 2, 20 + l4len);
    p[8] = 64;
    p[9] = proto;
    uint8_t a[4] = {10, net, host, 1}, b[4] = {10, net, host, 2};
    memcpy(p + 12, c2s ? a : b, 4);
    memcpy(p + 16, c2s ? b : a, 4);
    return 20;
}

static unsigned ipv6(uint8_t *p, uint8_t net, uint8_t host, int c2s, uint8_t proto, unsigned l4len) {
    memset(p, 0, 40);
    p[0] = 0x60;
    be16(p + 4, l4len);
    p[6] = proto;
    p[7] = 64;
    p[8] = 0x20; p[9] = 0x01; p[10] = 0x0d; p[11] = 0xb8;
    p[22] = net; p[23] = host;
    memcpy(p + 24, p + 8, 16);
    p[c2s ? 39 : 23] = 1;
    p[c2s ? 23 : 39] = 2;
    return 40;
}

static unsigned udp(uint8_t *p, uint16_t sport, uint16_t dport, unsigned paylen) {
    be16(p, sport); be16(p + 2, dport); be16(p + 4, 8 + paylen); be16(p + 6, 0);
    return 8;
}

static const char http_get[] = "GET /index.html HTTP/1.1\r\nHost: encap.example\r\n\r\n";

/* Inner IPv4/TCP segment of the case's flow (SYN, SYN-ACK, ACK, GET). */
static unsigned inner_tcp(uint8_t *p, int v6, uint8_t net, uint8_t host, int step) {
    static const uint8_t flags[4] = {0x02, 0x12, 0x10, 0x18};
    int c2s = step != 1;
    unsigned paylen = step == 3 ? (unsigned) sizeof(http_get) - 1 : 0;
    unsigned n = v6 ? ipv6(p, net, host, c2s, 6, 20 + paylen)
                    : ipv4(p, net, host, c2s, 6, 20 + paylen);
    uint8_t *t = p + n;
    memset(t, 0, 20);
    be16(t, c2s ? 40000 : 80);
    be16(t + 2, c2s ? 80 : 40000);
    uint32_t seq = c2s ? 1000 + (step >= 2) : 5000;
    uint32_t ack = step == 0 ? 0 : (c2s ? 5001 : 1001);
    for (int i = 0; i < 4; i++) {
        t[4 + i] = (uint8_t) (seq >> (24 - 8 * i));
        t[8 + i] = (uint8_t) (ack >> (24 - 8 * i));
    }
    t[12] = 0x50;
    t[13] = flags[step];
    be16(t + 14, 65535);
    memcpy(t + 20, http_get, paylen);
    return n + 20 + paylen;
}

/* Feeds `frame` cut to `caplen` bytes (0: whole) as an exactly-sized copy. */
static void feed(mmt_handler_t *h, const uint8_t *frame, unsigned len, unsigned caplen) {
    static int sec = 1;
    if (caplen == 0 || caplen > len)
        caplen = len;
    uint8_t *data = malloc(caplen);
    if (data == NULL) { perror("malloc"); exit(2); }
    memcpy(data, frame, caplen);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = sec++;
    hdr.caplen = caplen;
    hdr.len = len;
    g_path_len = 0;
    g_tcp_sport = -1;
    packet_process(h, &hdr, data);
    free(data);
}

/* --- encapsulations: write the outer headers, then the inner packet ------ */
enum encap {
    E_MPLS1, E_MPLS3_V6, E_VLAN_MPLS, E_MPLS_NULL, E_MPLS_PW,
    E_VXLAN, E_GENEVE_OPT, E_GENEVE_IP, E_PPPOE, E_PPPOE_V6, E_PPPOE_PFC,
    E_PPPOE_MPLS, E_GENEVE_TEB, E_PPTP,
};

/* Builds the frame of `step` of the case's inner TCP flow; returns its
 * length and the offset of the encapsulation header in *hdr_at. */
static unsigned build(uint8_t *f, enum encap e, uint8_t net, int step, unsigned *hdr_at) {
    uint8_t inner[256];
    int v6 = e == E_MPLS3_V6 || e == E_PPPOE_V6;
    unsigned ilen = 0, n = 0, k;
    int c2s = step != 1;
    /* Ethernet-in-tunnel cases carry an inner Ethernet header. */
    if (e == E_MPLS_PW || e == E_VXLAN || e == E_GENEVE_OPT || e == E_GENEVE_TEB) {
        ilen = eth(inner, 0x0800);
    }
    ilen += inner_tcp(inner + ilen, v6, net, 1, step);

    switch (e) {
    case E_MPLS1:
        n = eth(f, 0x8847); *hdr_at = n;
        n += mpls(f + n, 1000 + net, 1);
        break;
    case E_MPLS3_V6:
        n = eth(f, 0x8847); *hdr_at = n;
        n += mpls(f + n, 16001, 0);
        n += mpls(f + n, 16002, 0);
        n += mpls(f + n, 24003, 1);
        break;
    case E_VLAN_MPLS:
        n = eth(f, 0x8100);
        be16(f + n, 100); be16(f + n + 2, 0x8847); n += 4;
        *hdr_at = n;
        n += mpls(f + n, 2000 + net, 1);
        break;
    case E_MPLS_NULL:              /* IPv4 explicit null at the bottom */
        n = eth(f, 0x8848); *hdr_at = n;
        n += mpls(f + n, 3000, 0);
        n += mpls(f + n, 0, 1);
        break;
    case E_MPLS_PW:                /* Ethernet pseudowire with a control word */
        n = eth(f, 0x8847); *hdr_at = n;
        n += mpls(f + n, 4000, 0);
        n += mpls(f + n, 4001, 1);
        memset(f + n, 0, 4); n += 4;
        break;
    case E_VXLAN:
    case E_GENEVE_OPT:
    case E_GENEVE_TEB:
    case E_GENEVE_IP: {
        unsigned tun = e == E_VXLAN ? 8 : e == E_GENEVE_OPT ? 16 : 8;
        n = eth(f, 0x0800);
        n += ipv4(f + n, (uint8_t) (200 + net), 9, c2s, 17, 8 + tun + ilen);
        n += udp(f + n, (uint16_t) (50000 + net), e == E_VXLAN ? 4789 : 6081, tun + ilen);
        *hdr_at = n;
        memset(f + n, 0, tun);
        if (e == E_VXLAN) {
            f[n] = 0x08;                           /* I flag */
            f[n + 4] = 0x00; f[n + 5] = 0x10; f[n + 6] = net;   /* VNI */
        } else {
            f[n] = e == E_GENEVE_OPT ? 0x02 : 0x00;   /* ver 0, opt len 2 */
            be16(f + n + 2, e == E_GENEVE_IP ? 0x0800 : 0x6558);
            f[n + 6] = net;
            if (e == E_GENEVE_OPT) {               /* one 8-byte option */
                be16(f + n + 8, 0x0104); f[n + 10] = 0x80; f[n + 11] = 0x01;
            }
        }
        n += tun;
        break;
    }
    case E_PPTP:                   /* enhanced GRE (RFC 2637 §4.1), K+S+A */
        n = eth(f, 0x0800);
        n += ipv4(f + n, (uint8_t) (200 + net), 9, c2s, 47, 16 + 4 + ilen);
        *hdr_at = n;
        f[n] = 0x30; f[n + 1] = 0x81;             /* K, S | A, version 1 */
        be16(f + n + 2, 0x880b);
        be16(f + n + 4, 4 + ilen); be16(f + n + 6, 0x0100 + net);   /* key */
        memset(f + n + 8, 0, 8); f[n + 11] = (uint8_t) step; f[n + 15] = 1;
        n += 16;
        f[n] = 0xff; f[n + 1] = 0x03; be16(f + n + 2, 0x0021);       /* PPP */
        n += 4;
        break;
    case E_PPPOE:
    case E_PPPOE_V6:
    case E_PPPOE_PFC:
    case E_PPPOE_MPLS: {
        unsigned ppp = e == E_PPPOE_PFC ? 1 : 2;
        unsigned extra = e == E_PPPOE_MPLS ? 4 : 0;
        n = eth(f, 0x8864); *hdr_at = n;
        f[n] = 0x11; f[n + 1] = 0x00; be16(f + n + 2, 0x0100 + net);
        be16(f + n + 4, ppp + extra + ilen);
        n += 6;
        if (e == E_PPPOE_PFC) {
            f[n++] = 0x21;
        } else {
            be16(f + n, e == E_PPPOE_V6 ? 0x0057 : e == E_PPPOE_MPLS ? 0x0281 : 0x0021);
            n += 2;
        }
        if (e == E_PPPOE_MPLS)
            n += mpls(f + n, 5000, 1);
        break;
    }
    }
    for (k = 0; k < ilen; k++)
        f[n + k] = inner[k];
    return n + ilen;
}

static mmt_handler_t *new_handler(void) {
    char errbuf[1024];
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        exit(2);
    }
    register_packet_handler(h, 1, packet_handler, NULL);
    return h;
}

/* Replays the case's whole inner TCP flow and checks the last packet's path
 * holds the encapsulation, then the inner IP / TCP, and that HTTP is seen. */
static void positive(mmt_handler_t *h, const char *name, enum encap e, uint8_t net,
                     int encap_proto, int inner_ip) {
    uint8_t f[512];
    unsigned at;
    char msg[160];
    g_http_seen = 0;
    for (int step = 0; step < 4; step++) {
        unsigned len = build(f, e, net, step, &at);
        feed(h, f, len, 0);
    }
    snprintf(msg, sizeof msg, "%s: path walks %s to the inner TCP flow", name,
             get_protocol_name_by_id((uint32_t) encap_proto));
    CHECK(PATH_HAS(encap_proto, inner_ip, PROTO_TCP), msg);
    snprintf(msg, sizeof msg, "%s: the inner flow classifies as HTTP", name);
    CHECK(g_http_seen && path_last() == PROTO_HTTP, msg);
}

/* One inner TCP flow whose client packets ride `c2s` and whose server
 * packets ride `s2c` (an MPLS stack one direction pops, GENEVE options only
 * one VTEP adds): the server's SYN-ACK must be read at its own offsets, not
 * at those of the packet that created the inner session. */
static void asymmetric(mmt_handler_t *h, const char *name, enum encap c2s, enum encap s2c,
                       uint8_t net) {
    uint8_t f[512];
    unsigned at;
    char msg[160];
    int sport[4];
    g_http_seen = 0;
    for (int step = 0; step < 4; step++) {
        unsigned len = build(f, step == 1 ? s2c : c2s, net, step, &at);
        feed(h, f, len, 0);
        sport[step] = g_tcp_sport;
    }
    snprintf(msg, sizeof msg, "%s: each direction's TCP header is read at its own offset", name);
    CHECK(sport[0] == 40000 && sport[1] == 80 && sport[2] == 40000 && sport[3] == 40000, msg);
    snprintf(msg, sizeof msg, "%s: the inner flow still classifies as HTTP", name);
    CHECK(g_http_seen, msg);
}

/* Truncation: every cut inside the encapsulation header (and, for a header
 * that announces more, inside what it announces) ends the path at the
 * encapsulation, on a fresh flow and on the established one. */
static void truncated(mmt_handler_t *h, const char *name, enum encap e, uint8_t net,
                      int encap_proto, unsigned hdr_len) {
    uint8_t f[512];
    unsigned at, len;
    char msg[160];
    int ok_fresh = 1, ok_est = 1;
    for (unsigned cut = 0; cut < hdr_len; cut++) {
        len = build(f, e, (uint8_t) (net + 1), 3, &at);  /* fresh flow */
        feed(h, f, len, at + cut);
        if (path_count(PROTO_TCP) != 0)
            ok_fresh = 0;
    }
    for (int step = 0; step < 4; step++) {            /* establish it */
        len = build(f, e, net, step, &at);
        feed(h, f, len, 0);
    }
    for (unsigned cut = 0; cut < hdr_len; cut++) {
        len = build(f, e, net, 3, &at);
        feed(h, f, len, at + cut);
        if (path_count(PROTO_TCP) != 0)   /* no stale inner layer either */
            ok_est = 0;
    }
    snprintf(msg, sizeof msg, "%s: a %s header cut short of caplen is not walked (fresh flow)",
             name, get_protocol_name_by_id((uint32_t) encap_proto));
    CHECK(ok_fresh, msg);
    snprintf(msg, sizeof msg, "%s: ... nor on an established flow", name);
    CHECK(ok_est, msg);
}

int main(void) {
    init_extraction();
    mmt_handler_t *h = new_handler();
    printf("issue #572: MPLS, VXLAN, GENEVE and PPPoE are walked to the inner flow\n");

    CHECK(get_protocol_id_by_name("mpls") == PROTO_MPLS
          && get_protocol_id_by_name("vxlan") == PROTO_VXLAN
          && get_protocol_id_by_name("geneve") == PROTO_GENEVE,
          "mpls, vxlan and geneve are registered under their ids");

    positive(h, "Ethernet/MPLS", E_MPLS1, 1, PROTO_MPLS, PROTO_IP);
    positive(h, "Ethernet/MPLS x3/IPv6", E_MPLS3_V6, 2, PROTO_MPLS, PROTO_IPV6);
    CHECK(path_count(PROTO_MPLS) == 1, "a three-label stack is one MPLS layer");
    positive(h, "802.1Q/MPLS", E_VLAN_MPLS, 3, PROTO_MPLS, PROTO_IP);
    CHECK(PATH_HAS(PROTO_8021Q, PROTO_MPLS), "802.1Q hands the stack to MPLS");
    positive(h, "MPLS IPv4 explicit null", E_MPLS_NULL, 4, PROTO_MPLS, PROTO_IP);
    positive(h, "MPLS Ethernet pseudowire", E_MPLS_PW, 5, PROTO_MPLS, PROTO_IP);
    CHECK(PATH_HAS(PROTO_ETHERNET, PROTO_MPLS, PROTO_ETHERNET, PROTO_IP),
          "the control word hands the pseudowire to Ethernet");
    positive(h, "VXLAN", E_VXLAN, 6, PROTO_VXLAN, PROTO_IP);
    CHECK(PATH_HAS(PROTO_IP, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IP, PROTO_TCP),
          "VXLAN re-enters Ethernet beneath the outer UDP");
    positive(h, "GENEVE with options", E_GENEVE_OPT, 7, PROTO_GENEVE, PROTO_IP);
    CHECK(PATH_HAS(PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IP),
          "GENEVE steps over its options to transparent Ethernet bridging");
    positive(h, "GENEVE IPv4", E_GENEVE_IP, 8, PROTO_GENEVE, PROTO_IP);
    CHECK(PATH_HAS(PROTO_GENEVE, PROTO_IP) && path_count(PROTO_ETHERNET) == 1,
          "GENEVE protocol type 0x0800 hands the payload to IPv4");
    positive(h, "PPPoE/PPP", E_PPPOE, 9, PROTO_PPPOE, PROTO_IP);
    CHECK(PATH_HAS(PROTO_PPPOE, PROTO_PPP, PROTO_IP), "a PPPoE session hands PPP to IPv4");
    positive(h, "PPPoE/PPP/IPv6", E_PPPOE_V6, 10, PROTO_PPP, PROTO_IPV6);
    positive(h, "PPPoE/PPP compressed protocol", E_PPPOE_PFC, 11, PROTO_PPP, PROTO_IP);
    positive(h, "PPPoE/PPP/MPLS", E_PPPOE_MPLS, 12, PROTO_MPLS, PROTO_IP);
    CHECK(PATH_HAS(PROTO_PPPOE, PROTO_PPP, PROTO_MPLS, PROTO_IP), "PPP protocol 0x0281 is MPLS");
    positive(h, "PPTP enhanced GRE with an ack", E_PPTP, 13, PROTO_PPP, PROTO_IP);
    CHECK(PATH_HAS(PROTO_GRE, PROTO_PPP, PROTO_IP, PROTO_TCP),
          "GRE version 1 steps over the acknowledgment number to PPP");

    if (!register_extraction_attribute(h, PROTO_TCP, TCP_SRC_PORT)) {
        fprintf(stderr, "register_extraction_attribute(tcp.src_port) failed\n");
        return 2;
    }
    asymmetric(h, "MPLS 2 labels / 1 label", E_MPLS_NULL, E_MPLS1, 20);
    asymmetric(h, "MPLS 1 label / 2 labels", E_MPLS1, E_MPLS_NULL, 21);
    asymmetric(h, "GENEVE options / none", E_GENEVE_OPT, E_GENEVE_TEB, 22);
    asymmetric(h, "GENEVE none / options", E_GENEVE_TEB, E_GENEVE_OPT, 23);

    /* --- the walk refuses what is not a user flow ----------------------- */
    uint8_t f[512];
    unsigned at, len;

    /* 17 label entries, none at the bottom of the stack. */
    len = eth(f, 0x8847);
    for (int i = 0; i < 17; i++)
        len += mpls(f + len, 100u + (unsigned) i, 0);
    len += inner_tcp(f + len, 0, 30, 1, 3);
    feed(h, f, len, 0);
    CHECK(path_last() == PROTO_MPLS && path_count(PROTO_IP) == 0,
          "a stack without a bottom entry within 16 labels ends at MPLS");
    /* 16 entries with the bottom one last is still walked. */
    len = eth(f, 0x8847);
    for (int i = 0; i < 16; i++)
        len += mpls(f + len, 200u + (unsigned) i, i == 15);
    len += inner_tcp(f + len, 0, 31, 1, 0);
    feed(h, f, len, 0);
    CHECK(PATH_HAS(PROTO_MPLS, PROTO_IP, PROTO_TCP), "a 16-label stack is walked to IPv4");
    /* The G-ACh label carries OAM, not a user flow. */
    len = eth(f, 0x8847);
    len += mpls(f + len, 13, 1);
    len += inner_tcp(f + len, 0, 32, 1, 0);
    feed(h, f, len, 0);
    CHECK(path_last() == PROTO_MPLS, "the G-ACh label ends the path at MPLS");
    /* An unknown payload nibble is reported unknown. */
    len = eth(f, 0x8847);
    len += mpls(f + len, 300, 1);
    memset(f + len, 0x9a, 20); len += 20;
    feed(h, f, len, 0);
    CHECK(PATH_HAS(PROTO_MPLS, PROTO_UNKNOWN), "an unrecognised MPLS payload is unknown");

    /* VXLAN with the I flag clear is not VXLAN. */
    len = build(f, E_VXLAN, 40, 3, &at);
    f[at] = 0x00;
    feed(h, f, len, 0);
    CHECK(path_count(PROTO_VXLAN) == 0 && path_count(PROTO_TCP) == 0,
          "a UDP/4789 datagram without the VXLAN I flag is not walked");
    /* GENEVE version 1 is not GENEVE. */
    len = build(f, E_GENEVE_IP, 41, 3, &at);
    f[at] = 0x40;
    feed(h, f, len, 0);
    CHECK(path_count(PROTO_GENEVE) == 0 && path_count(PROTO_TCP) == 0,
          "a GENEVE version-1 header is not walked");
    /* GENEVE options running past the datagram are not GENEVE. */
    len = build(f, E_GENEVE_IP, 42, 3, &at);
    f[at] = 0x3f;
    feed(h, f, at + 8 + 4, 0);
    CHECK(path_count(PROTO_GENEVE) == 0, "GENEVE options past the datagram are refused");
    /* A GENEVE control packet carries no user flow. */
    for (int step = 0; step < 4; step++) {
        len = build(f, E_GENEVE_IP, 43, step, &at);
        feed(h, f, len, 0);
    }
    len = build(f, E_GENEVE_IP, 43, 3, &at);
    f[at + 1] = 0x80;
    feed(h, f, len, 0);
    CHECK(path_last() == PROTO_GENEVE, "a GENEVE control packet ends the path at GENEVE");
    /* PPPoE discovery (PADI) carries tags, not PPP. */
    len = eth(f, 0x8863);
    f[len] = 0x11; f[len + 1] = 0x09; be16(f + len + 2, 0); be16(f + len + 4, 4);
    be16(f + len + 6, 0x0101); be16(f + len + 8, 0); len += 10;
    feed(h, f, len, 0);
    CHECK(path_last() == PROTO_PPPOE, "a PPPoE discovery packet ends the path at PPPoE");
    /* A PPP control protocol (LCP) carries no user flow. */
    len = build(f, E_PPPOE, 45, 3, &at);
    be16(f + at + 6, 0xc021);
    feed(h, f, len, 0);
    CHECK(path_last() == PROTO_PPP, "PPP LCP ends the path at PPP");
    /* A PPP protocol field with an even low octet is malformed. */
    len = build(f, E_PPPOE, 46, 3, &at);
    be16(f + at + 6, 0x0022);
    feed(h, f, len, 0);
    CHECK(path_last() == PROTO_PPP, "a malformed PPP protocol field ends the path at PPP");
    /* The Ethernet LCP EtherType maps to PPP: no Protocol field follows. */
    len = eth(f, 0xc021);
    f[len] = 0x01; f[len + 1] = 0x01; be16(f + len + 2, 4); len += 4;
    feed(h, f, len, 0);
    CHECK(path_last() == PROTO_PPP, "an Ethernet LCP frame ends the path at PPP");

    /* --- truncation (ASan brackets every capture) ----------------------- */
    truncated(h, "MPLS x3", E_MPLS3_V6, 50, PROTO_MPLS, 12);
    truncated(h, "MPLS pseudowire", E_MPLS_PW, 52, PROTO_MPLS, 8 + 4 + 14);
    truncated(h, "VXLAN", E_VXLAN, 54, PROTO_VXLAN, 8 + 14);
    truncated(h, "GENEVE options", E_GENEVE_OPT, 56, PROTO_GENEVE, 16);
    truncated(h, "PPPoE/PPP", E_PPPOE, 58, PROTO_PPPOE, 6 + 2);
    truncated(h, "PPPoE/PPP compressed", E_PPPOE_PFC, 60, PROTO_PPP, 6 + 1);

    /* --- nesting is bounded by the protocol path ------------------------- */
    {
        uint8_t deep[2048];
        unsigned n = 0, k;
        unsigned starts[8];
        /* 7 nested VXLAN tunnels, each Eth/IPv4/UDP/VXLAN (50 bytes). */
        for (k = 0; k < 7; k++) {
            starts[k] = n;
            n += eth(deep + n, 0x0800);
            n += 20 + 8;
            memset(deep + n, 0, 8);
            deep[n] = 0x08;
            n += 8;
        }
        n += eth(deep + n, 0x0800);            /* the innermost frame */
        unsigned tail = inner_tcp(deep + n, 0, 70, 1, 0);
        unsigned total = n + tail;
        for (k = 0; k < 7; k++) {
            unsigned ip = starts[k] + 14;
            unsigned rest = total - ip;
            ipv4(deep + ip, (uint8_t) (71 + k), 1, 1, 17, rest - 20);
            udp(deep + ip + 20, (uint16_t) (51000 + k), 4789, rest - 28);
        }
        feed(h, deep, total, 0);
        CHECK(g_raw_len == PROTO_PATH_SIZE && path_count(PROTO_VXLAN) == 3,
              "nested VXLAN tunnels stop at PROTO_PATH_SIZE layers");
    }

    mmt_close_handler(h);
    close_extraction();
    printf("  %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
