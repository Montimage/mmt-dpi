/*
 * test_quic_short_header_api.c — QUIC from a capture that starts
 * mid-connection: short headers only (issue #571).
 *
 * Crafted Ethernet/IPv4/UDP datagrams go through mmt_init_handler +
 * packet_process, a fresh handler per scenario; after each packet the test
 * reads whether the path holds quic_ietf, what follows it and the session's
 * classification method. "c" is a client packet to UDP/443 with the
 * scenario's DCID, "s" one from 443 with a zero-length DCID.
 *
 *   verdict     c c c: no verdict; the 4th c is quic_ietf (DPI), and so are
 *               the packets after it, s included
 *   restart     a different DCID restarts the count: c c c c' c' c' c'
 *   server      s neither counts nor resets: c s c s c s c
 *   tiny        a client packet below 21 bytes neither counts nor resets
 *   port        UDP/8443 never: 8 c
 *   fixed bit   a packet with the fixed bit clear, either way, rejects the
 *               flow for good
 *   turn        TURN ChannelData framing (length + 4 = datagram, constant
 *               size) on 443: never, and a ChannelData from the server
 *               rejects as well
 *   ip range    a server in an IP-range block (8.8.8.8: google, from
 *               goog.json since issue #565) gets the guess first; the
 *               verdict keeps it after quic_ietf, with its method (N2)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: ");                                      \
        } else {                                                     \
            printf("  FAIL: ");                                      \
            g_failures++;                                            \
        }                                                            \
        printf(__VA_ARGS__);                                         \
        printf("\n");                                                \
    } while (0)

/* What the last packet showed. */
static int g_quic;            /* quic_ietf in the path */
static uint32_t g_after;      /* the protocol after quic_ietf, 0 = none */
static uint32_t g_last;       /* the last protocol of the path */
static int g_method;          /* session classification method */

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    const proto_hierarchy_t *p = ipacket->proto_hierarchy;
    g_quic = 0;
    g_after = 0;
    g_last = 0;
    for (int i = 0; p != NULL && i < p->len && i < PROTO_PATH_SIZE; i++) {
        g_last = p->proto_path[i];
        if (p->proto_path[i] == PROTO_QUIC_IETF) {
            g_quic = 1;
            g_after = (i + 1 < p->len) ? p->proto_path[i + 1] : 0;
        }
    }
    g_method = get_session_classification_method(ipacket->session);
    return 0;
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t) (v >> 8); p[1] = (uint8_t) v; }

static uint8_t g_server[4] = {10, 0, 0, 2};
static uint16_t g_port = 443;
static uint32_t g_sec;

/* Ethernet/IPv4/UDP frame of an exact-size heap buffer; dir 0 = client
 * 10.0.0.1:50000 -> server:g_port. */
static void run(mmt_handler_t *h, int dir, const uint8_t *pl, size_t n) {
    size_t len = 14 + 20 + 8 + n;
    uint8_t *f = malloc(len);
    if (f == NULL) {
        perror("malloc");
        exit(2);
    }
    static const uint8_t mac_a[6] = {0x02, 0, 0, 0, 0, 1}, mac_b[6] = {0x02, 0, 0, 0, 0, 2};
    static const uint8_t cli[4] = {10, 0, 0, 1};
    memcpy(f, dir ? mac_a : mac_b, 6);
    memcpy(f + 6, dir ? mac_b : mac_a, 6);
    put_be16(f + 12, 0x0800);
    uint8_t *ip = f + 14;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    put_be16(ip + 2, (uint16_t) (20 + 8 + n));
    ip[8] = 64;
    ip[9] = 17;
    memcpy(ip + 12, dir ? g_server : cli, 4);
    memcpy(ip + 16, dir ? cli : g_server, 4);
    uint8_t *udp = ip + 20;
    put_be16(udp, dir ? g_port : 50000);
    put_be16(udp + 2, dir ? 50000 : g_port);
    put_be16(udp + 4, (uint16_t) (8 + n));
    put_be16(udp + 6, 0);
    memcpy(udp + 8, pl, n);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.ts.tv_sec = ++g_sec;
    hdr.caplen = (unsigned) len;
    hdr.len = (unsigned) len;
    g_quic = 0;
    g_after = 0;
    packet_process(h, &hdr, f);
    free(f);
}

static const uint8_t DCID_A[8] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7};
static const uint8_t DCID_B[8] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7};
static unsigned g_pn;

/* 1-RTT packet: `first`, the DCID (if any), a 2-byte packet number and
 * `body` bytes of varying content. */
static size_t short_pkt(uint8_t *b, uint8_t first, const uint8_t *dcid, size_t body) {
    size_t n = 0;
    b[n++] = first;
    if (dcid != NULL) {
        memcpy(b + n, dcid, 8);
        n += 8;
    }
    g_pn++;
    put_be16(b + n, (uint16_t) g_pn);
    n += 2;
    for (size_t i = 0; i < body; i++) {
        b[n++] = (uint8_t) (g_pn * 31 + i * 7);
    }
    return n;
}

static void cli(mmt_handler_t *h, const uint8_t *dcid) {
    uint8_t b[256];
    run(h, 0, b, short_pkt(b, (uint8_t) (0x41 | ((g_pn & 1) << 5)), dcid, 40 + (g_pn % 5) * 9));
}

static void srv(mmt_handler_t *h) {
    uint8_t b[256];
    run(h, 1, b, short_pkt(b, 0x52, NULL, 60 + (g_pn % 3) * 11));
}

static mmt_handler_t *fresh(void) {
    char errbuf[1024];
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler: %s\n", errbuf);
        exit(2);
    }
    register_packet_handler(h, 1, packet_handler, NULL);
    memcpy(g_server, (const uint8_t[4]) {10, 0, 0, 2}, 4);
    g_port = 443;
    return h;
}

static void test_verdict(void) {
    printf("verdict\n");
    mmt_handler_t *h = fresh();
    int early = 0;
    for (int i = 0; i < 3; i++) {
        cli(h, DCID_A);
        early |= g_quic;
    }
    CHECK(!early, "three client packets with one DCID: no verdict");
    cli(h, DCID_A);
    CHECK(g_quic && g_method == MMT_CLASSIFICATION_METHOD_DPI,
          "the fourth: quic_ietf, method DPI (got quic %d, method %d)", g_quic, g_method);
    srv(h);
    CHECK(g_quic, "the server's next packet: quic_ietf");
    cli(h, DCID_A);
    CHECK(g_quic && g_after == 0, "and the client's: quic_ietf, nothing after it");
    mmt_close_handler(h);
}

static void test_restart(void) {
    printf("restart\n");
    mmt_handler_t *h = fresh();
    int early = 0;
    for (int i = 0; i < 3; i++) {
        cli(h, DCID_A);
        early |= g_quic;
    }
    for (int i = 0; i < 3; i++) {
        cli(h, DCID_B);
        early |= g_quic;
    }
    CHECK(!early, "c c c then c' c' c': the new DCID restarted the count");
    cli(h, DCID_B);
    CHECK(g_quic, "the fourth c': quic_ietf");
    mmt_close_handler(h);
}

static void test_server(void) {
    printf("server\n");
    mmt_handler_t *h = fresh();
    int early = 0;
    for (int i = 0; i < 3; i++) {
        cli(h, DCID_A);
        early |= g_quic;
        srv(h);
        early |= g_quic;
    }
    CHECK(!early, "c s c s c s: server packets do not count");
    cli(h, DCID_A);
    CHECK(g_quic, "...and do not reset: the fourth c is quic_ietf");
    mmt_close_handler(h);
}

static void test_tiny(void) {
    printf("tiny\n");
    mmt_handler_t *h = fresh();
    uint8_t b[64];
    int early = 0;
    for (int i = 0; i < 3; i++) {
        cli(h, DCID_A);
        early |= g_quic;
    }
    run(h, 0, b, short_pkt(b, 0x41, DCID_A, 5)); /* 16 bytes */
    early |= g_quic;
    CHECK(!early, "a 16-byte client packet after three: no verdict");
    cli(h, DCID_A);
    CHECK(g_quic, "it neither counted nor reset: the next c is quic_ietf");
    mmt_close_handler(h);
}

static void test_port(void) {
    printf("port\n");
    mmt_handler_t *h = fresh();
    g_port = 8443;
    int any = 0;
    for (int i = 0; i < 8; i++) {
        cli(h, DCID_A);
        any |= g_quic;
    }
    CHECK(!any, "UDP/8443: eight packets, one DCID, never quic_ietf");
    mmt_close_handler(h);
}

static void test_fixed_bit(int from_server) {
    printf("fixed bit (%s)\n", from_server ? "server" : "client");
    mmt_handler_t *h = fresh();
    uint8_t b[128];
    int any = 0;
    cli(h, DCID_A);
    cli(h, DCID_A);
    run(h, from_server, b, short_pkt(b, 0x01, from_server ? NULL : DCID_A, 40));
    any |= g_quic;
    for (int i = 0; i < 6; i++) {
        cli(h, DCID_A);
        any |= g_quic;
    }
    CHECK(!any, "fixed bit clear once: never quic_ietf, even after six good packets");
    mmt_close_handler(h);
}

/* TURN ChannelData (RFC 8656 §12.4): channel 0x4001, length 72, a DTLS 1.2
 * record header and data, 76 bytes in all. */
static size_t channel_data(uint8_t *b, unsigned seq) {
    memset(b, 0, 76);
    b[0] = 0x40;
    b[1] = 0x01;
    put_be16(b + 2, 72);
    b[4] = 23;
    b[5] = 0xfe;
    b[6] = 0xfd;
    b[8] = 1;
    b[14] = (uint8_t) seq;
    put_be16(b + 15, 59);
    for (int i = 17; i < 76; i++) {
        b[i] = (uint8_t) (seq * 13 + (unsigned) i);
    }
    return 76;
}

static void test_turn(void) {
    printf("turn\n");
    mmt_handler_t *h = fresh();
    uint8_t b[128];
    int any = 0;
    for (unsigned i = 0; i < 8; i++) {
        run(h, 0, b, channel_data(b, i));
        any |= g_quic;
    }
    CHECK(!any, "eight constant-size ChannelData to 443 (bytes 1-8 repeat): never quic_ietf");
    mmt_close_handler(h);

    h = fresh();
    any = 0;
    cli(h, DCID_A);
    cli(h, DCID_A);
    run(h, 1, b, channel_data(b, 1));
    for (int i = 0; i < 6; i++) {
        cli(h, DCID_A);
        any |= g_quic;
    }
    CHECK(!any, "a ChannelData from the server rejects the flow");
    mmt_close_handler(h);
}

static void test_ip_range(void) {
    printf("ip range\n");
    mmt_handler_t *h = fresh();
    memcpy(g_server, (const uint8_t[4]) {8, 8, 8, 8}, 4);
    cli(h, DCID_A);
    CHECK(!g_quic && g_last == PROTO_GOOGLE && g_method == MMT_CLASSIFICATION_METHOD_IP,
          "first packet: the IP-range guess google (method IP; got last %u, method %d)", g_last, g_method);
    for (int i = 0; i < 3; i++) {
        cli(h, DCID_A);
    }
    CHECK(g_quic && g_after == PROTO_GOOGLE && g_method == MMT_CLASSIFICATION_METHOD_IP,
          "fourth: quic_ietf, the guess kept after it with method IP (got after %u, method %d)", g_after, g_method);
    srv(h);
    CHECK(g_quic && g_after == PROTO_GOOGLE, "the next packet keeps both");
    mmt_close_handler(h);
}

int main(void) {
    init_extraction();
    test_verdict();
    test_restart();
    test_server();
    test_tiny();
    test_port();
    test_fixed_bit(0);
    test_fixed_bit(1);
    test_turn();
    test_ip_range();
    close_extraction();
    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}
