/*
 * test_classifier_audit_api.c — packet/API-path test for issue #330, the
 * audit of the weak TCP/IP classifier sites. It pins the classifier fixes:
 *
 *   - MQTT (proto_mqtt.c): on port 1883 the payload must start with a
 *     well-formed fixed header (type nibble 1..15, Remaining Length varint of
 *     1..4 bytes); the port alone no longer classifies.
 *   - NetFlow (proto_netflow.c): IPFIX (version 10) is read with its own
 *     header layout (message length at 2, export time at 4); NetFlow v5 keeps
 *     classifying as before.
 *   - sFlow (proto_sflow.c): the agent address type must be 1 (IPv4) or
 *     2 (IPv6) and the payload must hold the header it implies.
 *   - RADIUS (proto_radius.c): every RFC 2865/5176 packet code classifies a
 *     flow (Access-Challenge, CoA-Request), code 0 does not, and a payload
 *     shorter than the header is not read past (ASan under SANITIZE=asan).
 *   - FTP (proto_ftp.c): a PASV "227" reply on an IPv6 control connection
 *     used to dereference the NULL IPv4 header, and the IPv6 session tuple
 *     buffers (17 bytes) were copied and compared as 32 bytes (ASan heap
 *     overflow); both must be processed safely.
 *
 * Crafted Ethernet/IPv{4,6}/{TCP,UDP} frames go through mmt_init_handler +
 * packet_process; the packet handler records which protocols the path holds.
 * Every case uses its own source port (its own session) and exactly-sized
 * heap copies so ASan brackets each capture.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

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

static int      g_want;     /* protocol looked for in the path */
static int      g_seen;     /* g_want was in the path of some packet */

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (ipacket->proto_hierarchy != NULL) {
        for (int i = 0; i < ipacket->proto_hierarchy->len && i < PROTO_PATH_SIZE; i++)
            if (ipacket->proto_hierarchy->proto_path[i] == g_want)
                g_seen = 1;
    }
    return 0;
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

/* Builds Ethernet + IPv4 or IPv6 + TCP (PSH|ACK) or UDP + payload. `to_server`
 * selects the direction between the client (port sport) and the server (port
 * dport). Returns the frame length. */
static int build(uint8_t *pkt, int ipv6, int tcp, uint16_t sport, uint16_t dport,
                 int to_server, uint32_t seq, const uint8_t *pl, unsigned plen) {
    static const uint8_t mac_a[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t mac_b[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    const unsigned l4len = (tcp ? 20u : 8u) + plen;
    const unsigned iplen = ipv6 ? 40u : 20u;
    uint8_t *ip = pkt + 14, *l4 = pkt + 14 + iplen;

    memcpy(pkt, to_server ? mac_a : mac_b, 6);
    memcpy(pkt + 6, to_server ? mac_b : mac_a, 6);
    put_be16(pkt + 12, ipv6 ? 0x86dd : 0x0800);

    memset(ip, 0, iplen);
    if (ipv6) {
        uint8_t cli[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01};
        uint8_t srv[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x02};
        ip[0] = 0x60;
        put_be16(ip + 4, (uint16_t) l4len);
        ip[6] = tcp ? 6 : 17;
        ip[7] = 64;
        memcpy(ip + 8, to_server ? cli : srv, 16);
        memcpy(ip + 24, to_server ? srv : cli, 16);
    } else {
        ip[0] = 0x45;
        put_be16(ip + 2, (uint16_t)(20 + l4len));
        ip[8] = 64;
        ip[9] = tcp ? 6 : 17;
        ip[12] = 10; ip[15] = to_server ? 1 : 2;
        ip[16] = 10; ip[19] = to_server ? 2 : 1;
    }

    put_be16(l4, to_server ? sport : dport);
    put_be16(l4 + 2, to_server ? dport : sport);
    if (tcp) {
        memset(l4 + 4, 0, 16);
        put_be32(l4 + 4, seq);
        put_be32(l4 + 8, 1);
        l4[12] = 0x50;                      /* data offset 5 */
        l4[13] = 0x18;                      /* PSH|ACK */
        put_be16(l4 + 14, 0xffff);
        memcpy(l4 + 20, pl, plen);
    } else {
        put_be16(l4 + 4, (uint16_t) l4len);
        put_be16(l4 + 6, 0);
        memcpy(l4 + 8, pl, plen);
    }
    return (int)(14 + iplen + l4len);
}

static unsigned g_ts;

static void send_frame(mmt_handler_t *h, const uint8_t *frame, int len) {
    /* An exactly-sized heap copy lets ASan bracket the capture. */
    uint8_t *data = malloc((size_t) len);
    if (!data) { perror("malloc"); exit(2); }
    memcpy(data, frame, (size_t) len);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = ++g_ts;
    hdr.caplen = (unsigned) len;
    hdr.len = (unsigned) len;
    packet_process(h, &hdr, data);
    free(data);
}

/* Sends one client-to-server packet (twice for UDP, so the verdict does not
 * hinge on the first packet of the session) and reports whether `want` was
 * in the path. */
static int classifies(mmt_handler_t *h, int tcp, uint16_t sport, uint16_t dport,
                      const uint8_t *pl, unsigned plen, int want) {
    static uint8_t frame[2048];
    g_want = want;
    g_seen = 0;
    int n = build(frame, 0, tcp, sport, dport, 1, 1, pl, plen);
    send_frame(h, frame, n);
    if (!tcp)
        send_frame(h, frame, n);
    return g_seen;
}

static void test_mqtt(mmt_handler_t *h) {
    /* CONNECT: fixed header 0x10, Remaining Length 16, then the variable
     * header and a 2-byte client id. */
    static const uint8_t connect[] = {
        0x10, 0x10, 0x00, 0x04, 'M','Q','T','T', 0x04, 0x02, 0x00, 0x3c,
        0x00, 0x04, 'm','m','t','!' };
    static const uint8_t type0[] = { 0x00, 0x02, 0xde, 0xad };
    static const uint8_t long_varint[] = { 0x30, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00 };

    CHECK(classifies(h, 1, 41001, 1883, connect, sizeof connect, PROTO_MQTT),
          "MQTT CONNECT to port 1883 is classified as MQTT");
    CHECK(!classifies(h, 1, 41002, 1883, type0, sizeof type0, PROTO_MQTT),
          "reserved packet type 0 on port 1883 is not MQTT");
    CHECK(!classifies(h, 1, 41003, 1883, long_varint, sizeof long_varint, PROTO_MQTT),
          "a 5-byte Remaining Length on port 1883 is not MQTT");
}

static void test_netflow(mmt_handler_t *h) {
    uint8_t v5[24 + 48], ipfix[16 + 20];
    const uint32_t when = 1700000000u;   /* 2023-11-14 */

    memset(v5, 0, sizeof v5);
    put_be16(v5, 5);                     /* version */
    put_be16(v5 + 2, 1);                 /* count */
    put_be32(v5 + 4, 123456);            /* sys_uptime */
    put_be32(v5 + 8, when);              /* unix_secs */
    CHECK(classifies(h, 0, 42001, 2055, v5, sizeof v5, PROTO_NETFLOW),
          "NetFlow v5 export is classified as NETFLOW");

    memset(ipfix, 0, sizeof ipfix);
    put_be16(ipfix, 10);                 /* version: IPFIX */
    put_be16(ipfix + 2, sizeof ipfix);   /* message length */
    put_be32(ipfix + 4, when);           /* export time */
    put_be32(ipfix + 8, 7);              /* sequence number */
    put_be32(ipfix + 12, 1);             /* observation domain */
    put_be16(ipfix + 16, 2);             /* template set */
    put_be16(ipfix + 18, 20);
    CHECK(classifies(h, 0, 42002, 4739, ipfix, sizeof ipfix, PROTO_NETFLOW),
          "IPFIX (v10) message is classified as NETFLOW");

    put_be16(ipfix + 2, sizeof ipfix + 4);   /* length disagrees with payload */
    CHECK(!classifies(h, 0, 42003, 4739, ipfix, sizeof ipfix, PROTO_NETFLOW),
          "IPFIX header whose length is not the datagram's is not NETFLOW");
}

static void test_sflow(mmt_handler_t *h) {
    uint8_t d[28 + 8];
    memset(d, 0, sizeof d);
    put_be32(d, 5);                      /* version */
    put_be32(d + 4, 1);                  /* agent address type: IPv4 */
    d[8] = 10; d[11] = 1;                /* agent address */
    put_be32(d + 16, 1);                 /* sequence number */
    CHECK(classifies(h, 0, 43001, 6343, d, sizeof d, PROTO_SFLOW),
          "sFlow v5 datagram with an IPv4 agent is classified as SFLOW");

    put_be32(d + 4, 7);                  /* no such address type */
    CHECK(!classifies(h, 0, 43002, 6343, d, sizeof d, PROTO_SFLOW),
          "version 5 prefix with address type 7 is not SFLOW");

    put_be32(d + 4, 2);                  /* IPv6 agent needs 40 bytes */
    CHECK(!classifies(h, 0, 43003, 6343, d, sizeof d, PROTO_SFLOW),
          "IPv6-agent sFlow v5 header cut to 36 bytes is not SFLOW");
}

static void test_radius(mmt_handler_t *h) {
    uint8_t r[20 + 6];
    memset(r, 0x11, sizeof r);
    put_be16(r + 2, sizeof r);
    r[20] = 18; r[21] = 6;               /* Reply-Message "abcd" */
    memcpy(r + 22, "abcd", 4);

    r[0] = 11;                           /* Access-Challenge */
    CHECK(classifies(h, 0, 44001, 40812, r, sizeof r, PROTO_RADIUS),
          "Access-Challenge (11) is classified as RADIUS");
    r[0] = 43;                           /* CoA-Request (RFC 5176) */
    CHECK(classifies(h, 0, 44002, 40812, r, sizeof r, PROTO_RADIUS),
          "CoA-Request (43) is classified as RADIUS");
    r[0] = 0;                            /* not a RADIUS code */
    CHECK(!classifies(h, 0, 44003, 40812, r, sizeof r, PROTO_RADIUS),
          "code 0 is not RADIUS");

    static const uint8_t tiny[] = { 0x01, 0x02, 0x00 };
    CHECK(!classifies(h, 0, 44004, 40812, tiny, sizeof tiny, PROTO_RADIUS),
          "3-byte payload is not RADIUS (and is not read past)");

    uint8_t bare[20];                    /* Access-Reject, no attributes */
    memset(bare, 0x22, sizeof bare);
    bare[0] = 3;
    put_be16(bare + 2, sizeof bare);
    CHECK(classifies(h, 0, 44005, 40812, bare, sizeof bare, PROTO_RADIUS),
          "attribute-less 20-byte Access-Reject is classified as RADIUS");
    put_be16(bare + 2, 8);               /* self-consistent but below 20 */
    CHECK(!classifies(h, 0, 44006, 40812, bare, 8, PROTO_RADIUS),
          "8-byte payload with a matching length field is not RADIUS");
}

static void test_ftp_pasv_ipv6(mmt_handler_t *h) {
    static uint8_t frame[256];
    static const char *const replies[] = {
        "220 mmt FTP server ready\r\n",
        "227 Entering Passive Mode (10,0,0,2,4,1)\r\n",
    };
    int ftp_seen = 0;
    uint32_t seq = 1;

    g_want = PROTO_FTP;
    for (size_t i = 0; i < sizeof replies / sizeof replies[0]; i++) {
        unsigned plen = (unsigned) strlen(replies[i]);
        int n = build(frame, 1, 1, 45001, 21, 0, seq, (const uint8_t *) replies[i], plen);
        seq += plen;
        g_seen = 0;
        send_frame(h, frame, n);
        ftp_seen |= g_seen;
    }
    /* Reaching this check at all means the 227 reply was processed: before
     * the fix it dereferenced the NULL IPv4 header and crashed. */
    CHECK(ftp_seen, "IPv6 FTP control connection with a PASV reply is classified as FTP");
}

int main(void) {
    char errbuf[1024];
    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);

    printf("issue #330: audited classifiers (MQTT, NetFlow/IPFIX, sFlow, RADIUS, FTP)\n");
    test_mqtt(h);
    test_netflow(h);
    test_sflow(h);
    test_radius(h);
    test_ftp_pasv_ipv6(h);

    mmt_close_handler(h);
    close_extraction();
    printf("  %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
