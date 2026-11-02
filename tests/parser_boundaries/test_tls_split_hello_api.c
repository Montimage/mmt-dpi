/*
 * test_tls_split_hello_api.c — a TLS ClientHello split over several TCP
 * segments yields its SNI (issue #568, F-BUG-302).
 *
 * Crafted Ethernet/IPv4/TCP frames go through mmt_init_handler +
 * packet_process with ssl.server_name registered. Each case is its own flow
 * (client port); per client segment the test records whether ssl.server_name
 * was extracted and the deepest application of the protocol path:
 *
 *   single     the whole record in one segment: SNI on that packet
 *   split      1,800-byte record, 1,460 + 340: the SNI (in the second
 *              segment) is read when the record completes, ssl.google
 *   boundary   the cut falls inside the host name itself
 *   reordered  three segments sent 1, 3, 1 (retransmission), 2
 *   server     a server packet with payload between the two client segments
 *   truncated  the second segment never arrives: ssl, no SNI
 *   oversize   a record declaring 20,000 bytes (> 2^14): never collected,
 *              no SNI — the bytes that would complete it are ignored
 *   stalled    the first segment retransmitted until the collection gives
 *              up (TLS_HELLO_MAX_STALLS): the real rest yields no SNI
 *
 * Every frame is heap-allocated to its exact size, so ASan brackets it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <pcap.h>            /* DLT_EN10MB */

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

static const char *g_ignore[] = {
    "meta", "ethernet", "ip", "tcp", "unknown", NULL,
};

/* What the handler saw on the last packet. */
static char g_sni[300];
static char g_app[64];

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    g_sni[0] = '\0';
    g_app[0] = '\0';
    const mmt_header_line_t *sn = get_attribute_extracted_data(ipacket, PROTO_SSL, SSL_SERVER_NAME);
    if (sn != NULL && sn->ptr != NULL) {
        size_t n = sn->len < sizeof g_sni - 1 ? sn->len : sizeof g_sni - 1;
        memcpy(g_sni, sn->ptr, n);
        g_sni[n] = '\0';
    }
    if (ipacket->proto_hierarchy != NULL) {
        for (int i = 0; i < ipacket->proto_hierarchy->len && i < PROTO_PATH_SIZE; i++) {
            const char *name = get_protocol_name_by_id(ipacket->proto_hierarchy->proto_path[i]);
            int skip = (name == NULL);
            for (int k = 0; !skip && g_ignore[k] != NULL; k++) {
                skip = strcasecmp(name, g_ignore[k]) == 0;
            }
            if (!skip) {
                snprintf(g_app, sizeof g_app, "%s", name);
            }
        }
    }
    return 0;
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t) (v >> 8); p[1] = (uint8_t) v; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) (v >> 24); p[1] = (uint8_t) (v >> 16); p[2] = (uint8_t) (v >> 8); p[3] = (uint8_t) v;
}

static unsigned g_ts;
enum { FIN = 0x01, SYN = 0x02, PSH = 0x08, ACK = 0x10 };

/* One Ethernet/IPv4/TCP frame, client 192.0.2.1:cport <-> 198.51.100.2:443. */
static void send_seg(mmt_handler_t *h, uint16_t cport, int to_server, uint8_t flags,
                     uint32_t seq, uint32_t ack, const uint8_t *payload, size_t plen) {
    size_t len = 54 + plen;
    uint8_t *f = calloc(1, len);
    if (f == NULL) { perror("calloc"); exit(2); }
    static const uint8_t mac_c[6] = {0x02, 0, 0, 0, 0x02, 0x01};
    static const uint8_t mac_s[6] = {0x02, 0, 0, 0, 0x64, 0x02};
    memcpy(f, to_server ? mac_s : mac_c, 6);
    memcpy(f + 6, to_server ? mac_c : mac_s, 6);
    put_be16(f + 12, 0x0800);
    uint8_t *ip = f + 14, *tcp = f + 34;
    ip[0] = 0x45;
    put_be16(ip + 2, (uint16_t) (40 + plen));
    ip[8] = 64;
    ip[9] = 6;
    static const uint8_t cli[4] = {192, 0, 2, 1}, srv[4] = {198, 51, 100, 2};
    memcpy(ip + 12, to_server ? cli : srv, 4);
    memcpy(ip + 16, to_server ? srv : cli, 4);
    put_be16(tcp, to_server ? cport : 443);
    put_be16(tcp + 2, to_server ? 443 : cport);
    put_be32(tcp + 4, seq);
    put_be32(tcp + 8, ack);
    tcp[12] = 0x50;
    tcp[13] = flags;
    put_be16(tcp + 14, 0xffff);
    if (plen) memcpy(f + 54, payload, plen);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.ts.tv_sec = ++g_ts;
    hdr.caplen = (unsigned) len;
    hdr.len = (unsigned) len;
    g_sni[0] = g_app[0] = '\0';
    packet_process(h, &hdr, f);
    free(f);
}

#define CISN 1000u
#define SISN 50000u

static void handshake(mmt_handler_t *h, uint16_t cport) {
    send_seg(h, cport, 1, SYN, CISN, 0, NULL, 0);
    send_seg(h, cport, 0, SYN | ACK, SISN, CISN + 1, NULL, 0);
    send_seg(h, cport, 1, ACK, CISN + 1, SISN + 1, NULL, 0);
}

/* Client data at record offset `off` (sequence CISN + 1 + off). */
static void client(mmt_handler_t *h, uint16_t cport, const uint8_t *rec, size_t off, size_t n) {
    send_seg(h, cport, 1, PSH | ACK, CISN + 1 + (uint32_t) off, SISN + 1, rec + off, n);
}

/* A TLS 1.2 ClientHello record of exactly `total` bytes (padding extension
 * first, server_name last); `declared` overrides the record length field
 * when non-zero. Returns the offset of the host name in the record. */
static size_t build_hello(uint8_t *rec, size_t total, const char *host, uint16_t declared) {
    size_t hl = strlen(host);
    size_t fixed = 5 + 4 + 2 + 32 + 1 + 6 + 2 + 2;   /* through the extensions length */
    size_t sni_ext = 4 + 5 + hl;
    size_t pad = total - fixed - 4 - sni_ext;
    uint8_t *p = rec;
    memset(rec, 0, total);
    p[0] = 0x16; p[1] = 0x03; p[2] = 0x01;
    put_be16(p + 3, declared ? declared : (uint16_t) (total - 5));
    p[5] = 1;
    p[6] = 0; put_be16(p + 7, (uint16_t) (total - 9));
    p[9] = 0x03; p[10] = 0x03;
    for (int i = 0; i < 32; i++) p[11 + i] = (uint8_t) i;
    p[43] = 0;                                   /* session id */
    put_be16(p + 44, 4); put_be16(p + 46, 0x002f); put_be16(p + 48, 0x0035);
    p[50] = 1; p[51] = 0;                        /* null compression */
    put_be16(p + 52, (uint16_t) (total - fixed));
    size_t o = fixed;
    put_be16(p + o, 21); put_be16(p + o + 2, (uint16_t) pad);  /* padding (RFC 7685) */
    o += 4 + pad;
    put_be16(p + o, 0); put_be16(p + o + 2, (uint16_t) (5 + hl));
    put_be16(p + o + 4, (uint16_t) (3 + hl)); p[o + 6] = 0; put_be16(p + o + 7, (uint16_t) hl);
    memcpy(p + o + 9, host, hl);
    return o + 9;
}

static mmt_handler_t *g_h;
static uint16_t g_port = 40000;

static void test_single(void) {
    printf("case single: the whole record in one segment\n");
    static uint8_t rec[300];
    uint16_t port = g_port++;
    build_hello(rec, sizeof rec, "www.google.com", 0);
    handshake(g_h, port);
    client(g_h, port, rec, 0, sizeof rec);
    CHECK(strcmp(g_sni, "www.google.com") == 0, "server_name on the hello packet (got '%s')", g_sni);
    CHECK(strcasecmp(g_app, "google") == 0, "attributed google (got '%s')", g_app);
}

static void test_split(const char *label, size_t cut_back, int server_between) {
    printf("case %s\n", label);
    static uint8_t rec[1800];
    uint16_t port = g_port++;
    size_t host_at = build_hello(rec, sizeof rec, "www.google.com", 0);
    size_t cut = cut_back ? host_at + cut_back : 1460;
    handshake(g_h, port);
    client(g_h, port, rec, 0, cut);
    CHECK(g_sni[0] == '\0', "%s: no server_name on the first segment (got '%s')", label, g_sni);
    CHECK(strcasecmp(g_app, "ssl") == 0, "%s: first segment is ssl (got '%s')", label, g_app);
    if (server_between) {
        static const uint8_t junk[] = "\x17\x03\x03\x00\x05hello";
        send_seg(g_h, port, 0, PSH | ACK, SISN + 1, CISN + 1 + (uint32_t) cut, junk, sizeof junk - 1);
    }
    client(g_h, port, rec, cut, sizeof rec - cut);
    CHECK(strcmp(g_sni, "www.google.com") == 0, "%s: server_name once the record completes (got '%s')",
          label, g_sni);
    CHECK(strcasecmp(g_app, "google") == 0, "%s: attributed google (got '%s')", label, g_app);
}

static void test_reordered(void) {
    printf("case reordered: segments 1, 3, 1 again, 2\n");
    static uint8_t rec[1800];
    uint16_t port = g_port++;
    build_hello(rec, sizeof rec, "teams.microsoft.com", 0);
    handshake(g_h, port);
    client(g_h, port, rec, 0, 600);
    client(g_h, port, rec, 1200, 600);
    CHECK(g_sni[0] == '\0', "no server_name before the gap is filled (got '%s')", g_sni);
    client(g_h, port, rec, 0, 600);
    CHECK(g_sni[0] == '\0', "no server_name on the retransmission (got '%s')", g_sni);
    client(g_h, port, rec, 600, 600);
    CHECK(strcmp(g_sni, "teams.microsoft.com") == 0, "server_name once the gap is filled (got '%s')", g_sni);
    CHECK(strcasecmp(g_app, "ms_teams") == 0, "attributed ms_teams (got '%s')", g_app);
}

static void test_truncated(void) {
    printf("case truncated: the rest of the record never arrives\n");
    static uint8_t rec[1800];
    uint16_t port = g_port++;
    build_hello(rec, sizeof rec, "www.google.com", 0);
    handshake(g_h, port);
    client(g_h, port, rec, 0, 1460);
    send_seg(g_h, port, 1, FIN | ACK, CISN + 1 + 1460, SISN + 1, NULL, 0);
    send_seg(g_h, port, 0, FIN | ACK, SISN + 1, CISN + 2 + 1460, NULL, 0);
    CHECK(g_sni[0] == '\0', "no server_name (got '%s')", g_sni);
    CHECK(strcasecmp(g_app, "ssl") == 0, "the flow stays ssl (got '%s')", g_app);
}

static void test_oversize(void) {
    printf("case oversize: record length 20,000 (> 2^14)\n");
    static uint8_t rec[1800];
    uint16_t port = g_port++;
    build_hello(rec, sizeof rec, "www.google.com", 20000);
    /* keep the handshake length 4 below the declared record length */
    put_be16(rec + 7, 20000 - 4);
    handshake(g_h, port);
    client(g_h, port, rec, 0, 1460);
    CHECK(g_sni[0] == '\0', "no server_name on the first segment (got '%s')", g_sni);
    CHECK(strcasecmp(g_app, "ssl") != 0 && strcasecmp(g_app, "google") != 0,
          "an oversize record is not taken for a ClientHello (got '%s')", g_app);
    client(g_h, port, rec, 1460, sizeof rec - 1460);
    CHECK(g_sni[0] == '\0', "no server_name from the bytes after it (got '%s')", g_sni);
}

static void test_stalled(void) {
    printf("case stalled: the first segment retransmitted until the collection gives up\n");
    static uint8_t rec[1800];
    uint16_t port = g_port++;
    build_hello(rec, sizeof rec, "www.google.com", 0);
    handshake(g_h, port);
    client(g_h, port, rec, 0, 1460);
    for (int i = 0; i < 8; i++) {
        client(g_h, port, rec, 0, 1460);
    }
    client(g_h, port, rec, 1460, sizeof rec - 1460);
    CHECK(g_sni[0] == '\0', "no server_name after the collection was dropped (got '%s')", g_sni);
    CHECK(strcasecmp(g_app, "ssl") == 0, "the flow stays ssl (got '%s')", g_app);
}

int main(void) {
    char errbuf[1024];
    printf("=== TLS ClientHello split across TCP segments (issue #568) ===\n");
    init_extraction();
    g_h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (g_h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    CHECK(register_extraction_attribute(g_h, PROTO_SSL, SSL_SERVER_NAME) == 1, "register ssl.server_name");
    register_packet_handler(g_h, 1, packet_handler, NULL);

    test_single();
    test_split("split: 1,460 + 340", 0, 0);
    test_split("boundary: the cut inside the host name", 5, 0);
    test_split("server: a server packet between the segments", 0, 1);
    test_reordered();
    test_truncated();
    test_oversize();
    test_stalled();

    mmt_close_handler(g_h);
    close_extraction();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
