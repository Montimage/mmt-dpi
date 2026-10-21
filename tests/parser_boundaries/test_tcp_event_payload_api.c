/*
 * test_tcp_event_payload_api.c — packet/API-path test for issue #505
 * (F-BUG-107): the payload of the TCP connection events.
 *
 * tcp.syn_received (MMT_U32_DATA), tcp.established and tcp.closed
 * (MMT_U8_DATA) are fired from mmt_tcpip_plugin_internal.h. All three used
 * to point at one `static int seen = 1` per translation unit: a 4-byte int
 * behind the two 1-byte events (0 on a big-endian host), shared by every
 * handler, flow and thread, so a handler that wrote through the payload
 * changed the value every later event reported. Each fire site now passes
 * its own block-scope literal of the declared width.
 *
 * The handlers read each payload at its declared width, then overwrite it
 * with 0. Two complete TCP connections (handshake + FIN/FIN/ACK close) run
 * through mmt_init_handler + packet_process; every event of both must still
 * report 1.
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

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            printf("  FAIL: ");                                      \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
            g_failures++;                                            \
        }                                                            \
    } while (0)

enum { EV_SYN, EV_EST, EV_CLOSED, EV_N };
static const char *const ev_name[EV_N] = { "syn_received", "established", "closed" };
static int g_count[EV_N];
static int g_bad[EV_N];

static void event_cb(const ipacket_t *ipacket, attribute_t *attr, void *user) {
    (void) ipacket;
    int ev = (int) (intptr_t) user;
    g_count[ev]++;
    if (attr->data == NULL) { g_bad[ev]++; return; }
    if (ev == EV_SYN) {
        uint32_t v;
        if (attr->data_type != MMT_U32_DATA) g_bad[ev]++;
        memcpy(&v, attr->data, sizeof v);
        if (v != 1) g_bad[ev]++;
        v = 0;
        memcpy(attr->data, &v, sizeof v);   /* must not leak into later events */
    } else {
        uint8_t v;
        if (attr->data_type != MMT_U8_DATA) g_bad[ev]++;
        memcpy(&v, attr->data, sizeof v);
        if (v != 1) g_bad[ev]++;
        v = 0;
        memcpy(attr->data, &v, sizeof v);
    }
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

/* Ethernet + IPv4 + 20-byte TCP header, no payload. */
static int build(uint8_t *pkt, uint16_t cport, int to_server, uint8_t flags,
                 uint32_t seq, uint32_t ack) {
    static const uint8_t mac_a[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t mac_b[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    uint8_t *ip = pkt + 14, *tcp = pkt + 34;
    memcpy(pkt, to_server ? mac_b : mac_a, 6);
    memcpy(pkt + 6, to_server ? mac_a : mac_b, 6);
    put_be16(pkt + 12, 0x0800);
    memset(ip, 0, 20);
    ip[0] = 0x45;
    put_be16(ip + 2, 40);
    ip[8] = 64;
    ip[9] = 6;
    ip[12] = 10; ip[15] = to_server ? 1 : 2;
    ip[16] = 10; ip[19] = to_server ? 2 : 1;
    memset(tcp, 0, 20);
    put_be16(tcp, to_server ? cport : 80);
    put_be16(tcp + 2, to_server ? 80 : cport);
    put_be32(tcp + 4, seq);
    put_be32(tcp + 8, ack);
    tcp[12] = 0x50;
    tcp[13] = flags;
    put_be16(tcp + 14, 0xffff);
    return 54;
}

static unsigned g_ts;

static void send_seg(mmt_handler_t *h, uint16_t cport, int to_server, uint8_t flags,
                 uint32_t seq, uint32_t ack) {
    uint8_t frame[64];
    int len = build(frame, cport, to_server, flags, seq, ack);
    uint8_t *data = malloc((size_t) len);   /* exact size: ASan brackets it */
    if (!data) { perror("malloc"); exit(2); }
    memcpy(data, frame, (size_t) len);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.ts.tv_sec = ++g_ts;
    hdr.caplen = (unsigned) len;
    hdr.len = (unsigned) len;
    packet_process(h, &hdr, data);
    free(data);
}

enum { SYN = 0x02, ACK = 0x10, FIN = 0x01 };

static void connection(mmt_handler_t *h, uint16_t cport) {
    send_seg(h, cport, 1, SYN,       100, 0);     /* -> syn_received */
    send_seg(h, cport, 0, SYN | ACK, 500, 101);
    send_seg(h, cport, 1, ACK,       101, 501);   /* -> established  */
    send_seg(h, cport, 1, FIN | ACK, 101, 501);
    send_seg(h, cport, 0, FIN | ACK, 501, 102);
    send_seg(h, cport, 1, ACK,       102, 502);   /* -> closed       */
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
    static const uint32_t ids[EV_N] = { TCP_SYN_RCV, TCP_CONN_ESTABLISHED, TCP_CONN_CLOSED };
    for (int ev = 0; ev < EV_N; ev++)
        CHECK(register_attribute_handler(h, PROTO_TCP, ids[ev], event_cb, NULL,
                                         (void *) (intptr_t) ev) == 1,
              "register tcp.%s handler", ev_name[ev]);

    printf("issue #505: TCP connection event payloads\n");
    connection(h, 40001);
    connection(h, 40002);

    for (int ev = 0; ev < EV_N; ev++) {
        CHECK(g_count[ev] == 2, "tcp.%s fired %d time(s), expected 2 (one per connection)",
              ev_name[ev], g_count[ev]);
        CHECK(g_bad[ev] == 0, "tcp.%s: %d event(s) with a wrong type or a value other than 1",
              ev_name[ev], g_bad[ev]);
    }

    mmt_close_handler(h);
    close_extraction();
    printf("  %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
