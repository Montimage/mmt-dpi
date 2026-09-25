/*
 * test_radius_dns_ipv6_api.c — packet/API-path test for issue #331: the
 * radius.dns_ipv6 attribute (3GPP-IPv6-DNS-Servers, 3GPP vendor
 * sub-attribute 17, TS 29.061) used to be a stub that never extracted.
 * radius_dns_ipv6_extraction() now reports the first (primary) server
 * address of the sub-attribute as MMT_DATA_IP6_ADDR.
 *
 *   - a sub-attribute carrying two servers extracts the first one;
 *   - a sub-attribute shorter than one address (15 value bytes) does not
 *     extract;
 *   - a vendor-specific attribute running past the captured bytes is
 *     rejected by the parser, so nothing is extracted and nothing past
 *     caplen is read (ASan brackets the frame under SANITIZE=asan).
 *
 * Crafted Ethernet/IPv4/UDP/RADIUS Accounting-Request frames are fed through
 * mmt_init_handler + register_extraction_attribute + packet_process; the
 * packet handler snapshots the attribute. Each case uses its own UDP source
 * port (its own session) and is sent twice so the result does not depend on
 * which packet of the session the classifier accepts.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mmt_tcpip_attributes.h"      /* RADIUS_* attribute ids */

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

static int     g_radius_seen;    /* RADIUS was in the hierarchy */
static int     g_dns_seen;       /* radius.dns_ipv6 returned non-NULL */
static uint8_t g_dns[16];

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (ipacket->proto_hierarchy != NULL) {
        for (int i = 0; i < ipacket->proto_hierarchy->len; i++)
            if (ipacket->proto_hierarchy->proto_path[i] == PROTO_RADIUS)
                g_radius_seen = 1;
    }
    const uint8_t *a = (const uint8_t *)
        get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_DNS_IPV6);
    if (a != NULL) {
        g_dns_seen = 1;
        memcpy(g_dns, a, sizeof(g_dns));
    }
    return 0;
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static const uint8_t dns1[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x53};
static const uint8_t dns2[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0x01,0x53};

/* Builds an Accounting-Request whose only attribute is a 3GPP VSA with
 * sub-attribute 17 carrying `val_len` bytes (dns1 then dns2, truncated).
 * `vsa_len_extra` inflates the declared VSA/sub-TLV lengths without adding
 * bytes (a VSA running past the capture). Returns the frame length. */
static int build(uint8_t *pkt, uint16_t sport, unsigned val_len, unsigned vsa_len_extra) {
    uint8_t val[32];
    memcpy(val, dns1, 16);
    memcpy(val + 16, dns2, 16);

    uint8_t *r = pkt + 14 + 20 + 8;
    unsigned sub_len = 2 + val_len;
    unsigned vsa_len = 2 + 4 + sub_len;
    unsigned rlen = 20 + vsa_len;
    r[0] = 4;                                /* Accounting-Request */
    r[1] = 7;                                /* identifier */
    put_be16(r + 2, (uint16_t) rlen);
    memset(r + 4, 0x11, 16);                 /* authenticator */
    uint8_t *v = r + 20;
    v[0] = 26;                               /* Vendor-Specific */
    v[1] = (uint8_t)(vsa_len + vsa_len_extra);
    v[2] = 0x00; v[3] = 0x00; v[4] = 0x28; v[5] = 0xaf;   /* 10415 = 3GPP */
    v[6] = 17;                               /* 3GPP-IPv6-DNS-Servers */
    v[7] = (uint8_t)(sub_len + vsa_len_extra);
    memcpy(v + 8, val, val_len);

    uint8_t *e = pkt;
    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(e, dst, 6); memcpy(e + 6, src, 6); put_be16(e + 12, 0x0800);
    uint8_t *ip = pkt + 14;
    memset(ip, 0, 20);
    ip[0] = 0x45; put_be16(ip + 2, (uint16_t)(20 + 8 + rlen));
    ip[8] = 64; ip[9] = 17;
    ip[12] = 10; ip[15] = 1; ip[16] = 10; ip[19] = 2;
    uint8_t *u = pkt + 34;
    put_be16(u, sport); put_be16(u + 2, 1813);
    put_be16(u + 4, (uint16_t)(8 + rlen)); put_be16(u + 6, 0);
    return (int)(42 + rlen);
}

static void run_case(mmt_handler_t *h, uint16_t sport, unsigned val_len,
                     unsigned vsa_len_extra) {
    static uint8_t frame[128];
    int len = build(frame, sport, val_len, vsa_len_extra);
    g_radius_seen = g_dns_seen = 0;
    memset(g_dns, 0, sizeof(g_dns));
    for (int i = 0; i < 2; i++) {
        /* An exactly-sized heap copy lets ASan bracket the capture. */
        uint8_t *data = malloc((size_t) len);
        if (!data) { perror("malloc"); exit(2); }
        memcpy(data, frame, (size_t) len);
        struct pkthdr hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.ts.tv_sec = 1 + i;
        hdr.caplen = (unsigned) len;
        hdr.len = (unsigned) len;
        packet_process(h, &hdr, data);
        free(data);
    }
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
    if (register_extraction_attribute(h, PROTO_RADIUS, RADIUS_3GPP_DNS_IPV6) != true) {
        fprintf(stderr, "register_extraction_attribute(RADIUS_3GPP_DNS_IPV6) failed\n");
        mmt_close_handler(h);
        close_extraction();
        return 2;
    }

    printf("issue #331: radius.dns_ipv6 extracts the primary 3GPP IPv6 DNS server\n");

    run_case(h, 40001, 32, 0);
    CHECK(g_radius_seen, "two-server Accounting-Request is classified as RADIUS");
    CHECK(g_dns_seen && memcmp(g_dns, dns1, 16) == 0,
          "two-server sub-attribute extracts the first server 2001:db8::53");

    run_case(h, 40002, 16, 0);
    CHECK(g_dns_seen && memcmp(g_dns, dns1, 16) == 0,
          "one-server sub-attribute extracts that server");

    run_case(h, 40003, 15, 0);
    CHECK(g_radius_seen, "short sub-attribute frame is classified as RADIUS");
    CHECK(!g_dns_seen, "sub-attribute shorter than one address is not extracted");

    run_case(h, 40004, 16, 8);
    CHECK(g_radius_seen, "over-long VSA frame is classified as RADIUS");
    CHECK(!g_dns_seen, "VSA running past the capture is not extracted");

    mmt_close_handler(h);
    close_extraction();
    printf("  %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
