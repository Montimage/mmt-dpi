/*
 * test_gre_deprecated_attrs_api.c — packet/API-path test for issue #455:
 * the GRE sequence-tracking attributes gre.seq_out, gre.seq_in, gre.seq_gap
 * and gre.loss are deprecated. They are never extracted, but their ids stay
 * reserved: the names still resolve to the same ids and registering them
 * still succeeds, so existing consumers keep working.
 *
 *   - the four ids resolve by name and register on a handler;
 *   - on a GRE frame carrying a key and a sequence number, gre.key and
 *     gre.seqnb extract while the four deprecated attributes stay absent;
 *   - a capture cut inside the sequence-number word extracts the key but
 *     not the sequence number, and reads nothing past caplen (ASan brackets
 *     the frame under SANITIZE=asan).
 *
 * Crafted Ethernet/IPv4/GRE/IPv4/UDP frames are fed through
 * mmt_init_handler + register_extraction_attribute + packet_process.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mmt_tcpip_attributes.h"      /* GRE_* attribute ids */

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

static const uint32_t deprecated_ids[] = {
    GRE_OUT_SEQENCE, GRE_IN_SEQENCE, GRE_SEQENCE_GAP, GRE_LOSS
};
static const char * const deprecated_names[] = {
    "seq_out", "seq_in", "seq_gap", "loss"
};
#define NB_DEPRECATED (sizeof(deprecated_ids) / sizeof(deprecated_ids[0]))

static int      g_gre_seen;
static int      g_key_seen, g_seq_seen, g_deprecated_seen;
static uint32_t g_key, g_seq;

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (ipacket->proto_hierarchy != NULL) {
        for (int i = 0; i < ipacket->proto_hierarchy->len; i++)
            if (ipacket->proto_hierarchy->proto_path[i] == PROTO_GRE)
                g_gre_seen = 1;
    }
    const uint32_t *k = get_attribute_extracted_data(ipacket, PROTO_GRE, GRE_KEY);
    if (k != NULL) { g_key_seen = 1; g_key = *k; }
    const uint32_t *s = get_attribute_extracted_data(ipacket, PROTO_GRE, GRE_SEQ_NB);
    if (s != NULL) { g_seq_seen = 1; g_seq = *s; }
    for (size_t i = 0; i < NB_DEPRECATED; i++)
        if (get_attribute_extracted_data(ipacket, PROTO_GRE, deprecated_ids[i]) != NULL)
            g_deprecated_seen = 1;
    return 0;
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    put_be16(p, (uint16_t)(v >> 16)); put_be16(p + 2, (uint16_t) v);
}

/* Eth(14) / IPv4(20, proto 47) / GRE K+S (12) / IPv4(20) / UDP(8) + 4 bytes. */
static int build(uint8_t *pkt, uint32_t seq) {
    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    const int inner_len = 20 + 8 + 4;
    const int gre_len = 12;
    memcpy(pkt, dst, 6); memcpy(pkt + 6, src, 6); put_be16(pkt + 12, 0x0800);

    uint8_t *ip = pkt + 14;
    memset(ip, 0, 20);
    ip[0] = 0x45; put_be16(ip + 2, (uint16_t)(20 + gre_len + inner_len));
    ip[8] = 64; ip[9] = 47;                          /* GRE */
    ip[12] = 10; ip[15] = 1; ip[16] = 10; ip[19] = 2;

    uint8_t *g = ip + 20;
    put_be16(g, 0x3000);                             /* K and S bits, version 0 */
    put_be16(g + 2, 0x0800);                         /* IPv4 inside */
    put_be32(g + 4, 0x01020304);                     /* key */
    put_be32(g + 8, seq);                            /* sequence number */

    uint8_t *in = g + gre_len;
    memset(in, 0, (size_t) inner_len);
    in[0] = 0x45; put_be16(in + 2, (uint16_t) inner_len);
    in[8] = 64; in[9] = 17;
    in[12] = 192; in[13] = 168; in[15] = 1;
    in[16] = 192; in[17] = 168; in[19] = 2;
    uint8_t *u = in + 20;
    put_be16(u, 40000); put_be16(u + 2, 40001); put_be16(u + 4, 8 + 4);
    return 14 + 20 + gre_len + inner_len;
}

/* Feeds the frame truncated to `caplen` bytes, as an exactly-sized heap copy. */
static void run_case(mmt_handler_t *h, uint32_t seq, int caplen, int sec) {
    static uint8_t frame[128];
    int len = build(frame, seq);
    if (caplen <= 0 || caplen > len) caplen = len;
    g_gre_seen = g_key_seen = g_seq_seen = g_deprecated_seen = 0;
    g_key = g_seq = 0;
    uint8_t *data = malloc((size_t) caplen);
    if (!data) { perror("malloc"); exit(2); }
    memcpy(data, frame, (size_t) caplen);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = sec;
    hdr.caplen = (unsigned) caplen;
    hdr.len = (unsigned) len;
    packet_process(h, &hdr, data);
    free(data);
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

    printf("issue #455: deprecated GRE sequence attributes stay reserved, never extracted\n");

    int resolved = 1, registered = 1;
    for (size_t i = 0; i < NB_DEPRECATED; i++) {
        if (get_attribute_id_by_protocol_id_and_attribute_name(PROTO_GRE, deprecated_names[i])
                != deprecated_ids[i])
            resolved = 0;
        if (register_extraction_attribute(h, PROTO_GRE, deprecated_ids[i]) != true)
            registered = 0;
    }
    CHECK(resolved, "gre.seq_out/seq_in/seq_gap/loss resolve to their reserved ids");
    CHECK(registered, "the deprecated ids still register on a handler");
    if (register_extraction_attribute(h, PROTO_GRE, GRE_KEY) != true
            || register_extraction_attribute(h, PROTO_GRE, GRE_SEQ_NB) != true) {
        fprintf(stderr, "register_extraction_attribute(GRE_KEY/GRE_SEQ_NB) failed\n");
        mmt_close_handler(h);
        close_extraction();
        return 2;
    }

    for (uint32_t seq = 7; seq < 10; seq++) {
        run_case(h, seq, 0, (int) seq);
        CHECK(g_gre_seen, "GRE frame is classified as GRE");
        CHECK(g_key_seen && g_key == 0x01020304, "gre.key extracts the key");
        CHECK(g_seq_seen && g_seq == seq, "gre.seqnb extracts the sequence number");
        CHECK(!g_deprecated_seen, "no deprecated GRE attribute is extracted");
    }

    /* Cut two bytes into the sequence-number word (14 + 20 + 8 + 2). */
    run_case(h, 11, 14 + 20 + 10, 20);
    CHECK(g_gre_seen, "truncated GRE frame is still parsed as GRE");
    CHECK(g_key_seen && g_key == 0x01020304, "truncated frame: key inside the capture extracts");
    CHECK(!g_seq_seen, "truncated frame: sequence number past caplen is not extracted");
    CHECK(!g_deprecated_seen, "truncated frame: no deprecated GRE attribute is extracted");

    mmt_close_handler(h);
    close_extraction();
    printf("  %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
