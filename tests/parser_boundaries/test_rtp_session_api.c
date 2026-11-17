/*
 * test_rtp_session_api.c — packet/API-path test for issue #101: the RTP
 * session data of a UDP flow is created once and kept across its packets.
 *
 * The core calls the RTP session_data_init hook on every packet whose path
 * reports the RTP layer as an update. It used to allocate a fresh block each
 * time, so the order, loss and jitter analysis restarted on each such packet
 * (those attributes stayed 0 whatever the flow did) and the previous block
 * leaked: 36 blocks on this flow before the fix, LeakSanitizer measured.
 *
 * One client→server flow, built from the first packet of the accuracy-corpus
 * capture acc_rtp_positive.pcap (PCMU, 8 kHz, ts = seq * 160):
 *   1. seq 1000..1019, 20 ms apart: in order, no loss, no jitter;
 *   2. seq 1021 — 1020 is missing: the packet is reported out of order, and
 *      once the 8-slot window (rtp.h MMT_Window_Width) slides past the hole
 *      the loss is reported;
 *   3. arrivals alternately 10 ms and 30 ms apart for 20 ms of media each:
 *      the RFC 3550 jitter (rtp.jitter) becomes non-zero — rtp.inter_jitter
 *      is not used: it is non-zero on an evenly paced flow too;
 *   4. RTP_SESSION_LONG_FLOW more in-order packets: a long capture, so a run
 *      with ASAN_OPTIONS=detect_leaks=1 (run_tests.sh under SANITIZE=asan)
 *      reports any RTP session block that is not freed with the session.
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
        if (!(cond)) {                                               \
            printf("  FAIL: ");                                      \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
            g_failures++;                                            \
        }                                                            \
    } while (0)

#define RTP_SESSION_LONG_FLOW 2000

/* What the packets of the current phase reported. */
static unsigned g_rtp_pkts;
static unsigned g_unorder_pkts;  /* packets reporting rtp.unorder != 0 */
static unsigned g_loss_pkts;     /* packets reporting rtp.loss != 0 */
static unsigned g_jitter_pkts;   /* packets reporting a non-zero rtp.jitter */

static void reset_counts(void) {
    g_rtp_pkts = g_unorder_pkts = g_loss_pkts = g_jitter_pkts = 0;
}

static int pkt_cb(const ipacket_t *ipacket, mmt_opaque_t user) {
    (void) user;
    if (get_protocol_index_by_id(ipacket, PROTO_RTP) == MMT_NO_PROTO_INDEX) return 0;
    uint16_t *seq = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_SEQNB);
    if (seq == NULL) return 0;
    g_rtp_pkts++;
    uint16_t *unorder = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_UNORDER);
    uint16_t *loss = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_LOSS);
    uint32_t *jitter = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_JITTER);
    if (unorder != NULL && *unorder != 0) g_unorder_pkts++;
    if (loss != NULL && *loss != 0) g_loss_pkts++;
    if (jitter != NULL && *jitter != 0) g_jitter_pkts++;
    return 0;
}

static const char *accuracy_dir(void) {
    static char dir[4096];
    const char *env = getenv("MMT_ACCURACY_DIR");
    if (env != NULL && env[0] != '\0') return env;
    /* __FILE__ = <repo>/tests/parser_boundaries/test_rtp_session_api.c */
    snprintf(dir, sizeof dir, "%s", __FILE__);
    for (int up = 0; up < 3; up++) {
        char *slash = strrchr(dir, '/');
        if (slash == NULL) return NULL;
        *slash = '\0';
    }
    strncat(dir, "/tools/phase0/ci/accuracy", sizeof(dir) - strlen(dir) - 1);
    return dir;
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

static uint8_t g_tmpl[256];          /* the template client frame */
static unsigned g_tmpl_len, g_rtp_off;
static struct timeval g_ts;

/* One client packet of `seq`, `gap_us` after the previous one. */
static void send_rtp(mmt_handler_t *h, uint16_t seq, unsigned gap_us) {
    uint8_t *data = malloc(g_tmpl_len);     /* exact size: ASan brackets it */
    if (data == NULL) { perror("malloc"); exit(2); }
    memcpy(data, g_tmpl, g_tmpl_len);
    put_be16(data + g_rtp_off + 2, seq);
    put_be32(data + g_rtp_off + 4, (uint32_t) seq * 160u);
    g_ts.tv_usec += gap_us;
    while (g_ts.tv_usec >= 1000000) { g_ts.tv_sec++; g_ts.tv_usec -= 1000000; }
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.ts = g_ts;
    hdr.caplen = g_tmpl_len;
    hdr.len = g_tmpl_len;
    packet_process(h, &hdr, data);
    free(data);
}

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE > 1024 ? PCAP_ERRBUF_SIZE : 1024], path[4096 + 64];
    const char *dir = accuracy_dir();
    if (dir == NULL) {
        fprintf(stderr, "cannot locate the accuracy corpus (set MMT_ACCURACY_DIR)\n");
        return 2;
    }
    snprintf(path, sizeof path, "%s/acc_rtp_positive.pcap", dir);
    pcap_t *pc = pcap_open_offline(path, errbuf);
    if (pc == NULL) {
        fprintf(stderr, "cannot open %s: %s\n", path, errbuf);
        return 2;
    }
    struct pcap_pkthdr ph;
    const u_char *first = pcap_next(pc, &ph);
    int linktype = pcap_datalink(pc);
    if (first == NULL || ph.caplen > sizeof g_tmpl || ph.caplen < 14 + 20 + 8 + 12
            || first[23] != 17 /* UDP */) {
        fprintf(stderr, "%s: unexpected first packet\n", path);
        pcap_close(pc);
        return 2;
    }
    memcpy(g_tmpl, first, ph.caplen);
    g_tmpl_len = ph.caplen;
    g_rtp_off = 14 + (g_tmpl[14] & 15) * 4 + 8;
    g_ts = ph.ts;
    pcap_close(pc);
    if (g_tmpl_len <= g_rtp_off + 12 || g_tmpl[g_rtp_off] != 0x80) {
        fprintf(stderr, "%s: the first packet is no RTP version 2 packet\n", path);
        return 2;
    }

    init_extraction();
    mmt_handler_t *h = mmt_init_handler(linktype, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    static const uint32_t attrs[] = { RTP_SEQNB, RTP_UNORDER, RTP_LOSS, RTP_JITTER };
    for (size_t i = 0; i < sizeof attrs / sizeof attrs[0]; i++)
        CHECK(register_extraction_attribute(h, PROTO_RTP, attrs[i]), "register rtp attribute %u",
              (unsigned) attrs[i]);
    CHECK(register_packet_handler(h, 1, pkt_cb, NULL), "register packet handler");

    printf("issue #101: RTP session data kept across the packets of a UDP flow\n");

    printf("phase 1: seq 1000..1019 in order, 20 ms apart\n");
    reset_counts();
    for (uint16_t s = 1000; s < 1020; s++) send_rtp(h, s, 20000);
    CHECK(g_rtp_pkts >= 10, "only %u of 20 packets classified as RTP", g_rtp_pkts);
    CHECK(g_unorder_pkts == 0, "%u in-order packet(s) reported out of order", g_unorder_pkts);
    CHECK(g_loss_pkts == 0, "%u packet(s) reported a loss on a gap-free flow", g_loss_pkts);
    CHECK(g_jitter_pkts == 0, "%u packet(s) reported jitter on an evenly paced flow", g_jitter_pkts);

    printf("phase 2: seq 1020 missing, then 1021..1031\n");
    reset_counts();
    send_rtp(h, 1021, 40000);
    CHECK(g_unorder_pkts == 1, "the packet after the hole was not reported out of order "
          "(%u of %u)", g_unorder_pkts, g_rtp_pkts);
    for (uint16_t s = 1022; s < 1032; s++) send_rtp(h, s, 20000);
    CHECK(g_loss_pkts >= 1, "the missing seq 1020 was never reported lost (%u packets)",
          g_rtp_pkts);

    printf("phase 3: arrivals 10 ms / 30 ms apart for 20 ms of media\n");
    reset_counts();
    for (uint16_t s = 1032; s < 1052; s++) send_rtp(h, s, (s & 1) ? 30000 : 10000);
    CHECK(g_jitter_pkts >= 1, "no packet reported jitter on an unevenly paced flow "
          "(%u packets)", g_rtp_pkts);

    printf("phase 4: %u more in-order packets (leak check under detect_leaks=1)\n",
           RTP_SESSION_LONG_FLOW);
    reset_counts();
    for (unsigned i = 0; i < RTP_SESSION_LONG_FLOW; i++) send_rtp(h, (uint16_t) (1052 + i), 20000);
    CHECK(g_rtp_pkts == RTP_SESSION_LONG_FLOW, "%u of %u packets classified as RTP",
          g_rtp_pkts, RTP_SESSION_LONG_FLOW);

    mmt_close_handler(h);
    close_extraction();
    printf("  %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
