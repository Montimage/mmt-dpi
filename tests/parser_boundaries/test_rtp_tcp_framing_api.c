/*
 * test_rtp_tcp_framing_api.c — packet/API-path test for issue #92: the RTP
 * layer of an RFC 4571-framed RTP-over-TCP flow (stun.rtp, ICE-TCP media).
 *
 * mmt_check_rtp_tcp accepts RTP behind the RFC 4571 2-byte length prefix,
 * so the RTP header starts 2 bytes into each segment. The RTP layer used to
 * be placed at payload offset 0 (stacked application ids share the payload,
 * proto_tcp.c), so rtp.seqnb/timestamp/ssrc and the session analysis read
 * the prefix as the header, and the analysis read the 12-byte fixed header
 * with no captured-length check.
 *
 * Case 1 replays acc_rtp_tcp_keepalive_positive.pcap (accuracy corpus): an
 * ICE connectivity check, nine framed RTP packets (seq 100..108, ts seq*160,
 * SSRC 0x5A5A0001) and a STUN keep-alive in the middle. Every RTP version-2
 * packet must report those values, and the session analysis must report no
 * loss or misordering (the keep-alive is no RTP packet).
 *
 * Case 2 appends segments that end inside the RTP header — 5 bytes, 11
 * bytes, and a 12-byte fixed header whose CSRC count or extension header
 * declare more than the segment holds — each in an exact-size buffer, so
 * BUILD=asan (SANITIZE=asan) reports any over-read of the session analysis,
 * which must skip them; a full packet then still reports its fields.
 *
 * Case 3 (issue #101) continues the flow with seq 110, then 112..121: the
 * session analysis must keep its state across the segments — 112 is reported
 * out of order and, once the 8-slot window slides past it, 111 is reported
 * lost. The session data used to be re-created on every packet, so both
 * stayed 0 whatever the flow did.
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

#define SSRC 0x5A5A0001u

static unsigned g_rtp_pkts;     /* packets whose path holds RTP, version 2 */
static unsigned g_bad_fields;
static unsigned g_seq_mask;     /* bit (seq - 100) per reported sequence number */
static unsigned g_loss_pkts;    /* packets reporting rtp.loss != 0 */
static unsigned g_unorder_pkts; /* packets reporting rtp.unorder != 0 */
static int g_case2;            /* case 2: out-of-range sequence numbers are expected */
static int g_seq109;           /* the full packet after the short segments */
static int g_case3;            /* case 3: seq 110..121 */
static unsigned g_case3_pkts;

static int pkt_cb(const ipacket_t *ipacket, mmt_opaque_t user) {
    (void) user;
    if (get_protocol_index_by_id(ipacket, PROTO_RTP) == MMT_NO_PROTO_INDEX) return 0;
    uint8_t *ver = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_VERSION);
    if (ver == NULL || *ver != 2) return 0;   /* the STUN keep-alive */
    uint16_t *seq = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_SEQNB);
    uint32_t *ts = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_TIMESTAMP);
    uint32_t *ssrc = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_SSRC);
    uint16_t *loss = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_LOSS);
    uint16_t *unorder = get_attribute_extracted_data(ipacket, PROTO_RTP, RTP_UNORDER);
    if (seq == NULL || ts == NULL || ssrc == NULL) return 0;  /* truncated: fields absent */
    if (loss != NULL && *loss != 0) g_loss_pkts++;
    if (unorder != NULL && *unorder != 0) g_unorder_pkts++;
    if (g_case3) {
        if (*seq >= 110 && *seq <= 121) g_case3_pkts++;
        return 0;
    }
    if (g_case2) {
        if (*seq == 109 && *ts == 109u * 160u && *ssrc == SSRC) g_seq109 = 1;
        return 0;
    }
    if (*seq < 100 || *seq > 108) {
        g_bad_fields++;
        return 0;
    }
    g_rtp_pkts++;
    g_seq_mask |= 1u << (*seq - 100);
    if (*ts != (uint32_t) *seq * 160u || *ssrc != SSRC) g_bad_fields++;
    return 0;
}

static const char *accuracy_dir(void) {
    static char dir[4096];
    const char *env = getenv("MMT_ACCURACY_DIR");
    if (env != NULL && env[0] != '\0') return env;
    /* __FILE__ = <repo>/tests/parser_boundaries/test_rtp_tcp_framing_api.c */
    snprintf(dir, sizeof dir, "%s", __FILE__);
    for (int up = 0; up < 3; up++) {
        char *slash = strrchr(dir, '/');
        if (slash == NULL) return NULL;
        *slash = '\0';
    }
    strncat(dir, "/tools/phase0/ci/accuracy", sizeof(dir) - strlen(dir) - 1);
    return dir;
}

static void feed(mmt_handler_t *h, const uint8_t *frame, unsigned len, struct timeval ts) {
    uint8_t *data = malloc(len);            /* exact size: ASan brackets it */
    if (data == NULL) { perror("malloc"); exit(2); }
    memcpy(data, frame, len);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.ts = ts;
    hdr.caplen = len;
    hdr.len = len;
    packet_process(h, &hdr, data);
    free(data);
}

static uint32_t be32(const uint8_t *p) {
    return (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 | (uint32_t) p[2] << 8 | p[3];
}
static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

static uint8_t g_tmpl[256];             /* last full client RTP frame */
static unsigned g_tmpl_len, g_tmpl_l4;  /* frame length, TCP payload offset */
static uint32_t g_next_seq;             /* client TCP sequence number */
static struct timeval g_ts;

/* A client segment from the template with an RTP header of `seq`, cut to
 * `rtp_bytes` bytes after the 2-byte prefix; `b0` replaces RTP octet 0. */
static void send_rtp(mmt_handler_t *h, uint16_t seq, unsigned rtp_bytes, uint8_t b0) {
    uint8_t frame[256];
    unsigned len = g_tmpl_l4 + 2 + rtp_bytes;
    memcpy(frame, g_tmpl, len);
    uint8_t *rtp = frame + g_tmpl_l4 + 2;
    rtp[0] = b0;
    put_be16(rtp + 2, seq);
    if (rtp_bytes >= 8) put_be32(rtp + 4, (uint32_t) seq * 160u);
    put_be16(frame + 14 + 2, (uint16_t) (len - 14));          /* IPv4 total length */
    put_be32(frame + 14 + (frame[14] & 15) * 4 + 4, g_next_seq);
    g_next_seq += 2 + rtp_bytes;
    g_ts.tv_usec += 20000;
    if (g_ts.tv_usec >= 1000000) { g_ts.tv_sec++; g_ts.tv_usec -= 1000000; }
    feed(h, frame, len, g_ts);
}

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE > 1024 ? PCAP_ERRBUF_SIZE : 1024], path[4096 + 64];
    const char *dir = accuracy_dir();
    if (dir == NULL) {
        fprintf(stderr, "cannot locate the accuracy corpus (set MMT_ACCURACY_DIR)\n");
        return 2;
    }
    snprintf(path, sizeof path, "%s/acc_rtp_tcp_keepalive_positive.pcap", dir);
    pcap_t *pc = pcap_open_offline(path, errbuf);
    if (pc == NULL) {
        fprintf(stderr, "cannot open %s: %s\n", path, errbuf);
        return 2;
    }

    init_extraction();
    mmt_handler_t *h = mmt_init_handler(pcap_datalink(pc), 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        pcap_close(pc);
        close_extraction();
        return 2;
    }
    static const uint32_t attrs[] = { RTP_VERSION, RTP_SEQNB, RTP_TIMESTAMP, RTP_SSRC, RTP_LOSS, RTP_UNORDER };
    for (size_t i = 0; i < sizeof attrs / sizeof attrs[0]; i++)
        CHECK(register_extraction_attribute(h, PROTO_RTP, attrs[i]), "register rtp attribute %u",
              (unsigned) attrs[i]);
    CHECK(register_packet_handler(h, 1, pkt_cb, NULL), "register packet handler");

    printf("issue #92: RFC 4571-framed RTP over TCP (stun.rtp)\n");
    printf("case 1: acc_rtp_tcp_keepalive_positive.pcap\n");
    struct pcap_pkthdr ph;
    const u_char *data;
    while ((data = pcap_next(pc, &ph)) != NULL) {
        g_ts = ph.ts;
        feed(h, data, ph.caplen, ph.ts);
        unsigned l4 = 14 + (data[14] & 15) * 4;
        l4 += (data[l4 + 12] >> 4) * 4;
        /* a full framed RTP frame from the client (port 49709) */
        if (ph.caplen > l4 + 14 && ph.caplen <= sizeof g_tmpl && data[l4 + 2] == 0x80
                && data[14 + (data[14] & 15) * 4] == 0xc2) {
            memcpy(g_tmpl, data, ph.caplen);
            g_tmpl_len = ph.caplen;
            g_tmpl_l4 = l4;
            g_next_seq = be32(data + 14 + (data[14] & 15) * 4 + 4) + (ph.caplen - l4);
        }
    }
    pcap_close(pc);

    CHECK(g_bad_fields == 0, "%u RTP packet(s) reported a wrong seqnb/timestamp/ssrc "
          "(the RTP layer must start after the RFC 4571 prefix)", g_bad_fields);
    CHECK(g_rtp_pkts >= 3, "only %u RTP packet(s) reported seq 100..108", g_rtp_pkts);
    CHECK((g_seq_mask & 0x1c0u) == 0x1c0u, "seq 106..108 (after the keep-alive) not all reported "
          "(mask 0x%x)", g_seq_mask);
    CHECK(g_loss_pkts == 0, "%u RTP packet(s) reported a loss on a gap-free flow", g_loss_pkts);
    CHECK(g_unorder_pkts == 0, "%u RTP packet(s) reported out of order on an in-order flow",
          g_unorder_pkts);
    CHECK(g_tmpl_len != 0, "no client RTP frame to build case 2 from");

    if (g_tmpl_len != 0) {
        printf("case 2: segments ending inside the RTP header\n");
        g_case2 = 1;
        send_rtp(h, 500, 5, 0x80);              /* ends in the timestamp */
        send_rtp(h, 600, 11, 0x80);             /* fixed header 1 byte short */
        send_rtp(h, 700, 20, 0x80 | 0x10 | 0x0f); /* 15 CSRCs + extension declared, 20 bytes */
        send_rtp(h, 800, 16, 0x80 | 0x10);      /* extension of 0x7f7f words (payload fill) */
        send_rtp(h, 109, 172, 0x80);            /* the next full packet */
        CHECK(g_seq109, "the full packet after the short segments did not report "
              "seq 109 / ts 17440 / ssrc 0x%08x", SSRC);

        printf("case 3: seq 110, then 112..121 (111 missing)\n");
        g_case3 = 1;
        g_loss_pkts = g_unorder_pkts = 0;
        send_rtp(h, 110, 172, 0x80);
        CHECK(g_unorder_pkts == 0, "seq 110 (in order after 109) reported out of order");
        send_rtp(h, 112, 172, 0x80);
        CHECK(g_unorder_pkts == 1, "seq 112 (after the hole) not reported out of order — "
              "the session analysis restarted (issue #101)");
        for (uint16_t s = 113; s <= 121; s++) send_rtp(h, s, 172, 0x80);
        CHECK(g_case3_pkts == 11, "%u of 11 case-3 packets reported their fields", g_case3_pkts);
        CHECK(g_loss_pkts >= 1, "the missing seq 111 was never reported lost — "
              "the session analysis restarted (issue #101)");
    }

    mmt_close_handler(h);
    close_extraction();
    printf("  %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
