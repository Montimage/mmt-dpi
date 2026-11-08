/*
 * test_gtp_session_counts_api.c — per-direction session counters of a GTP-U
 * tunnel (Montimage/mmt-dpi#17).
 *
 * A tunnelled flow can ride two outer flows: in the issue's capture the
 * uplink G-PDU travels 10.128.1.220:57672 -> 10.128.1.230:2152 and the
 * downlink one 10.128.1.230:2152 -> 10.128.1.220:2152, two outer UDP
 * sessions carrying one inner ICMP session. The inner session credited its
 * sub_* counters to the outer session it was created under, so the second
 * packet was subtracted from an outer session that never counted it:
 * get_session_ul_packet_count() returned 1 - 2 = 2^64 - 1.
 *
 * Asserted, through packet_process() and the session-expiry callback that
 * mmt_close_handler() fires for every session:
 *   - no session's own (non-tunnelled) counter exceeds its total counter in
 *     either direction, packets or bytes — the wrap shows up as a huge value;
 *   - an outer GTP session that only carried G-PDUs owns 0 packets and bytes;
 *   - the inner ICMP session counts one packet each way.
 * Both shapes run: the issue's two outer flows, and one outer flow used in
 * both directions (the path that already worked).
 *
 * Exit status: 0 = all checks pass, 1 = a check failed, 2 = setup failed.
 */
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define ETH_HDR_LEN 14
#define MAX_SESSIONS 8

struct seen {
    int inner;                 /* has a tunnel parent */
    uint64_t own[2][2];        /* [ul,dl][packets,bytes] after subtraction */
    uint64_t total[2][2];      /* [ul,dl][packets,bytes] */
};

static struct seen g_seen[MAX_SESSIONS];
static int g_nseen;
static int g_failures;

static void put_be16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char) ((v >> 8) & 0xff);
    p[1] = (unsigned char) (v & 0xff);
}

static void on_expiry(const mmt_session_t *s, void *user) {
    struct seen *e;
    (void) user;
    if (g_nseen >= MAX_SESSIONS)
        return;
    e = &g_seen[g_nseen++];
    e->inner = get_session_parent(s) != NULL;
    e->own[0][0] = get_session_ul_packet_count(s);
    e->own[1][0] = get_session_dl_packet_count(s);
    e->own[0][1] = get_session_ul_byte_count(s);
    e->own[1][1] = get_session_dl_byte_count(s);
    e->total[0][0] = get_session_total_ul_packet_count(s);
    e->total[1][0] = get_session_total_dl_packet_count(s);
    e->total[0][1] = get_session_total_ul_byte_count(s);
    e->total[1][1] = get_session_total_dl_byte_count(s);
}

static void ip4(unsigned char *p, const unsigned char a[4]) { memcpy(p, a, 4); }

/*
 * Ethernet / IPv4 / UDP sport->2152 dport / GTPv1-U G-PDU / IPv4 / ICMP echo.
 * `reply` selects echo reply (inner addresses swapped) over echo request.
 */
static int build_frame(unsigned char *buf, const unsigned char osrc[4],
                       const unsigned char odst[4], unsigned sport,
                       unsigned dport, int reply) {
    static const unsigned char ue[4] = {10, 45, 0, 2};
    static const unsigned char dn[4] = {10, 45, 0, 1};
    const int icmp_len = 8 + 32;
    const int inner_len = 20 + icmp_len;
    int o = 0;

    memset(buf, 0, ETH_HDR_LEN);
    buf[5] = 0x01; buf[11] = 0x02;
    put_be16(buf + 12, 0x0800);
    o = ETH_HDR_LEN;

    memset(buf + o, 0, 20);                         /* outer IPv4 */
    buf[o] = 0x45;
    put_be16(buf + o + 2, (unsigned) (20 + 8 + 8 + inner_len));
    buf[o + 8] = 64;
    buf[o + 9] = 17;
    ip4(buf + o + 12, osrc);
    ip4(buf + o + 16, odst);
    o += 20;

    put_be16(buf + o, sport);                       /* UDP */
    put_be16(buf + o + 2, dport);
    put_be16(buf + o + 4, (unsigned) (8 + 8 + inner_len));
    put_be16(buf + o + 6, 0);
    o += 8;

    buf[o] = 0x30;                                  /* GTPv1, PT=1 */
    buf[o + 1] = 0xff;                              /* G-PDU */
    put_be16(buf + o + 2, (unsigned) inner_len);
    buf[o + 4] = 0; buf[o + 5] = 0; buf[o + 6] = 0;
    buf[o + 7] = reply ? 0x02 : 0x01;               /* TEID */
    o += 8;

    memset(buf + o, 0, 20);                         /* inner IPv4 */
    buf[o] = 0x45;
    put_be16(buf + o + 2, (unsigned) inner_len);
    buf[o + 8] = 64;
    buf[o + 9] = 1;                                 /* ICMP */
    ip4(buf + o + 12, reply ? dn : ue);
    ip4(buf + o + 16, reply ? ue : dn);
    o += 20;

    memset(buf + o, 0x5a, (size_t) icmp_len);       /* ICMP echo */
    buf[o] = reply ? 0 : 8;
    buf[o + 1] = 0;
    put_be16(buf + o + 2, 0);
    put_be16(buf + o + 4, 0x1234);                  /* identifier */
    put_be16(buf + o + 6, 1);                       /* sequence */
    o += icmp_len;
    return o;
}

static void push(mmt_handler_t *h, const unsigned char *buf, int n, int usec) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = 1742474435;
    hdr.ts.tv_usec = usec;
    hdr.len = (unsigned) n;
    hdr.caplen = (unsigned) n;
    packet_process(h, &hdr, buf);
}

static void check(const char *label, int ok) {
    printf("  %-72s [%s]\n", label, ok ? "PASS" : "FAIL");
    if (!ok)
        g_failures++;
}

static void run_case(const char *name, unsigned reply_sport) {
    static const unsigned char enb[4] = {10, 128, 1, 220};
    static const unsigned char upf[4] = {10, 128, 1, 230};
    unsigned char buf[256];
    char errbuf[1024];
    char label[160];
    mmt_handler_t *h;
    int i, d, k, n, outer = 0, inner = 0;

    printf("== %s ==\n", name);
    g_nseen = 0;
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "FAIL: mmt_init_handler: %s\n", errbuf);
        g_failures++;
        return;
    }
    if (!register_session_timeout_handler(h, on_expiry, NULL)) {
        fprintf(stderr, "FAIL: register_session_timeout_handler\n");
        g_failures++;
        mmt_close_handler(h);
        return;
    }
    /* Uplink: eNB:57672 -> UPF:2152; downlink: UPF:2152 -> eNB:reply_sport. */
    n = build_frame(buf, enb, upf, 57672, 2152, 0);
    push(h, buf, n, 277175);
    n = build_frame(buf, upf, enb, 2152, reply_sport, 1);
    push(h, buf, n, 288435);
    mmt_close_handler(h);           /* expires every session */

    for (i = 0; i < g_nseen; i++) {
        const struct seen *e = &g_seen[i];
        int bounded = 1;
        for (d = 0; d < 2; d++)
            for (k = 0; k < 2; k++)
                if (e->own[d][k] > e->total[d][k])
                    bounded = 0;
        snprintf(label, sizeof(label),
                 "%s session %d: own <= total (ul %" PRIu64 "/%" PRIu64 " pkts, dl %" PRIu64 "/%" PRIu64 ")",
                 e->inner ? "inner" : "outer", i,
                 e->own[0][0], e->total[0][0], e->own[1][0], e->total[1][0]);
        check(label, bounded);
        if (e->inner) {
            inner++;
            check("  inner ICMP session counts one packet each way",
                  e->own[0][0] + e->own[1][0] == 2 && e->own[0][0] == 1);
        } else {
            outer++;
            check("  outer GTP session owns no packet or byte (all were G-PDUs)",
                  e->own[0][0] == 0 && e->own[1][0] == 0
                  && e->own[0][1] == 0 && e->own[1][1] == 0);
        }
    }
    snprintf(label, sizeof(label), "sessions seen: %d outer, %d inner (want %d outer, 1 inner)",
             outer, inner, reply_sport == 57672 ? 1 : 2);
    check(label, inner == 1 && outer == (reply_sport == 57672 ? 1 : 2));
}

int main(void) {
    init_extraction();
    run_case("uplink and downlink on two outer flows (Montimage/mmt-dpi#17)", 2152);
    run_case("uplink and downlink on one outer flow", 57672);
    close_extraction();

    if (g_failures) {
        printf("\n✗ %d check(s) failed\n", g_failures);
        return 1;
    }
    printf("\n✓ all checks passed\n");
    return 0;
}
