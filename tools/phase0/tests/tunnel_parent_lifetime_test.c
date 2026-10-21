/*
 * tunnel_parent_lifetime_test — regression harness for issue #499
 * (F-BUG-001, "Stop tunnel child sessions from outliving their parent").
 *
 * Root cause: an embedded (tunnel) session keeps a raw parent_session
 * pointer to the outer session (packet_session.c, setup_new_session) that
 * nothing reference-counted or cleared. Each session expires on its own
 * milestone, so when the inner flow has the longer timeout the outer
 * session expired and was freed first; the next tunnel packet created a new
 * outer session, found the still-live inner one and walked its dangling
 * parent pointer (the children-counter loop in proto_session_management) —
 * a heap use-after-free under ASan.
 *
 * The fix counts a parent's live children: a parent is never freed while it
 * has any (its expiry is deferred), a child's milestone is carried up to its
 * ancestors, and the teardown drain expires children before their parents.
 *
 * This harness drives GTP-U tunnelled UDP through the real packet path
 * (mmt_init_handler + packet_process, BUILD=asan SDK):
 *   1. the inner (child) session gets a 600 s delay, the outer one keeps
 *      the 30 s default — the outer session is due first;
 *   2. an unrelated flow advances the clock past the outer session's own
 *      milestone: it must stay live (nothing expires);
 *   3. the next tunnel packet must reuse it (no new outer session) — this is
 *      the packet that read freed memory before the fix;
 *   4. once both are due, and at teardown, every child expires before its
 *      parent, and a child's expiry handler can still read its parent.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"

typedef unsigned char u_char;

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

#define DEFAULT_TIMEOUT 30u
#define INNER_TIMEOUT   600u
#define MAX_EXPIRED     64

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

static int put_eth(uint8_t *b) {
    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(b, dst, 6);
    memcpy(b + 6, src, 6);
    put_be16(b + 12, 0x0800);
    return 14;
}

/* IPv4 (ihl=5) + UDP header; `payload` bytes follow the UDP header. */
static int put_ip_udp(uint8_t *b, uint32_t saddr, uint32_t daddr,
                      uint16_t sport, uint16_t dport, int payload) {
    memset(b, 0, 28);
    b[0] = (4 << 4) | 5;
    put_be16(b + 2, (uint16_t) (28 + payload));
    put_be16(b + 4, 0x1234);
    b[8] = 64;
    b[9] = 17;                      /* UDP */
    put_be32(b + 12, saddr);
    put_be32(b + 16, daddr);
    put_be16(b + 20, sport);
    put_be16(b + 22, dport);
    put_be16(b + 24, (uint16_t) (8 + payload));
    return 28;
}

/* ETH / IPv4 / UDP 2152 / GTP-U G-PDU / IPv4 / UDP / 8-byte payload */
static int build_tunnel_packet(uint8_t *b) {
    const int inner_payload = 8;
    const int inner_len = 28 + inner_payload;
    const int gtp_len = 8 + inner_len;
    int off = put_eth(b);
    off += put_ip_udp(b + off, 0x0a000001, 0x0a000002, 2152, 2152, gtp_len);
    b[off + 0] = 0x30;              /* version 1, PT=1, no E/S/PN */
    b[off + 1] = 0xff;              /* G-PDU */
    put_be16(b + off + 2, (uint16_t) inner_len);
    put_be32(b + off + 4, 0x00000042);
    off += 8;
    off += put_ip_udp(b + off, 0xc0a80001, 0xc0a80002, 40000, 5000, inner_payload);
    memset(b + off, 0x61, inner_payload);
    return off + inner_payload;
}

/* ETH / IPv4 / UDP — an unrelated flow that only advances the clock. */
static int build_advancer_packet(uint8_t *b) {
    int off = put_eth(b);
    off += put_ip_udp(b + off, 0x0a000003, 0x0a000004, 6666, 7777, 0);
    return off;
}

static void run_packet_at(mmt_handler_t *h, const uint8_t *data, int caplen, uint32_t tv_sec) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = tv_sec;
    hdr.caplen    = (unsigned) caplen;
    hdr.len       = (unsigned) caplen;
    packet_process(h, &hdr, data);
}

/* --- observers --------------------------------------------------------- */

static uint64_t g_outer_id, g_inner_id;   /* ids of the tunnel sessions */
static uint64_t g_expired[MAX_EXPIRED];
static int g_nexpired;
static int g_child_after_parent;          /* a child expired after its parent */

static int expired_already(uint64_t id) {
    for (int i = 0; i < g_nexpired; i++)
        if (g_expired[i] == id) return 1;
    return 0;
}

/* The packet handler gives the inner session the longer delay once. */
static int on_packet(const ipacket_t *ipacket, void *args) {
    (void) args;
    mmt_session_t *s = get_session_from_packet(ipacket);
    if (s == NULL) return 0;
    mmt_session_t *parent = get_session_parent(s);
    if (parent != NULL && g_inner_id == 0) {
        g_inner_id = get_session_id(s);
        g_outer_id = get_session_id(parent);
        set_session_timeout_delay(s, INNER_TIMEOUT);
    }
    return 0;
}

static void on_expiry(const mmt_session_t *expired, void *args) {
    (void) args;
    mmt_session_t *parent = get_session_parent(expired);
    if (parent != NULL) {
        /* Reads through the parent pointer: a freed parent is an ASan
         * heap-use-after-free here. */
        if (expired_already(get_session_id(parent))) g_child_after_parent++;
    }
    if (g_nexpired < MAX_EXPIRED)
        g_expired[g_nexpired++] = get_session_id(expired);
}

/* ====================================================================== */

int main(void) {
    char errbuf[1024];
    uint8_t tun[128], adv[64];
    int tun_len = build_tunnel_packet(tun);
    int adv_len = build_advancer_packet(adv);

    alarm(120);
    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    set_default_session_timed_out(h, DEFAULT_TIMEOUT);
    register_packet_handler(h, 1, on_packet, NULL);
    register_session_timeout_handler(h, on_expiry, NULL);

    printf("issue #499: a tunnel parent session must not expire before its child\n");

    run_packet_at(h, tun, tun_len, 1000);
    CHECK(g_inner_id != 0 && g_outer_id != 0, "the GTP-U packet created an inner session under the outer one");
    run_packet_at(h, tun, tun_len, 1001);   /* inner milestone -> 1601 */
    uint64_t live = get_active_session_count(h);
    CHECK(live == 2, "outer and inner sessions are live");

    /* Past the outer session's own milestone (1031): before the fix it
     * expired here, leaving the inner session's parent pointer dangling. */
    run_packet_at(h, adv, adv_len, 1100);
    CHECK(g_nexpired == 0, "the outer session outlives its own timeout while its child lives");
    CHECK(get_active_session_count(h) == live + 1, "no session expired (advancer added)");

    /* The packet that walked the freed parent before the fix. */
    run_packet_at(h, tun, tun_len, 1101);
    CHECK(get_active_session_count(h) == live + 1, "the tunnel packet reused the live outer session");

    /* Both tunnel sessions due (milestone 1701): the inner one goes first,
     * the outer one is deferred until its child is gone. */
    run_packet_at(h, adv, adv_len, 1702);
    run_packet_at(h, adv, adv_len, 1703);
    CHECK(expired_already(g_inner_id) && expired_already(g_outer_id), "both tunnel sessions expired once due");
    CHECK(g_child_after_parent == 0, "the inner session expired before the outer one");

    /* Teardown with a live tunnel: the close drain also goes child-first. */
    g_inner_id = g_outer_id = 0;
    run_packet_at(h, tun, tun_len, 2000);
    CHECK(g_inner_id != 0, "a second tunnel is live at teardown");
    uint64_t inner2 = g_inner_id, outer2 = g_outer_id;
    mmt_close_handler(h);
    CHECK(expired_already(inner2) && expired_already(outer2), "teardown expired both tunnel sessions");
    CHECK(g_child_after_parent == 0, "teardown expired every child before its parent");
    close_extraction();

    printf("%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}
