/*
 * session_timeout_jump_test — regression harness for issue #306
 * ("Fuzz-discovered hangs: mutated golden pcaps stall the classifier").
 *
 * Root cause: process_timedout_sessions() advanced the session-timeout
 * horizon one second at a time — get_timed_out_session_list() +
 * delete_timeout_milestone() per second across
 * [last_expiry_timeout, current_seconds). The pcap record timestamp is
 * attacker-controlled, so a single mutated packet jumping ~3e9 seconds
 * ahead made the expiry pass iterate billions of times (a CPU denial of
 * service; the mutation-fuzz gate timed out on five golden-pcap mutants).
 *
 * The fix expires the same milestone range through the timeout ring in a
 * pass bounded by O(min(gap, ring capacity)): per-second stepping when the
 * gap fits the ring, a single O(cap) sweep when it does not.
 *
 * This harness drives packets with hostile timestamp jumps through the real
 * packet path (mmt_init_handler + packet_process) and asserts:
 *   1. a ~3e9-second forward jump completes in well under a second;
 *   2. the sweep expires exactly the sessions whose milestone fell inside
 *      [last_expiry, current) — a session is never expired by its own
 *      packet (the sessionizer refreshes its milestone first), so a second
 *      "advancer" flow drives the horizon;
 *   3. small-gap stepping semantics are unchanged: a session is due only
 *      once a packet arrives strictly past its milestone;
 *   4. the sweep honours the [lo, hi) bound: a milestone >= hi survives;
 *   5. repeated huge jumps stay fast (the horizon always advances).
 *
 * Build (see run_session_timeout_jump_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all ...
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "tcpip/mmt_tcpip_protocols.h"
#include "tcpip/mmt_tcpip_attributes.h"

/* Internals — pulled from the source tree, not the installed include set. */
#include "packet_processing.h"          /* struct mmt_handler_struct        */
#include "internal_decls.h"             /* shared internal decls            */

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

/* A forward jump this size used to cost ~3e9 loop iterations (~30+ s). */
#define HUGE_JUMP_SEC 3000000000u
/* Wall-clock budget for one expiry pass over a huge gap. */
#define JUMP_BUDGET_SEC 5.0

static double now_monotonic(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

static int put_eth(uint8_t *b, uint16_t ethertype) {
    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(b, dst, 6);
    memcpy(b + 6, src, 6);
    put_be16(b + 12, ethertype);
    return 14;
}

/* Plain IPv4 header (ihl=5) + 8-byte UDP header — enough for the IP
 * sessionizer to build a live 5-tuple session. `sport` selects the flow:
 * packets on different sports are different sessions. */
static int put_udp4(uint8_t *b, uint16_t sport, uint16_t dport) {
    memset(b, 0, 20);
    b[0]  = (4 << 4) | 5;
    put_be16(b + 2, 28);            /* tot_len = 20 + 8 */
    put_be16(b + 4, 0x1234);
    b[8]  = 64;
    b[9]  = 17;                     /* UDP */
    put_be32(b + 12, 0x0a000001);
    put_be32(b + 16, 0x0a000002);
    put_be16(b + 20, sport);
    put_be16(b + 22, dport);
    put_be16(b + 24, 8);
    return 28;
}

static void run_packet_at(mmt_handler_t *h, const uint8_t *data, uint32_t caplen,
                          uint32_t tv_sec) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec  = tv_sec;
    hdr.ts.tv_usec = 0;
    hdr.caplen     = caplen;
    hdr.len        = caplen;
    packet_process(h, &hdr, data);
}

/* ====================================================================== */

int main(void) {
    char errbuf[1024];
    mmt_handler_t *h;
    /* flow A: the session under observation; flow B/C: horizon advancers */
    uint8_t pkt_a[64], pkt_b[64], pkt_c[64];
    int len_a, len_b, len_c;
    double t0, elapsed;

    alarm(120); /* hard stop: pre-fix runs need ~30 s per jump */

    len_a = put_eth(pkt_a, 0x0800) + put_udp4(pkt_a + 14, 4444, 80);
    len_b = put_eth(pkt_b, 0x0800) + put_udp4(pkt_b + 14, 5555, 80);
    len_c = put_eth(pkt_c, 0x0800) + put_udp4(pkt_c + 14, 6666, 80);

    init_extraction();
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }

    printf("issue #306: attacker-controlled pcap timestamp jumps must not\n");
    printf("stall the session-timeout expiry pass\n");

    /* ---------------------------------------------------------------
     * Case 1 — the pure DoS repro: a single +3e9 s forward jump. The old
     * loop iterated once per second of the gap regardless of ring
     * contents, so this alone burned ~30 s of CPU.
     */
    run_packet_at(h, pkt_a, len_a, 1);
    t0 = now_monotonic();
    run_packet_at(h, pkt_b, len_b, 1 + HUGE_JUMP_SEC);
    elapsed = now_monotonic() - t0;
    printf("       (+%us jump took %.3fs)\n", HUGE_JUMP_SEC, elapsed);
    CHECK(elapsed < JUMP_BUDGET_SEC,
          "+3e9s timestamp jump does not stall packet_process");
    /* The jump expired flow A (milestone 61) and created flow B. */
    CHECK(get_active_session_count(h) == 1,
          "huge jump expired the stale session (only advancer B remains)");
    /* The horizon advanced: a second huge jump is equally cheap. */
    t0 = now_monotonic();
    run_packet_at(h, pkt_c, len_c, 1 + 2u * HUGE_JUMP_SEC);
    elapsed = now_monotonic() - t0;
    printf("       (second +%us jump took %.3fs)\n", HUGE_JUMP_SEC, elapsed);
    CHECK(elapsed < JUMP_BUDGET_SEC,
          "repeated huge jumps stay bounded");

    /* ---------------------------------------------------------------
     * Case 2 — small-gap stepping semantics are unchanged (default
     * session timeout 60 s): flow A@milestone 1060 is due only once an
     * advancer packet arrives strictly past its milestone. Fresh handler:
     * the horizon is already ~6e9 on h.
     */
    {
        mmt_handler_t *h2 = mmt_init_handler(DLT_EN10MB, 0, errbuf);
        CHECK(h2 != NULL, "case 2: handler init");
        run_packet_at(h2, pkt_a, len_a, 1000);       /* A: milestone 1060 */
        CHECK(get_active_session_count(h2) == 1,
              "small gap: session live after creation");
        run_packet_at(h2, pkt_b, len_b, 1059);       /* step [1000,1059): A not due */
        CHECK(get_active_session_count(h2) == 2,
              "small gap: session not due before its milestone");
        run_packet_at(h2, pkt_b, len_b, 1060);       /* range [1059,1060): 1060 not due */
        CHECK(get_active_session_count(h2) == 2,
              "small gap: milestone == packet ts is not yet due");
        run_packet_at(h2, pkt_b, len_b, 1061);       /* range [1060,1061): A due */
        CHECK(get_active_session_count(h2) == 1,
              "small gap: session expired one second past its milestone");
        mmt_close_handler(h2);
    }

    mmt_close_handler(h);

    /* ---------------------------------------------------------------
     * Case 3 — the sweep honours [lo, hi): a milestone >= hi survives.
     * Default timeout set above the initial ring capacity (1024 s) so a
     * gap that triggers the sweep still leaves the milestone in the
     * future.
     */
    {
        mmt_handler_t *h4 = mmt_init_handler(DLT_EN10MB, 0, errbuf);
        CHECK(h4 != NULL, "case 3: handler init");
        CHECK(set_default_session_timed_out(h4, 2000) == 1,
              "case 3: default session timeout set to 2000 s");
        run_packet_at(h4, pkt_a, len_a, 5000);       /* A: milestone 7000 */
        /* gap 1500 > ring cap 1024 -> sweep [5000,6500); 7000 >= hi */
        t0 = now_monotonic();
        run_packet_at(h4, pkt_b, len_b, 6500);       /* B: milestone 8500 */
        elapsed = now_monotonic() - t0;
        printf("       (sweep-path +1500s jump took %.3fs)\n", elapsed);
        CHECK(elapsed < JUMP_BUDGET_SEC,
              "sweep path: gap > ring cap stays bounded");
        CHECK(get_active_session_count(h4) == 2,
              "sweep: milestone >= hi survives");
        /* B is refreshed by its own packet (milestone 11000); the sweep
         * [6500,9000) expires only A (7000). */
        run_packet_at(h4, pkt_b, len_b, 9000);
        CHECK(get_active_session_count(h4) == 1,
              "sweep: session expired once its milestone passed");
        mmt_close_handler(h4);
    }

    close_extraction();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
