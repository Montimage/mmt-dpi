/**
 * classified_flow_fastpath_test — issue #252 (F-PERF-002) regression harness.
 *
 * Asserts the acceptance criterion directly: an already-classified TCP flow
 * invokes ZERO classifier checkers per packet on its own classification
 * chain (IP -> TCP/UDP -> app). The chain walk is replaced by an O(1)
 * dispatch to the session's recorded owning protocol engine (the winning
 * checker keeps its per-packet role — stage machines, SNI/hostname service
 * detection); those direct dispatches are counted separately and reported
 * for transparency. The link-layer protocols (META, ETH) have no session
 * context — they run their single checker per packet to identify the L3
 * protocol at all; those calls are reported but are not part of the flow's
 * classification chain.
 *
 * How it works:
 *   1. Replays a pcap through a real mmt_handler (packet_process per record),
 *      exactly like tcpip_pcap_harness.
 *   2. Around every packet_process() it snapshots the debug-build counters
 *      exported by packet_pipeline.c (armed under BUILD=asan / NDEBUG=1 /
 *      non-NDEBUG builds): total checker calls and calls per chain-owner
 *      protocol (IP, TCP, UDP).
 *   3. In the packet handler it records each packet's session id (public
 *      get_session_id_from_packet) and whether the L4->app transition had
 *      already converged (proto_path[4] set to a non-UNKNOWN protocol).
 *   4. Post-pass: for every packet whose session was already classified at
 *      the previous observation, the IP/TCP/UDP checker deltas MUST be 0.
 *      Any non-zero delta is an F-PERF-002 regression.
 *
 * The counters are declared __attribute__((weak)) so the binary still links
 * against an SDK that predates them; a missing symbol fails the test loudly
 * instead of passing vacuously.
 *
 * Usage: classified_flow_fastpath_test <file.pcap>
 * Exit 0 = PASS. Prints a summary line plus one FAIL line per violation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

/* Debug-build classifier counters exported by packet_pipeline.c (issue #252).
 * Weak so the binary links against an SDK that predates them; a NULL symbol
 * is a hard FAIL below — a vacuous pass is worse than a crash. */
extern uint64_t mmt_classify_checker_call_count(void) __attribute__((weak));
extern uint64_t mmt_classify_checker_calls_for_proto(uint32_t proto_id) __attribute__((weak));
extern uint64_t mmt_classify_walk_skip_count(void) __attribute__((weak));
extern uint64_t mmt_classify_direct_call_count(void) __attribute__((weak));
extern void mmt_classify_stats_reset(void) __attribute__((weak));

#define NO_SESSION UINT64_MAX
#define MAX_RECORDS 200000

typedef struct {
    uint64_t session_id;       /* NO_SESSION when the packet has no session */
    int l4_converged;          /* proto_path[4] resolved to a real protocol */
    uint64_t delta_ip;
    uint64_t delta_tcp;
    uint64_t delta_udp;
    uint64_t delta_total;
} packet_record_t;

typedef struct {
    uint64_t session_id;
    int converged;             /* L4->app transition resolved at last sighting */
} session_state_t;

static packet_record_t g_records[MAX_RECORDS];
static int g_nrecords = 0;

static session_state_t *g_sessions = NULL;
static size_t g_sessions_len = 0;
static size_t g_sessions_cap = 0;

/* Per-packet observation captured inside packet_process() by the handler. */
static uint64_t g_pending_session_id = NO_SESSION;
static int g_pending_l4_converged = 0;

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void)user_args;
    g_pending_session_id = get_session_id_from_packet(ipacket);
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;
    /* The L4 -> app transition is resolved when the path carries a real
     * protocol at index 4 (META.ETH.IP.TCP.<app>). This is exactly the slot
     * the fast path checks before deciding to skip the checker walk. */
    g_pending_l4_converged =
        (ph != NULL && ph->len > 4 && ph->proto_path[4] != PROTO_UNKNOWN) ? 1 : 0;
    return 0;
}

static int session_was_converged(uint64_t session_id) {
    for (size_t i = 0; i < g_sessions_len; i++) {
        if (g_sessions[i].session_id == session_id) return g_sessions[i].converged;
    }
    return -1; /* never seen */
}

static void session_mark(uint64_t session_id, int converged) {
    for (size_t i = 0; i < g_sessions_len; i++) {
        if (g_sessions[i].session_id == session_id) {
            g_sessions[i].converged = converged;
            return;
        }
    }
    if (g_sessions_len == g_sessions_cap) {
        size_t next = g_sessions_cap ? g_sessions_cap * 2 : 64;
        session_state_t *grown = (session_state_t *) realloc(g_sessions, next * sizeof(*grown));
        if (grown == NULL) {
            fprintf(stderr, "classified_flow_fastpath_test: out of memory\n");
            exit(2);
        }
        g_sessions = grown;
        g_sessions_cap = next;
    }
    g_sessions[g_sessions_len].session_id = session_id;
    g_sessions[g_sessions_len].converged = converged;
    g_sessions_len++;
}

static uint64_t count_for(uint32_t proto_id) {
    return mmt_classify_checker_calls_for_proto
        ? mmt_classify_checker_calls_for_proto(proto_id)
        : 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.pcap>\n", argv[0]);
        return 2;
    }
    const char *pcap_path = argv[1];

    if (mmt_classify_checker_call_count == NULL ||
        mmt_classify_checker_calls_for_proto == NULL ||
        mmt_classify_walk_skip_count == NULL) {
        fprintf(stderr,
            "FAIL: classifier counters are not exported by this build "
            "(needs an assert-enabled or sanitizer build — BUILD=asan).\n");
        return 1;
    }

    if (init_extraction() != 1) {
        fprintf(stderr, "init_extraction failed\n");
        return 2;
    }

    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_path, pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", pcap_path, pcap_errbuf);
        return 2;
    }

    char mmt_errbuf[1024];
    mmt_handler_t *mmt_handler = mmt_init_handler((uint32_t)pcap_datalink(pcap), 0, mmt_errbuf);
    if (mmt_handler == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", mmt_errbuf);
        pcap_close(pcap);
        return 2;
    }
    register_packet_handler(mmt_handler, 1, packet_handler, NULL);
    if (mmt_classify_stats_reset) mmt_classify_stats_reset();

    const u_char *data;
    struct pcap_pkthdr p_pkthdr;
    struct pkthdr header;
    memset(&header, 0, sizeof(header));

    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        if (g_nrecords >= MAX_RECORDS) break;
        if (p_pkthdr.caplen == 0) continue;
        header.ts = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len = p_pkthdr.len;

        uint64_t t0 = mmt_classify_checker_call_count();
        uint64_t ip0 = count_for(PROTO_IP);
        uint64_t tcp0 = count_for(PROTO_TCP);
        uint64_t udp0 = count_for(PROTO_UDP);

        g_pending_session_id = NO_SESSION;
        g_pending_l4_converged = 0;
        packet_process(mmt_handler, &header, data);

        packet_record_t *rec = &g_records[g_nrecords++];
        rec->session_id = g_pending_session_id;
        rec->l4_converged = g_pending_l4_converged;
        rec->delta_ip = count_for(PROTO_IP) - ip0;
        rec->delta_tcp = count_for(PROTO_TCP) - tcp0;
        rec->delta_udp = count_for(PROTO_UDP) - udp0;
        rec->delta_total = mmt_classify_checker_call_count() - t0;
    }
    pcap_close(pcap);
    mmt_close_handler(mmt_handler);

    /* Post-pass: a packet on an already-classified session must invoke zero
     * checkers on the flow's own chain (IP, TCP, UDP). "Already classified"
     * means the previous packet on the same session left proto_path[4]
     * resolved to a real protocol — exactly the slot the fast path checks. */
    int failures = 0;
    int fastpathed = 0;
    uint64_t link_layer_calls = 0;
    for (int i = 0; i < g_nrecords; i++) {
        packet_record_t *rec = &g_records[i];
        if (rec->session_id == NO_SESSION) continue;
        int prev = session_was_converged(rec->session_id);
        if (prev == 1) {
            fastpathed++;
            link_layer_calls += rec->delta_total;
            if (rec->delta_ip != 0 || rec->delta_tcp != 0 || rec->delta_udp != 0) {
                failures++;
                if (failures <= 20) {
                    fprintf(stderr,
                        "FAIL packet %d: session %llu already classified but invoked "
                        "%llu IP + %llu TCP + %llu UDP checker calls\n",
                        i, (unsigned long long)rec->session_id,
                        (unsigned long long)rec->delta_ip,
                        (unsigned long long)rec->delta_tcp,
                        (unsigned long long)rec->delta_udp);
                }
            }
        }
        session_mark(rec->session_id, rec->l4_converged);
    }

    uint64_t total_calls = mmt_classify_checker_call_count
        ? mmt_classify_checker_call_count() : 0;
    uint64_t skips = mmt_classify_walk_skip_count
        ? mmt_classify_walk_skip_count() : 0;
    uint64_t direct_calls = mmt_classify_direct_call_count
        ? mmt_classify_direct_call_count() : 0;

    fprintf(stdout,
        "classified_flow_fastpath: packets=%d on_classified_flow=%d "
        "checker_calls_total=%llu walk_skips=%llu direct_dispatches=%llu "
        "link_layer_calls_per_fastpathed_packet=%.2f violations=%d\n",
        g_nrecords, fastpathed,
        (unsigned long long)total_calls,
        (unsigned long long)skips,
        (unsigned long long)direct_calls,
        fastpathed ? (double)link_layer_calls / (double)fastpathed : 0.0,
        failures);

    if (failures > 0) {
        fprintf(stderr, "FAIL: %d packet(s) on already-classified flows invoked checkers\n", failures);
        return 1;
    }
    if (fastpathed == 0) {
        fprintf(stderr,
            "FAIL: no packet rode an already-classified session — the test is "
            "vacuous on this pcap (choose a capture with a classified TCP/UDP flow)\n");
        return 1;
    }
    if (skips == 0) {
        fprintf(stderr, "FAIL: classified-flow packets present but the fast path never engaged\n");
        return 1;
    }
    fprintf(stdout, "PASS: %d packets on already-classified flows invoked 0 IP/TCP/UDP checkers\n",
            fastpathed);
    return 0;
}
