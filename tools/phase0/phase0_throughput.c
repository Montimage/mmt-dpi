/**
 * phase0_throughput — packet-processing throughput baseline (packets/second).
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 0 (baseline harness).
 * See tools/phase0/README.md.
 *
 * Loads an entire pcap into memory once, then replays it through the SDK
 * `iterations` times, measuring wall-clock time with CLOCK_MONOTONIC.
 * Replaying from memory removes pcap/disk I/O from the measured loop, so the
 * reported pps reflects the SDK hot path. Capture this on Phase-0 `main` and
 * compare after Phase 4 (build/LTO) and Phase 5 (hot-path performance).
 *
 * A *fresh* mmt_handler is created for each iteration, but only the inner
 * packet-processing loop is timed: the per-iteration mmt_init_handler /
 * mmt_close_handler calls are excluded from the measured window, so the
 * reported pps reflects the SDK hot path rather than handler setup/teardown
 * (the expensive one-time cost is init_extraction(), also outside the window).
 * A fresh handler per pass matters: replaying the identical packets through one
 * persistent handler drives stateful parsers and the TCP reassembly/session
 * tables into states the SDK never sees in real capture (same 5-tuple, same
 * sequence numbers, forever) and can crash. A fresh handler per pass keeps each
 * replay a clean, representative single-trace run.
 *
 * Memory reporting (issue #251, F-PERF-016): the trace is preloaded, NOT
 * streamed, so the process peak RSS used to attribute the whole capture to
 * the library. The driver now samples the live RSS (/proc VmRSS — unlike
 * getrusage's ru_maxrss it is not a monotonic high-water mark, so deltas
 * attribute cost to the phase that allocated it) and reports two separate
 * figures next to the process peak:
 *   harness_rss_kib = RSS delta of the trace preload (driver-side cost,
 *                     subtracted explicitly rather than streamed away)
 *   library_rss_kib = RSS delta on top of the preloaded trace attributable
 *                     to the library's own allocations (init_extraction
 *                     tables, the per-iteration handler and its session /
 *                     reassembly state — peak over the replay)
 *   peak_rss_kib    = process ru_maxrss high-water mark, for context
 *
 * Build (done by capture_baseline.sh against an installed prefix):
 *   gcc -O2 -o phase0_throughput phase0_throughput.c \
 *       -I <prefix>/dpi/include -L <prefix>/dpi/lib -lmmt_core -ldl -lpcap
 *
 * Usage:
 *   phase0_throughput <file.pcap> [iterations]   (default iterations: 200)
 *
 * Output (one line, tab-separated, stable/diffable; -1 = RSS unavailable):
 *   <packets>\t<iterations>\t<elapsed_s>\t<pps>\t<harness_rss_kib>\t<library_rss_kib>\t<peak_rss_kib>\t<ns_per_pkt>
 * ns_per_pkt (issue #555) is the timed window per packet, 1e9 / pps; it is
 * appended last so the earlier column positions are unchanged.
 *
 * Modes (issue #555): PHASE0_MODE selects what each iteration's handler
 * registers before the timed replay, so the attribute/handler path real
 * consumers pay for is measured, not only the bare classifier:
 *   bare    (default) no attribute, no handler — the classifier hot path
 *   attrs8  the fixed 8-attribute set PHASE0_ATTRS8 below plus a packet
 *           handler that fetches each one
 *   all     fetch-all: every attribute of every registered protocol, plus a
 *           handler that fetches, for each layer of the packet's protocol
 *           path, every attribute of that layer's protocol
 * One line goes to stderr first: mode\t<mode>\t<attributes registered>.
 *
 * Attribute reads (issue #506, opt-in): PHASE0_ATTRS="proto.attr,..." (e.g.
 * "dns.queries,ftp.packet_request") registers those attributes on every
 * iteration's handler and reads each one from a packet handler (mode
 * "custom"; PHASE0_MODE must then be unset). The reads sit inside the timed
 * window. With any attribute registered, one extra line per iteration goes
 * to stderr: rss\t<iteration>\t<library_rss_kib>, the live RSS above the
 * preloaded trace after that pass — flat across iterations when the
 * extractors release what they allocate.
 *
 * Instruction counts (issue #555): when <valgrind/callgrind.h> is available
 * at compile time (the valgrind package ships it), each replay pass is
 * bracketed by CALLGRIND_TOGGLE_COLLECT, so
 *   valgrind --tool=callgrind --collect-atstart=no phase0_throughput <pcap> 1
 * counts the replay alone — init_extraction(), handler setup and teardown and
 * the attribute registration stay outside. Outside Valgrind the requests are
 * a few no-op instructions, outside the timed window. The bracket is client
 * requests rather than --toggle-collect on a function: callgrind's call/return
 * tracking on aarch64 left collection on past the function's return.
 * tools/phase0/ci/check_instructions.sh gates those counts.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <pcap.h>

#if defined(__has_include)
#  if __has_include(<valgrind/callgrind.h>)
#    include <valgrind/callgrind.h>
#  endif
#endif
#ifndef CALLGRIND_TOGGLE_COLLECT
#  define CALLGRIND_TOGGLE_COLLECT do { } while (0)
#endif

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

typedef struct {
    struct pkthdr header;
    unsigned char *data;
} stored_pkt_t;

/* Live resident set in KiB from /proc (VmRSS), or -1 when unreadable. */
static long current_rss_kib(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char  line[256];
    long  kib = -1;
    if (f == NULL) return -1;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "VmRSS: %ld kB", &kib) == 1) break;
    }
    fclose(f);
    return kib;
}

/* Process RSS high-water mark in KiB (ru_maxrss on Linux), or -1. */
static long peak_rss_kib(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_maxrss;
}

/* Issue #555: the attrs8 mode's attributes — a flow record's 5-tuple
 * fields, the packet length and one L7 field. Fixed: the instruction-count
 * baseline (tools/phase0/ci/baseline/instructions.txt) is measured on it. */
#define PHASE0_ATTRS8 "ip.src,ip.dst,tcp.src_port,tcp.dest_port," \
                      "udp.src_port,udp.dest_port,meta.packet_len,http.uri"

/* The attributes the mode registers (issues #506, #555), read once per
 * packet; grown on demand, so fetch-all has no fixed cap. */
static uint32_t *g_attr_proto, *g_attr_id;
static size_t    g_attr_n, g_attr_cap;

static int add_attr(uint32_t proto, uint32_t attr) {
    if (g_attr_n == g_attr_cap) {
        size_t    cap = g_attr_cap ? g_attr_cap * 2 : 64;
        uint32_t *p   = (uint32_t *)realloc(g_attr_proto, cap * sizeof(*p));
        if (p == NULL) return -1;
        g_attr_proto = p;
        p = (uint32_t *)realloc(g_attr_id, cap * sizeof(*p));
        if (p == NULL) return -1;
        g_attr_id  = p;
        g_attr_cap = cap;
    }
    g_attr_proto[g_attr_n] = proto;
    g_attr_id[g_attr_n++]  = attr;
    return 0;
}

static int read_attrs_cb(const ipacket_t *ipacket, void *args) {
    (void)args;
    for (size_t a = 0; a < g_attr_n; a++)
        (void)get_attribute_extracted_data(ipacket, g_attr_proto[a], g_attr_id[a]);
    return 0;
}

/* Parses a "proto.attr,..." list after init_extraction(); -1 on a bad entry. */
static int parse_attrs(const char *spec, const char *what) {
    char *buf = strdup(spec);
    int   rc  = 0;
    if (buf == NULL) return -1;
    for (char *save = NULL, *tok = strtok_r(buf, ",", &save); tok != NULL;
         tok = strtok_r(NULL, ",", &save)) {
        char *dot = strchr(tok, '.');
        if (dot == NULL) {
            fprintf(stderr, "%s: entry %s is not proto.attr\n", what, tok);
            rc = -1;
            break;
        }
        *dot = '\0';
        uint32_t proto = get_protocol_id_by_name(tok);
        uint32_t attr  = get_attribute_id_by_protocol_id_and_attribute_name(proto, dot + 1);
        if (proto == 0 || attr == 0) {
            fprintf(stderr, "%s: unknown attribute %s.%s\n", what, tok, dot + 1);
            rc = -1;
            break;
        }
        if (add_attr(proto, attr) != 0) { rc = -1; break; }
    }
    free(buf);
    return rc;
}

/* Fetch-all: every attribute of every registered protocol. An entry without
 * an extraction function is skipped (none today), as
 * tools/phase0/tests/position_unknown_guard_test.c does. The iteration visits
 * one protocol's attributes in a row, so g_all_first/g_all_count index them
 * by protocol id for the handler below. */
static int    g_all_failed;
static size_t g_all_first[PROTO_MAX_IDENTIFIER], g_all_count[PROTO_MAX_IDENTIFIER];
static void all_attr_cb(attribute_metadata_t *attr, uint32_t proto_id, void *args) {
    (void)args;
    if (attr == NULL || attr->extraction_function == NULL) return;
    if (proto_id >= PROTO_MAX_IDENTIFIER || add_attr(proto_id, (uint32_t)attr->id) != 0) {
        g_all_failed = 1;
        return;
    }
    if (g_all_count[proto_id]++ == 0) g_all_first[proto_id] = g_attr_n - 1;
}
static void all_proto_cb(uint32_t proto_id, void *args) {
    iterate_through_protocol_attributes(proto_id, all_attr_cb, args);
}

/* The fetch-all handler: for each layer of the packet's protocol path, fetch
 * every attribute of that layer's protocol at that layer — every attribute
 * the packet can carry, encapsulated repeats included. Fetching the other
 * protocols' attributes too would only time thousands of "not in this
 * packet" misses. */
static int read_all_cb(const ipacket_t *ipacket, void *args) {
    (void)args;
    const proto_hierarchy_t *path = ipacket->proto_hierarchy;
    for (int l = 0; path != NULL && l < path->len; l++) {
        int proto = path->proto_path[l];
        if (proto < 0 || proto >= PROTO_MAX_IDENTIFIER) continue;
        for (size_t a = g_all_first[proto], end = a + g_all_count[proto]; a < end; a++)
            (void)get_attribute_extracted_data_at_index(ipacket, (uint32_t)proto,
                                                        g_attr_id[a], (unsigned)l);
    }
    return 0;
}

/* One replay pass; under callgrind only this is counted (issue #555). */
static void phase0_replay_pass(mmt_handler_t *mmt_handler, stored_pkt_t *pkts, size_t n) {
    CALLGRIND_TOGGLE_COLLECT;
    for (size_t i = 0; i < n; i++)
        packet_process(mmt_handler, &pkts[i].header, pkts[i].data);
    CALLGRIND_TOGGLE_COLLECT;
}

int main(int argc, char **argv) {
    char            mmt_errbuf[1024];
    char            pcap_errbuf[PCAP_ERRBUF_SIZE];
    mmt_handler_t  *mmt_handler;
    pcap_t         *pcap;
    const u_char   *data;
    struct pcap_pkthdr  p_pkthdr;
    int             datalink;
    long            iterations = 200;
    long            it, i;
    size_t          cap = 4096, n = 0;
    stored_pkt_t   *pkts;
    struct timespec t0, t1;
    double          elapsed, pps, ns_per_pkt;
    size_t          registered = 0;
    long            rss_base, rss_preloaded, rss_now, rss_lib_peak;
    long            harness_rss, library_rss, peak_rss;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.pcap> [iterations]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc >= 3) {
        iterations = strtol(argv[2], NULL, 10);
        if (iterations <= 0) iterations = 200;
    }

    pcap = pcap_open_offline(argv[1], pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", argv[1], pcap_errbuf);
        return EXIT_FAILURE;
    }
    datalink = pcap_datalink(pcap);

    /* Baseline RSS: everything below this sample is harness/process overhead;
     * the preload delta measured against it is the harness share (issue #251). */
    rss_base = current_rss_kib();

    /* Slurp the whole trace into memory. */
    pkts = (stored_pkt_t *)malloc(cap * sizeof(*pkts));
    if (pkts == NULL) { fprintf(stderr, "OOM\n"); pcap_close(pcap); return EXIT_FAILURE; }
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        if (n == cap) {
            cap *= 2;
            stored_pkt_t *tmp = (stored_pkt_t *)realloc(pkts, cap * sizeof(*pkts));
            if (tmp == NULL) { fprintf(stderr, "OOM\n"); free(pkts); pcap_close(pcap); return EXIT_FAILURE; }
            pkts = tmp;
        }
        memset(&pkts[n].header, 0, sizeof(pkts[n].header));
        pkts[n].header.ts     = p_pkthdr.ts;
        pkts[n].header.caplen = p_pkthdr.caplen;
        pkts[n].header.len    = p_pkthdr.len;
        /* malloc(0) is implementation-defined (may return NULL); use >=1. */
        pkts[n].data = (unsigned char *)malloc(p_pkthdr.caplen ? p_pkthdr.caplen : 1);
        if (pkts[n].data == NULL) { fprintf(stderr, "OOM\n"); free(pkts); pcap_close(pcap); return EXIT_FAILURE; }
        memcpy(pkts[n].data, data, p_pkthdr.caplen);
        n++;
    }
    pcap_close(pcap);
    rss_preloaded = current_rss_kib();

    if (n == 0) {
        fprintf(stderr, "%s: no packets\n", argv[1]);
        free(pkts);
        return EXIT_FAILURE;
    }

    init_extraction();
    const char *mode_spec  = getenv("PHASE0_MODE");
    const char *attrs_spec = getenv("PHASE0_ATTRS");
    const char *mode       = "bare";
    int         rc_mode    = 0;
    if (attrs_spec != NULL && *attrs_spec != '\0') {
        if (mode_spec != NULL && *mode_spec != '\0') {
            fprintf(stderr, "PHASE0_ATTRS and PHASE0_MODE are exclusive\n");
            rc_mode = -1;
        } else {
            mode    = "custom";
            rc_mode = parse_attrs(attrs_spec, "PHASE0_ATTRS");
        }
    } else if (mode_spec == NULL || *mode_spec == '\0' || strcmp(mode_spec, "bare") == 0) {
        mode = "bare";
    } else if (strcmp(mode_spec, "attrs8") == 0) {
        mode    = "attrs8";
        rc_mode = parse_attrs(PHASE0_ATTRS8, "PHASE0_ATTRS8");
    } else if (strcmp(mode_spec, "all") == 0) {
        mode = "all";
        iterate_through_protocols(all_proto_cb, NULL);
        if (g_all_failed || g_attr_n == 0) {
            fprintf(stderr, "PHASE0_MODE=all: %s\n",
                    g_all_failed ? "out of memory" : "no attribute found");
            rc_mode = -1;
        }
    } else {
        fprintf(stderr, "PHASE0_MODE: unknown mode %s (bare, attrs8, all)\n", mode_spec);
        rc_mode = -1;
    }
    if (rc_mode != 0) {
        free(pkts);
        close_extraction();
        return EXIT_FAILURE;
    }
    /* Probe once so an unsupported link-type fails cleanly before timing. */
    mmt_handler = mmt_init_handler(datalink, 0, mmt_errbuf);
    if (mmt_handler == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", mmt_errbuf);
        free(pkts);
        close_extraction();
        return EXIT_FAILURE;
    }
    mmt_close_handler(mmt_handler);
    /* RSS after init_extraction() + the probe handler lifecycle: the floor of
     * the library share (its one-time tables); the replay peak may exceed it. */
    rss_lib_peak = current_rss_kib();

    /* Time only the packet-processing inner loop, accumulated across all
     * iterations. The per-iteration handler init/close stays (a fresh handler
     * per pass — see file header) but is kept out of the measured window. */
    elapsed = 0.0;
    for (it = 0; it < iterations; it++) {
        mmt_handler = mmt_init_handler(datalink, 0, mmt_errbuf);
        if (mmt_handler == NULL) break;
        registered = 0;
        if (g_attr_n > 0) {
            for (size_t a = 0; a < g_attr_n; a++)
                registered += register_extraction_attribute(mmt_handler, g_attr_proto[a], g_attr_id[a]) ? 1 : 0;
            register_packet_handler(mmt_handler, 1,
                                    strcmp(mode, "all") == 0 ? read_all_cb : read_attrs_cb, NULL);
        }
        if (it == 0) fprintf(stderr, "mode\t%s\t%zu\n", mode, registered);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        phase0_replay_pass(mmt_handler, pkts, n);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        elapsed += (double)(t1.tv_sec - t0.tv_sec)
                 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        /* Live RSS while the handler's session/reassembly state is still
         * allocated — the library share peaks here, outside the timed window. */
        rss_now = current_rss_kib();
        if (rss_now > rss_lib_peak) rss_lib_peak = rss_now;
        mmt_close_handler(mmt_handler);
        if (g_attr_n > 0 && rss_preloaded >= 0) {
            rss_now = current_rss_kib();
            fprintf(stderr, "rss\t%ld\t%ld\n", it + 1,
                    rss_now >= 0 ? rss_now - rss_preloaded : -1L);
        }
    }
    mmt_handler = NULL;
    pps = (elapsed > 0.0) ? ((double)n * (double)iterations / elapsed) : 0.0;
    ns_per_pkt = (n > 0 && iterations > 0)
               ? elapsed * 1e9 / ((double)n * (double)iterations) : 0.0;

    harness_rss = (rss_base >= 0 && rss_preloaded >= 0)
                ? rss_preloaded - rss_base : -1;
    library_rss = (rss_preloaded >= 0 && rss_lib_peak >= 0)
                ? rss_lib_peak - rss_preloaded : -1;
    peak_rss    = peak_rss_kib();

    printf("%zu\t%ld\t%.4f\t%.0f\t%ld\t%ld\t%ld\t%.1f\n",
           n, iterations, elapsed, pps, harness_rss, library_rss, peak_rss,
           ns_per_pkt);

    close_extraction();
    for (i = 0; i < (long)n; i++) free(pkts[i].data);
    free(pkts);
    free(g_attr_proto);
    free(g_attr_id);
    return EXIT_SUCCESS;
}
