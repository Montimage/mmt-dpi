/**
 * mobile_pcap_harness — pcap-driven harness for mobile/security parsers (issue #144).
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 3 (4.2).
 * See MASTER_IMPROVEMENT_PLAN.md and docs/DECISIONS.md.
 *
 * Counterpart to tools/phase0/tests/tcpip_pcap_harness.c (issue #143, 4.1)
 * which targets the TCP/IP-stack parsers. This harness exercises the
 * mobile/security plugin family:
 *   - GTP  (src/mmt_tcpip/lib/protocols/proto_gtp.c, UDP 2152/2123)
 *   - GTPv2 (src/mmt_mobile/proto_gtpv2.c, UDP 2123, version=2)
 *   - RADIUS (src/mmt_tcpip/lib/protocols/proto_radius.c, UDP, code<=5)
 *   - SCTP + mobile payloads over SCTP_DATA:
 *       Diameter (PPID 46), S1AP (PPID 18), NGAP (PPID 60)
 *   - SCTP itself and its chunks (INIT, SACK, etc.) are exercised as
 *     transport for the mobile payloads.
 *
 * What it does (identical oracle to tcpip_pcap_harness):
 *   1. Opens the given pcap (DLT from file, via pcap_open_offline).
 *   2. Creates an mmt_handler for that DLT and registers a packet handler that
 *      records the classified protocol path (proto_hierarchy -> dot-joined names,
 *      identical to tools/phase0/phase0_classify.c's fingerprint logic).
 *   3. Replays every packet through packet_process(), exercising the mobile/
 *      security parsers on real captured bytes (not synthetic ipacket_t).
 *   4. Prints a deterministic, sorted fingerprint: one line per distinct path,
 *      "<count>\t<path>".
 *   5. Validates two invariants:
 *        - Fingerprint stability: replaying the same pcap through a fresh
 *          handler must yield an identical fingerprint (no hidden global state).
 *        - No crash under sanitizers: truncated/empty/unsupported pcaps are
 *          handled without aborting; any sanitizer hit inside the SDK aborts
 *          when built with BUILD=asan (-fno-sanitize-recover=all).
 *
 * Build (done by run_mobile_pcap_harness_test.sh against an installed prefix):
 *   gcc -O2 -o mobile_pcap_harness mobile_pcap_harness.c \
 *       -I <prefix>/dpi/include -L <prefix>/dpi/lib -lmmt_core -ldl -lpcap
 *
 * Usage:
 *   mobile_pcap_harness <file.pcap>
 *   mobile_pcap_harness <file.pcap> --self-test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define MAX_PATH_STR 512
#define MAX_DISTINCT 4096

typedef struct {
    char path[MAX_PATH_STR];
    unsigned long count;
} path_entry_t;

static path_entry_t g_paths[MAX_DISTINCT];
static int g_npaths = 0;

static void reset_paths(void) {
    g_npaths = 0;
    memset(g_paths, 0, sizeof(g_paths));
}

static void record_path(const char *path) {
    int i;
    for (i = 0; i < g_npaths; i++) {
        if (strcmp(g_paths[i].path, path) == 0) {
            g_paths[i].count++;
            return;
        }
    }
    if (g_npaths >= MAX_DISTINCT) {
        fprintf(stderr, "mobile_pcap_harness: distinct-path table full (%d)\n",
                MAX_DISTINCT);
        return;
    }
    snprintf(g_paths[g_npaths].path, MAX_PATH_STR, "%s", path);
    g_paths[g_npaths].count = 1;
    g_npaths++;
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void)user_args;
    char path[MAX_PATH_STR];
    int len = 0;
    int i;
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;

    if (ph == NULL || ph->len <= 0) {
        record_path("<none>");
        return 0;
    }
    path[0] = '\0';
    for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
        const char *name = get_protocol_name_by_id(ph->proto_path[i]);
        int n;
        if (name == NULL) name = "?";
        n = snprintf(path + len, sizeof(path) - len,
                     (i == 0) ? "%s" : ".%s", name);
        if (n < 0 || n >= (int)(sizeof(path) - len)) {
            len = (int)sizeof(path) - 1;
            break;
        }
        len += n;
    }
    record_path(path);
    return 0;
}

static int cmp_path(const void *a, const void *b) {
    const path_entry_t *pa = (const path_entry_t *)a;
    const path_entry_t *pb = (const path_entry_t *)b;
    return strcmp(pa->path, pb->path);
}

/* Replay pcap_path through a fresh handler; caller must have called
 * init_extraction() once. do_print==1 prints fingerprint to stdout. */
static int replay_pcap(const char *pcap_path, int do_print) {
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    char mmt_errbuf[1024];
    pcap_t *pcap;
    mmt_handler_t *mmt_handler;
    const u_char *data;
    struct pcap_pkthdr p_pkthdr;
    struct pkthdr header;
    int datalink;
    int i;

    pcap = pcap_open_offline(pcap_path, pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", pcap_path, pcap_errbuf);
        return -1;
    }
    datalink = pcap_datalink(pcap);

    mmt_handler = mmt_init_handler((uint32_t)datalink, 0, mmt_errbuf);
    if (mmt_handler == NULL) {
        fprintf(stderr, "<unsupported link-type: %s>\n", mmt_errbuf);
        pcap_close(pcap);
        return 0;
    }

    register_packet_handler(mmt_handler, 1, packet_handler, NULL);

    memset(&header, 0, sizeof(header));
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        header.ts = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len = p_pkthdr.len;
        packet_process(mmt_handler, &header, data);
    }

    if (do_print) {
        qsort(g_paths, g_npaths, sizeof(g_paths[0]), cmp_path);
        for (i = 0; i < g_npaths; i++) {
            printf("%lu\t%s\n", g_paths[i].count, g_paths[i].path);
        }
        fflush(stdout);
    }

    mmt_close_handler(mmt_handler);
    pcap_close(pcap);
    return 0;
}

static void snapshot_paths(path_entry_t *dst, int *n_dst) {
    *n_dst = g_npaths;
    memcpy(dst, g_paths, sizeof(g_paths[0]) * g_npaths);
}

static int compare_snapshots(const path_entry_t *a, int na,
                             const path_entry_t *b, int nb) {
    int i;
    if (na != nb) return 0;
    for (i = 0; i < na; i++) {
        if (a[i].count != b[i].count) return 0;
        if (strcmp(a[i].path, b[i].path) != 0) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *pcap_path;
    int self_test = 0;
    int rc = 0;
    path_entry_t snap1[MAX_DISTINCT], snap2[MAX_DISTINCT];
    int n1 = 0, n2 = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.pcap> [--self-test]\n", argv[0]);
        return 2;
    }
    pcap_path = argv[1];
    if (argc >= 3 && strcmp(argv[2], "--self-test") == 0) self_test = 1;

    /* Single init_extraction lifetime — mirrors phase0_classify and avoids the
     * heap-use-after-free that occurs if init_extraction is called a second
     * time after close_extraction (protocol_stack_map is deleted but the global
     * ctor is not re-run). */
    init_extraction();

    if (!self_test) {
        reset_paths();
        rc = replay_pcap(pcap_path, 1);
    } else {
        /* --self-test: replay twice through fresh handlers and compare. */
        reset_paths();
        if (replay_pcap(pcap_path, 0) != 0) {
            fprintf(stderr, "mobile_pcap_harness: first replay failed\n");
            rc = 1;
        } else {
            qsort(g_paths, g_npaths, sizeof(g_paths[0]), cmp_path);
            snapshot_paths(snap1, &n1);

            reset_paths();
            if (replay_pcap(pcap_path, 0) != 0) {
                fprintf(stderr, "mobile_pcap_harness: second replay failed\n");
                rc = 1;
            } else {
                qsort(g_paths, g_npaths, sizeof(g_paths[0]), cmp_path);
                snapshot_paths(snap2, &n2);

                if (!compare_snapshots(snap1, n1, snap2, n2)) {
                    fprintf(stderr, "mobile_pcap_harness: fingerprint instability on %s\n",
                            pcap_path);
                    rc = 1;
                } else {
                    for (int i = 0; i < n1; i++) {
                        printf("%lu\t%s\n", snap1[i].count, snap1[i].path);
                    }
                    printf("# self-test: fingerprint stable (%d distinct paths)\n", n1);
                }
            }
        }
    }

    close_extraction();
    return rc;
}
