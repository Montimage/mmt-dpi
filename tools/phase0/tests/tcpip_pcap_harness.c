/**
 * tcpip_pcap_harness — pcap-driven harness for TCP/IP-stack parsers (issue #143).
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 3 (4.1).
 * See MASTER_IMPROVEMENT_PLAN.md and docs/DECISIONS.md.
 *
 * What it does:
 *   1. Opens the given pcap (DLT from the file, via pcap_open_offline).
 *   2. Creates an mmt_handler for that DLT and registers a packet handler that
 *      records the classified protocol path (proto_hierarchy -> dot-joined names,
 *      identical to tools/phase0/phase0_classify.c's fingerprint logic). It also
 *      registers extraction attributes for the FTP / NDN(-HTTP) / IPS_DATA
 *      dissectors hardened by issue #195 so attribute extractors run on the
 *      replayed bytes, not just classification.
 *   3. Replays every packet through packet_process(), exercising the TCP/IP
 *      parsers on real captured bytes (not synthetic ipacket_t). Each record
 *      is first memcpy'd into an exactly-sized, ASan-instrumented heap buffer
 *      so a parser over-read past caplen lands in a redzone — the libpcap
 *      buffers are not instrumented and would mask such reads.
 *   4. Prints a deterministic, sorted fingerprint: one line per distinct path,
 *      "<count>\\t<path>", free of timestamps/addresses so it diffs cleanly.
 *   5. Validates two invariants needed for the harness to be a trustworthy
 *      regression oracle:
 *        - Fingerprint stability: replaying the same pcap through a fresh
 *          handler must yield an identical fingerprint (no hidden global state).
 *        - No crash under sanitizers: the harness itself handles
 *          truncated/empty/unsupported pcaps without aborting; any sanitizer
 *          hit inside the SDK (H1-H8, K3/K4 class) aborts the process when
 *          built with BUILD=asan (-fno-sanitize-recover=all), so a clean
 *          exit means the parsers survived the pcap's bytes.
 *
 * Build (done by run_tcpip_pcap_harness_test.sh against an installed prefix):
 *   gcc -O2 -o tcpip_pcap_harness tcpip_pcap_harness.c \
 *       -I <prefix>/dpi/include -L <prefix>/dpi/lib -lmmt_core -ldl -lpcap
 *
 * Usage:
 *   tcpip_pcap_harness <file.pcap>
 *   tcpip_pcap_harness --self-test   # stability check on the given pcap
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
        fprintf(stderr, "tcpip_pcap_harness: distinct-path table full (%d)\n",
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

/* Register the packet-scope extraction attributes of the dissectors hardened
 * by issue #195 (FTP, NDN/NDN_HTTP, business-app IPS_DATA) so replaying a pcap
 * runs the extractors — not only classification — on the captured bytes.
 * Registration failures are ignored on purpose: an attribute whose protocol is
 * absent from a handler's stack simply never fires. The IPS_DATA attributes
 * are resolved by alias because the business-app headers are not installed
 * (rules/common.mk B_APP_HEADERS misses the 'include/' path). */
static void register_extraction_attributes(mmt_handler_t *mmt_handler) {
    static const struct {
        const char *proto;
        const char *attr;
    } by_name[] = {
        {"lps_data", "trolley_pos"},   {"lps_data", "hoist_pos"},
        {"lps_data", "no_of_marker"},  {"lps_data", "m1_x"},
        {"lps_data", "m1_y"},          {"lps_data", "m2_x"},
        {"lps_data", "m2_y"},          {"lps_data", "m3_x"},
        {"lps_data", "m3_y"},          {"lps_data", "m4_x"},
        {"lps_data", "m4_y"},          {"lps_data", "m5_x"},
        {"lps_data", "m5_y"},          {"lps_data", "m6_x"},
        {"lps_data", "m6_y"},          {"lps_data", "order"},
    };
    static const struct {
        uint32_t proto;
        uint32_t attr;
    } by_id[] = {
        {PROTO_FTP, FTP_PACKET_TYPE},
        {PROTO_FTP, FTP_PACKET_REQUEST},
        {PROTO_FTP, FTP_PACKET_REQUEST_PARAMETER},
        {PROTO_FTP, FTP_PACKET_RESPONSE_CODE},
        {PROTO_FTP, FTP_PACKET_RESPONSE_VALUE},
        {PROTO_NDN, NDN_PACKET_TYPE},
        {PROTO_NDN, NDN_PACKET_LENGTH},
        {PROTO_NDN, NDN_NAME_COMPONENTS},
        {PROTO_NDN_HTTP, NDN_NAME_COMPONENTS},
        {PROTO_NDN_HTTP, NDN_INTEREST_NONCE},
        {PROTO_NDN_HTTP, NDN_INTEREST_LIFETIME},
        {PROTO_NDN_HTTP, NDN_DATA_CONTENT},
        {PROTO_NDN_HTTP, NDN_HTTP_URL},
        {PROTO_NDN_HTTP, NDN_HTTP_METHOD},
        {PROTO_NDN_HTTP, NDN_HTTP_FIRST_GW},
        {PROTO_NDN_HTTP, NDN_HTTP_SECOND_GW},
    };
    unsigned i;
    for (i = 0; i < sizeof(by_name) / sizeof(by_name[0]); i++)
        (void) register_extraction_attribute_by_name(mmt_handler,
                                                     by_name[i].proto,
                                                     by_name[i].attr);
    for (i = 0; i < sizeof(by_id) / sizeof(by_id[0]); i++)
        (void) register_extraction_attribute(mmt_handler,
                                             by_id[i].proto,
                                             by_id[i].attr);
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
        /* Unsupported link-type is a stable boundary, not a harness failure. */
        fprintf(stderr, "<unsupported link-type: %s>\n", mmt_errbuf);
        pcap_close(pcap);
        return 0;
    }

    register_packet_handler(mmt_handler, 1, packet_handler, NULL);
    register_extraction_attributes(mmt_handler);

    memset(&header, 0, sizeof(header));
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        header.ts = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len = p_pkthdr.len;
        /* Copy into an exactly-sized ASan-instrumented heap buffer so parser
         * over-reads past caplen abort instead of sliding through libpcap's
         * uninstrumented allocation. */
        if (p_pkthdr.caplen > 0) {
            u_char *copy = (u_char *) malloc(p_pkthdr.caplen);
            if (copy == NULL) {
                fprintf(stderr, "tcpip_pcap_harness: out of memory\n");
                mmt_close_handler(mmt_handler);
                pcap_close(pcap);
                return -1;
            }
            memcpy(copy, data, p_pkthdr.caplen);
            packet_process(mmt_handler, &header, copy);
            free(copy);
        } else {
            packet_process(mmt_handler, &header, data);
        }
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
            fprintf(stderr, "tcpip_pcap_harness: first replay failed\n");
            rc = 1;
        } else {
            qsort(g_paths, g_npaths, sizeof(g_paths[0]), cmp_path);
            snapshot_paths(snap1, &n1);

            reset_paths();
            if (replay_pcap(pcap_path, 0) != 0) {
                fprintf(stderr, "tcpip_pcap_harness: second replay failed\n");
                rc = 1;
            } else {
                qsort(g_paths, g_npaths, sizeof(g_paths[0]), cmp_path);
                snapshot_paths(snap2, &n2);

                if (!compare_snapshots(snap1, n1, snap2, n2)) {
                    fprintf(stderr, "tcpip_pcap_harness: fingerprint instability on %s\n",
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
