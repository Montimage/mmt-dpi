/**
 * phase0_precision — labelled-pcap precision/recall harness.
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 7 (M9, issue #74).
 * See tools/phase0/README.md.
 *
 * The golden classification fingerprint (phase0_classify) is unlabelled: it
 * pins *that* the classifier's per-packet decisions do not change, but it cannot
 * say whether a change made classification more or less *correct*. This tool
 * adds ground truth.
 *
 * Each capture in the labelled set is annotated with the single application
 * protocol it is known to carry (these fixtures are single-application pcaps).
 * For such a pcap labelled P, every packet's "application protocol" is the
 * deepest protocol in its classified path that is not a link/network/transport
 * layer and not "unknown". The tool RETAINS that predicted label per packet
 * and emits the full prediction histogram (issue #373, F-TEST-002), from which
 * the runner builds an actual-by-predicted confusion matrix over the labelled
 * set:
 *
 *     tp           : packets whose application protocol == P   (true positive)
 *     fp           : packets given a *different* application protocol -- an FN
 *                    of P and an FP of the predicted class
 *     app_unknown  : packets with no application verdict -- an abstention,
 *                    counted as an FN of P only
 *     total        : tp + fp + app_unknown
 *
 * Per class C the runner then derives, from the matrix alone:
 *
 *     TP = C[C][C];  FP = sum_{a != C} C[a][C];  FN = sum_{p != C} C[C][p]
 *     recall    = TP / (TP + FN)   (abstentions included in FN)
 *     precision = TP / (TP + FP)
 *
 * so a true-FTP packet predicted HTTP increments HTTP false positives AND FTP
 * false negatives -- the accounting the pre-#373 `fp` column could not express.
 *
 * The counts are derived purely from the classifier's deterministic decisions
 * (the same source as the golden fingerprint), so they are stable across
 * machines and can be committed as a baseline and diffed: a heuristic change
 * that lowers recall or precision shows up as a diff (acceptance criterion:
 * "precision/recall improves or holds").
 *
 * Build (done by the runner against an installed prefix):
 *   gcc -O2 -o phase0_precision phase0_precision.c \
 *       -I <prefix>/dpi/include -L <prefix>/dpi/lib -lmmt_core -ldl -lpcap
 *
 * Usage:
 *   phase0_precision <file.pcap> <expected_protocol> [extra_ignore_csv]
 *
 * Output (one tab-separated line on stdout):
 *   <expected>\t<total>\t<tp>\t<fp>\t<app_unknown>\t<predicted_csv>
 *
 * where <predicted_csv> is the retained prediction histogram -- sorted,
 * comma-separated <name>:<count> pairs over the predicted application
 * protocols (or '-' when every packet abstained). tp == the count of the
 * expected label inside the histogram; fp == its sum over the other labels.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define MAX_PATH_STR   512
#define MAX_IGNORE     64

/* Link / network / transport protocol names that never count as an application
 * verdict. Names are lowercase to match get_protocol_name_by_id() (see the
 * committed fingerprints under tools/phase0/ci/baseline/classification/).
 * "unknown" is the explicit no-verdict marker (PROTO_UNKNOWN). */
static const char *g_builtin_ignore[] = {
    "meta", "ethernet", "ip", "ipv4", "ipv6", "arp", "rarp",
    "tcp", "udp", "sctp", "icmp", "icmpv6", "igmp", "gre",
    "ppp", "pppoe", "vlan", "mpls", "sll", "ipsec", "esp", "ah",
    "unknown", "?",
};
#define N_BUILTIN_IGNORE ((int)(sizeof(g_builtin_ignore) / sizeof(g_builtin_ignore[0])))

static char  g_extra_ignore[MAX_IGNORE][64];
static int   g_n_extra_ignore = 0;

static char  g_expected[64];

static unsigned long g_total = 0;
static unsigned long g_tp = 0;
static unsigned long g_fp = 0;
static unsigned long g_app_unknown = 0;

/* Retained prediction histogram (issue #373, F-TEST-002): every distinct
 * predicted application name mapped to its packet count, so the runner can
 * build the actual-by-predicted confusion matrix instead of collapsing all
 * non-expected verdicts into a bare `fp`. Distinct application names are
 * bounded by the registered protocol space; a defensive overflow bucket keeps
 * the counts reconciled (tp + fp == histogram sum) even past that bound. */
#define MAX_PRED_NAMES 1024
static char          g_pred_names[MAX_PRED_NAMES][64];
static unsigned long g_pred_counts[MAX_PRED_NAMES];
static int           g_n_pred = 0;
static unsigned long g_pred_overflow = 0;

static void record_pred(const char *name) {
    int i;
    for (i = 0; i < g_n_pred; i++) {
        if (strcmp(g_pred_names[i], name) == 0) {
            g_pred_counts[i]++;
            return;
        }
    }
    if (g_n_pred < MAX_PRED_NAMES) {
        snprintf(g_pred_names[g_n_pred], sizeof(g_pred_names[g_n_pred]), "%s", name);
        g_pred_counts[g_n_pred] = 1;
        g_n_pred++;
    } else {
        g_pred_overflow++;
    }
}

/* qsort comparator over an index array into g_pred_names (byte-wise strcmp:
 * deterministic across hosts/locales). */
static int cmp_pred_index(const void *a, const void *b) {
    return strcmp(g_pred_names[*(const int *)a], g_pred_names[*(const int *)b]);
}

static int is_ignored(const char *name) {
    int i;
    for (i = 0; i < N_BUILTIN_IGNORE; i++) {
        if (strcasecmp(name, g_builtin_ignore[i]) == 0) return 1;
    }
    for (i = 0; i < g_n_extra_ignore; i++) {
        if (strcasecmp(name, g_extra_ignore[i]) == 0) return 1;
    }
    return 0;
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;
    const char *app = NULL; /* deepest non-ignored protocol name */
    int i;

    g_total++;

    if (ph != NULL) {
        for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
            const char *name = get_protocol_name_by_id(ph->proto_path[i]);
            if (name == NULL) continue;
            if (!is_ignored(name)) {
                app = name; /* keep going: we want the DEEPEST app protocol */
            }
        }
    }

    if (app == NULL) {
        g_app_unknown++;
    } else {
        record_pred(app);
        if (strcasecmp(app, g_expected) == 0) {
            g_tp++;
        } else {
            g_fp++;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    char            mmt_errbuf[1024];
    char            pcap_errbuf[PCAP_ERRBUF_SIZE];
    mmt_handler_t  *mmt_handler;
    pcap_t         *pcap;
    const u_char   *data;
    struct pcap_pkthdr  p_pkthdr;
    struct pkthdr   header;
    int             datalink;

    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <file.pcap> <expected_protocol> [extra_ignore_csv]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    snprintf(g_expected, sizeof(g_expected), "%s", argv[2]);

    if (argc >= 4 && argv[3][0] != '\0') {
        char *copy = strdup(argv[3]);
        if (copy != NULL) {
            char *tok = strtok(copy, ",");
            while (tok != NULL && g_n_extra_ignore < MAX_IGNORE) {
                snprintf(g_extra_ignore[g_n_extra_ignore++], 64, "%s", tok);
                tok = strtok(NULL, ",");
            }
            free(copy);
        }
    }

    pcap = pcap_open_offline(argv[1], pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", argv[1], pcap_errbuf);
        return EXIT_FAILURE;
    }
    datalink = pcap_datalink(pcap);

    init_extraction();
    mmt_handler = mmt_init_handler(datalink, 0, mmt_errbuf);
    if (mmt_handler == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", mmt_errbuf);
        pcap_close(pcap);
        close_extraction();
        return EXIT_FAILURE;
    }

    register_packet_handler(mmt_handler, 1, packet_handler, NULL);

    memset(&header, 0, sizeof(header));
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        header.ts     = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len    = p_pkthdr.len;
        packet_process(mmt_handler, &header, data);
    }

    /* expected \t total \t tp \t fp \t app_unknown \t predicted_csv */
    printf("%s\t%lu\t%lu\t%lu\t%lu\t",
           g_expected, g_total, g_tp, g_fp, g_app_unknown);
    if (g_n_pred == 0 && g_pred_overflow == 0) {
        printf("-\n");
    } else {
        int  order[MAX_PRED_NAMES];
        int  i, first = 1;
        for (i = 0; i < g_n_pred; i++) order[i] = i;
        qsort(order, g_n_pred, sizeof(order[0]), cmp_pred_index);
        for (i = 0; i < g_n_pred; i++) {
            printf("%s%s:%lu", first ? "" : ",",
                   g_pred_names[order[i]], g_pred_counts[order[i]]);
            first = 0;
        }
        if (g_pred_overflow > 0) {
            printf("%s<overflow>:%lu", first ? "" : ",", g_pred_overflow);
        }
        printf("\n");
    }

    mmt_close_handler(mmt_handler);
    close_extraction();
    pcap_close(pcap);
    return EXIT_SUCCESS;
}
