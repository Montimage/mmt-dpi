/**
 * installed_consumer — release-package smoke consumer (issue #374, F-CI-002).
 *
 * Driven by tools/ci/tests/run-installed-consumer.sh inside every package
 * test container (release-packages.yml matrix row). It links ONLY against the
 * packaged SDK — <prefix>/dpi/include headers, <prefix>/dpi/lib libraries —
 * and relies on the packaged plugins under <prefix>/plugins, proving the
 * installed artifact is a usable SDK, not just a fileset that installs.
 *
 * The program performs, in order:
 *   1. init_extraction()        — the registry is always initialized before
 *                                 any handler exists (contract required by the
 *                                 acceptance criteria);
 *   2. protocol enumeration     — iterate_through_protocols() counts the
 *                                 registered protocols and every name in the
 *                                 required CSV must resolve through
 *                                 get_protocol_id_by_name(). The list covers
 *                                 one name per shipped plugin, so a plugin
 *                                 that failed to dlopen (missing soname,
 *                                 wrong path) turns up here as a missing
 *                                 registration rather than as a later
 *                                 misclassification;
 *   3. fixture classification   — a vendored capture with a known label is
 *                                 replayed through a fresh handler; the
 *                                 expected application protocol must be the
 *                                 most frequent non-transport verdict;
 *   4. orderly shutdown         — mmt_close_handler() + close_extraction().
 *
 * Build (done by the runner):
 *   gcc -O2 -o installed_consumer installed_consumer.c \
 *       -I <prefix>/dpi/include -L <prefix>/dpi/lib -lmmt_core -ldl -lpcap
 *
 * Usage:
 *   installed_consumer <file.pcap> <expected_protocol> [required_proto_csv]
 *
 * Output (one line on stdout):
 *   consumer_result expected=<label> predicted=<top|-> protocols=<n> \
 *       packets=<n> verdict=PASS|FAIL
 *
 * Missing required registrations and open/init failures go to stderr.
 * Exit codes: 0 = PASS, 1 = wrong/absent classification, 2 = environment or
 * usage failure, 3 = required protocol missing (plugin not registered).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define MAX_PRED_NAMES 1024

/* Link / network / transport names that never count as an application
 * verdict — the same boundary phase0_precision uses so this consumer agrees
 * with the labelled-pcap ground truth (tools/phase0/ci/labels.txt). Names are
 * lowercase to match get_protocol_name_by_id(). "unknown" is the explicit
 * no-verdict marker (PROTO_UNKNOWN). */
static const char *g_builtin_ignore[] = {
    "meta", "ethernet", "ip", "ipv4", "ipv6", "arp", "rarp",
    "tcp", "udp", "sctp", "sctp_data", "icmp", "icmpv6", "igmp", "gre",
    "ppp", "pppoe", "vlan", "mpls", "sll", "ipsec", "esp", "ah",
    "unknown", "?",
};
#define N_BUILTIN_IGNORE ((int)(sizeof(g_builtin_ignore) / sizeof(g_builtin_ignore[0])))

static char          g_pred_names[MAX_PRED_NAMES][64];
static unsigned long g_pred_counts[MAX_PRED_NAMES];
static int           g_n_pred = 0;
static unsigned long g_pred_overflow = 0;

static unsigned long g_total = 0;
static unsigned long g_app_unknown = 0;
static int           g_protocol_count = 0;

static void count_protocol(uint32_t proto_id, void *args) {
    (void) proto_id;
    (void) args;
    g_protocol_count++;
}

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

static int is_ignored(const char *name) {
    int i;
    for (i = 0; i < N_BUILTIN_IGNORE; i++) {
        if (strcasecmp(name, g_builtin_ignore[i]) == 0) return 1;
    }
    return 0;
}

/* Per packet, retain the deepest non-transport protocol in the classified
 * path — the same "application verdict" the precision harness derives. */
static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;
    const char *app = NULL;
    int i;
    (void) user_args;

    g_total++;

    if (ph != NULL) {
        for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
            const char *name = get_protocol_name_by_id(ph->proto_path[i]);
            if (name == NULL) continue;
            if (!is_ignored(name)) {
                app = name;
            }
        }
    }

    if (app == NULL) {
        g_app_unknown++;
    } else {
        record_pred(app);
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
    const char     *expected;
    int             datalink;
    int             i;

    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <file.pcap> <expected_protocol> [required_proto_csv]\n",
                argv[0]);
        return 2;
    }
    expected = argv[2];

    /* 1. Registry first — before any handler exists. init_extraction() also
     *    loads the installed plugins (PLUGINS_REPOSITORY_OPT), so a package
     *    whose plugin payload is missing or unloadable degrades the registry
     *    here and is caught by the enumeration checks below. */
    if (!init_extraction()) {
        fprintf(stderr, "installed_consumer: init_extraction() failed\n");
        return 2;
    }

    /* 2. Enumerate registered protocols, then require one name per shipped
     *    plugin so a missing plugin cannot hide behind a passing fixture. */
    iterate_through_protocols(count_protocol, NULL);

    if (g_protocol_count <= 0) {
        fprintf(stderr, "installed_consumer: no protocols registered — "
                "plugin loading produced an empty registry\n");
        close_extraction();
        return 2;
    }

    if (argc >= 4 && argv[3][0] != '\0') {
        char *copy = strdup(argv[3]);
        char *saveptr = NULL;
        char *tok;
        int  missing = 0;
        if (copy == NULL) {
            fprintf(stderr, "installed_consumer: out of memory\n");
            close_extraction();
            return 2;
        }
        for (tok = strtok_r(copy, ",", &saveptr);
             tok != NULL;
             tok = strtok_r(NULL, ",", &saveptr)) {
            if (get_protocol_id_by_name(tok) == 0) {
                fprintf(stderr, "installed_consumer: required protocol '%s' "
                        "is not registered\n", tok);
                missing++;
            }
        }
        free(copy);
        if (missing > 0) {
            fprintf(stderr, "installed_consumer: %d required protocol(s) "
                    "missing — a packaged plugin failed to load\n", missing);
            close_extraction();
            return 3;
        }
    }

    /* 3. Replay the vendored fixture through a fresh handler. */
    pcap = pcap_open_offline(argv[1], pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "installed_consumer: pcap_open_offline(%s) failed: %s\n",
                argv[1], pcap_errbuf);
        close_extraction();
        return 2;
    }
    datalink = pcap_datalink(pcap);

    mmt_handler = mmt_init_handler(datalink, 0, mmt_errbuf);
    if (mmt_handler == NULL) {
        fprintf(stderr, "installed_consumer: mmt_init_handler failed: %s\n",
                mmt_errbuf);
        pcap_close(pcap);
        close_extraction();
        return 2;
    }

    register_packet_handler(mmt_handler, 1, packet_handler, NULL);

    memset(&header, 0, sizeof(header));
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        header.ts     = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len    = p_pkthdr.len;
        packet_process(mmt_handler, &header, data);
    }

    /* Verdict: the expected application protocol must be the most frequent
     * prediction (a strict top — a tie with another label fails, since the
     * fixtures are single-application captures). */
    {
        int  top = -1;
        int  tie = 0;
        int  expected_idx = -1;
        int  pass;
        for (i = 0; i < g_n_pred; i++) {
            if (strcasecmp(g_pred_names[i], expected) == 0) expected_idx = i;
            if (top < 0 || g_pred_counts[i] > g_pred_counts[top]) {
                top = i;
                tie = 0;
            } else if (g_pred_counts[i] == g_pred_counts[top]) {
                tie = 1;
            }
        }
        pass = (expected_idx >= 0) && (expected_idx == top) && !tie;

        printf("consumer_result expected=%s predicted=%s protocols=%d "
               "packets=%lu overflow=%lu verdict=%s\n",
               expected,
               (top >= 0) ? g_pred_names[top] : "-",
               g_protocol_count, g_total, g_pred_overflow,
               pass ? "PASS" : "FAIL");

        /* 4. Orderly shutdown — handler, then registry. */
        mmt_close_handler(mmt_handler);
        close_extraction();
        pcap_close(pcap);

        if (!pass) {
            fprintf(stderr, "installed_consumer: expected '%s' to be the top "
                    "verdict; top='%s' (expected seen=%lu, abstained=%lu)\n",
                    expected, (top >= 0) ? g_pred_names[top] : "-",
                    (expected_idx >= 0) ? g_pred_counts[expected_idx] : 0UL,
                    g_app_unknown);
            return 1;
        }
    }
    return 0;
}
