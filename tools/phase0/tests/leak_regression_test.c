/*
 * leak_regression_test.c — named leak-regression cases for the four memory
 * leaks fixed in 1.8.0 (issue #216, F-TEST-008; fixes shipped in commits
 * e1ba1b54, bd627613, f07ec5b0, a257305f).
 *
 * The binary itself only exercises the code paths; the leak verdict comes
 * from the outer oracle: the run script executes each case as its own
 * process under Valgrind (--errors-for-leak-kinds=definite) or, when
 * Valgrind is unavailable, an ASan/LSan build with detect_leaks=1. A
 * definite leak in any case => nonzero exit => CI gate failure.
 *
 * Cases (one process per case, replaying the matching golden pcaps):
 *   reassembly_drop_skip      — 1.8.0 fix: reassembly packets on analyzer
 *                               DROP/SKIP paths (TCP reassembly enabled,
 *                               out-of-order + fragmented traffic).
 *   embedded_session_offsets  — 1.8.0 fix: proto_headers_offset of embedded
 *                               sessions (multi-packet flows with attribute
 *                               extraction registered).
 *   ftp_context_teardown      — 1.8.0 fix: FTP protocol context teardown
 *                               (all golden FTP captures).
 *   session_evasion_ownership — 1.8.0 fix: allocator ownership for
 *                               sessions/hashmap/evasion handler (session
 *                               timeout handler + evasion handler + active
 *                               session accounting over session traffic).
 *   golden_corpus_teardown    — fresh handler per capture over the whole CI
 *                               golden corpus; catches residual per-pcap
 *                               leaks outside the four named fixes.
 *
 * Usage: leak_regression_test <case> <pcap> [<pcap>...]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

static int failures;

#define EXPECT(cond, ...) do {                                  \
        if (!(cond)) {                                          \
            failures++;                                         \
            fprintf(stderr, "  FAIL %d: ", __LINE__);           \
            fprintf(stderr, __VA_ARGS__);                       \
            fprintf(stderr, "\n");                              \
        }                                                       \
    } while (0)

/* ------------------------------------------------------------------ */
/*  packet fixtures                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    struct pkthdr header;
    unsigned char *data;
} stored_pkt_t;

static stored_pkt_t *load_pcap(const char *path, long *npkts, int *datalink,
                               char *errbuf)
{
    pcap_t *pcap = pcap_open_offline(path, errbuf);
    if (!pcap)
        return NULL;
    *datalink = pcap_datalink(pcap);

    size_t cap = 4096, n = 0;
    stored_pkt_t *pkts = malloc(cap * sizeof(*pkts));
    if (!pkts) {
        pcap_close(pcap);
        return NULL;
    }
    const u_char *d;
    struct pcap_pkthdr ph;
    while ((d = pcap_next(pcap, &ph)) != NULL) {
        if (n == cap) {
            cap *= 2;
            stored_pkt_t *tmp = realloc(pkts, cap * sizeof(*pkts));
            if (!tmp) {
                for (size_t j = 0; j < n; j++) free(pkts[j].data);
                free(pkts);
                pcap_close(pcap);
                return NULL;
            }
            pkts = tmp;
        }
        memset(&pkts[n].header, 0, sizeof(pkts[n].header));
        pkts[n].header.ts     = ph.ts;
        pkts[n].header.caplen = ph.caplen;
        pkts[n].header.len    = ph.len;
        pkts[n].data = malloc(ph.caplen ? ph.caplen : 1);
        if (!pkts[n].data) {
            for (size_t j = 0; j < n; j++) free(pkts[j].data);
            free(pkts);
            pcap_close(pcap);
            return NULL;
        }
        memcpy(pkts[n].data, d, ph.caplen);
        n++;
    }
    pcap_close(pcap);
    *npkts = (long)n;
    return pkts;
}

static void free_pcap(stored_pkt_t *pkts, long n)
{
    for (long i = 0; i < n; i++)
        free(pkts[i].data);
    free(pkts);
}

/* ------------------------------------------------------------------ */
/*  handler configurations per case                                     */
/* ------------------------------------------------------------------ */

static uint64_t g_events;
static void session_expiry_cb(const mmt_session_t *s, void *args)
{
    (void)s;
    (void)args;
    g_events++;
}
static void evasion_cb(const ipacket_t *ip, uint32_t proto_id,
                       unsigned proto_index, unsigned evasion_id,
                       void *data, void *args)
{
    (void)ip; (void)proto_id; (void)proto_index; (void)evasion_id;
    (void)data; (void)args;
    g_events++;
}

static void configure_handler(mmt_handler_t *h, const char *pcase)
{
    if (strcmp(pcase, "reassembly_drop_skip") == 0) {
        /* 1.8.0: reassembly packets were lost on DROP/SKIP analyzer paths */
        EXPECT(enable_mmt_reassembly(h) == 1, "enable_mmt_reassembly");
        register_extraction_attribute_by_name(h, "META", "PACKET_LEN");
        register_extraction_attribute_by_name(h, "IP", "SRC");
        register_extraction_attribute_by_name(h, "IP", "DST");
        register_extraction_attribute_by_name(h, "TCP", "SRC_PORT");
        register_extraction_attribute_by_name(h, "TCP", "DEST_PORT");
    } else if (strcmp(pcase, "embedded_session_offsets") == 0) {
        /* 1.8.0: proto_headers_offset leaked for embedded sessions */
        register_extraction_attribute_by_name(h, "META", "PACKET_LEN");
        register_extraction_attribute_by_name(h, "IP", "SRC");
        register_extraction_attribute_by_name(h, "IP", "DST");
        register_extraction_attribute_by_name(h, "IP", "PROTO_ID");
        register_extraction_attribute_by_name(h, "TCP", "SRC_PORT");
        register_extraction_attribute_by_name(h, "TCP", "DEST_PORT");
        register_extraction_attribute_by_name(h, "UDP", "SRC_PORT");
        register_extraction_attribute_by_name(h, "UDP", "DEST_PORT");
    } else if (strcmp(pcase, "ftp_context_teardown") == 0) {
        /* 1.8.0: FTP protocol context was never torn down */
        register_extraction_attribute_by_name(h, "META", "PACKET_LEN");
        register_extraction_attribute_by_name(h, "FTP", "SESSION");
        register_extraction_attribute_by_name(h, "FTP", "RESPONSE");
        register_extraction_attribute_by_name(h, "FTP", "REQUEST");
        register_extraction_attribute_by_name(h, "TCP", "SRC_PORT");
        register_extraction_attribute_by_name(h, "TCP", "DEST_PORT");
    } else if (strcmp(pcase, "session_evasion_ownership") == 0) {
        /* 1.8.0: allocator ownership for sessions / hashmap / evasion */
        register_session_timeout_handler(h, session_expiry_cb, &g_events);
        register_evasion_handler(h, evasion_cb, &g_events);
        register_extraction_attribute_by_name(h, "META", "PACKET_LEN");
        register_extraction_attribute_by_name(h, "IP", "SRC");
        register_extraction_attribute_by_name(h, "IP", "DST");
    } else if (strcmp(pcase, "golden_corpus_teardown") == 0) {
        /* whole-corpus guard: minimal handler + one attribute */
        register_extraction_attribute_by_name(h, "META", "PACKET_LEN");
    }
}

/* ------------------------------------------------------------------ */
/*  case driver                                                         */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <case> <pcap> [<pcap>...]\n", argv[0]);
        return 2;
    }
    const char *pcase = argv[1];
    static const char *known[] = {
        "reassembly_drop_skip", "embedded_session_offsets",
        "ftp_context_teardown", "session_evasion_ownership",
        "golden_corpus_teardown", NULL
    };
    int i, ok = 0;
    for (i = 0; known[i]; i++)
        if (strcmp(pcase, known[i]) == 0)
            ok = 1;
    if (!ok) {
        fprintf(stderr, "unknown case '%s'\n", pcase);
        return 2;
    }

    printf("case=%s pcaps=%d\n", pcase, argc - 2);
    init_extraction();

    for (i = 2; i < argc; i++) {
        char errbuf[PCAP_ERRBUF_SIZE];
        long npkts = 0;
        int datalink = 0;
        stored_pkt_t *pkts = load_pcap(argv[i], &npkts, &datalink, errbuf);
        if (!pkts) {
            EXPECT(0, "load_pcap(%s): %s", argv[i], errbuf);
            continue;
        }
        char mmt_errbuf[1024];
        mmt_handler_t *h = mmt_init_handler((uint32_t)datalink, 0, mmt_errbuf);
        if (!h) {
            /* unsupported link type — not a leak-relevant failure */
            printf("  skip %s (DLT=%d unsupported)\n", argv[i], datalink);
            free_pcap(pkts, npkts);
            continue;
        }
        configure_handler(h, pcase);
        for (long k = 0; k < npkts; k++)
            packet_process(h, &pkts[k].header, pkts[k].data);
        (void)get_active_session_count(h);
        if (strcmp(pcase, "reassembly_drop_skip") == 0)
            disable_mmt_reassembly(h);
        mmt_close_handler(h);
        free_pcap(pkts, npkts);
        printf("  done %s (%ld packets)\n", argv[i], npkts);
    }

    close_extraction();
    if (failures) {
        printf("leak_regression[%s]: %d internal check(s) FAILED\n",
               pcase, failures);
        return 1;
    }
    printf("leak_regression[%s]: exercised cleanly\n", pcase);
    return 0;
}
