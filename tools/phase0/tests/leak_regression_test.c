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
 *   non_en10mb_reassembly     — issue #505 (F-BUG-019): IP-fragment
 *                               reassembly on a non-Ethernet link stack.
 *                               clean_packet() freed the reassembled datagram
 *                               buffer only on DLT_EN10MB, so every datagram
 *                               rebuilt on another stack leaked. The Ethernet
 *                               captures are replayed as Linux cooked (SLL)
 *                               frames on the PROTO_SLL stack, without
 *                               mmt reassembly enabled (clean_packet path).
 *   extractor_heap_attrs      — issue #506 (F-PERF-103, F-PERF-109): the DNS
 *                               queries/answers/auth records, FTP request/
 *                               parameter/response-value and NDN string
 *                               extractors returned heap objects through
 *                               attribute->data that nothing freed, and
 *                               mmt_check_ndn_payload() leaked its TLV root.
 *                               A packet handler reads every one of them
 *                               (twice per packet) over the DNS/FTP captures
 *                               plus crafted NDN frames (over Ethernet and
 *                               over UDP) and DNS responses, and the case
 *                               fails unless each family was extracted.
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

/* Issue #505: rewrite an Ethernet frame as a Linux cooked (SLL) frame —
 * 16-byte header carrying the same EtherType, then the same L3 bytes. */
#define SLL_HDR_LEN 16
static int to_sll(const stored_pkt_t *in, stored_pkt_t *out)
{
    if (in->header.caplen < 14)
        return 0;
    unsigned l3 = in->header.caplen - 14;
    out->header = in->header;
    out->header.caplen = SLL_HDR_LEN + l3;
    out->header.len = in->header.len - 14 + SLL_HDR_LEN;
    out->data = calloc(1, SLL_HDR_LEN + l3);
    if (!out->data)
        return 0;
    out->data[1] = 4;                        /* packet type: sent by us     */
    out->data[3] = 1;                        /* ARPHRD_ETHER                */
    out->data[5] = 6;                        /* link-layer address length   */
    memcpy(out->data + 6, in->data + 6, 6);  /* source MAC                  */
    memcpy(out->data + 14, in->data + 12, 2);/* EtherType                   */
    memcpy(out->data + SLL_HDR_LEN, in->data + 14, l3);
    return 1;
}

/* Issue #506: the heap-returning attributes, read from a packet handler —
 * register_extraction_attribute() alone extracts nothing; the value is
 * produced when it is read. */
static const struct { uint32_t proto; uint32_t attr; int family; } heap_attrs[] = {
    { PROTO_DNS, DNS_QUERIES, 0 },
    { PROTO_DNS, DNS_ANSWERS, 0 },
    { PROTO_DNS, DNS_AUTH_RECORDS, 0 },
    { PROTO_FTP, FTP_PACKET_REQUEST, 1 },
    { PROTO_FTP, FTP_PACKET_REQUEST_PARAMETER, 1 },
    { PROTO_FTP, FTP_PACKET_RESPONSE_VALUE, 1 },
    { PROTO_NDN, NDN_NAME_COMPONENTS, 2 },
    { PROTO_NDN, NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR, 2 },
    { PROTO_NDN, NDN_INTEREST_EXCLUDE, 2 },
    { PROTO_NDN, NDN_DATA_CONTENT, 2 },
    { PROTO_NDN, NDN_DATA_SIGNATURE_VALUE, 2 },
    { PROTO_NDN, NDN_DATA_FINAL_BLOCK_ID, 2 },
    { PROTO_NDN, NDN_DATA_KEY_LOCATOR, 2 },
};
#define HEAP_ATTRS_NB (sizeof(heap_attrs) / sizeof(heap_attrs[0]))
static const char *heap_family[3] = { "dns", "ftp", "ndn" };
static uint64_t heap_seen[3];
static uint64_t heap_attr_seen[sizeof(heap_attrs) / sizeof(heap_attrs[0])];

static int heap_attrs_cb(const ipacket_t *ipacket, void *args)
{
    (void)args;
    for (int pass = 0; pass < 2; pass++) {   /* a second read re-extracts */
        for (size_t i = 0; i < HEAP_ATTRS_NB; i++) {
            if (get_attribute_extracted_data(ipacket, heap_attrs[i].proto,
                                             heap_attrs[i].attr) != NULL) {
                heap_seen[heap_attrs[i].family]++;
                heap_attr_seen[i]++;
            }
        }
    }
    return 0;
}

/* Issue #506: crafted NDN packets (TLV per the NDN packet format, the
 * types mmt_tcpip decodes) — an Interest with a name, a publisher locator,
 * an exclude filter and a MetaInfo final block id (the extractor looks for
 * it in Interests), and a Data packet with a final block id, content, a key
 * locator and a signature value. */
static const uint8_t ndn_interest[] = {
    0x05, 0x27,
    0x07, 0x0B, 0x08, 0x04, 't', 'e', 's', 't', 0x08, 0x03, 'a', 'b', 'c',
    0x09, 0x0B,
        0x0F, 0x03, 'k', 'e', 'y',
        0x10, 0x04, 0x08, 0x02, 'x', 'y',
    0x0A, 0x04, 0x01, 0x02, 0x03, 0x04,
    0x14, 0x05, 0x1A, 0x03, 0x08, 0x01, '0'
};
static const uint8_t ndn_data[] = {
    0x06, 0x2F,
    0x07, 0x0B, 0x08, 0x04, 't', 'e', 's', 't', 0x08, 0x03, 'a', 'b', 'c',
    0x14, 0x08, 0x18, 0x01, 0x00, 0x1A, 0x03, 0x08, 0x01, '0',
    0x15, 0x05, 'h', 'e', 'l', 'l', 'o',
    0x16, 0x09, 0x1B, 0x01, 0x01, 0x1C, 0x04, 0x07, 0x02, 0x08, 0x00,
    0x17, 0x04, 0xDE, 0xAD, 0xBE, 0xEF
};
/* Error exits: an exclude filter holding a non-name-component TLV, and a
 * Data packet with nothing but a name (no content, key locator or
 * signature value) — each used to leak the TLV nodes it had parsed. */
static const uint8_t ndn_interest_bad_exclude[] = {
    0x05, 0x1A,
    0x07, 0x0B, 0x08, 0x04, 't', 'e', 's', 't', 0x08, 0x03, 'a', 'b', 'c',
    0x09, 0x05, 0x10, 0x03, 0x0A, 0x01, 0x00,
    0x0A, 0x04, 0x01, 0x02, 0x03, 0x04
};
static const uint8_t ndn_data_bare[] = {
    0x06, 0x0D,
    0x07, 0x0B, 0x08, 0x04, 't', 'e', 's', 't', 0x08, 0x03, 'a', 'b', 'c'
};

/* Issue #506: a crafted DNS exchange — the query classifies the flow, the
 * response carries one A answer and one NS authority record (the
 * dns_query.pcap capture holds a lone query). */
static const uint8_t dns_query[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
    0x00, 0x01, 0x00, 0x01
};
static const uint8_t dns_response[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
    0x00, 0x01, 0x00, 0x01,
    0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04,
    93, 184, 216, 34,
    0xC0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x05,
    2, 'n', 's', 0xC0, 0x10
};

/* Ethernet (EtherType 0x8624, NDN over Ethernet) when dport is 0, else
 * Ethernet/IPv4/UDP 10.0.0.1 -> 10.0.0.2 (swapped when reply is set; NDN
 * over UDP is classified by mmt_check_ndn_payload()). */
static unsigned build_frame(uint8_t *f, const uint8_t *payload, unsigned len,
                            unsigned sport, unsigned dport, int reply)
{
    static const uint8_t mac[12] = { 0, 1, 2, 3, 4, 5, 0, 6, 7, 8, 9, 10 };
    memcpy(f, mac, 12);
    if (dport == 0) {
        f[12] = 0x86; f[13] = 0x24;
        memcpy(f + 14, payload, len);
        return 14 + len;
    }
    f[12] = 0x08; f[13] = 0x00;
    uint8_t *ip = f + 14, *udp = ip + 20;
    unsigned ip_len = 20 + 8 + len, udp_len = 8 + len;
    memset(ip, 0, 28);
    ip[0] = 0x45; ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)ip_len;
    ip[8] = 64; ip[9] = 17;
    ip[12] = 10; ip[15] = reply ? 2 : 1; ip[16] = 10; ip[19] = reply ? 1 : 2;
    udp[0] = (uint8_t)(sport >> 8); udp[1] = (uint8_t)sport;
    udp[2] = (uint8_t)(dport >> 8); udp[3] = (uint8_t)dport;
    udp[4] = (uint8_t)(udp_len >> 8); udp[5] = (uint8_t)udp_len;
    memcpy(udp + 8, payload, len);
    return 14 + ip_len;
}

static void replay_crafted_frames(void)
{
    char errbuf[1024];
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    EXPECT(h != NULL, "mmt_init_handler(crafted): %s", errbuf);
    if (h == NULL)
        return;
    for (size_t i = 0; i < HEAP_ATTRS_NB; i++)
        register_extraction_attribute(h, heap_attrs[i].proto, heap_attrs[i].attr);
    register_packet_handler(h, 1, heap_attrs_cb, NULL);
    uint8_t frame[256];
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    for (int k = 0; k < 96; k++) {
        const uint8_t *payload = ndn_interest;
        unsigned len = sizeof(ndn_interest), sport = 40000u + (unsigned)(k % 8), dport = 0;
        int reply = 0;
        switch (k % 8) {
        case 1: dport = 6363; break;                        /* NDN over UDP */
        case 2: payload = ndn_data; len = sizeof(ndn_data); break;
        case 3: payload = ndn_data; len = sizeof(ndn_data); dport = 6363; break;
        case 4:
            payload = dns_query; len = sizeof(dns_query);
            sport = 50000u + (unsigned)k; dport = 53;
            break;
        case 5:
            payload = dns_response; len = sizeof(dns_response);
            sport = 53; dport = 50000u + (unsigned)k - 1; reply = 1;
            break;
        case 6: payload = ndn_interest_bad_exclude; len = sizeof(ndn_interest_bad_exclude); break;
        case 7: payload = ndn_data_bare; len = sizeof(ndn_data_bare); break;
        }
        hdr.ts.tv_sec = 1000 + k;
        hdr.caplen = hdr.len = build_frame(frame, payload, len, sport, dport, reply);
        packet_process(h, &hdr, frame);
    }
    mmt_close_handler(h);
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
    } else if (strcmp(pcase, "non_en10mb_reassembly") == 0) {
        /* #505: reassembled datagrams on the SLL stack, clean_packet path */
        register_extraction_attribute_by_name(h, "META", "PACKET_LEN");
        register_extraction_attribute_by_name(h, "IP", "SRC");
        register_extraction_attribute_by_name(h, "IP", "DST");
    } else if (strcmp(pcase, "extractor_heap_attrs") == 0) {
        /* #506: heap-returning DNS/FTP/NDN attributes, read per packet */
        for (size_t i = 0; i < HEAP_ATTRS_NB; i++)
            register_extraction_attribute(h, heap_attrs[i].proto, heap_attrs[i].attr);
        register_packet_handler(h, 1, heap_attrs_cb, NULL);
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
        "golden_corpus_teardown", "non_en10mb_reassembly",
        "extractor_heap_attrs", NULL
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
        int sll = strcmp(pcase, "non_en10mb_reassembly") == 0;
        if (sll) {
            EXPECT(datalink == DLT_EN10MB, "%s: SLL replay needs an Ethernet capture", argv[i]);
            for (long k = 0; k < npkts; k++) {
                stored_pkt_t cooked = { .data = NULL };
                EXPECT(to_sll(&pkts[k], &cooked), "to_sll(%s #%ld)", argv[i], k);
                if (cooked.data == NULL)
                    continue;
                free(pkts[k].data);
                pkts[k] = cooked;
            }
            datalink = PROTO_SLL;   /* the SLL stack id registered by mmt_tcpip */
        }
        char mmt_errbuf[1024];
        mmt_handler_t *h = mmt_init_handler((uint32_t)datalink, 0, mmt_errbuf);
        if (sll)
            EXPECT(h != NULL, "mmt_init_handler(PROTO_SLL): %s", mmt_errbuf);
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

    if (strcmp(pcase, "extractor_heap_attrs") == 0) {
        replay_crafted_frames();
        for (size_t i = 0; i < HEAP_ATTRS_NB; i++)
            printf("  attribute %u.%u extracted %llu time(s)\n", heap_attrs[i].proto,
                   heap_attrs[i].attr, (unsigned long long)heap_attr_seen[i]);
        for (int f = 0; f < 3; f++) {
            printf("  %s heap attributes extracted: %llu\n", heap_family[f],
                   (unsigned long long)heap_seen[f]);
            EXPECT(heap_seen[f] > 0, "no %s heap attribute was extracted — the case proves nothing",
                   heap_family[f]);
        }
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
