/*
 * test_dns_mixed_name_length.c — packet/API-path regression test for issue
 * #409: dns_extract_queries() and dns_extract_answers() in proto_dns.c must
 * advance past an owner name by its consumed wire length. The old
 * real_length + 1 convention was exact for terminator-ended and pure-pointer
 * names but one byte too long for a mixed name — literal labels followed by
 * a compression pointer — so every following field and record was read one
 * byte late.
 *
 *   - question section: a mixed second question ("x" + pointer) keeps its
 *     QTYPE/QCLASS, and the answer that follows it is located correctly
 *     (the answers offset sums each question's qlength);
 *   - answer section: a mixed owner name on the first answer keeps its
 *     TYPE/RDATA and the second answer stays aligned;
 *   - control: terminator-ended and pure-pointer names keep parsing as
 *     before;
 *   - a name truncated by the end of the packet stops the chain without reading the
 *     fixed fields from inside the name.
 *
 * The test drives the full public packet path (mmt_init_handler +
 * register_extraction_attribute + packet_process) over crafted
 * Ethernet/IPv4/UDP/DNS responses and reads DNS_QUERIES / DNS_ANSWERS back
 * through get_attribute_extracted_data() inside the packet handler. Built
 * with sanitizers by run_tests.sh, so any residual over-read aborts the run.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mmt_tcpip_plugin_structs.h"   /* source tree, not installed */
#include "mmt_tcpip_attributes.h"      /* DNS_* attribute ids */

/* Mirrors of the dns.h layouts (not an installed header), same declaration
 * order as src/mmt_tcpip/lib/protocols/dns.h. */
typedef struct dns_query_struct {
    char *name;
    uint16_t type;
    uint16_t qclass;
    uint16_t qlength;
    struct dns_query_struct *next;
} dns_query_t;

typedef struct dns_answer_struct {
    char *name;
    uint16_t type;
    uint16_t aclass;
    uint64_t a_ttl;
    uint16_t a_length;
    uint16_t data_length;
    void * data;
    struct dns_answer_struct *next;
} dns_answer_t;

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

#define MAX_RECS 4

/* Per-packet snapshot of what the attributes reported. */
typedef struct {
    char     name[64];
    uint16_t type;
    uint16_t cls;
    uint16_t len;          /* qlength / a_length */
    uint16_t data_length;
    uint8_t  rdata[4];     /* first bytes of an A record's data */
    int      has_data;
} rec_t;

static int   g_dns_seen;
static int   g_nq, g_na;
static rec_t g_q[MAX_RECS], g_a[MAX_RECS];

static void snap_name(char *dst, const char *src) {
    dst[0] = '\0';
    if (src != NULL) {
        strncpy(dst, src, 63);
        dst[63] = '\0';
    }
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    int dns = 0;
    if (ipacket->proto_hierarchy != NULL) {
        for (int i = 0; i < ipacket->proto_hierarchy->len; i++)
            if (ipacket->proto_hierarchy->proto_path[i] == PROTO_DNS)
                dns = 1;
    }
    g_dns_seen = dns;
    if (!dns)
        return 0;
    const dns_query_t *q = (const dns_query_t *)
        get_attribute_extracted_data(ipacket, PROTO_DNS, DNS_QUERIES);
    for (; q != NULL && g_nq < MAX_RECS; q = q->next, g_nq++) {
        snap_name(g_q[g_nq].name, q->name);
        g_q[g_nq].type = q->type;
        g_q[g_nq].cls  = q->qclass;
        g_q[g_nq].len  = q->qlength;
    }
    const dns_answer_t *a = (const dns_answer_t *)
        get_attribute_extracted_data(ipacket, PROTO_DNS, DNS_ANSWERS);
    for (; a != NULL && g_na < MAX_RECS; a = a->next, g_na++) {
        snap_name(g_a[g_na].name, a->name);
        g_a[g_na].type = a->type;
        g_a[g_na].cls  = a->aclass;
        g_a[g_na].len  = a->a_length;
        g_a[g_na].data_length = a->data_length;
        if (a->type == 1 && a->data_length == 4 && a->data != NULL) {
            memcpy(g_a[g_na].rdata, a->data, 4);
            g_a[g_na].has_data = 1;
        }
    }
    return 0;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static size_t put_bytes(uint8_t *b, const void *src, size_t n) {
    memcpy(b, src, n);
    return n;
}

/* QTYPE A, QCLASS IN */
static size_t put_qtail(uint8_t *b) {
    put_be16(b, 1);
    put_be16(b + 2, 1);
    return 4;
}

/* TYPE A, CLASS IN, TTL 60, RDLENGTH 4, address a.b.c.d */
static size_t put_a_rr(uint8_t *b, uint8_t a0, uint8_t a1, uint8_t a2,
        uint8_t a3) {
    put_be16(b, 1);
    put_be16(b + 2, 1);
    b[4] = 0; b[5] = 0; b[6] = 0; b[7] = 60;
    put_be16(b + 8, 4);
    b[10] = a0; b[11] = a1; b[12] = a2; b[13] = a3;
    return 14;
}

/* DNS response header satisfying dns_check_payload()'s second branch: tid is
 * patched to (dns_len - 2) by run_dns(), the first question must be a root
 * name so the u16 at offset 12 stays <= MMT_MAX_DNS_REQUESTS. */
static size_t put_hdr(uint8_t *b, uint16_t qd, uint16_t an) {
    memset(b, 0, 12);
    put_be16(b + 2, 0x8180);
    put_be16(b + 4, qd);
    put_be16(b + 6, an);
    return 12;
}

static void run_dns(mmt_handler_t *h, uint8_t *pkt, size_t dns_len,
        uint16_t sport) {
    uint8_t *dns = pkt + 42;
    put_be16(dns, (uint16_t)(dns_len - 2));
    /* Ethernet */
    static const uint8_t macs[12] = {0x00,0x11,0x22,0x33,0x44,0x55,
                                     0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(pkt, macs, 12);
    put_be16(pkt + 12, 0x0800);
    /* IPv4 */
    uint8_t *ip = pkt + 14;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    put_be16(ip + 2, (uint16_t)(20 + 8 + dns_len));
    put_be16(ip + 4, 0x1234);
    ip[8] = 64; ip[9] = 17;
    ip[12] = 10; ip[15] = 1; ip[16] = 10; ip[19] = 2;
    /* UDP */
    uint8_t *udp = pkt + 34;
    put_be16(udp, sport);
    put_be16(udp + 2, 53);
    put_be16(udp + 4, (uint16_t)(8 + dns_len));
    put_be16(udp + 6, 0);

    uint32_t len = (uint32_t)(42 + dns_len);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = 1;
    hdr.caplen = len;
    hdr.len    = len;
    g_dns_seen = 0;
    g_nq = g_na = 0;
    memset(g_q, 0, sizeof(g_q));
    memset(g_a, 0, sizeof(g_a));
    /* Copy into an exactly caplen-sized heap buffer so ASan catches any read
     * past the capture. */
    uint8_t *cap = malloc(hdr.caplen);
    if (cap == NULL) { perror("malloc"); exit(2); }
    memcpy(cap, pkt, hdr.caplen);
    packet_process(h, &hdr, cap);
    free(cap);
}

int main(void) {
    char errbuf[1024];
    uint8_t pkt[512];

    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);
    if (register_extraction_attribute(h, PROTO_DNS, DNS_QUERIES) != true ||
        register_extraction_attribute(h, PROTO_DNS, DNS_ANSWERS) != true) {
        fprintf(stderr, "register_extraction_attribute failed\n");
        mmt_close_handler(h);
        close_extraction();
        return 2;
    }

    printf("issue #409: question/answer names advance by consumed wire bytes\n");

    /* 1. Mixed name in the question section.
     *    DNS offset 12: q1 root name        00 | A IN
     *    DNS offset 17: q2 "x" + ptr -> 12  01 'x' C0 0C | A IN  (4 name bytes)
     *    DNS offset 25: answer "b"          01 'b' 00 | A IN 60 4 | 1.2.3.4 */
    {
        uint8_t *d = pkt + 42;
        size_t o = put_hdr(d, 2, 1);
        d[o++] = 0x00;                         o += put_qtail(d + o);
        o += put_bytes(d + o, "\x01" "x" "\xC0\x0C", 4);
        o += put_qtail(d + o);
        o += put_bytes(d + o, "\x01" "b" "\x00", 3);
        o += put_a_rr(d + o, 1, 2, 3, 4);
        run_dns(h, pkt, o, 54001);
        CHECK(g_dns_seen, "mixed question: packet classified as DNS");
        CHECK(g_nq == 2, "mixed question: both questions extracted");
        CHECK(g_nq == 2 && strcmp(g_q[1].name, "x") == 0,
              "mixed question: second name is \"x\"");
        CHECK(g_nq == 2 && g_q[1].type == 1 && g_q[1].cls == 1,
              "mixed question: QTYPE/QCLASS read at the right offset");
        CHECK(g_nq == 2 && g_q[1].len == 8,
              "mixed question: qlength is 4 name bytes + 4");
        CHECK(g_na == 1 && strcmp(g_a[0].name, "b") == 0 && g_a[0].type == 1,
              "mixed question: following answer located exactly");
        CHECK(g_na == 1 && g_a[0].has_data && g_a[0].rdata[0] == 1
              && g_a[0].rdata[3] == 4,
              "mixed question: following answer address 1.2.3.4");
    }

    /* 2. Mixed owner name in the answer section.
     *    DNS offset 12: q1 root name
     *    DNS offset 17: an1 "x" + ptr -> 12 | A IN 60 4 | 5.6.7.8
     *    DNS offset 35: an2 ptr -> 17       | A IN 60 4 | 9.10.11.12 */
    {
        uint8_t *d = pkt + 42;
        size_t o = put_hdr(d, 1, 2);
        d[o++] = 0x00;                         o += put_qtail(d + o);
        o += put_bytes(d + o, "\x01" "x" "\xC0\x0C", 4);
        o += put_a_rr(d + o, 5, 6, 7, 8);
        o += put_bytes(d + o, "\xC0\x11", 2);
        o += put_a_rr(d + o, 9, 10, 11, 12);
        run_dns(h, pkt, o, 54002);
        CHECK(g_na == 2, "mixed owner: both answers extracted");
        CHECK(g_na >= 1 && strcmp(g_a[0].name, "x") == 0 && g_a[0].type == 1
              && g_a[0].cls == 1,
              "mixed owner: first answer TYPE/CLASS at the right offset");
        CHECK(g_na >= 1 && g_a[0].has_data && g_a[0].rdata[0] == 5
              && g_a[0].rdata[3] == 8,
              "mixed owner: first answer address 5.6.7.8");
        CHECK(g_na >= 1 && g_a[0].len == 18,
              "mixed owner: a_length is 4 name bytes + 10 + 4");
        CHECK(g_na == 2 && strcmp(g_a[1].name, "x") == 0 && g_a[1].type == 1,
              "mixed owner: second answer stays aligned");
        CHECK(g_na == 2 && g_a[1].has_data && g_a[1].rdata[0] == 9
              && g_a[1].rdata[3] == 12,
              "mixed owner: second answer address 9.10.11.12");
    }

    /* 3. Control: terminator-ended ("a.b") and pure-pointer owner names —
     *    already exact under the old convention — keep parsing unchanged. */
    {
        uint8_t *d = pkt + 42;
        size_t o = put_hdr(d, 1, 2);
        d[o++] = 0x00;                         o += put_qtail(d + o);
        o += put_bytes(d + o, "\x01" "a" "\x01" "b" "\x00", 5);
        o += put_a_rr(d + o, 13, 14, 15, 16);
        o += put_bytes(d + o, "\xC0\x11", 2);
        o += put_a_rr(d + o, 17, 18, 19, 20);
        run_dns(h, pkt, o, 54003);
        CHECK(g_nq == 1 && g_q[0].len == 5,
              "control: root question qlength is 5");
        CHECK(g_na == 2 && strcmp(g_a[0].name, "a.b") == 0
              && g_a[0].len == 19 && g_a[0].has_data && g_a[0].rdata[0] == 13,
              "control: literal owner \"a.b\" parses as before");
        CHECK(g_na == 2 && strcmp(g_a[1].name, "a.b") == 0
              && g_a[1].len == 16 && g_a[1].has_data && g_a[1].rdata[0] == 17,
              "control: pointer owner parses as before");
    }

    /* 4. Truncated name: the second answer's owner label declares 63
     *    content bytes but the packet ends 12 bytes in — enough bytes for the
     *    old code to read TYPE..RDLENGTH from inside the label. The name is
     *    now taken to consume the rest of the capture: the chain stops and
     *    no field is read from inside (or past) the name. */
    {
        uint8_t *d = pkt + 42;
        size_t o = put_hdr(d, 1, 2);
        d[o++] = 0x00;                         o += put_qtail(d + o);
        o += put_bytes(d + o, "\x01" "a" "\x00", 3);
        o += put_a_rr(d + o, 21, 22, 23, 24);
        d[o++] = 0x3f;
        memset(d + o, 'A', 12);                o += 12;
        run_dns(h, pkt, o, 54004);
        CHECK(g_na >= 1 && g_a[0].has_data && g_a[0].rdata[0] == 21,
              "truncated: first answer intact");
        CHECK(g_na < 2 || (g_a[1].type == 0 && !g_a[1].has_data),
              "truncated: no fields read from the cut name");
    }

    mmt_close_handler(h);
    close_extraction();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
