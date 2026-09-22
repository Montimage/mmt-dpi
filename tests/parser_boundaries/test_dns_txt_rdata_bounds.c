/*
 * test_dns_txt_rdata_bounds.c — packet/API-path regression test for issue
 * #378 (F-BUG-004): the TXT answer parser in proto_dns.c must confine every
 * <character-string> field — a length byte plus that many content bytes —
 * to the record's declared RDATA extent (RDLENGTH clamped to captured
 * bytes), not the end of the captured message. A string whose declared
 * length runs past the record rejects (data NULL) instead of consuming
 * the next record's bytes, and the record chain still advances by
 * RDLENGTH so following resource records stay aligned. The extracted
 * value concatenates all field contents — the usual reading of a
 * multi-string TXT (RFC 7208 §3.3).
 *
 *   - headline (acceptance reproducer): RDLENGTH=1 with a string length of
 *     3 and the captured bytes 'a','b','c' following the record — the old
 *     code read them as the TXT value; now the record rejects;
 *   - a malformed first answer followed by a valid second: the malformed
 *     record rejects and the next record parses intact;
 *   - empty, single, multiple and empty-mid-sequence strings with fields
 *     ending exactly at the rdata end;
 *   - a mid-sequence field truncated inside the rdata rejects even when
 *     trailing capture would have fed the old payload_end-bounded read;
 *   - consecutive resource records both extract.
 *
 * The test drives the full public packet path (mmt_init_handler +
 * register_extraction_attribute + packet_process) over crafted
 * Ethernet/IPv4/UDP/DNS responses, then reads the DNS_ANSWERS attribute
 * through get_attribute_extracted_data() inside the packet handler and
 * snapshots the TXT values for assertion. Built with sanitizers by
 * run_tests.sh, so any residual over-read also aborts the run.
 *
 * Build (see run_tests.sh):
 *   gcc -g -O1 -o test_dns_txt_rdata_bounds test_dns_txt_rdata_bounds.c \
 *       -I<repo>/src/mmt_core/{public,private}_include \
 *       -I<repo>/src/mmt_tcpip/{lib,include} -I<repo>/src/mmt_fuzz_engine \
 *       -I<prefix>/dpi/include \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpcap -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mmt_tcpip_plugin_structs.h"   /* struct mmt_tcpip_internal_packet_struct — source tree, not installed */
#include "mmt_tcpip_attributes.h"      /* DNS_* attribute ids */

typedef unsigned char u_char;

/* The DNS_ANSWERS attribute data is a dns_answer_t* list whose layout lives
 * in src/mmt_tcpip/lib/protocols/dns.h — not an installed header. Mirror the
 * struct the test reads back, in the same declaration order as
 * tools/phase0/tests/internal_decls.h mirrors dns_name_t. */
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

/* Values observed per packet — the packet handler snapshots the first two
 * answers' TXT values so the assertions never read attribute memory after
 * packet_process. */
static int      g_pkt_seen;
static int      g_dns_index;     /* index of PROTO_DNS in the hierarchy */
static int      g_answers_seen;  /* DNS_ANSWERS attribute returned non-NULL */
static uint16_t g_answer_type;   /* first answer's RR type */
static int      g_data_present;  /* first answer carried non-NULL data */
static char     g_txt[512];
static int      g_second_seen;   /* a second answer record exists */
static uint16_t g_answer2_type;
static int      g_data2_present;
static char     g_txt2[512];

static void snapshot_txt(char *dst, size_t dst_len, const void *data) {
    dst[0] = '\0';
    if (data != NULL) {
        strncpy(dst, (const char *) data, dst_len - 1);
        dst[dst_len - 1] = '\0';
    }
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    g_pkt_seen = 1;
    g_dns_index = -1;
    g_answers_seen = 0;
    g_answer_type = 0;
    g_data_present = 0;
    g_txt[0] = '\0';
    g_second_seen = 0;
    g_answer2_type = 0;
    g_data2_present = 0;
    g_txt2[0] = '\0';
    if (ipacket->proto_hierarchy != NULL) {
        for (int i = 0; i < ipacket->proto_hierarchy->len; i++) {
            if (ipacket->proto_hierarchy->proto_path[i] == PROTO_DNS)
                g_dns_index = i;
        }
    }
    if (g_dns_index < 0)
        return 0;
    const dns_answer_t *da = (const dns_answer_t *)
        get_attribute_extracted_data(ipacket, PROTO_DNS, DNS_ANSWERS);
    if (da == NULL)
        return 0;
    g_answers_seen = 1;
    g_answer_type = da->type;
    g_data_present = (da->data != NULL);
    snapshot_txt(g_txt, sizeof(g_txt), da->data);
    if (da->next != NULL) {
        g_second_seen = 1;
        g_answer2_type = da->next->type;
        g_data2_present = (da->next->data != NULL);
        snapshot_txt(g_txt2, sizeof(g_txt2), da->next->data);
    }
    return 0;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

static int put_eth(uint8_t *b, uint16_t ethertype) {
    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(b, dst, 6);
    memcpy(b + 6, src, 6);
    put_be16(b + 12, ethertype);
    return 14;
}

static int put_ip4(uint8_t *b, uint8_t proto, uint16_t tot_len) {
    memset(b, 0, 20);
    b[0]  = 0x45;
    put_be16(b + 2, tot_len);
    put_be16(b + 4, 0x1234);
    put_be16(b + 6, 0);
    b[8]  = 64;
    b[9]  = proto;
    b[12] = 10; b[13] = 0; b[14] = 0; b[15] = 1;
    b[16] = 10; b[17] = 0; b[18] = 0; b[19] = 2;
    return 20;
}

static int put_udp(uint8_t *b, uint16_t sport, uint16_t dport, uint16_t len) {
    put_be16(b, sport);
    put_be16(b + 2, dport);
    put_be16(b + 4, len);
    put_be16(b + 6, 0);
    return 8;
}

/* One resource record as laid on the wire: owner name bytes, the fixed
 * TYPE/CLASS/TTL/RDLENGTH fields, then the RDATA bytes actually present in
 * the capture (rdata_present may differ from the declared `rdlength` for
 * truncation fixtures). */
typedef struct {
    const uint8_t *owner;
    size_t         owner_len;
    uint16_t       type;
    uint16_t       rdlength;
    const uint8_t *rdata;
    size_t         rdata_present;
} rr_t;

/* DNS response over UDP that satisfies dns_check_payload()'s second branch:
 * tid is patched to (dns_len - 2) at the end, qdcount's high byte is 0,
 * 0 < ancount <= MMT_MAX_DNS_REQUESTS, nscount = arcount = 0, and the first
 * question bytes — a root qname plus a qtype < 256 — keep the u16 at
 * offset 12 <= MMT_MAX_DNS_REQUESTS.
 *
 *   header(12) | question: 00 qtype qclass (5) | answers: each
 *   owner_name | type | class IN | ttl | rdlength | rdata
 *
 * `trail`/`trail_len` are extra captured bytes appended after the last
 * record — bytes that are in the packet but outside every declared rdata
 * extent. Returns the DNS payload length. */
static int put_dns_response(uint8_t *b, const rr_t *rrs, int n_rrs,
        const uint8_t *trail, size_t trail_len) {
    memset(b, 0, 12);
    put_be16(b + 2, 0x8180);          /* standard response, no error */
    put_be16(b + 4, 1);               /* qdcount */
    put_be16(b + 6, (uint16_t) n_rrs);/* ancount */
    /* question at offset 12: root name, QTYPE A, QCLASS IN */
    b[12] = 0x00;
    put_be16(b + 13, 1);
    put_be16(b + 15, 1);
    int off = 17;
    for (int i = 0; i < n_rrs; i++) {
        memcpy(b + off, rrs[i].owner, rrs[i].owner_len);
        off += (int) rrs[i].owner_len;
        put_be16(b + off, rrs[i].type);
        put_be16(b + off + 2, 1);         /* CLASS IN */
        put_be32(b + off + 4, 60);        /* TTL */
        put_be16(b + off + 8, rrs[i].rdlength);
        off += 10;
        if (rrs[i].rdata_present)
            memcpy(b + off, rrs[i].rdata, rrs[i].rdata_present);
        off += (int) rrs[i].rdata_present;
    }
    if (trail_len) memcpy(b + off, trail, trail_len);
    off += (int) trail_len;
    put_be16(b, (uint16_t)(off - 2)); /* tid = dns_len - 2 for the classifier */
    return off;
}

static void run_packet(mmt_handler_t *h, const uint8_t *data, uint32_t caplen,
        uint32_t wire_len) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec  = 1;
    hdr.ts.tv_usec = 0;
    hdr.caplen     = caplen;
    hdr.len        = wire_len;
    g_pkt_seen = 0;
    g_dns_index = -1;
    g_answers_seen = 0;
    g_answer_type = 0;
    g_data_present = 0;
    g_txt[0] = '\0';
    g_second_seen = 0;
    g_answer2_type = 0;
    g_data2_present = 0;
    g_txt2[0] = '\0';
    packet_process(h, &hdr, data);
}

/* Feed one DNS-answer fixture through the full stack. Afterwards the
 * g_* globals describe what the DNS_ANSWERS attribute reported. */
static void run_dns(mmt_handler_t *h, uint8_t *pkt,
        const rr_t *rrs, int n_rrs,
        const uint8_t *trail, size_t trail_len, uint16_t sport) {
    uint8_t *dns = pkt + 14 + 20 + 8;
    int dns_len = put_dns_response(dns, rrs, n_rrs, trail, trail_len);
    int off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 17, (uint16_t)(20 + 8 + dns_len));
    off += put_udp(pkt + off, sport, 53, (uint16_t)(8 + dns_len));
    off += dns_len;
    run_packet(h, pkt, (uint32_t) off, (uint32_t) off);
}

int main(void) {
    char errbuf[1024];
    uint8_t pkt[512];
    static const uint8_t owner_b[] = {0x01,'b',0x00};   /* literal name "b" at
                                                           DNS offset 17 */
    static const uint8_t owner_z[] = {0x01,'z',0x00};   /* literal name "z"    */

    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);
    /* DNS_ANSWERS is a SCOPE_PACKET attribute: it is only extracted for a
     * handler that registered it for extraction. */
    if (register_extraction_attribute(h, PROTO_DNS, DNS_ANSWERS) != true) {
        fprintf(stderr, "register_extraction_attribute(DNS_ANSWERS) failed\n");
        mmt_close_handler(h);
        close_extraction();
        return 2;
    }

    printf("issue #378: TXT character-strings confined to their RDATA\n");

    /* 1. HEADLINE (acceptance reproducer): RDLENGTH=1 — the rdata holds only
     *    the string-length byte, which declares 3 content bytes — and the
     *    captured bytes 'a','b','c' follow the record. The old code read
     *    them as the TXT value; the record must now reject (data NULL)
     *    instead of consuming bytes outside its RDATA. */
    {
        static const uint8_t rdata[] = {0x03};          /* declares len 3 */
        static const uint8_t trail[] = {'a','b','c'};   /* captured, not rdata */
        const rr_t rr = {owner_b, sizeof(owner_b), 16, 1,
                         rdata, sizeof(rdata)};
        run_dns(h, pkt, &rr, 1, trail, sizeof(trail), 53101);
        CHECK(g_pkt_seen && g_dns_index >= 0,
              "rdlength-short: packet classified as DNS");
        CHECK(g_answers_seen && g_answer_type == 16,
              "rdlength-short: TXT answer header extracted");
        CHECK(g_answers_seen && !g_data_present,
              "rdlength-short: TXT data rejects, \"abc\" not consumed");
        CHECK(!g_second_seen,
              "rdlength-short: single answer, no next record");
    }

    /* 2. Malformed first answer + valid second: the first rdata is a lone
     *    length byte declaring 3 — under the old code it would have
     *    absorbed the second record's owner-name bytes. The record rejects
     *    and the chain still advances by RDLENGTH, so the second TXT
     *    parses intact. */
    {
        static const uint8_t rdata1[] = {0x03};
        static const uint8_t rdata2[] = {0x02,'h','i'};
        const rr_t rrs[2] = {
            {owner_b, sizeof(owner_b), 16, 1, rdata1, sizeof(rdata1)},
            {owner_z, sizeof(owner_z), 16, 3, rdata2, sizeof(rdata2)},
        };
        run_dns(h, pkt, rrs, 2, NULL, 0, 53102);
        CHECK(g_answers_seen && g_answer_type == 16,
              "reject+next: first answer header extracted");
        CHECK(g_answers_seen && !g_data_present,
              "reject+next: malformed first TXT rejects");
        CHECK(g_second_seen && g_answer2_type == 16 && g_data2_present,
              "reject+next: second record parsed, not consumed");
        CHECK(g_data2_present && strcmp(g_txt2, "hi") == 0,
              "reject+next: second TXT value is \"hi\"");
    }

    /* 3. Single string ending exactly at the rdata end. */
    {
        static const uint8_t rdata[] = {0x03,'a','b','c'};
        const rr_t rr = {owner_b, sizeof(owner_b), 16, sizeof(rdata),
                         rdata, sizeof(rdata)};
        run_dns(h, pkt, &rr, 1, NULL, 0, 53103);
        CHECK(g_data_present && strcmp(g_txt, "abc") == 0,
              "single: TXT value is \"abc\"");
    }

    /* 4. Empty character-string: the rdata is a lone zero length byte. */
    {
        static const uint8_t rdata[] = {0x00};
        const rr_t rr = {owner_b, sizeof(owner_b), 16, sizeof(rdata),
                         rdata, sizeof(rdata)};
        run_dns(h, pkt, &rr, 1, NULL, 0, 53104);
        CHECK(g_answers_seen && g_answer_type == 16 && g_data_present,
              "empty: TXT data present");
        CHECK(g_data_present && g_txt[0] == '\0',
              "empty: TXT value is the empty string");
    }

    /* 5. Multiple strings: "abc" then "hello" tile the rdata exactly —
     *    the extracted value concatenates the field contents. */
    {
        static const uint8_t rdata[] = {0x03,'a','b','c',0x05,'h','e','l','l','o'};
        const rr_t rr = {owner_b, sizeof(owner_b), 16, sizeof(rdata),
                         rdata, sizeof(rdata)};
        run_dns(h, pkt, &rr, 1, NULL, 0, 53105);
        CHECK(g_data_present && strcmp(g_txt, "abchello") == 0,
              "multi: TXT value is \"abchello\"");
    }

    /* 6. Empty string mid-sequence: "abc" + "" + "hi". */
    {
        static const uint8_t rdata[] = {0x03,'a','b','c',0x00,0x02,'h','i'};
        const rr_t rr = {owner_b, sizeof(owner_b), 16, sizeof(rdata),
                         rdata, sizeof(rdata)};
        run_dns(h, pkt, &rr, 1, NULL, 0, 53106);
        CHECK(g_data_present && strcmp(g_txt, "abchi") == 0,
              "multi+empty: TXT value is \"abchi\"");
    }

    /* 7. Malformed mid-sequence field: "abc" is well-formed, then a field
     *    declares 5 content bytes with only 2 left inside the rdata — and
     *    3 trailing captured bytes would have fed the old
     *    payload_end-bounded read. The record rejects. */
    {
        static const uint8_t rdata[] = {0x03,'a','b','c',0x05,'h','e'};
        static const uint8_t trail[] = {'X','Y','Z'};   /* captured, not rdata */
        const rr_t rr = {owner_b, sizeof(owner_b), 16, sizeof(rdata),
                         rdata, sizeof(rdata)};
        run_dns(h, pkt, &rr, 1, trail, sizeof(trail), 53107);
        CHECK(g_answers_seen && g_answer_type == 16,
              "truncated field: answer header still parsed");
        CHECK(g_answers_seen && !g_data_present,
              "truncated field: TXT data rejects");
    }

    /* 8. Declared string runs past RDLENGTH but stays inside the capture:
     *    field declares 8, the rdata holds 3 content bytes, the next 5 are
     *    the following record's bytes — must reject, not absorb them. */
    {
        static const uint8_t rdata[] = {0x08,'a','b','c'};
        static const uint8_t trail[] = {'d','e','f','g','h'};
        const rr_t rr = {owner_b, sizeof(owner_b), 16, sizeof(rdata),
                         rdata, sizeof(rdata)};
        run_dns(h, pkt, &rr, 1, trail, sizeof(trail), 53108);
        CHECK(g_answers_seen && !g_data_present,
              "past-rdlength: TXT data rejects despite captured tail");
    }

    /* 9. Consecutive valid records: two TXT answers extract in order. */
    {
        static const uint8_t rdata1[] = {0x03,'a','b','c'};
        static const uint8_t rdata2[] = {0x05,'h','e','l','l','o'};
        const rr_t rrs[2] = {
            {owner_b, sizeof(owner_b), 16, sizeof(rdata1), rdata1, sizeof(rdata1)},
            {owner_z, sizeof(owner_z), 16, sizeof(rdata2), rdata2, sizeof(rdata2)},
        };
        run_dns(h, pkt, rrs, 2, NULL, 0, 53109);
        CHECK(g_data_present && strcmp(g_txt, "abc") == 0,
              "consecutive: first TXT is \"abc\"");
        CHECK(g_second_seen && g_data2_present && strcmp(g_txt2, "hello") == 0,
              "consecutive: second TXT is \"hello\"");
    }

    /* 10. RDLENGTH=0: no rdata at all — header parses, data stays NULL. */
    {
        const rr_t rr = {owner_b, sizeof(owner_b), 16, 0, NULL, 0};
        run_dns(h, pkt, &rr, 1, NULL, 0, 53110);
        CHECK(g_answers_seen && g_answer_type == 16 && !g_data_present,
              "empty rdata: header parsed, no data");
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
