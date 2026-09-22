/*
 * test_dns_soa_consumed_bytes.c — packet/API-path regression test for issue
 * #377 (F-BUG-003): the SOA answer parser in proto_dns.c must advance by each
 * name's consumed wire length — literal labels plus the root terminator, or
 * the two bytes of a compression pointer — not by real_length, which is one
 * byte short for terminator-ended names (and whose is_ref shortcut counted
 * a pointer as 1, not 2). Every step is bounded by the declared rdata
 * extent, so truncated records reject instead of sliding into the next
 * record's bytes.
 *
 *   - headline: primary "a" (literal), mailbox "b" (compressed pointer to
 *     the answer owner name) and serial 42 come back exactly;
 *   - mixed compression ("x" + pointer) and a fully-compressed primary name
 *     parse with the right advancement;
 *   - self/out-of-range pointer targets decode as empty names while the
 *     record stays aligned (cycles reject safely);
 *   - the five 32-bit fields must fit inside RDLENGTH — trailing captured
 *     bytes past the record are not field data;
 *   - a name truncated inside the rdata rejects the record (data NULL).
 *
 * The test drives the full public packet path (mmt_init_handler +
 * register_extraction_attribute + packet_process) over crafted
 * Ethernet/IPv4/UDP/DNS responses, then reads the DNS_ANSWERS attribute
 * through get_attribute_extracted_data() inside the packet handler and
 * snapshots the SOA fields for assertion. Built with sanitizers by
 * run_tests.sh, so any residual over-read also aborts the run.
 *
 * Build (see run_tests.sh):
 *   gcc -g -O1 -o test_dns_soa_consumed_bytes test_dns_soa_consumed_bytes.c \
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
 * two structs the test reads back, in the same declaration order as
 * tools/phase0/tests/internal_decls.h mirrors dns_name_t. */
typedef struct dns_answer_soa_struct {
    char * soa_pri_server;
    char * soa_mail_box;
    uint64_t soa_serial_number;
    uint64_t soa_refresh_interval;
    uint64_t soa_retry_interval;
    uint64_t soa_expire_limit;
    uint64_t soa_min_ttl;
} dns_answer_soa_t;

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

/* Values observed per packet — the packet handler snapshots the SOA fields
 * so the assertions never read attribute memory after packet_process. */
static int      g_pkt_seen;
static int      g_dns_index;     /* index of PROTO_DNS in the hierarchy */
static int      g_answers_seen;  /* DNS_ANSWERS attribute returned non-NULL */
static uint16_t g_answer_type;   /* first answer's RR type */
static int      g_soa_present;   /* first answer carried a parsed SOA record */
static char     g_pri[256];
static char     g_box[256];
static uint64_t g_serial, g_refresh, g_retry, g_expire, g_minttl;

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    g_pkt_seen = 1;
    g_dns_index = -1;
    g_answers_seen = 0;
    g_answer_type = 0;
    g_soa_present = 0;
    g_pri[0] = g_box[0] = '\0';
    g_serial = g_refresh = g_retry = g_expire = g_minttl = 0;
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
    if (da->type == 6 && da->data != NULL) {
        const dns_answer_soa_t *s = (const dns_answer_soa_t *) da->data;
        g_soa_present = 1;
        if (s->soa_pri_server != NULL) {
            strncpy(g_pri, s->soa_pri_server, sizeof(g_pri) - 1);
            g_pri[sizeof(g_pri) - 1] = '\0';
        }
        if (s->soa_mail_box != NULL) {
            strncpy(g_box, s->soa_mail_box, sizeof(g_box) - 1);
            g_box[sizeof(g_box) - 1] = '\0';
        }
        g_serial  = s->soa_serial_number;
        g_refresh = s->soa_refresh_interval;
        g_retry   = s->soa_retry_interval;
        g_expire  = s->soa_expire_limit;
        g_minttl  = s->soa_min_ttl;
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

/* The five 32-bit SOA fields: serial, refresh, retry, expire, minimum TTL. */
static int put_soa_ints(uint8_t *b, uint32_t serial, uint32_t refresh,
        uint32_t retry, uint32_t expire, uint32_t minttl) {
    put_be32(b, serial);
    put_be32(b + 4, refresh);
    put_be32(b + 8, retry);
    put_be32(b + 12, expire);
    put_be32(b + 16, minttl);
    return 20;
}

/* DNS response over UDP that satisfies dns_check_payload()'s second branch:
 * tid is patched to (dns_len - 2) at the end, qdcount's high byte is 0,
 * ancount = 1, nscount = arcount = 0, and the first question bytes — a root
 * qname plus a qtype < 256 — keep the u16 at offset 12 <= MMT_MAX_DNS_REQUESTS.
 *
 *   header(12) | question: 00 qtype qclass (5) | answer:
 *   owner_name | type SOA | class IN | ttl | rdlength | rdata
 *
 * `owner`/`owner_len` is the answer owner name as raw wire bytes, `rdata` the
 * RDATA bytes actually present in the capture, `rdlength` the declared
 * RDLENGTH (may differ from what is present for truncation fixtures), and
 * `trail`/`trail_len` extra captured bytes appended after the record —
 * bytes that are in the packet but outside the declared rdata extent.
 * Returns the DNS payload length. */
static int put_dns_response(uint8_t *b,
        const uint8_t *owner, size_t owner_len,
        const uint8_t *rdata, size_t rdata_present, uint16_t rdlength,
        const uint8_t *trail, size_t trail_len) {
    memset(b, 0, 12);
    put_be16(b + 2, 0x8180);          /* standard response, no error */
    put_be16(b + 4, 1);               /* qdcount */
    put_be16(b + 6, 1);               /* ancount */
    /* question at offset 12: root name, QTYPE A, QCLASS IN */
    b[12] = 0x00;
    put_be16(b + 13, 1);
    put_be16(b + 15, 1);
    int off = 17;
    memcpy(b + off, owner, owner_len);
    off += (int) owner_len;
    put_be16(b + off, 6);             /* TYPE SOA */
    put_be16(b + off + 2, 1);         /* CLASS IN */
    put_be32(b + off + 4, 60);        /* TTL */
    put_be16(b + off + 8, rdlength);
    off += 10;
    memcpy(b + off, rdata, rdata_present);
    off += (int) rdata_present;
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
    g_soa_present = 0;
    g_pri[0] = g_box[0] = '\0';
    g_serial = g_refresh = g_retry = g_expire = g_minttl = 0;
    packet_process(h, &hdr, data);
}

/* Feed one SOA-answer fixture through the full stack. Afterwards the
 * g_* globals describe what the DNS_ANSWERS attribute reported. */
static void run_soa(mmt_handler_t *h, uint8_t *pkt,
        const uint8_t *owner, size_t owner_len,
        const uint8_t *rdata, size_t rdata_present, uint16_t rdlength,
        const uint8_t *trail, size_t trail_len, uint16_t sport) {
    uint8_t *dns = pkt + 14 + 20 + 8;
    int dns_len = put_dns_response(dns, owner, owner_len, rdata,
            rdata_present, rdlength, trail, trail_len);
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

    printf("issue #377: SOA names advance by consumed wire bytes\n");

    /* 1. HEADLINE (acceptance reproducer): literal primary "a" — consumes
     *    its root terminator — plus compressed mailbox "b" pointing at the
     *    owner name — consumes the entire 2-byte pointer — then serial 42. */
    {
        uint8_t rdata[3 + 2 + 20], *r = rdata;
        memcpy(r, "\x01" "a" "\x00", 3); r += 3;   /* primary "a" literal   */
        memcpy(r, "\xC0\x11", 2);        r += 2;   /* mailbox -> owner "b"  */
        r += put_soa_ints(r, 42, 1, 2, 3, 4);
        run_soa(h, pkt, owner_b, sizeof(owner_b),
                rdata, sizeof(rdata), sizeof(rdata), NULL, 0, 53001);
        CHECK(g_pkt_seen && g_dns_index >= 0,
              "literal+ptr: packet classified as DNS");
        CHECK(g_answers_seen && g_answer_type == 6,
              "literal+ptr: SOA answer extracted");
        CHECK(g_soa_present && strcmp(g_pri, "a") == 0,
              "literal+ptr: primary name is \"a\"");
        CHECK(g_soa_present && strcmp(g_box, "b") == 0,
              "literal+ptr: mailbox name is \"b\"");
        CHECK(g_soa_present && g_serial == 42,
              "literal+ptr: serial is exactly 42");
        CHECK(g_soa_present && g_refresh == 1 && g_retry == 2
              && g_expire == 3 && g_minttl == 4,
              "literal+ptr: refresh/retry/expire/minTTL aligned after names");
    }

    /* 2. Mixed compression: primary "x" + pointer -> "x.b" (4 wire bytes),
     *    mailbox a bare pointer -> "b" (2 wire bytes). */
    {
        uint8_t rdata[4 + 2 + 20], *r = rdata;
        memcpy(r, "\x01" "x" "\xC0\x11", 4); r += 4;
        memcpy(r, "\xC0\x11", 2);            r += 2;
        r += put_soa_ints(r, 43, 5, 6, 7, 8);
        run_soa(h, pkt, owner_b, sizeof(owner_b),
                rdata, sizeof(rdata), sizeof(rdata), NULL, 0, 53002);
        CHECK(g_soa_present && strcmp(g_pri, "x.b") == 0,
              "mixed: primary name is \"x.b\"");
        CHECK(g_soa_present && strcmp(g_box, "b") == 0,
              "mixed: mailbox name is \"b\"");
        CHECK(g_soa_present && g_serial == 43,
              "mixed: serial is exactly 43");
    }

    /* 3. Fully-compressed primary (2 wire bytes) + literal mailbox. */
    {
        uint8_t rdata[2 + 3 + 20], *r = rdata;
        memcpy(r, "\xC0\x11", 2);        r += 2;   /* primary -> owner "b"  */
        memcpy(r, "\x01" "a" "\x00", 3); r += 3;   /* mailbox "a" literal   */
        r += put_soa_ints(r, 44, 9, 10, 11, 12);
        run_soa(h, pkt, owner_b, sizeof(owner_b),
                rdata, sizeof(rdata), sizeof(rdata), NULL, 0, 53003);
        CHECK(g_soa_present && strcmp(g_pri, "b") == 0,
              "compressed primary: name is \"b\"");
        CHECK(g_soa_present && strcmp(g_box, "a") == 0,
              "compressed primary: mailbox is \"a\"");
        CHECK(g_soa_present && g_serial == 44,
              "compressed primary: serial is exactly 44");
    }

    /* 4. Cycle: the primary name is a pointer to its own position (rdata
     *    starts at DNS offset 30 = 0x1E). Decode rejects the self target so
     *    the name is empty, but the 2 pointer bytes are consumed and the
     *    record stays aligned. */
    {
        uint8_t rdata[2 + 3 + 20], *r = rdata;
        memcpy(r, "\xC0\x1E", 2);        r += 2;   /* primary -> itself     */
        memcpy(r, "\x01" "b" "\x00", 3); r += 3;   /* mailbox "b" literal   */
        r += put_soa_ints(r, 45, 13, 14, 15, 16);
        run_soa(h, pkt, owner_b, sizeof(owner_b),
                rdata, sizeof(rdata), sizeof(rdata), NULL, 0, 53004);
        CHECK(g_answers_seen && g_answer_type == 6 && g_soa_present,
              "self-pointer: record still parsed, no crash");
        CHECK(g_soa_present && g_pri[0] == '\0',
              "self-pointer: primary decodes empty");
        CHECK(g_soa_present && strcmp(g_box, "b") == 0,
              "self-pointer: mailbox \"b\" stays aligned");
        CHECK(g_soa_present && g_serial == 45,
              "self-pointer: serial is exactly 45");
    }

    /* 5. Out-of-range target: pointer offset 255 is past this ~55-byte
     *    payload — empty decode, record stays aligned. */
    {
        uint8_t rdata[2 + 3 + 20], *r = rdata;
        memcpy(r, "\xC0\xFF", 2);        r += 2;   /* primary -> offset 255 */
        memcpy(r, "\x01" "b" "\x00", 3); r += 3;
        r += put_soa_ints(r, 46, 17, 18, 19, 20);
        run_soa(h, pkt, owner_b, sizeof(owner_b),
                rdata, sizeof(rdata), sizeof(rdata), NULL, 0, 53005);
        CHECK(g_soa_present, "out-of-range pointer: no crash");
        CHECK(g_soa_present && g_pri[0] == '\0',
              "out-of-range pointer: primary decodes empty");
        CHECK(g_soa_present && g_serial == 46,
              "out-of-range pointer: serial is exactly 46");
    }

    /* 6. RDLENGTH cuts the fields short: names occupy 5 of the declared 8
     *    rdata bytes, leaving 3 for the 20-byte integer block — it must NOT
     *    be filled from the 20 captured bytes trailing the record. */
    {
        uint8_t rdata[8], *r = rdata;
        memcpy(r, "\x01" "a" "\x00", 3); r += 3;
        memcpy(r, "\xC0\x11", 2);        r += 2;
        memset(r, 0, 3);                 r += 3;   /* only 3 field bytes fit */
        uint8_t trail[20];
        memset(trail, 0x42, sizeof(trail));        /* captured, not rdata */
        run_soa(h, pkt, owner_b, sizeof(owner_b),
                rdata, sizeof(rdata), 8 /* rdlength */, trail, sizeof(trail),
                53006);
        CHECK(g_soa_present, "short rdlength: names still extracted");
        CHECK(g_soa_present && strcmp(g_pri, "a") == 0,
              "short rdlength: primary \"a\"");
        CHECK(g_soa_present && strcmp(g_box, "b") == 0,
              "short rdlength: mailbox \"b\"");
        CHECK(g_soa_present && g_serial == 0,
              "short rdlength: fields not read past the rdata extent");
    }

    /* 7. Name truncated inside the rdata: mailbox label declares 2 content
     *    bytes with only 1 present — the record rejects (data NULL). */
    {
        uint8_t rdata[5], *r = rdata;
        memcpy(r, "\x01" "a" "\x00", 3); r += 3;
        memcpy(r, "\x02" "b", 2);        r += 2;   /* truncated mailbox */
        run_soa(h, pkt, owner_b, sizeof(owner_b),
                rdata, sizeof(rdata), sizeof(rdata), NULL, 0, 53007);
        CHECK(g_answers_seen && g_answer_type == 6,
              "truncated name: answer header still parsed");
        CHECK(g_answers_seen && !g_soa_present,
              "truncated name: SOA data rejected");
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
