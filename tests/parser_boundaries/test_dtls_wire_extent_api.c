/*
 * test_dtls_wire_extent_api.c — packet/API-path regression test for issue
 * #376 (F-BUG-001 follow-up): the central wire-extent guard must not refuse
 * an extractor whose declared data_len is the OUTPUT capacity, larger than
 * the captured wire bytes it actually reads.
 *
 *   - the valid 67-byte DTLS ClientHello over Ethernet/IPv4/UDP must
 *     extract one cipher 0x1301 through the normal API even though the
 *     attribute's result capacity is the 132-byte mmt_u16_array_t;
 *   - truncated ClientHello fields and a cipher list larger than the
 *     64-entry output array reject/clamp safely;
 *   - the direct extractor call (_dtls_extract_attribute on the live
 *     ipacket) and the normal API must agree on every fixture.
 *
 * The test drives the full public packet path (mmt_init_handler +
 * register_attribute_handler + packet_process) and, inside the packet
 * handler, cross-checks the registered attribute-handler result against
 * get_attribute_extracted_data() and a direct _dtls_extract_attribute()
 * call on the same ipacket. Built with sanitizers by run_tests.sh, so any
 * residual over-read also aborts the run.
 *
 * Build (see run_tests.sh):
 *   gcc -g -O1 -o test_dtls_wire_extent_api test_dtls_wire_extent_api.c \
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
#include "mmt_tcpip_attributes.h"      /* DTLS_* attribute ids + content types */
#include "types_defs.h"                /* mmt_u16_array_t, BINARY_64DATA_LEN */

typedef unsigned char u_char;

/* Internal seam: the DTLS attribute extractor, exported non-static for the
 * crafted-input harnesses (same declaration as
 * tools/phase0/tests/internal_decls.h). */
int _dtls_extract_attribute(const ipacket_t *ipacket, unsigned proto_index,
        attribute_t *extracted_data);

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

/* Values observed per packet. */
static int      g_pkt_seen;
static int      g_dtls_index;          /* index of PROTO_DTLS in the hierarchy, -1 if absent */
static int      g_attr_fired;          /* registered attribute handler fired */
static uint32_t g_attr_len;            /* mmt_u16_array_t.len snapshot */
static uint16_t g_attr_first;          /* first cipher value */
static uint16_t g_attr_last;           /* last published cipher value */
static int      g_normal_set;          /* get_attribute_extracted_data returned non-NULL */
static uint32_t g_normal_len;
static int      g_direct_rc;           /* direct _dtls_extract_attribute verdict */
static uint32_t g_direct_len;

/* Registered attribute handler: fires only when the central guard let the
 * extractor run AND the extractor reported the attribute set. */
static void cipher_attr_handler(const ipacket_t *ipacket, attribute_t *attribute,
        void *user_args) {
    (void) ipacket; (void) user_args;
    const mmt_u16_array_t *arr = (const mmt_u16_array_t *) attribute->data;
    g_attr_fired = 1;
    g_attr_len = arr->len;
    g_attr_first = arr->len ? arr->data[0] : 0;
    g_attr_last = arr->len ? arr->data[arr->len - 1] : 0;
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    g_pkt_seen = 1;
    g_dtls_index = -1;
    if (ipacket->proto_hierarchy != NULL) {
        for (int i = 0; i < ipacket->proto_hierarchy->len; i++) {
            if (ipacket->proto_hierarchy->proto_path[i] == PROTO_DTLS)
                g_dtls_index = i;
        }
    }
    if (g_dtls_index < 0) {
        g_normal_set = 0;
        g_direct_rc = -1;
        return 0;
    }

    /* Normal on-demand API. */
    const mmt_u16_array_t *arr = (const mmt_u16_array_t *)
        get_attribute_extracted_data(ipacket, PROTO_DTLS,
                DTLS_CLIENT_HELLO_CIPHER_SUITE);
    g_normal_set = (arr != NULL);
    g_normal_len = arr ? arr->len : 0;

    /* Direct extractor call on the same live ipacket. */
    attribute_t a;
    mmt_u16_array_t out;
    memset(&a, 0, sizeof(a));
    memset(&out, 0, sizeof(out));
    a.field_id = DTLS_CLIENT_HELLO_CIPHER_SUITE;
    a.data = &out;
    g_direct_rc = _dtls_extract_attribute(ipacket, (unsigned) g_dtls_index, &a);
    g_direct_len = out.len;
    return 0;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

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

/* DTLS record + client_hello — byte map as in
 * tools/phase0/tests/quic_dtls_extractor_test.c. Returns the record length. */
static int put_dtls_hello(uint8_t *b, uint8_t content_type,
        uint16_t cipher_bytes_declared, size_t cipher_bytes_present,
        uint16_t first_cipher, int with_compression_tail) {
    size_t len = 63 + cipher_bytes_present
               + (with_compression_tail ? 2 : 0);
    memset(b, 0, len);
    b[0] = content_type;
    b[1] = 0xFE; b[2] = 0xFD;        /* DTLS 1.2 */
    uint16_t rec = (uint16_t)(len - 13);
    b[11] = (uint8_t)(rec >> 8); b[12] = (uint8_t)(rec & 0xFF);
    b[13] = 1;                       /* client_hello */
    b[59] = 0;                       /* session_id_len */
    b[60] = 0;                       /* cookie_len */
    b[61] = (uint8_t)(cipher_bytes_declared >> 8);
    b[62] = (uint8_t)(cipher_bytes_declared & 0xFF);
    for (size_t i = 0; i + 1 < cipher_bytes_present; i += 2) {
        uint16_t c = (i == 0) ? first_cipher : 0x002F;
        b[63 + i] = (uint8_t)(c >> 8); b[63 + i + 1] = (uint8_t)(c & 0xFF);
    }
    if (with_compression_tail) {
        b[63 + cipher_bytes_present] = 1;
        b[64 + cipher_bytes_present] = 0;
    }
    return (int) len;
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
    g_dtls_index = -1;
    g_attr_fired = 0;
    g_normal_set = 0;
    g_direct_rc = -1;
    packet_process(h, &hdr, data);
}

int main(void) {
    char errbuf[1024];
    uint8_t pkt[320];
    int off;
    uint16_t sport = 45000;
    const uint16_t dport = 4444;

    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);
    if (register_attribute_handler(h, PROTO_DTLS, DTLS_CLIENT_HELLO_CIPHER_SUITE,
            cipher_attr_handler, NULL, NULL) != true) {
        fprintf(stderr, "register_attribute_handler(DTLS cipher suite) failed\n");
        mmt_close_handler(h);
        close_extraction();
        return 2;
    }

    printf("issue #376: extraction wire extent separated from output capacity\n");

    /* 1. HEADLINE: the valid 67-byte ClientHello — one cipher 0x1301 must
     *    extract through the normal API despite the 132-byte result
     *    capacity (pre-#376 the central guard refused on data_len). */
    off  = put_eth(pkt, 0x0800);
    int dtls_len = put_dtls_hello(pkt + 14 + 20 + 8, 22, 2, 2, 0x1301, 1);
    off += put_ip4(pkt + off, 17, 20 + 8 + dtls_len);
    off += put_udp(pkt + off, sport++, dport, 8 + dtls_len);
    off += dtls_len;
    run_packet(h, pkt, off, off);
    CHECK(g_pkt_seen && g_dtls_index >= 0,
          "valid record: packet classified as DTLS");
    CHECK(g_attr_fired && g_attr_len == 1 && g_attr_first == 0x1301,
          "valid 67B ClientHello: attribute handler reports one cipher 0x1301");
    CHECK(g_normal_set && g_normal_len == 1,
          "valid record: get_attribute_extracted_data agrees (len 1)");
    CHECK(g_direct_rc == 1 && g_direct_len == 1,
          "valid record: direct extractor call agrees (set, len 1)");

    /* 2. Truncated ClientHello: capture cuts the record inside the 46-byte
     *    hello prefix — the field walk must reject on every path. */
    off  = put_eth(pkt, 0x0800);
    dtls_len = put_dtls_hello(pkt + 14 + 20 + 8, 22, 2, 2, 0x1301, 1);
    off += put_ip4(pkt + off, 17, 20 + 8 + dtls_len);
    off += put_udp(pkt + off, sport++, dport, 8 + 40);
    off += 40;                                  /* only 40 of the 67 record bytes captured */
    run_packet(h, pkt, off, off + (dtls_len - 40));
    CHECK(g_pkt_seen && g_dtls_index >= 0,
          "truncated record (40B): still classified as DTLS");
    CHECK(!g_attr_fired && !g_normal_set && g_direct_rc == 0,
          "truncated hello prefix rejects on handler, API and direct paths");

    /* 3. Declared cipher list longer than the captured tail: the parse
     *    clamps to the bytes present (declared 100B, captured 10B = 5). */
    off  = put_eth(pkt, 0x0800);
    dtls_len = put_dtls_hello(pkt + 14 + 20 + 8, 22, 100, 10, 0x1301, 0);
    off += put_ip4(pkt + off, 17, 20 + 8 + dtls_len);
    off += put_udp(pkt + off, sport++, dport, 8 + dtls_len);
    off += dtls_len;
    run_packet(h, pkt, off, off);
    CHECK(g_attr_fired && g_attr_len == 5,
          "declared 100B list over 10 captured bytes: handler reports len 5");
    CHECK(g_normal_set && g_normal_len == 5 && g_direct_rc == 1 && g_direct_len == 5,
          "truncated list: API and direct paths agree (len 5)");

    /* 4. Insufficient output capacity: 100 presented suites over the
     *    64-entry result array clamps safely, never overflows. */
    off  = put_eth(pkt, 0x0800);
    dtls_len = put_dtls_hello(pkt + 14 + 20 + 8, 22, 200, 200, 0x1301, 0);
    off += put_ip4(pkt + off, 17, 20 + 8 + dtls_len);
    off += put_udp(pkt + off, sport++, dport, 8 + dtls_len);
    off += dtls_len;
    run_packet(h, pkt, off, off);
    CHECK(g_attr_fired && g_attr_len == BINARY_64DATA_LEN,
          "100-suite list clamps to the 64-entry output capacity");
    CHECK(g_attr_first == 0x1301 && g_attr_last == 0x002F,
          "clamped array: first/last cipher values correct");
    CHECK(g_normal_set && g_normal_len == BINARY_64DATA_LEN
          && g_direct_rc == 1 && g_direct_len == BINARY_64DATA_LEN,
          "capacity clamp: API and direct paths agree (len 64)");

    /* 5. A non-handshake DTLS record yields no cipher attribute. */
    off  = put_eth(pkt, 0x0800);
    dtls_len = put_dtls_hello(pkt + 14 + 20 + 8, 23 /* application */, 2, 2, 0x1301, 0);
    off += put_ip4(pkt + off, 17, 20 + 8 + dtls_len);
    off += put_udp(pkt + off, sport++, dport, 8 + dtls_len);
    off += dtls_len;
    run_packet(h, pkt, off, off);
    CHECK(g_pkt_seen && g_dtls_index >= 0,
          "application record: still classified as DTLS");
    CHECK(!g_attr_fired && !g_normal_set && g_direct_rc == 0,
          "application-data record: no cipher on any path");

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
