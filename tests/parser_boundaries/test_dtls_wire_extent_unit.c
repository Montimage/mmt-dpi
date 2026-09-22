/*
 * test_dtls_wire_extent_unit.c — crafted-fixture test for issue #376
 * (F-BUG-001 follow-up): the central wire-extent guard in
 * internal_extract_attribute() (src/mmt_core/src/packet_pipeline.c) must
 * separate the extractor's WIRE EXTENT — the captured bytes it may read —
 * from data_len, the capacity of the attribute's output buffer.
 *
 * The DTLS_CLIENT_HELLO_CIPHER_SUITE attribute declares data_len =
 * U16_ARRAY_TYPE_LEN (132 bytes, the mmt_u16_array_t result capacity) at
 * position 0, while _dtls_extract_attribute() bounds its own reads: a
 * valid 67-byte ClientHello record must reach the extractor instead of
 * being refused on the 132-byte output capacity, and truncated fields or
 * an undersized result array must still reject/clamp safely — with the
 * direct extractor call and the central path agreeing on every fixture.
 *
 * The test links the built SDK and drives internal_extract_attribute()
 * with attribute_internal_struct / ipacket_t instances shaped exactly like
 * the registered DTLS attribute (same convention as
 * tools/phase0/tests/position_unknown_guard_test.c), and calls
 * _dtls_extract_attribute() directly as the "direct" reference.
 *
 * Build (see run_tests.sh):
 *   gcc -g -O1 -o test_dtls_wire_extent_unit test_dtls_wire_extent_unit.c \
 *       -I<repo>/src/mmt_core/{public,private}_include \
 *       -I<repo>/src/mmt_tcpip/{lib,include} -I<repo>/src/mmt_fuzz_engine \
 *       -I<prefix>/dpi/include \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpcap -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "packet_processing.h"     /* attribute_internal_struct, ipacket wiring */
#include "mmt_tcpip_attributes.h"  /* DTLS_* attribute ids + content types */
#include "mmt_tcpip_protocols.h"   /* PROTO_DTLS */

/* Exported non-static but absent from the installed headers — internal
 * seams, declared here the same way tools/phase0/tests/internal_decls.h does. */
int internal_extract_attribute(const ipacket_t *ipacket,
        struct attribute_internal_struct *tmp_attr_ref, unsigned index);
int _dtls_extract_attribute(const ipacket_t *ipacket, unsigned proto_index,
        attribute_t *extracted_data);

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: %s\n", (msg));                           \
        } else {                                                     \
            printf("  FAIL: %s\n", (msg));                           \
            g_failures++;                                            \
        }                                                            \
    } while (0)

/* -------------------------------------------------------------------------
 * Fixture: heap-allocated, exactly caplen-sized capture buffer (ASan brackets
 * it) + the ipacket wiring internal_extract_attribute() reads: p_hdr, data,
 * proto_headers_offset (layer header sizes — get_packet_offset_at_index()
 * prefix-sums them), proto_hierarchy and a zeroed mmt_handler for the
 * success-path bookkeeping.
 * ------------------------------------------------------------------------- */
typedef struct {
    ipacket_t pkt;
    proto_hierarchy_t offsets;
    proto_hierarchy_t hier;
    pkthdr_t hdr;
    mmt_handler_t *hdlr;
    u_char *buf;
} fixture_t;

static void fixture_init(fixture_t *f, int proto_offset, unsigned caplen) {
    memset(f, 0, sizeof(*f));
    f->buf = (u_char *)malloc(caplen ? caplen : 1);
    if (!f->buf) { perror("malloc"); exit(2); }
    memset(f->buf, 0, caplen ? caplen : 1);
    f->hdlr = (mmt_handler_t *)calloc(1, sizeof(mmt_handler_t));
    if (!f->hdlr) { perror("calloc"); exit(2); }
    f->offsets.proto_path[0] = proto_offset;
    f->offsets.len = 1;
    f->hier.proto_path[0] = PROTO_DTLS;
    f->hier.len = 1;
    f->hdr.caplen = caplen;
    f->hdr.len = caplen;
    f->pkt.p_hdr = &f->hdr;
    f->pkt.data = f->buf;
    f->pkt.proto_headers_offset = &f->offsets;
    f->pkt.proto_hierarchy = &f->hier;
    f->pkt.internal_cumulative_offset_valid = 0;
    f->pkt.mmt_handler = f->hdlr;
}

static void fixture_free(fixture_t *f) {
    free(f->buf);
    free(f->hdlr);
}

/* Attribute shaped exactly like the registered DTLS_CLIENT_HELLO_CIPHER_SUITE
 * (proto_dtls.c): position 0, data_len = 132-byte mmt_u16_array_t capacity. */
static void make_dtls_attr(struct attribute_internal_struct *a, void *scratch) {
    memset(a, 0, sizeof(*a));
    a->proto_id = PROTO_DTLS;
    a->field_id = DTLS_CLIENT_HELLO_CIPHER_SUITE;
    a->data_type = MMT_U16_ARRAY;
    a->position_in_packet = 0;
    a->data_len = (int) sizeof(mmt_u16_array_t);
    a->extraction_function = _dtls_extract_attribute;
    a->data = scratch;
    a->status = ATTRIBUTE_UNSET;
}

/* -------------------------------------------------------------------------
 * DTLS record builder — same byte map as
 * tools/phase0/tests/quic_dtls_extractor_test.c:
 *   [0]     content_type 22 (handshake)
 *   [1..2]  version 0xFEFD (DTLS 1.2)
 *   [3..12] epoch, sequence_number, record length — 13-byte record header
 *   [13]    handshake type 1 (client_hello)
 *   [14..58] hs length / msg seq / fragment / client version / random
 *   [59]    session_id_len, then session id bytes
 *   [..]    cookie_len, then cookie bytes
 *   [..2]   cipher_suites_len, then 2 bytes per suite (big-endian)
 * The valid record finishes with a 2-byte compression-methods section so a
 * single 0x1301 cipher yields exactly the 67-byte record of the issue.
 * ------------------------------------------------------------------------- */
static size_t build_dtls_hello(uint8_t *b, uint8_t content_type,
        uint16_t cipher_bytes_declared, size_t cipher_bytes_present,
        uint16_t first_cipher, int with_compression_tail) {
    size_t len = 63 + cipher_bytes_present
               + (with_compression_tail ? 2 : 0);
    memset(b, 0, len);
    b[0] = content_type;
    b[1] = 0xFE; b[2] = 0xFD;
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
        b[63 + cipher_bytes_present] = 1;     /* compression_methods_len */
        b[64 + cipher_bytes_present] = 0;     /* null compression */
    }
    return len;
}

/* Direct reference: _dtls_extract_attribute() on the same fixture, with an
 * output array sized like the registered scratch. */
static int direct_extract(fixture_t *f, unsigned index, mmt_u16_array_t *out) {
    attribute_t a;
    memset(&a, 0, sizeof(a));
    a.field_id = DTLS_CLIENT_HELLO_CIPHER_SUITE;
    a.data = out;
    memset(out, 0, sizeof(*out));
    return _dtls_extract_attribute(&f->pkt, index, &a);
}

int main(void) {
    printf("=== DTLS wire-extent vs output capacity unit test (issue #376) ===\n");

    fixture_t f;
    struct attribute_internal_struct a;
    mmt_u16_array_t *scratch = (mmt_u16_array_t *)calloc(1, sizeof(mmt_u16_array_t));
    mmt_u16_array_t direct_out;
    int r_central, r_direct;

    /* --- headline case: the valid 67-byte ClientHello ---------------------
     * 132-byte result capacity over a 67-byte record: pre-#376 the central
     * guard refused on data_len; now the extractor's own bounds decide. */
    fixture_init(&f, 0, 67);
    build_dtls_hello(f.buf, 22 /* handshake */, 2, 2, 0x1301, 1);
    make_dtls_attr(&a, scratch);
    r_central = internal_extract_attribute(&f.pkt, &a, 0);
    r_direct = direct_extract(&f, 0, &direct_out);
    CHECK(r_central == 1 && a.status == ATTRIBUTE_SET,
          "67-byte ClientHello extracts through the central path despite 132-byte capacity");
    CHECK(scratch->len == 1 && scratch->data[0] == 0x1301,
          "one cipher 0x1301 extracted");
    CHECK(r_direct == 1 && direct_out.len == scratch->len
          && direct_out.data[0] == scratch->data[0],
          "direct and central extraction agree on the valid record");
    fixture_free(&f);

    /* --- truncated hello: record cut inside the 46-byte hello prefix ------
     * Build on a scratch pad and copy only the captured prefix so the heap
     * fixture stays exactly caplen-sized under ASan. */
    {
        uint8_t pad[300];
        size_t full = build_dtls_hello(pad, 22, 2, 2, 0x1301, 1);
        (void) full;
        fixture_init(&f, 0, 40);
        memcpy(f.buf, pad, 40);
    }
    make_dtls_attr(&a, scratch);
    memset(scratch, 0, sizeof(*scratch));
    r_central = internal_extract_attribute(&f.pkt, &a, 0);
    r_direct = direct_extract(&f, 0, &direct_out);
    CHECK(r_central == 0 && r_direct == 0,
          "hello truncated inside the prefix rejects on both paths");
    fixture_free(&f);

    /* --- truncated cipher list: declared 100, captured 10 ----------------- */
    {
        uint8_t pad[300];
        size_t full = build_dtls_hello(pad, 22, 100, 10, 0x1301, 0);
        fixture_init(&f, 0, (unsigned) full); /* 73 bytes captured */
        memcpy(f.buf, pad, full);
    }
    make_dtls_attr(&a, scratch);
    memset(scratch, 0, sizeof(*scratch));
    r_central = internal_extract_attribute(&f.pkt, &a, 0);
    r_direct = direct_extract(&f, 0, &direct_out);
    CHECK(r_central == 1 && scratch->len == 5,
          "declared 100B cipher list over 10 captured bytes clamps to 5 suites");
    CHECK(r_direct == 1 && direct_out.len == scratch->len,
          "direct and central extraction agree on the truncated list");
    fixture_free(&f);

    /* --- insufficient output capacity: 100 suites over a 64-entry array --- */
    {
        uint8_t pad[300];
        size_t full = build_dtls_hello(pad, 22, 200, 200, 0x1301, 0);
        fixture_init(&f, 0, (unsigned) full);
        memcpy(f.buf, pad, full);
    }
    make_dtls_attr(&a, scratch);
    memset(scratch, 0, sizeof(*scratch));
    r_central = internal_extract_attribute(&f.pkt, &a, 0);
    r_direct = direct_extract(&f, 0, &direct_out);
    CHECK(r_central == 1 && scratch->len == BINARY_64DATA_LEN,
          "100-suite list clamps to the 64-entry output capacity");
    CHECK(scratch->data[0] == 0x1301 && scratch->data[BINARY_64DATA_LEN - 1] == 0x002F,
          "clamped array contents correct");
    CHECK(r_direct == 1 && direct_out.len == scratch->len,
          "direct and central extraction agree on capacity clamp");
    fixture_free(&f);

    /* --- non-handshake record: cipher attribute must not extract ---------- */
    {
        uint8_t pad[300];
        size_t full = build_dtls_hello(pad, 23 /* application */, 2, 2, 0x1301, 0);
        fixture_init(&f, 0, (unsigned) full);
        memcpy(f.buf, pad, full);
    }
    make_dtls_attr(&a, scratch);
    memset(scratch, 0, sizeof(*scratch));
    r_central = internal_extract_attribute(&f.pkt, &a, 0);
    r_direct = direct_extract(&f, 0, &direct_out);
    CHECK(r_central == 0 && r_direct == 0,
          "application-data record yields no cipher on either path");
    fixture_free(&f);

    /* --- protocol offset past caplen: refused before the extractor -------- */
    fixture_init(&f, 70, 60); /* proto starts at 70, only 60 captured */
    make_dtls_attr(&a, scratch);
    memset(scratch, 0, sizeof(*scratch));
    r_central = internal_extract_attribute(&f.pkt, &a, 0);
    r_direct = direct_extract(&f, 0, &direct_out);
    CHECK(r_central == 0 && r_direct == 0,
          "protocol offset past caplen refuses on both paths");
    fixture_free(&f);

    free(scratch);
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
