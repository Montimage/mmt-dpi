/*
 * http2_parser_test — crafted-input regression test for the hardened HTTP/2
 * frame parser.
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 2b (issue #4, H1).
 *
 * It drives the HTTP/2 attribute-extraction and classification entry points
 * with deliberately truncated / malformed frames that, before the hardening,
 * caused out-of-bounds reads:
 *
 *   - H1  2-4 byte field reads at attacker-controlled offsets that were only
 *         guarded for their first byte (`offset >= caplen`) or not at all.
 *   - H1  `proto_offset - 1` step-back underflowing to a negative index when
 *         the HTTP/2 header sits at offset 0.
 *   - H1  the connection-preface strncmp() reading up to 24 bytes without a
 *         bounds check.
 *   - H1  the off-by-one `payload_offset <= caplen` accept (one past the end).
 *
 * Each packet buffer is heap-allocated to EXACTLY caplen bytes, so
 * AddressSanitizer brackets it tightly and flags any read past the last
 * captured byte. The library must be built with BUILD=asan; the runner script
 * (run_http2_parser_test.sh) takes care of that. With -fno-sanitize-recover=all
 * any sanitizer hit aborts the process, so a clean exit 0 with all assertions
 * passing is the success condition.
 *
 * Build (see run_http2_parser_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -o http2_parser_test \
 *       http2_parser_test.c -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#include "mmt_core.h"

/*
 * HTTP/2 parser entry points under test — non-static in
 * src/mmt_tcpip/lib/protocols/http2.c, declared in the shared internal
 * header (issue #186).
 */
#include "internal_decls.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do {                                         \
        g_checks++;                                                   \
        if (cond) {                                                   \
            printf("  PASS: %s\n", (msg));                            \
        } else {                                                      \
            printf("  FAIL: %s\n", (msg));                            \
            g_failures++;                                             \
        }                                                             \
    } while (0)

/* Scratch storage for extracted_data->data (functions write up to 4 bytes). */
static uint32_t g_attr_storage;

/*
 * Build a minimal ipacket_t whose only HTTP/2 layer starts at byte
 * `http2_offset`. get_packet_offset_at_index() sums proto_path[0..index], so:
 *   - proto_path[0] = 0           -> offset at index 0 (e.g. TCP) = 0
 *   - proto_path[1] = http2_offset-> offset at index 1 (HTTP/2)  = http2_offset
 * Functions tested at proto_index 1 therefore see the HTTP/2 header at
 * http2_offset; mmt_check_http2 (proto_index 0) sees a TCP header of
 * `http2_offset` bytes. `data` and `caplen` describe the captured packet.
 */
static void init_packet(ipacket_t *pkt, pkthdr_t *hdr, proto_hierarchy_t *off,
                        const u_char *data, unsigned int caplen, int http2_offset)
{
    memset(pkt, 0, sizeof(*pkt));
    memset(hdr, 0, sizeof(*hdr));
    memset(off, 0, sizeof(*off));
    hdr->caplen = caplen;
    pkt->p_hdr = hdr;
    pkt->data = data;
    off->len = 2;
    off->proto_path[0] = 0;
    off->proto_path[1] = http2_offset;
    pkt->proto_headers_offset = off;
}

/* Allocate an exactly-sized buffer (ASan brackets it) and copy in `len` bytes
 * from src (rest zeroed). Caller frees. */
static u_char *make_buf(const u_char *src, size_t len)
{
    u_char *b = (u_char *)malloc(len ? len : 1);
    if (!b) { perror("malloc"); exit(2); }
    if (len) {
        memset(b, 0, len);
        if (src) memcpy(b, src, len);
    }
    return b;
}

static attribute_t make_attr(int position_in_packet)
{
    attribute_t a;
    memset(&a, 0, sizeof(a));
    a.position_in_packet = position_in_packet;
    a.data = &g_attr_storage;
    return a;
}

/* ---- header length extraction (offset 0 underflow + signature window) ---- */
static void test_header_length(void)
{
    printf("[H1] http2_header_length_extraction bounds\n");
    ipacket_t pkt; pkthdr_t hdr; proto_hierarchy_t off;

    /* offset 0, 4-byte capture: signature compare (10 bytes) and the
     * position-1 step-back (read at index -1) must both be skipped. */
    u_char *b4 = make_buf(NULL, 4);
    init_packet(&pkt, &hdr, &off, b4, 4, 0);
    attribute_t a = make_attr(0);
    CHECK(http2_header_length_extraction(&pkt, 1, &a) == 0,
          "offset 0 / 4-byte capture rejected without over-read");
    free(b4);

    /* offset 0, 16-byte capture: signature window is readable but the
     * position-1 read still underflows to index -1 -> must be rejected. */
    u_char *b16 = make_buf(NULL, 16);
    init_packet(&pkt, &hdr, &off, b16, 16, 0);
    a = make_attr(0);
    CHECK(http2_header_length_extraction(&pkt, 1, &a) == 0,
          "offset 0 position-1 underflow rejected");
    free(b16);

    /* Well-formed: HTTP/2 at offset 1, read the 4-byte length window at index
     * 0 (= offset+position-1). Encodes a 24-bit length of 16. */
    u_char raw[4] = {0x00, 0x00, 0x00, 0x10};
    u_char *bok = make_buf(raw, 4);
    init_packet(&pkt, &hdr, &off, bok, 4, 1);
    a = make_attr(0);
    int r = http2_header_length_extraction(&pkt, 1, &a);
    CHECK(r == 1 && g_attr_storage == 16,
          "well-formed length still decodes to 16 (no regression)");
    free(bok);
}

/* ---- header method extraction (1-byte read) ---- */
static void test_header_method(void)
{
    printf("[H1] http2_header_method_extraction bounds\n");
    ipacket_t pkt; pkthdr_t hdr; proto_hierarchy_t off;

    /* The 1-byte field sits exactly at caplen -> reject without reading. */
    u_char *b4 = make_buf(NULL, 4);
    init_packet(&pkt, &hdr, &off, b4, 4, 3);
    attribute_t a = make_attr(1); /* read at offset 3+1 = 4 == caplen */
    CHECK(http2_header_method_extraction(&pkt, 1, &a) == 0,
          "1-byte field at caplen rejected");
    free(b4);

    /* Well-formed: read the byte at offset 3. */
    u_char raw[4] = {0x00, 0x00, 0x00, 0x42};
    u_char *bok = make_buf(raw, 4);
    init_packet(&pkt, &hdr, &off, bok, 4, 0);
    a = make_attr(3);
    int r = http2_header_method_extraction(&pkt, 1, &a);
    CHECK(r == 1 && (g_attr_storage & 0xFF) == 0x42,
          "well-formed 1-byte method still read (no regression)");
    free(bok);
}

/* ---- payload stream id extraction ---- */
static void test_payload_stream_id(void)
{
    printf("[H1] http2_payload_stream_id_extraction bounds\n");
    ipacket_t pkt; pkthdr_t hdr; proto_hierarchy_t off;

    /* offset 0, method byte (131) at index 9, 10-byte capture: the
     * offset_header_length = proto_offset-1 = -1 read must be rejected. */
    u_char b10[10]; memset(b10, 0, sizeof(b10)); b10[9] = 131;
    u_char *p10 = make_buf(b10, 10);
    init_packet(&pkt, &hdr, &off, p10, 10, 0);
    attribute_t a = make_attr(0);
    CHECK(http2_payload_stream_id_extraction(&pkt, 1, &a) == 0,
          "offset 0 header-length underflow rejected");
    free(p10);

    /* offset 1: header_length read is valid (=4) but the 4-byte stream-id sits
     * partly past the end (offset caplen-2). Old `>= caplen` admitted it. */
    unsigned int caplen = 21;
    u_char *p = make_buf(NULL, caplen);
    p[3] = 0x04;   /* 24-bit header length = 4, read at index 0..3 */
    p[10] = 131;   /* method byte at proto_offset(1)+9 = 10 */
    init_packet(&pkt, &hdr, &off, p, caplen, 1);
    a = make_attr(0);
    /* stream_id_payload_offset = 4+9+1 +5 = 19; 19+4 > 21 -> reject. */
    CHECK(http2_payload_stream_id_extraction(&pkt, 1, &a) == 0,
          "stream id straddling caplen rejected (4-byte window)");
    free(p);
}

/* ---- payload length extraction ---- */
static void test_payload_length(void)
{
    printf("[H1] http2_payload_length_extraction bounds\n");
    ipacket_t pkt; pkthdr_t hdr; proto_hierarchy_t off;

    /* 5-byte capture, offset 0: the method byte at index 9 was read with no
     * bounds check before the fix -> must now be rejected. */
    u_char *b5 = make_buf(NULL, 5);
    init_packet(&pkt, &hdr, &off, b5, 5, 0);
    attribute_t a = make_attr(0);
    CHECK(http2_payload_length_extraction(&pkt, 1, &a) == 0,
          "missing method byte rejected (no unguarded read)");
    free(b5);

    /* offset 1, method 131 at 10, header_length=4: payload_offset = 4+9 = 13;
     * 13+4 > 15 -> the 4-byte length read straddles the end. */
    unsigned int caplen = 15;
    u_char *p = make_buf(NULL, caplen);
    p[3] = 0x04;
    p[10] = 131;
    init_packet(&pkt, &hdr, &off, p, caplen, 1);
    a = make_attr(0);
    CHECK(http2_payload_length_extraction(&pkt, 1, &a) == 0,
          "payload length straddling caplen rejected (4-byte window)");
    free(p);
}

/* ---- payload data extraction ---- */
static void test_payload_data(void)
{
    printf("[H1] http2_payload_data_extraction bounds\n");
    ipacket_t pkt; pkthdr_t hdr; proto_hierarchy_t off;

    /* offset 0, method 131 at 9, 10-byte capture: offset_header_length = -1. */
    u_char b10[10]; memset(b10, 0, sizeof(b10)); b10[9] = 131;
    u_char *p10 = make_buf(b10, 10);
    init_packet(&pkt, &hdr, &off, p10, 10, 0);
    attribute_t a = make_attr(0);
    CHECK(http2_payload_data_extraction(&pkt, 1, &a) == 0,
          "offset 0 header-length underflow rejected");
    free(p10);

    /* offset 1, method 131 at 10, header_length=4: the intermediate 4-byte
     * payload-length read at index 13 straddles a 15-byte capture. */
    unsigned int caplen = 15;
    u_char *p = make_buf(NULL, caplen);
    p[3] = 0x04;
    p[10] = 131;
    init_packet(&pkt, &hdr, &off, p, caplen, 1);
    a = make_attr(0);
    CHECK(http2_payload_data_extraction(&pkt, 1, &a) == 0,
          "payload-length read straddling caplen rejected");
    free(p);

    /* Off-by-one: craft so the final payload_offset == caplen exactly. The old
     * `payload_offset <= caplen` accepted it and handed back a pointer one past
     * the buffer; the fix uses `<` and rejects. final = header_length+9+1+10. */
    unsigned int caplen2 = 23;
    u_char *p2 = make_buf(NULL, caplen2);
    p2[3] = 0x04;   /* header_length = 4 */
    p2[10] = 131;   /* method byte */
    init_packet(&pkt, &hdr, &off, p2, caplen2, 1);
    a = make_attr(0);
    /* payload_offset = 4+9+1-1 = 13, then += 10 -> 23 == caplen -> reject. */
    CHECK(http2_payload_data_extraction(&pkt, 1, &a) == 0,
          "payload_offset == caplen rejected (off-by-one '<' not '<=')");
    free(p2);
}

/* ---- stream id extraction (4-byte read) ---- */
static void test_stream_id(void)
{
    printf("[H1] http2_stream_id_extraction bounds\n");
    ipacket_t pkt; pkthdr_t hdr; proto_hierarchy_t off;

    /* offset 0, position 5, 7-byte capture: read window 5..8 straddles end.
     * Old `>= caplen` (5 >= 7 == false) admitted the 4-byte read. */
    u_char *b7 = make_buf(NULL, 7);
    init_packet(&pkt, &hdr, &off, b7, 7, 0);
    attribute_t a = make_attr(5);
    CHECK(http2_stream_id_extraction(&pkt, 1, &a) == 0,
          "stream id straddling caplen rejected (4-byte window)");
    free(b7);

    /* Well-formed: 12-byte capture, read window 5..8 fully inside. */
    u_char raw[12]; memset(raw, 0, sizeof(raw));
    raw[5] = 0x00; raw[6] = 0x00; raw[7] = 0x00; raw[8] = 0x07;
    u_char *bok = make_buf(raw, 12);
    init_packet(&pkt, &hdr, &off, bok, 12, 0);
    a = make_attr(5);
    int r = http2_stream_id_extraction(&pkt, 1, &a);
    CHECK(r == 1 && g_attr_storage == 7,
          "well-formed stream id still decodes to 7 (no regression)");
    free(bok);
}

/* ---- next-proto classification (preface read + step-back) ---- */
static void test_classify_next_proto(void)
{
    printf("[H1] _http2_classify_next_proto bounds\n");
    ipacket_t pkt; pkthdr_t hdr; proto_hierarchy_t off;

    /* offset 0, 4-byte capture: the 24-byte preface compare must be skipped
     * and the proto_offset-1 step-back rejected. */
    u_char *b4 = make_buf(NULL, 4);
    init_packet(&pkt, &hdr, &off, b4, 4, 0);
    CHECK(_http2_classify_next_proto(&pkt, 1) == 0,
          "offset 0 / short capture rejected without over-read");
    free(b4);

    /* offset 0, 24-byte capture (preface window readable, but not the preface):
     * the else-branch proto_offset-1 read at index -1 must be rejected. */
    u_char *b24 = make_buf(NULL, 24);
    init_packet(&pkt, &hdr, &off, b24, 24, 0);
    CHECK(_http2_classify_next_proto(&pkt, 1) == 0,
          "offset 0 length step-back underflow rejected");
    free(b24);
}

/* ---- TCP-level classifier (preface read) ---- */
static void test_check_http2(void)
{
    printf("[H1] mmt_check_http2 bounds\n");
    ipacket_t pkt; pkthdr_t hdr; proto_hierarchy_t off;

    /* HTTP/2 payload at offset 2, only 5 bytes captured: the 24-byte preface
     * strncmp() must be skipped (was unguarded before the fix). */
    u_char *b5 = make_buf(NULL, 5);
    init_packet(&pkt, &hdr, &off, b5, 5, 2);
    CHECK(mmt_check_http2(&pkt, 0) == 0,
          "short capture rejected without preface over-read");
    free(b5);
}

int main(void)
{
    printf("=== HTTP/2 parser hardening test (issue #4: H1) ===\n");
    test_header_length();
    test_header_method();
    test_payload_stream_id();
    test_payload_length();
    test_payload_data();
    test_stream_id();
    test_classify_next_proto();
    test_check_http2();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
