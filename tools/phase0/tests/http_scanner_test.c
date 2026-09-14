/*
 * http_scanner_test — crafted-input regression test for the bounded HTTP
 * line/request scanners and the signed-char ctype fixes.
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 2e (issue #7, H4 + H5).
 *
 * Two memory-safety defects are exercised:
 *
 *   H4  _mmt_parse_packet_line_info() (mmt_tcpip_utils.c) read str[8] for any
 *       line starting with 'C'/'c' before checking the line was that long, and
 *       computed `line[0].len - 9` for a "HTTP/1." response line without
 *       guaranteeing the line was >= 9 bytes (uint16 underflow -> ~64 KiB
 *       bogus .len that downstream code then walks off the end of the buffer).
 *
 *   H5  get_next_white_space_offset_no_limit() / *_non_white_space_*()
 *       (rfc2822utils.c) scanned until isgraph()/isspace() turned false with no
 *       bound, so a non-NUL-terminated payload over-read past its last byte.
 *       The ctype argument was a (possibly negative) plain char -> undefined
 *       behaviour for bytes >= 0x80.
 *
 * Every input buffer is heap-allocated to EXACTLY its captured length, so
 * AddressSanitizer brackets it tightly and aborts on any read past the end.
 * The library must be built with BUILD=asan; the runner (run_http_scanner_test.sh)
 * takes care of that, and compiles this file with
 * -fsanitize=address,undefined -fno-sanitize-recover=all so any sanitizer hit
 * aborts. A clean exit 0 with all CHECKs passing is the success condition.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "mmt_tcpip_plugin_structs.h"   /* struct mmt_tcpip_internal_packet_struct */

/* Bounded scanners (rfc2822utils.c) and the HTTP header-line parser under
 * test — declared in the shared internal header (issue #186). */
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

/*
 * Run _mmt_parse_packet_line_info() over a payload of exactly `len` bytes.
 * The payload is copied into a tightly-sized heap buffer so ASan flags any
 * over-read. The internal packet struct is returned (heap-allocated); the
 * caller frees it together with the payload via free_parsed().
 */
static struct mmt_tcpip_internal_packet_struct *
run_line_info(const void *bytes, uint16_t len, uint8_t **out_payload)
{
    uint8_t *payload = (uint8_t *) malloc(len);
    memcpy(payload, bytes, len);

    struct mmt_tcpip_internal_packet_struct *pkt =
        (struct mmt_tcpip_internal_packet_struct *) calloc(1, sizeof(*pkt));
    pkt->payload = payload;
    pkt->payload_packet_len = len;

    ipacket_t ipacket;
    memset(&ipacket, 0, sizeof(ipacket));
    ipacket.internal_packet = pkt;
    ipacket.packet_id = 1;

    _mmt_parse_packet_line_info(&ipacket);

    *out_payload = payload;
    return pkt;
}

static void test_h4_line_parser(void)
{
    uint8_t *payload;
    struct mmt_tcpip_internal_packet_struct *pkt;

    printf("[H4] _mmt_parse_packet_line_info bounds + underflow\n");

    /* Issue #212 (F-BUG-043): a zero-length payload made
     * `end = payload_packet_len - 1` underflow to 65535 and the line loop
     * walked out of bounds — this helper is exported, so the guard must live
     * here, not only in the mmt_parse_packet_line_info() wrapper. Pre-fix this
     * aborts under ASan; post-fix it returns early and marks nothing parsed. */
    pkt = run_line_info("", 0, &payload);
    CHECK(pkt->packet_lines_parsed_complete == 0 && pkt->parsed_lines == 0,
          "zero-length payload is rejected without parsing (no OOB walk)");
    free(pkt); free(payload);

    /* Truncated "C\r\n": a one-byte 'C' line. Pre-fix this dereferenced
     * str[8], 7 bytes past the 3-byte buffer. */
    pkt = run_line_info("C\r\n", 3, &payload);
    CHECK(pkt->content_line.ptr == NULL && pkt->http_contentlen.ptr == NULL &&
          pkt->connection_line.ptr == NULL && pkt->http_cookie.ptr == NULL,
          "truncated 'C' line extracts nothing (no str[8] over-read)");
    free(pkt); free(payload);

    /* Truncated "Co\r\n": two-byte 'C' line, same str[8] over-read path. */
    pkt = run_line_info("Co\r\n", 4, &payload);
    CHECK(pkt->content_line.ptr == NULL,
          "truncated 'Co' line extracts nothing (no str[8] over-read)");
    free(pkt); free(payload);

    /* Truncated response "HTTP/1.\r\n": 7-byte line. Pre-fix this set
     * http_response.len = 7 - 9 = 65534 (uint16 underflow). */
    pkt = run_line_info("HTTP/1.\r\n", 9, &payload);
    CHECK(pkt->http_response.len < 9,
          "truncated 'HTTP/1.' response line does not underflow .len");
    free(pkt); free(payload);

    /* Well-formed response: "HTTP/1.1 200 OK\r\n". line len 15, value at
     * str[9] = "200 OK" (6 bytes). Classification must be unchanged. */
    pkt = run_line_info("HTTP/1.1 200 OK\r\n", 17, &payload);
    CHECK(pkt->http_response.ptr != NULL && pkt->http_response.len == 6,
          "well-formed response line still extracts a 6-byte status");
    free(pkt); free(payload);

    /* Well-formed response followed by a Content-Type header. The
     * "Content-Type: text/html" line (23 bytes) yields a 9-byte value
     * ("text/html") at str[14] — regression for the str[8] switch path. */
    {
        const char *msg = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        pkt = run_line_info(msg, (uint16_t) strlen(msg), &payload);
        CHECK(pkt->content_line.ptr != NULL && pkt->content_line.len == 9,
              "well-formed Content-Type still extracts a 9-byte value");
        free(pkt); free(payload);
    }
}

static void test_h5_scanners(void)
{
    printf("[H5] bounded white-space scanners + ctype unsigned-char cast\n");

    /* No whitespace at all, no NUL terminator: pre-fix isgraph() ran off the
     * end. With max == len it must stop exactly at the bound. */
    {
        size_t n = 8;
        char *buf = (char *) malloc(n);
        memset(buf, '/', n);                /* all isgraph, never NUL */
        int off = get_next_white_space_offset_no_limit(buf, (int) n);
        CHECK(off == (int) n, "white-space scan stops at max with no whitespace");
        free(buf);
    }

    /* All whitespace, no NUL terminator: non-white-space scanner must stop at
     * the bound. */
    {
        size_t n = 8;
        char *buf = (char *) malloc(n);
        memset(buf, ' ', n);                /* all isspace */
        int off = get_next_non_white_space_offset_no_limit(buf, (int) n);
        CHECK(off == (int) n, "non-white-space scan stops at max with all spaces");
        free(buf);
    }

    /* Correctness: whitespace found before the bound. */
    {
        const char *s = "abc def";          /* space at index 3 */
        int off = get_next_white_space_offset_no_limit(s, (int) strlen(s));
        CHECK(off == 3, "white-space scan returns first-space offset");
    }
    {
        const char *s = "   word";           /* first non-space at index 3 */
        int off = get_next_non_white_space_offset_no_limit(s, (int) strlen(s));
        CHECK(off == 3, "non-white-space scan returns first-non-space offset");
    }

    /* ctype with high-bit bytes: pre-fix isgraph((char)0xFF) passed a negative
     * value -> UB. Cast to unsigned char makes it well-defined; the scan must
     * remain in-bounds (UBSan-clean) and return a value within [0, len]. */
    {
        size_t n = 4;
        unsigned char *buf = (unsigned char *) malloc(n);
        buf[0] = 0xFF; buf[1] = 0x80; buf[2] = 0xA0; buf[3] = 0xC3;
        int off = get_next_white_space_offset_no_limit((const char *) buf, (int) n);
        CHECK(off >= 0 && off <= (int) n,
              "white-space scan over high-bit bytes is well-defined and bounded");
        free(buf);
    }

    /* A zero-length window must be a no-op (no read at all). */
    {
        char *buf = (char *) malloc(1);     /* allocate 1, pass max 0 */
        buf[0] = '/';
        int a = get_next_white_space_offset_no_limit(buf, 0);
        int b = get_next_non_white_space_offset_no_limit(buf, 0);
        CHECK(a == 0 && b == 0, "zero-length window reads nothing");
        free(buf);
    }
}

int main(void)
{
    printf("== http_scanner_test (issue #7, H4 + H5) ==\n");
    test_h4_line_parser();
    test_h5_scanners();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures) {
        printf("RESULT: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
