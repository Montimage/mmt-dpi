/*
 * proto_http_method_classification_test — regression test for the *third*
 * HTTP method table, `http_request_url_offset()` in
 * src/mmt_tcpip/lib/protocols/proto_http.c (issue #113).
 *
 * Part of the MMT-DPI Master Improvement Plan performance/accuracy pass.
 *
 * Issue #101 (PR #109) fixed two hand-maintained method tables that both
 * live in http.c: `get_request_method_uri_offset()` (used for the
 * `http.method` attribute lookup path) and the classification-path
 * `http_request_url_offset()` (which decides whether a flow gets
 * permanently excluded from PROTO_HTTP). Neither of those changes touched
 * proto_http.c.
 *
 * proto_http.c defines its OWN, unrelated, non-static function of the exact
 * same name — `http_request_url_offset(ipacket_t *ipacket)` — used by the
 * separate http_parser-integration code path
 * (`http_internal_session_data_analysis()`). It feeds `packet->http_method`
 * and `packet->http_url_name`, which is what `http_new_method_extraction()`
 * / `http_new_uri_extraction()` read to populate the live `http.method` /
 * `http.uri` attributes. This third table also lacked PATCH, MKCOL, and
 * LOCK, so those attributes stayed unpopulated for such requests even once
 * PROTO_HTTP classification correctly recognized the flow as HTTP.
 *
 * `http_method_classification_test.c` (issue #101) documents that it
 * cannot link proto_http.c's `http_request_url_offset()` because http.c
 * defines a `static` function of the same name at link scope — declaring
 * this one `extern` here does not collide because the proto_http.c
 * definition has external (non-static) linkage and http.c's is static.
 *
 * The library must be built with BUILD=asan; the runner
 * (run_proto_http_method_classification_test.sh) takes care of that.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "mmt_tcpip_plugin_structs.h"   /* struct mmt_tcpip_internal_packet_struct */

/* Function under test — non-static (exported) in
 * src/mmt_tcpip/lib/protocols/proto_http.c, declared in the shared internal
 * header (issue #186). */
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
 * Build a tightly-sized (ASan-friendly) heap payload of exactly `len` bytes
 * plus a heap-allocated internal packet struct + ipacket_t wired to it, then
 * run http_request_url_offset() and return the offset. Frees everything
 * before returning so each call leaves no live allocations behind.
 */
static uint16_t run_offset(const char *bytes, uint16_t len)
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

    uint16_t off = http_request_url_offset(&ipacket);

    free(pkt);
    free(payload);
    return off;
}

static void check_offset(const char *line, uint16_t expect_offset, const char *label)
{
    uint16_t off = run_offset(line, (uint16_t) strlen(line));
    CHECK(off == expect_offset, label);
}

/* issue #113: PATCH, MKCOL, LOCK were absent from proto_http.c's
 * http_request_url_offset() table and fell through to "not a valid
 * request" (offset 0) -- the exact defect that leaves http.method/http.uri
 * unpopulated for these requests. */
static void test_new_methods_recognized(void)
{
    printf("[#113] previously-missing methods are now recognized\n");

    check_offset("PATCH /api/widgets/42 HTTP/1.1\r\n", 6,
                 "PATCH is recognized (offset 6)");
    check_offset("MKCOL /dav/newdir/ HTTP/1.1\r\n", 6,
                 "MKCOL is recognized (offset 6)");
    check_offset("LOCK /dav/file.txt HTTP/1.1\r\n", 5,
                 "LOCK is recognized (offset 5)");
}

/* Regression: every previously-recognized method must still resolve to the
 * same offset (acceptance criterion 2). */
static void test_existing_methods_unchanged(void)
{
    printf("[#113] existing methods are unaffected\n");

    check_offset("GET / HTTP/1.1\r\n", 4, "GET unchanged");
    check_offset("POST /submit HTTP/1.1\r\n", 5, "POST unchanged");
    check_offset("OPTIONS * HTTP/1.1\r\n", 8, "OPTIONS unchanged");
    check_offset("HEAD /index HTTP/1.1\r\n", 5, "HEAD unchanged");
    check_offset("PUT /file HTTP/1.1\r\n", 4, "PUT unchanged");
    check_offset("DELETE /item/1 HTTP/1.1\r\n", 7, "DELETE unchanged");
    check_offset("CONNECT proxy:443 HTTP/1.1\r\n", 8, "CONNECT unchanged");
    check_offset("PROPFIND /dav/ HTTP/1.1\r\n", 9, "PROPFIND unchanged");
    check_offset("REPORT /dav/ HTTP/1.1\r\n", 7, "REPORT unchanged");
}

/* A genuinely unrecognized method must still be rejected (offset 0) -- the
 * fix must not turn off the exclusion path entirely. */
static void test_unrecognized_method_still_rejected(void)
{
    printf("[#113] a truly unknown method is still rejected\n");

    check_offset("FOOBAR /x HTTP/1.1\r\n", 0,
                 "unrecognized method still returns offset 0");
}

/* Short/truncated input must not be misread as one of the new methods
 * (defensive: the length guards on PATCH/MKCOL/LOCK mirror the pattern
 * already used for every other method in this table). */
static void test_truncated_input_rejected(void)
{
    printf("[#113] truncated input does not falsely match the new methods\n");

    check_offset("PATC", 0, "truncated 'PATC' does not match PATCH");
    check_offset("MKCO", 0, "truncated 'MKCO' does not match MKCOL");
    check_offset("LOC", 0, "truncated 'LOC' does not match LOCK");
}

int main(void)
{
    printf("== proto_http_method_classification_test (issue #113) ==\n");
    test_new_methods_recognized();
    test_existing_methods_unchanged();
    test_unrecognized_method_still_rejected();
    test_truncated_input_rejected();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures) {
        printf("RESULT: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
