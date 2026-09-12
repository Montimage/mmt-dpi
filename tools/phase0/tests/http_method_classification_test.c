/*
 * http_method_classification_test — regression test for the HTTP method
 * table gap and the hot-path stdout prints (issue #101, finding ACC-16).
 *
 * Part of the MMT-DPI Master Improvement Plan performance/accuracy pass.
 *
 * Before this fix, `get_request_method_uri_offset()` (http.c) — the
 * hand-maintained switch that turns the first bytes of an HTTP request line
 * into a method code for the `http.method` attribute — recognized only
 * GET/POST/PUT/DELETE/OPTIONS/HEAD/CONNECT/PROPFIND/REPORT. PATCH, MKCOL, and
 * LOCK fell through and returned a zero offset, i.e. "not a request line".
 *
 * The sibling classification-path function `http_request_url_offset()`
 * (also in http.c) has the identical bug: an unrecognized first method makes
 * it return 0, and its only caller then permanently excludes the whole flow
 * from PROTO_HTTP via `http_bitmask_exclude()` — so a flow whose first
 * request used PATCH/MKCOL/LOCK falls to UNKNOWN for its entire lifetime on
 * non-80 ports. Both functions were fixed together (identical new cases,
 * same method strings); `http_request_url_offset()` cannot be exercised
 * directly from this test binary because it is `static` in http.c AND a
 * second, unrelated, already non-static function of the exact same name
 * lives in proto_http.c (used by the separate http_parser-integration code
 * path) — declaring it `extern` here would collide with that symbol at link
 * time. `get_request_method_uri_offset()` has no such collision (grep
 * confirms it is only ever defined/used in http.c), so it was made
 * non-static (matching the existing http2.c extraction-function convention)
 * specifically so this regression test can drive it directly. It exercises
 * the exact same table-gap bug pattern the issue describes.
 *
 * The library must be built with BUILD=asan; the runner
 * (run_http_method_classification_test.sh) takes care of that.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Method-table lookup under test — non-static (exported) in
 * src/mmt_tcpip/lib/protocols/http.c but not declared in any public header,
 * so it is declared in the shared internal header (issue #186).
 */
#include "internal_decls.h"

/* Mirrors the MMT_HTTP_*_CODE constants in http.h (not a public header). */
#define MMT_HTTP_GET_CODE       1
#define MMT_HTTP_POST_CODE      2
#define MMT_HTTP_OPTIONS_CODE   3
#define MMT_HTTP_HEAD_CODE      4
#define MMT_HTTP_PUT_CODE       5
#define MMT_HTTP_DELETE_CODE    6
#define MMT_HTTP_CONNECT_CODE   7
#define MMT_HTTP_PROPFIND_CODE  8
#define MMT_HTTP_REPORT_CODE    9
#define MMT_HTTP_PATCH_CODE     10
#define MMT_HTTP_MKCOL_CODE     11
#define MMT_HTTP_LOCK_CODE      12

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

/* Run one method line through the lookup and check both the returned
 * offset (start of the URI) and the method code written back. */
static void check_method(const char *line, int expect_offset, int expect_method, const char *label)
{
    int method = -1;
    int off = get_request_method_uri_offset(line, (int) strlen(line), &method);
    CHECK(off == expect_offset && method == expect_method, label);
}

/* issue #101: PATCH, MKCOL, LOCK were absent from the table and fell through
 * to "not a valid request" (offset 0, method 0) -- the exact defect that
 * excludes REST/WebDAV flows from HTTP classification. */
static void test_new_methods_recognized(void)
{
    printf("[#101] previously-missing methods are now recognized\n");

    check_method("PATCH /api/widgets/42 HTTP/1.1\r\n", 6, MMT_HTTP_PATCH_CODE,
                 "PATCH is recognized (offset 6, PATCH code)");
    check_method("MKCOL /dav/newdir/ HTTP/1.1\r\n", 6, MMT_HTTP_MKCOL_CODE,
                 "MKCOL is recognized (offset 6, MKCOL code)");
    check_method("LOCK /dav/file.txt HTTP/1.1\r\n", 5, MMT_HTTP_LOCK_CODE,
                 "LOCK is recognized (offset 5, LOCK code)");
}

/* Regression: every previously-recognized method must still resolve to the
 * same offset and method code (acceptance criterion 3). */
static void test_existing_methods_unchanged(void)
{
    printf("[#101] existing methods are unaffected\n");

    check_method("GET / HTTP/1.1\r\n", 4, MMT_HTTP_GET_CODE, "GET unchanged");
    check_method("POST /submit HTTP/1.1\r\n", 5, MMT_HTTP_POST_CODE, "POST unchanged");
    check_method("PUT /file HTTP/1.1\r\n", 4, MMT_HTTP_PUT_CODE, "PUT unchanged");
    check_method("DELETE /item/1 HTTP/1.1\r\n", 7, MMT_HTTP_DELETE_CODE, "DELETE unchanged");
    check_method("OPTIONS * HTTP/1.1\r\n", 8, MMT_HTTP_OPTIONS_CODE, "OPTIONS unchanged");
    check_method("HEAD /index HTTP/1.1\r\n", 5, MMT_HTTP_HEAD_CODE, "HEAD unchanged");
    check_method("CONNECT proxy:443 HTTP/1.1\r\n", 8, MMT_HTTP_CONNECT_CODE, "CONNECT unchanged");
    check_method("PROPFIND /dav/ HTTP/1.1\r\n", 9, MMT_HTTP_PROPFIND_CODE, "PROPFIND unchanged");
    check_method("REPORT /dav/ HTTP/1.1\r\n", 7, MMT_HTTP_REPORT_CODE, "REPORT unchanged");
}

/* A genuinely unrecognized method must still be rejected (offset 0) -- the
 * fix must not turn off the exclusion path entirely. */
static void test_unrecognized_method_still_rejected(void)
{
    printf("[#101] a truly unknown method is still rejected\n");

    int method = -1;
    int off = get_request_method_uri_offset("FOOBAR /x HTTP/1.1\r\n", 20, &method);
    CHECK(off == 0 && method == 0, "unrecognized method still returns offset 0 / method 0");
}

/* Short/truncated input must not be misread as one of the new methods
 * (defensive: the length guards on PATCH/MKCOL/LOCK mirror the pattern
 * already used for every other method in this table). */
static void test_truncated_input_rejected(void)
{
    printf("[#101] truncated input does not falsely match the new methods\n");

    int method = -1;
    int off = get_request_method_uri_offset("PATC", 4, &method);
    CHECK(off == 0 && method == 0, "truncated 'PATC' does not match PATCH");

    off = get_request_method_uri_offset("MKCO", 4, &method);
    CHECK(off == 0 && method == 0, "truncated 'MKCO' does not match MKCOL");

    off = get_request_method_uri_offset("LOC", 3, &method);
    CHECK(off == 0 && method == 0, "truncated 'LOC' does not match LOCK");
}

int main(void)
{
    printf("== http_method_classification_test (issue #101, ACC-16) ==\n");
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
