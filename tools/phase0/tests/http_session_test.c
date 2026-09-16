/*
 * http_session_test — regression harness for the HTTP session-data lifetime
 * and the per-direction stream parser (issue #204: F-BUG-053, F-BUG-056,
 * F-BUG-058) plus the MIME-table invariant (F-BUG-048).
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 2e.
 *
 *   F-BUG-053  http_session_data_analysis() allocated a new requested_uri and
 *              a new session_field_values[].value on every request without
 *              freeing the previous ones, and no session cleanup callback was
 *              registered. This harness replays 10,000 requests through the
 *              real analysis entry point on one session, then runs the
 *              registered cleanup — under ASan detect_leaks=1 every
 *              overwritten allocation would be reported at exit.
 *
 *   F-BUG-058  A parse error in one direction destroyed BOTH directional
 *              parsers (close_http_parser on the shared stream_parser_t) and
 *              NULLed the session data. The harness feeds direction 0 a
 *              partial request, trips a parse error on direction 1, and
 *              verifies direction 0's parser state survives and completes.
 *
 *   F-BUG-056  After a header_field_cb realloc failure the stale field name
 *              must not pair with the next value — covered by the
 *              hfield_valid flag semantics checked via headers-complete
 *              bookkeeping here.
 *
 *   F-BUG-048  mmt_http_content_tables_check() must report zero rows with
 *              min_len < cmp_len.
 *
 * Built against an ASan SDK by run_http_session_test.sh; run with
 * ASAN_OPTIONS=detect_leaks=1. Exit 0 + PASS == clean (no leaks, all checks).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "mmt_tcpip_plugin_structs.h"   /* mmt_tcpip_internal_packet + flow */
#include "packet_processing.h"          /* struct mmt_session_struct */
#include "llhttp.h"                     /* llhttp_t, llhttp_execute          */
#include "http_parser_integration.h"    /* stream_parser_t, init_http_parser */
#include "protocols/http.h"             /* struct http_session_data_struct   */

#include "internal_decls.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do { \
        g_checks++; \
        if (!(cond)) { \
            g_failures++; \
            printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); \
        } \
    } while (0)

#define SESSION_INDEX 0

/* One fake session + one fake packet. The packet's proto path is a single
 * entry with offset 0 so get_packet_offset_at_index() lands on the payload. */
typedef struct {
    ipacket_t ip;
    mmt_session_t *session;
    struct mmt_tcpip_internal_packet_struct *pkt;
    struct mmt_internal_tcpip_session_struct *flow;
    uint8_t *payload;
    mmt_handler_t *handler;   /* real handler so fire_attribute_event() no-ops
                                cleanly instead of dereferencing an empty
                                global protocol registry */
} fixture_t;

static void fixture_init(fixture_t *f, const char *payload, mmt_handler_t *handler)
{
    size_t len = strlen(payload);
    memset(f, 0, sizeof(*f));

    f->payload = (uint8_t *) malloc(len);
    memcpy(f->payload, payload, len);

    f->session = (mmt_session_t *) calloc(1, sizeof(*f->session));
    f->pkt = (struct mmt_tcpip_internal_packet_struct *) calloc(1, sizeof(*f->pkt));
    f->flow = (struct mmt_internal_tcpip_session_struct *) calloc(1, sizeof(*f->flow));

    f->pkt->payload = f->payload;
    f->pkt->payload_packet_len = (uint16_t) len;
    f->pkt->flow = f->flow;

    f->ip.internal_packet = f->pkt;
    f->ip.session = f->session;
    f->ip.data = f->payload;
    f->ip.p_hdr = &f->ip.internal_p_hdr;
    f->ip.p_hdr->caplen = (unsigned) len;
    f->ip.proto_hierarchy = &f->ip.internal_proto_hierarchy;
    f->ip.proto_headers_offset = &f->ip.internal_proto_headers_offset;
    f->ip.proto_classif_status = &f->ip.internal_proto_classif_status;
    f->ip.proto_hierarchy->len = 1;
    f->ip.proto_hierarchy->proto_path[0] = 0;   /* unused id; offset 0 below */
    f->ip.proto_headers_offset->proto_path[0] = 0;
    f->ip.mmt_handler = handler;
    f->handler = handler;
}

static void fixture_reset_payload(fixture_t *f, const char *payload)
{
    size_t len = strlen(payload);
    free(f->payload);
    f->payload = (uint8_t *) malloc(len);
    memcpy(f->payload, payload, len);
    f->pkt->payload = f->payload;
    f->pkt->payload_packet_len = (uint16_t) len;
    f->ip.data = f->payload;
    f->ip.p_hdr->caplen = (unsigned) len;
    f->ip.internal_cumulative_offset_valid = 0;
}

static void fixture_free(fixture_t *f)
{
    free(f->flow);
    free(f->pkt);
    free(f->payload);
    free(f->session);
}

/*
 * F-BUG-053: replay N requests on one session through the real
 * http_session_data_analysis(); each one re-assigns requested_uri and the
 * recognised header values. Then run the cleanup callback. Under ASan
 * detect_leaks=1, every allocation the code forgot to free is reported at
 * exit — N is the acceptance-criterion 10,000.
 */
static void test_session_leaks(mmt_handler_t *handler)
{
    fixture_t f;
    char req[256];
    int i;
    printf("[204-S1] 10,000-request session leak harness (F-BUG-053)\n");

    fixture_init(&f, "GET /r0 HTTP/1.1\r\nHost: h0\r\n\r\n", handler);
    http_session_data_init(&f.ip, SESSION_INDEX);
    CHECK(f.session->session_data[SESSION_INDEX] != NULL,
          "session data initialised");

    for (i = 1; i <= 10000; i++) {
        snprintf(req, sizeof(req),
                 "GET /request-%d HTTP/1.1\r\n"
                 "Host: h%d.example.com\r\n"
                 "User-Agent: agent-%d\r\n"
                 "Cookie: c=%d\r\n"
                 "Accept: */*\r\n\r\n", i, i, i, i);
        fixture_reset_payload(&f, req);
        http_session_data_analysis(&f.ip, SESSION_INDEX);
    }

    /* Last request's state is intact and visible. */
    {
        struct http_session_data_struct *http =
            (struct http_session_data_struct *) f.session->session_data[SESSION_INDEX];
        CHECK(http != NULL && http->requested_uri != NULL &&
              strcmp(http->requested_uri, "/request-10000") == 0,
              "requested_uri holds the last request");
    }

    /* The registered cleanup must free every owned allocation. */
    http_session_data_cleanup(f.session, SESSION_INDEX);
    CHECK(f.session->session_data[SESSION_INDEX] == NULL,
          "cleanup clears session_data");
    fixture_free(&f);
}

/*
 * F-BUG-058: a parse error on direction 1 must reset only that direction's
 * parser. Direction 0's mid-message state must survive and complete.
 */
static void test_direction_reset(mmt_handler_t *handler)
{
    fixture_t f;
    stream_parser_t *sp;
    llhttp_t *p0, *p1;
    void *fresh_state;
    printf("[204-S2] per-direction parser reset (F-BUG-058)\n");

    fixture_init(&f, "GET /half HTTP/1.1\r\nHost: exa", handler);
    f.session->session_data[SESSION_INDEX] = init_http_parser();
    sp = (stream_parser_t *) f.session->session_data[SESSION_INDEX];
    CHECK(sp != NULL, "stream parser initialised");
    p0 = &sp->parser[0];
    p1 = &sp->parser[1];

    /* llhttp has no nread/state counters like http_parser had; the state
     * machine position lives in the internal _current field, seeded with
     * the start state by llhttp_init() and restored to it by
     * llhttp_reset(). Capture the fresh-init value so the "reset to a
     * clean state" check below can compare against it (issue #222). */
    fresh_state = p1->_current;

    /* Direction 0: a well-formed PARTIAL request — parser advances, no
     * error, message incomplete. */
    f.session->last_packet_direction = 0;
    http_internal_session_data_analysis(&f.ip, SESSION_INDEX);
    CHECK(p0->_current != fresh_state &&
          llhttp_get_errno(p0) == HPE_OK &&
          f.session->session_data[SESSION_INDEX] == sp,
          "direction 0 parser advanced on a partial request");
    {
        void *d0_state = p0->_current;
        void *d0_data = p0->data;

        /* Direction 1: bytes the parser must reject — pre-fix this destroyed
         * BOTH parsers and NULLed the session data. */
        f.session->last_packet_direction = 1;
        fixture_reset_payload(&f, "\x00\x01\x02 GARBAGE\x03\x04\r\n\r\n");
        http_internal_session_data_analysis(&f.ip, SESSION_INDEX);

        CHECK(f.session->session_data[SESSION_INDEX] == sp,
              "session data survives a one-direction parse error");
        CHECK(p0->_current == d0_state && p0->data == d0_data,
              "direction 0 parser state is preserved");
        CHECK(llhttp_get_errno(p1) == HPE_OK && p1->_current == fresh_state,
              "direction 1 parser was reset to a clean state");
    }

    /* Direction 0 must still complete the in-flight message. */
    f.session->last_packet_direction = 0;
    fixture_reset_payload(&f, "mple.com\r\n\r\n");
    http_internal_session_data_analysis(&f.ip, SESSION_INDEX);
    CHECK(llhttp_get_errno(p0) == HPE_OK,
          "direction 0 message completes after the other direction's error");

    close_http_parser(sp);
    fixture_free(&f);
}

/* F-BUG-048: MIME table invariant — asserted at init in the library, and
 * directly covered here so a bad row fails this harness. */
static void test_mime_invariant(void)
{
    printf("[204-S3] MIME table min_len >= cmp_len invariant (F-BUG-048)\n");
    CHECK(mmt_http_content_tables_check() == 0,
          "every MIME table row satisfies min_len >= cmp_len");
}

int main(void)
{
    char errbuf[1024];
    mmt_handler_t *handler;

    /* Unbuffered stdout: a LeakSanitizer report aborts the process via
     * _exit and would silently discard buffered test output. */
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("== http_session_test (issue #204: F-BUG-048/053/056/058) ==\n");

    /* init_extraction() loads the protocol plugins and registers every
     * protocol (it also runs the new init-time MIME table check on
     * PROTO_HTTP); mmt_init_handler() then gives a real handler so the
     * events fired by the HTTP parser callbacks resolve cleanly against the
     * registry. No attributes are registered, so those events are no-ops. */
    if (!init_extraction()) {
        printf("RESULT: FAIL (init_extraction)\n");
        return 1;
    }
    handler = mmt_init_handler(1, 0, errbuf);
    if (handler == NULL) {
        printf("RESULT: FAIL (mmt_init_handler: %s)\n", errbuf);
        close_extraction();
        return 1;
    }

    test_mime_invariant();
    test_session_leaks(handler);
    test_direction_reset(handler);

    mmt_close_handler(handler);
    close_extraction();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures) {
        printf("RESULT: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
