/*
 * classifier_init_test — issue #212 regression harness for the classifier
 * wiring and hostname tables:
 *
 *   F-BUG-041  every inter-protocol classification function registered by
 *              init_app_classification() had its return value discarded — a
 *              failed register_classification_function_with_parent_protocol()
 *              silently left a protocol never classified. The fix exports
 *              mmt_register_classifier(), which checks the return value and
 *              returns 0 (the init-failure signal) after printing a diagnostic
 *              naming the entry. This harness registers a bad entry and
 *              asserts the failure is reported — and that a good one works.
 *
 *   F-BUG-026  mmt_case_sensitive_reverse_hostname_matching() decremented
 *              url_len - 1 / hostname_len - 1 before any guard: url_len == 0
 *              underflowed size_t and hostname_len == 0 placed the cursor one
 *              byte BEFORE the hostname buffer, then dereferenced it.
 *
 *   F-BUG-030  get_proto_id_by_hostname() dereferenced the trie root without
 *              a NULL check, attributed an empty hostname through the
 *              "one more chance" fallback, and let a NULL protocol on the '.'
 *              child overwrite a longer match found during the walk.
 *
 * Every string buffer passed to the reverse matcher is heap-allocated to
 * EXACTLY its captured length so AddressSanitizer brackets it tightly and
 * aborts on any read outside it. Built + run by run_classifier_init_test.sh;
 * a clean exit 0 with all CHECKs passing is the success condition.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#include "mmt_core.h"
#include "mmt_tcpip_protocols.h"   /* PROTO_TCP, PROTO_GOOGLE, PROTO_UNKNOWN */
#include "packet_processing.h"     /* struct mmt_session_struct (content_flags) */
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

static int dummy_classifier(ipacket_t *ipacket, unsigned previous_index) {
    (void) ipacket;
    (void) previous_index;
    return 0;
}

/*
 * Call mmt_case_sensitive_reverse_hostname_matching() with both operands in
 * tightly-sized heap buffers so ASan catches a one-byte over/under-read.
 */
static int run_reverse_match(const char *hostname, size_t hostname_len,
                             const char *pattern, size_t pattern_len)
{
    char *hbuf = (char *) malloc(hostname_len ? hostname_len : 1);
    char *pbuf = (char *) malloc(pattern_len ? pattern_len : 1);
    int rc;

    memcpy(hbuf, hostname, hostname_len);
    memcpy(pbuf, pattern, pattern_len);
    rc = mmt_case_sensitive_reverse_hostname_matching(
            hbuf, pbuf, hostname_len, pattern_len);
    free(hbuf);
    free(pbuf);
    return rc;
}

static void test_registration_checks(void)
{
    printf("[F-BUG-041] inter-protocol registration return values\n");

    /* A bad entry must fail — this is the signal that propagates to
     * init_app_classification() returning 0. */
    CHECK(mmt_register_classifier(0xF000u, dummy_classifier, 50,
                                  "harness_bad_parent") == 0,
          "unknown parent proto id fails registration (init failure signal)");
    CHECK(mmt_register_classifier(PROTO_TCP, NULL, 50,
                                  "harness_null_fn") == 0,
          "NULL classification function fails registration");

    /* And a well-formed entry must still succeed, so the check above is not
     * vacuous (a helper that always returned 0 would pass the bad cases). */
    CHECK(mmt_register_classifier(PROTO_TCP, dummy_classifier, 50,
                                  "harness_dummy") != 0,
          "valid inter-protocol registration succeeds");
}

static void test_reverse_hostname_matching(void)
{
    printf("[F-BUG-026] reverse hostname matching bounds\n");

    /* Zero-length operands used to underflow / read one byte before the
     * buffers — under ASan those abort; they must now return "no match". */
    CHECK(run_reverse_match("", 0, ".com", 4) == 0,
          "empty hostname: no match, no read-before-buffer");
    CHECK(run_reverse_match("www.example.com", 15, "", 0) == 0,
          "empty pattern: no match, no size_t underflow");
    CHECK(run_reverse_match("", 0, "", 0) == 0,
          "both operands empty: no match");

    /* Behaviour preservation: suffix semantics unchanged for real input. */
    CHECK(run_reverse_match("www.example.com", 15, ".example.com", 12) == 1,
          "hostname ending in .example.com matches");
    CHECK(run_reverse_match("example.com", 11, ".example.com", 12) == 1,
          "hostname equal to pattern minus leading dot matches");
    CHECK(run_reverse_match("notexample.com", 14, ".example.com", 12) == 0,
          "hostname merely ending in 'example.com' does not match");
    CHECK(run_reverse_match("www.example.com", 15, ".ample.com", 10) == 0,
          "non-suffix pattern does not match");
}

static void test_hostname_trie_lookup(void)
{
    printf("[F-BUG-030] hostname trie lookup guards\n");

    mmt_session_t sess;
    ipacket_t pkt;
    memset(&sess, 0, sizeof(sess));
    memset(&pkt, 0, sizeof(pkt));
    pkt.session = &sess;

    /* An empty hostname must not walk the trie nor hit the degenerate
     * "i == -1" fallback on the root — it resolves to PROTO_UNKNOWN. */
    CHECK(get_proto_id_by_hostname(&pkt, "", 0) == PROTO_UNKNOWN,
          "empty hostname resolves to PROTO_UNKNOWN (no fallback)");

    /* ".google.com" is a compiled-in table entry (PROTO_GOOGLE). */
    CHECK(get_proto_id_by_hostname(&pkt, "google.com", 10) == PROTO_GOOGLE,
          "google.com resolves to PROTO_GOOGLE via the '.google.com' entry");
    CHECK(get_proto_id_by_hostname(&pkt, "www.google.com", 14) == PROTO_GOOGLE,
          "www.google.com resolves to PROTO_GOOGLE (longest suffix)");
    CHECK(get_proto_id_by_hostname(&pkt, "no-such-host.invalid", 20)
          == PROTO_UNKNOWN,
          "unlisted hostname resolves to PROTO_UNKNOWN");
}

int main(void)
{
    printf("== classifier_init_test (issue #212) ==\n");

    /* init_extraction() registers the tcpip protocol set so PROTO_TCP is a
     * registered parent for the F-BUG-041 checks. It must run from the
     * install prefix so the CWD-relative "plugins/" lookup resolves. */
    if (!init_extraction()) {
        fprintf(stderr, "init_extraction failed\n");
        return 2;
    }

    test_registration_checks();
    test_reverse_hostname_matching();
    test_hostname_trie_lookup();

    close_extraction();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures ? 1 : 0;
}
