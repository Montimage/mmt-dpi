/*
 * redis_resp_test — unit test for the broadened Redis RESP first-byte
 * heuristic (issue #60).
 *
 * proto_redis.c classifies a TCP flow as Redis from the first payload byte
 * seen in each direction. The legacy heuristic only recognized a flow when one
 * direction started with '*' (a client command array) and the other with '+'
 * or ':'. That missed legitimate Redis flows whose reply started with any of
 * the other valid RESP/RESP3 type-opener bytes ('$', '-', and the RESP3
 * openers). This test pins down the two pure decision helpers extracted from
 * proto_redis.c:
 *
 *   redis_is_resp_opener(c)        — is c a valid RESP/RESP3 type opener?
 *   redis_resp_exchange_match(a,b) — do the two per-direction first bytes form
 *                                    a RESP-shaped request/reply exchange?
 *
 * The helpers are exported (non-static) from proto_redis.c; they are not in any
 * public header, so they are re-declared here and linked against libmmt_tcpip.
 * A clean exit 0 with every CHECK passing is the success condition.
 */
#include <stdio.h>
#include <stdint.h>

/* Decision helpers under test — exported from proto_redis.c, declared in the
 * shared internal header (issue #186). */
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

static void test_resp_openers(void)
{
    printf("[1] redis_is_resp_opener accepts the full RESP/RESP3 set\n");

    /* RESP2 openers. */
    CHECK(redis_is_resp_opener('+'), "'+' simple string is an opener");
    CHECK(redis_is_resp_opener('-'), "'-' error is an opener");
    CHECK(redis_is_resp_opener(':'), "':' integer is an opener");
    CHECK(redis_is_resp_opener('$'), "'$' bulk string is an opener");
    CHECK(redis_is_resp_opener('*'), "'*' array is an opener");

    /* RESP3 openers. */
    CHECK(redis_is_resp_opener('#'), "'#' boolean is an opener");
    CHECK(redis_is_resp_opener(','), "',' double is an opener");
    CHECK(redis_is_resp_opener('_'), "'_' null is an opener");
    CHECK(redis_is_resp_opener('('), "'(' big number is an opener");
    CHECK(redis_is_resp_opener('!'), "'!' bulk error is an opener");
    CHECK(redis_is_resp_opener('='), "'=' verbatim string is an opener");
    CHECK(redis_is_resp_opener('%'), "'%' map is an opener");
    CHECK(redis_is_resp_opener('~'), "'~' set is an opener");
    CHECK(redis_is_resp_opener('>'), "'>' push is an opener");

    /* Non-openers must be rejected to keep false positives low. */
    CHECK(!redis_is_resp_opener('\0'), "NUL is not an opener");
    CHECK(!redis_is_resp_opener('G'), "'G' (HTTP GET) is not an opener");
    CHECK(!redis_is_resp_opener('a'), "'a' is not an opener");
    CHECK(!redis_is_resp_opener('0'), "'0' is not an opener");
    CHECK(!redis_is_resp_opener(0xFF), "0xFF is not an opener");
}

static void test_exchange_match(void)
{
    printf("[2] redis_resp_exchange_match recognizes a RESP exchange\n");

    /* Legacy-accepted pairs must still match (no regression). */
    CHECK(redis_resp_exchange_match('*', '+'), "'*' command / '+' simple reply");
    CHECK(redis_resp_exchange_match('*', ':'), "'*' command / ':' integer reply");
    CHECK(redis_resp_exchange_match('+', '*'), "reverse direction still matches");

    /* Newly broadened reply openers. */
    CHECK(redis_resp_exchange_match('*', '$'), "'*' command / '$' bulk reply");
    CHECK(redis_resp_exchange_match('*', '-'), "'*' command / '-' error reply");
    CHECK(redis_resp_exchange_match('*', '%'), "'*' command / '%' RESP3 map reply");
    CHECK(redis_resp_exchange_match('*', '>'), "'*' command / '>' RESP3 push reply");
    CHECK(redis_resp_exchange_match('*', '*'), "'*' command / '*' array reply");

    /* Non-Redis exchanges must not match: at least one side must be a '*'
     * client command array. */
    CHECK(!redis_resp_exchange_match('+', ':'), "'+'/':'  (no '*' anchor) does not match");
    CHECK(!redis_resp_exchange_match('G', 'H'), "'G'/'H' (HTTP-ish) does not match");
    CHECK(!redis_resp_exchange_match('*', 'X'), "'*' with non-opener reply does not match");
    CHECK(!redis_resp_exchange_match('\0', '\0'), "unset directions do not match");
}

int main(void)
{
    printf("== redis_resp_test (issue #60) ==\n");
    test_resp_openers();
    test_exchange_match();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures) {
        printf("RESULT: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
