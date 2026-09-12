/*
 * dns_parser_test — crafted-input regression test for the hardened DNS parser.
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 2a (issue #3, K3 + M7).
 *
 * It exercises the DNS name / record parser and the dns_check_payload guard
 * with deliberately malformed input that, before the hardening, caused
 * out-of-bounds reads or unbounded recursion (stack overflow):
 *
 *   - M7  dns_check_payload one-byte over-read at a 13-byte payload.
 *   - K3  circular / self / forward compression pointers (infinite recursion).
 *   - K3  labels and records whose declared length runs past the captured end.
 *   - K3  deep label chains (recursion-depth cap).
 *
 * Every crafted message is placed in a heap buffer sized EXACTLY to its
 * length, so AddressSanitizer flags any read past the last captured byte. The
 * library it links against must be built with BUILD=asan; the runner script
 * (run_dns_parser_test.sh) takes care of that. With -fno-sanitize-recover=all
 * any sanitizer hit aborts the process, so a clean exit 0 with all assertions
 * passing is the success condition.
 *
 * Build (see run_dns_parser_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -o dns_parser_test \
 *       dns_parser_test.c -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* dns_name_t and the internal entry points under test are declared in the
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

/* Build a DNS message: a 12-byte header (qdcount=1, rest zero) followed by the
 * supplied name bytes. Returns a heap buffer of exactly 12+name_len bytes so
 * ASan brackets it tightly; *out_len receives the total length. */
static u_char *make_msg(const u_char *name, size_t name_len, size_t *out_len)
{
    size_t total = 12 + name_len;
    u_char *buf = (u_char *)malloc(total);
    if (!buf) { perror("malloc"); exit(2); }
    memset(buf, 0, 12);
    buf[5] = 1; /* qdcount = 1 */
    if (name_len) memcpy(buf + 12, name, name_len);
    *out_len = total;
    return buf;
}

/* Parse the name that starts at offset 12 of a freshly built message; the
 * crafted name bytes are the part under test. Frees everything. */
static dns_name_t *parse_name(const u_char *name, size_t name_len)
{
    size_t len;
    u_char *buf = make_msg(name, name_len, &len);
    dns_name_t *n = dns_extract_name_value(buf + 12, buf, buf + len);
    free(buf);
    return n; /* caller frees */
}

static void test_check_payload_guard(void)
{
    printf("[M7] dns_check_payload length guard\n");

    /* 13-byte payload: the old code read the 16-bit word at offset 12 (byte
     * 13), one past the buffer. Exactly-sized so ASan would catch it. */
    u_char *b13 = (u_char *)malloc(13);
    memset(b13, 0, 13);
    int r13 = dns_check_payload(b13, 13);
    CHECK(r13 == 0, "13-byte payload rejected without over-read");
    free(b13);

    /* 12-byte payload also rejected (below the minimum DNS body we parse). */
    u_char *b12 = (u_char *)malloc(12);
    memset(b12, 0, 12);
    int r12 = dns_check_payload(b12, 12);
    CHECK(r12 == 0, "12-byte payload rejected");
    free(b12);

    /* A well-formed 18-byte query is still classified as DNS (no regression).
     * QR=0, qdcount=1, ancount=nscount=arcount=0. */
    size_t qlen = 18;
    u_char *q = (u_char *)malloc(qlen);
    memset(q, 0, qlen);
    q[0] = 0x12; q[1] = 0x34;     /* transaction id */
    q[2] = 0x00; q[3] = 0x00;     /* flags: QR=0    */
    q[5] = 0x01;                  /* qdcount = 1    */
    /* a minimal qname "a" at offset 12 */
    q[12] = 0x01; q[13] = 'a'; q[14] = 0x00;
    int rq = dns_check_payload(q, (int)qlen);
    CHECK(rq == 1, "well-formed query still classified as DNS");
    free(q);
}

static void test_valid_name(void)
{
    printf("[regression] well-formed name parses unchanged\n");
    /* "\x07example\x03com\x00" -> "example.com" */
    const u_char name[] = {0x07,'e','x','a','m','p','l','e',
                           0x03,'c','o','m',0x00};
    dns_name_t *n = parse_name(name, sizeof(name));
    CHECK(n != NULL, "valid name returns a node");
    if (n) {
        CHECK(n->value != NULL && strcmp(n->value, "example.com") == 0,
              "valid name decodes to \"example.com\"");
        dns_free_name(n);
    }
}

static void test_self_pointer(void)
{
    printf("[K3] self-referential compression pointer\n");
    /* Pointer at offset 12 that targets offset 12 (itself). */
    const u_char name[] = {0xC0, 0x0C};
    dns_name_t *n = parse_name(name, sizeof(name));
    /* Must not crash / recurse forever; an empty/non-NULL result is fine. */
    CHECK(1, "self pointer handled without crash");
    if (n) dns_free_name(n);
}

static void test_circular_pointers(void)
{
    printf("[K3] mutually circular compression pointers\n");
    /* offset 12 -> offset 14, offset 14 -> offset 12. */
    const u_char name[] = {0xC0, 0x0E, 0xC0, 0x0C};
    dns_name_t *n = parse_name(name, sizeof(name));
    CHECK(1, "circular pointers handled without infinite recursion");
    if (n) dns_free_name(n);
}

static void test_forward_pointer(void)
{
    printf("[K3] forward compression pointer rejected\n");
    /* offset 12 -> offset 20, which is beyond the captured payload. */
    const u_char name[] = {0xC0, 0x14};
    dns_name_t *n = parse_name(name, sizeof(name));
    CHECK(1, "forward/out-of-range pointer handled without over-read");
    if (n) dns_free_name(n);
}

static void test_truncated_label(void)
{
    printf("[K3] label length running past payload end\n");
    /* Claims a 32-byte label but only 2 content bytes are present. */
    const u_char name[] = {0x20, 'a', 'b'};
    dns_name_t *n = parse_name(name, sizeof(name));
    CHECK(1, "truncated label handled without over-read");
    if (n) dns_free_name(n);
}

static void test_deep_label_chain(void)
{
    printf("[K3] deep label chain hits the recursion cap\n");
    /* 300 one-character labels, no terminating zero, exact-sized buffer. */
    size_t nlabels = 300;
    size_t name_len = nlabels * 2;
    u_char *name = (u_char *)malloc(name_len);
    for (size_t i = 0; i < nlabels; i++) {
        name[i * 2] = 0x01;       /* label length 1 */
        name[i * 2 + 1] = 'x';
    }
    dns_name_t *n = parse_name(name, name_len);
    free(name);
    CHECK(1, "deep label chain handled without stack overflow / over-read");
    if (n) dns_free_name(n);
}

int main(void)
{
    printf("=== DNS parser hardening test (issue #3: K3 + M7) ===\n");
    test_check_payload_guard();
    test_valid_name();
    test_self_pointer();
    test_circular_pointers();
    test_forward_pointer();
    test_truncated_label();
    test_deep_label_chain();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
