/*
 * test_mmt_inet_ntop.c — comprehensive test suite for mmt_inet_ntop (src/mmt_core/src/mmt_inet_ntop.c),
 * the exported wrapper over the C library's inet_ntop (issue #496).
 *
 * Tests cover:
 *   - IPv4 basic addresses (loopback, private, public)
 *   - IPv4 boundary addresses (0.0.0.0, 255.255.255.255)
 *   - IPv6 loopback (::1)
 *   - IPv6 all zeros (::)
 *   - IPv6 mapped address (::ffff:1.2.3.4)
 *   - IPv6 full address
 *   - IPv6 compressed zeros
 *   - Buffer too small (returns NULL)
 *   - NULL address (returns NULL)
 *   - Invalid address family (returns NULL)
 *   - Exact buffer size fit
 *   - RFC 5952 canonical IPv6 text (issue #496): a single zero group is not
 *     compressed, the longest zero run wins, the first of equal runs wins
 *   - NULL destination buffer (returns NULL)
 *   - IPv6 buffer one byte short / exact
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "data_defs.h"

/* Declare the function under test */
extern const char *mmt_inet_ntop(int af, const void *addr, char *buf, socklen_t len);

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); g_failures++; } } while (0)
#define CHECK_STR_EQ(actual, expected, msg) do { \
        if (actual == NULL || expected == NULL || strcmp(actual, expected) != 0) { \
            fprintf(stderr, "  FAIL [%s:%d]: %s (got '%s', expected '%s')\n", \
                    __FILE__, __LINE__, (msg), actual ? actual : "(null)", expected ? expected : "(null)"); \
            g_failures++; \
        } \
    } while (0)

/* ---- Test: IPv4 loopback ---- */
static void test_ipv4_loopback(void) {
    fprintf(stderr, "  test: IPv4 loopback (127.0.0.1)\n");
    struct in_addr addr;
    addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 */
    char buf[INET_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "127.0.0.1", "IPv4 loopback");
}

/* ---- Test: IPv4 0.0.0.0 ---- */
static void test_ipv4_zero(void) {
    fprintf(stderr, "  test: IPv4 0.0.0.0\n");
    struct in_addr addr;
    addr.s_addr = 0;
    char buf[INET_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "0.0.0.0", "IPv4 0.0.0.0");
}

/* ---- Test: IPv4 255.255.255.255 ---- */
static void test_ipv4_broadcast(void) {
    fprintf(stderr, "  test: IPv4 255.255.255.255\n");
    struct in_addr addr;
    addr.s_addr = 0xFFFFFFFF;
    char buf[INET_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "255.255.255.255", "IPv4 255.255.255.255");
}

/* ---- Test: IPv4 private address ---- */
static void test_ipv4_private(void) {
    fprintf(stderr, "  test: IPv4 private address (192.168.1.100)\n");
    struct in_addr addr;
    /* 192.168.1.100 in network byte order */
    uint8_t bytes[] = {192, 168, 1, 100};
    memcpy(&addr, bytes, sizeof(addr));
    char buf[INET_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "192.168.1.100", "IPv4 private address");
}

/* ---- Test: IPv4 8.8.8.8 (Google DNS) ---- */
static void test_ipv4_dns(void) {
    fprintf(stderr, "  test: IPv4 8.8.8.8\n");
    struct in_addr addr;
    uint8_t bytes[] = {8, 8, 8, 8};
    memcpy(&addr, bytes, sizeof(addr));
    char buf[INET_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "8.8.8.8", "IPv4 8.8.8.8");
}

/* ---- Test: IPv6 loopback (::1) ---- */
static void test_ipv6_loopback(void) {
    fprintf(stderr, "  test: IPv6 loopback (::1)\n");
    struct in6_addr addr;
    memset(&addr, 0, sizeof(addr));
    addr.s6_addr[15] = 1; /* ::1 */
    char buf[INET6_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "::1", "IPv6 loopback");
}

/* ---- Test: IPv6 all zeros (::) ---- */
static void test_ipv6_zero(void) {
    fprintf(stderr, "  test: IPv6 all zeros (::)\n");
    struct in6_addr addr;
    memset(&addr, 0, sizeof(addr));
    char buf[INET6_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "::", "IPv6 all zeros");
}

/* ---- Test: IPv6 full address (no zero runs to compress) ---- */
static void test_ipv6_full(void) {
    fprintf(stderr, "  test: IPv6 full address\n");
    struct in6_addr addr;
    /* 2001:0db8:85a3:0001:0002:8a2e:0370:7334 — no run of zeros, so no :: */
    const unsigned char bytes[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x01,
        0x00, 0x02, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34
    };
    memcpy(&addr, bytes, sizeof(bytes));
    char buf[INET6_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "2001:db8:85a3:1:2:8a2e:370:7334", "IPv6 full address");
}

/* ---- Test: IPv6 mapped address (::ffff:1.2.3.4) ---- */
static void test_ipv6_mapped(void) {
    fprintf(stderr, "  test: IPv6 mapped address (::ffff:1.2.3.4)\n");
    struct in6_addr addr;
    memset(&addr, 0, sizeof(addr));
    addr.s6_addr[10] = 0xff;
    addr.s6_addr[11] = 0xff;
    addr.s6_addr[12] = 1;
    addr.s6_addr[13] = 2;
    addr.s6_addr[14] = 3;
    addr.s6_addr[15] = 4;
    char buf[INET6_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "::ffff:1.2.3.4", "IPv6 mapped address");
}

/* ---- Test: buffer too small ---- */
static void test_buffer_too_small(void) {
    fprintf(stderr, "  test: buffer too small returns NULL\n");
    struct in_addr addr;
    addr.s_addr = htonl(0x08080808); /* 8.8.8.8 */
    char buf[2]; /* Too small for "8.8.8.8" */
    const char *result = mmt_inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    CHECK(result == NULL, "buffer too small should return NULL");
}

/* ---- Test: exact buffer size ---- */
static void test_exact_buffer_size(void) {
    fprintf(stderr, "  test: exact buffer size fits\n");
    struct in_addr addr;
    addr.s_addr = htonl(0x08080808); /* 8.8.8.8 = 7 chars + null = 8 bytes */
    char buf[8]; /* Exactly enough for "8.8.8.8\0" */
    const char *result = mmt_inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "8.8.8.8", "exact buffer size should fit");
}

/* ---- Test: NULL address ---- */
static void test_null_address(void) {
    fprintf(stderr, "  test: NULL address returns NULL\n");
    char buf[INET_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET, NULL, buf, sizeof(buf));
    CHECK(result == NULL, "NULL address should return NULL");
}

/* ---- Test: invalid address family ---- */
static void test_invalid_family(void) {
    fprintf(stderr, "  test: invalid address family returns NULL\n");
    struct in_addr addr;
    addr.s_addr = 0;
    char buf[INET_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET6 + 1, &addr, buf, sizeof(buf));
    CHECK(result == NULL, "invalid family should return NULL");
}

/* ---- Test: IPv6 with leading zeros compressed ---- */
static void test_ipv6_compressed(void) {
    fprintf(stderr, "  test: IPv6 compressed zeros\n");
    struct in6_addr addr;
    memset(&addr, 0, sizeof(addr));
    addr.s6_addr[0] = 0x20;
    addr.s6_addr[1] = 0x01;
    char buf[INET6_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    /* Only the first 16 bits are set (0x2001), the remaining 112 bits are a
     * single zero run that compresses to "::" => "2001::". */
    CHECK_STR_EQ(result, "2001::", "IPv6 compressed zeros");
}

/* ---- Test: IPv4 with leading zeros (e.g., 0.0.0.1) ---- */
static void test_ipv4_leading_zeros(void) {
    fprintf(stderr, "  test: IPv4 0.0.0.1\n");
    struct in_addr addr;
    uint8_t bytes[] = {0, 0, 0, 1};
    memcpy(&addr, bytes, sizeof(addr));
    char buf[INET_ADDRSTRLEN];
    const char *result = mmt_inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    CHECK_STR_EQ(result, "0.0.0.1", "IPv4 0.0.0.1");
}

/* ---- Helper: IPv6 text round-trip through inet_pton ---- */
static const char *ntop6_of(const char *text, char *buf, socklen_t len) {
    struct in6_addr addr;
    if (inet_pton(AF_INET6, text, &addr) != 1) return "(inet_pton failed)";
    return mmt_inet_ntop(AF_INET6, &addr, buf, len);
}

/* ---- Test: RFC 5952 §4.2.2 — a single zero group is not shortened ---- */
static void test_ipv6_single_zero_group(void) {
    fprintf(stderr, "  test: IPv6 single zero group stays 0 (RFC 5952)\n");
    char buf[INET6_ADDRSTRLEN];
    CHECK_STR_EQ(ntop6_of("2001:db8:0:1:1:1:1:1", buf, sizeof(buf)),
                 "2001:db8:0:1:1:1:1:1", "single zero group not compressed");
}

/* ---- Test: RFC 5952 §4.2.3 — the longest run of zero groups is shortened ---- */
static void test_ipv6_longest_run(void) {
    fprintf(stderr, "  test: IPv6 longest zero run compressed (RFC 5952)\n");
    char buf[INET6_ADDRSTRLEN];
    CHECK_STR_EQ(ntop6_of("2001:0:0:1:0:0:0:1", buf, sizeof(buf)),
                 "2001:0:0:1::1", "longest zero run compressed");
}

/* ---- Test: RFC 5952 §4.2.3 — of equal runs, the first is shortened ---- */
static void test_ipv6_first_of_equal_runs(void) {
    fprintf(stderr, "  test: IPv6 first of equal zero runs compressed (RFC 5952)\n");
    char buf[INET6_ADDRSTRLEN];
    CHECK_STR_EQ(ntop6_of("2001:db8:0:0:1:0:0:1", buf, sizeof(buf)),
                 "2001:db8::1:0:0:1", "first of equal zero runs compressed");
}

/* ---- Test: NULL destination buffer ---- */
static void test_null_buffer(void) {
    fprintf(stderr, "  test: NULL buffer returns NULL\n");
    struct in_addr addr;
    addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(mmt_inet_ntop(AF_INET, &addr, NULL, INET_ADDRSTRLEN) == NULL,
          "NULL buffer should return NULL");
}

/* ---- Test: IPv6 buffer one byte short, then exact ---- */
static void test_ipv6_buffer_bounds(void) {
    fprintf(stderr, "  test: IPv6 buffer bounds (::1 needs 4 bytes)\n");
    char buf[4];
    CHECK(ntop6_of("::1", buf, 3) == NULL, "IPv6 buffer one byte short should return NULL");
    CHECK_STR_EQ(ntop6_of("::1", buf, 4), "::1", "IPv6 exact buffer size should fit");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    fprintf(stderr, "mmt_inet_ntop test suite\n");

    test_ipv4_loopback();
    test_ipv4_zero();
    test_ipv4_broadcast();
    test_ipv4_private();
    test_ipv4_dns();
    test_ipv6_loopback();
    test_ipv6_zero();
    test_ipv6_full();
    test_ipv6_mapped();
    test_buffer_too_small();
    test_exact_buffer_size();
    test_null_address();
    test_invalid_family();
    test_ipv6_compressed();
    test_ipv4_leading_zeros();
    test_ipv6_single_zero_group();
    test_ipv6_longest_run();
    test_ipv6_first_of_equal_runs();
    test_null_buffer();
    test_ipv6_buffer_bounds();

    if (g_failures == 0) {
        fprintf(stderr, "ALL CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
