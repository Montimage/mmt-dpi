/*
 * ftp_lprt_eprt_test — crafted-input regression test for the FTP LPRT/EPRT
 * IPv6 active-mode address parsers (issue #8, K4).
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 2f.
 *
 * The heap-overflow defects being exercised, all in proto_ftp.c:
 *
 *   K4  ftp_get_data_client_addr_v6_from_LPRT() rendered each comma-separated
 *       address element with sprintf("%X", atoi(token)) into a malloc(3)/(4)
 *       buffer — an element such as "16777215" produced "FFFFFF" and overran
 *       the 3-byte buffer — and accumulated the groups with an *unbounded*
 *       strcat into a malloc(33) buffer, so a forged host-address-length or a
 *       long element list walked off the end of the heap allocation. The first
 *       append also strcat'd onto an uninitialised malloc() buffer when the
 *       leading octet was zero.
 *
 *   K4  ftp_get_data_client_addr_v6_from_EPRT() dereferenced indexes[2] from
 *       str_get_indexes() without checking the delimiter count, reading past
 *       the returned array on a truncated "EPRT |2" command.
 *
 *   #35 ftp_get_data_client_port_from_EPRT() dereferenced indexes[3] (and
 *       indexes[2]) from str_get_indexes() without checking for NULL or a
 *       sufficient delimiter count — a NULL-deref / out-of-bounds read on a
 *       malformed or truncated EPRT command (follow-up to #8). Both the
 *       indexes[3]!=-1 branch and the strlen()-based else branch (3 delimiters,
 *       no trailing "|") are exercised, including their len<=0 guards.
 *
 *   #35 ftp_get_addr_from_parameter() (the IPv4 PORT-command parser, reachable
 *       from untrusted control traffic) read indexes[3] from
 *       str_get_indexes(payload, ",") with the same missing NULL/count guard.
 *       Hardened to mirror the EPRT port parser.
 *
 *   #195 All four parsers now take an explicit payload_len and locate
 *       delimiters with str_get_indexes_n() instead of strlen()-based scans —
 *       they must be safe on raw, non-NUL-terminated packet buffers. The
 *       test_bounded_buffers() cases allocate exactly payload_len bytes with
 *       no NUL inside the span so any over-read trips ASan.
 *
 * The library is built with BUILD=asan and this file is compiled with
 * -fsanitize=address,undefined -fno-sanitize-recover=all (see the runner
 * run_ftp_lprt_eprt_test.sh), so any out-of-bounds write/read aborts the
 * process. AddressSanitizer brackets the parsers' internal heap buffers, which
 * is where the overflow happens, so passing NUL-terminated C-string inputs is
 * sufficient to catch it. A clean exit 0 with all CHECKs passing is success.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Parsers under test — exported from proto_ftp.c, declared in the shared
 * internal header (issue #186). */
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

/* strtok()/str_copy() require a NUL-terminated, writable C string. Duplicate
 * the literal onto the heap so ASan brackets it and the parser may write into
 * its own copy. */
static char *dup_payload(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *) malloc(n);
    if (!p) { perror("malloc"); exit(2); }
    memcpy(p, s, n);
    return p;
}

/* #195: the parsers take an explicit payload_len and must never scan past it.
 * Allocate exactly len bytes — NO NUL terminator inside the allocation — so
 * any strlen()/unbounded read past payload_len lands in the ASan redzone.
 * The caller must ensure strlen(s) >= len. */
static char *raw_payload(const char *s, size_t len)
{
    char *p = (char *) malloc(len);
    if (!p) { perror("malloc"); exit(2); }
    memcpy(p, s, len);
    return p;
}

static void test_lprt_wellformed(void)
{
    printf("[K4] LPRT well-formed classification unchanged\n");

    /* The RFC 1639 example from the proto_ftp.c docstring. Must still decode to
     * exactly this IPv6 string. */
    char *in = dup_payload(
        "LPRT 6,16,32,2,81,131,67,131,0,0,0,0,0,0,81,131,67,131,2,4,7");
    char *out = ftp_get_data_client_addr_v6_from_LPRT(in, (uint32_t)strlen(in));
    CHECK(out != NULL && strcmp(out, "2002:5183:4383::5183:4383") == 0,
          "well-formed LPRT decodes to 2002:5183:4383::5183:4383");
    free(out);
    free(in);
}

static void test_lprt_overflow_inputs(void)
{
    printf("[K4] LPRT malformed inputs are bounded (no heap overflow)\n");

    /* Forged host-address-length (99) far beyond the 16-octet IPv6 maximum.
     * Pre-fix the loop ran 99 times appending into a malloc(33) buffer. */
    {
        char *in = dup_payload(
            "LPRT 6,99,255,255,255,255,255,255,255,255,255,255,255,255,"
            "255,255,255,255,255,255,255,255,255,255,255,255,255,255,"
            "255,255,255,255,255,255,255,255,255,255,255,255");
        char *out = ftp_get_data_client_addr_v6_from_LPRT(in, (uint32_t)strlen(in));
        CHECK(out != NULL && strlen(out) <= 32,
              "oversized host-address-length is rejected/bounded");
        free(out);
        free(in);
    }

    /* host-address-length within the valid range (16) but every octet is the
     * maximum value: 16 groups of "FF"/"FF:" overran malloc(33) pre-fix via the
     * unbounded strcat. Output must stay within the 32-char window. */
    {
        char *in = dup_payload(
            "LPRT 6,16,255,255,255,255,255,255,255,255,"
            "255,255,255,255,255,255,255,255");
        char *out = ftp_get_data_client_addr_v6_from_LPRT(in, (uint32_t)strlen(in));
        CHECK(out != NULL && strlen(out) <= 32,
              "all-255 octets accumulate within the 32-char bound");
        free(out);
        free(in);
    }

    /* Element value far larger than one octet: sprintf("%X", 16777215) wrote
     * "FFFFFF"+NUL (7 bytes) into a malloc(3) buffer pre-fix. */
    {
        char *in = dup_payload("LPRT 6,16,16777215,2,3,4");
        char *out = ftp_get_data_client_addr_v6_from_LPRT(in, (uint32_t)strlen(in));
        CHECK(out != NULL && strlen(out) <= 32,
              "out-of-range element (>255) does not overflow hvalue");
        free(out);
        free(in);
    }

    /* Leading zero octet: pre-fix this strcat'd ":" onto an uninitialised
     * malloc() buffer (ASan use-of-uninitialised via strstr/strcat). */
    {
        char *in = dup_payload("LPRT 6,16,0,0,81,131,67,131,2,4,7");
        char *out = ftp_get_data_client_addr_v6_from_LPRT(in, (uint32_t)strlen(in));
        CHECK(out != NULL && strlen(out) <= 32,
              "leading-zero octet handled on zero-initialised buffer");
        free(out);
        free(in);
    }
}

static void test_eprt(void)
{
    printf("[K4] EPRT delimiter validation + well-formed decode\n");

    /* Well-formed EPRT IPv6: the address between the 2nd and 3rd "|". */
    {
        char *in = dup_payload("EPRT |2|2002:5183:4383::5183:4383|1031");
        char *out = ftp_get_data_client_addr_v6_from_EPRT(in, (uint32_t)strlen(in));
        CHECK(out != NULL && strcmp(out, "2002:5183:4383::5183:4383") == 0,
              "well-formed EPRT extracts the IPv6 address");
        free(out);
        free(in);
    }

    /* Truncated EPRT with a single "|": pre-fix read indexes[2] past the
     * 2-element array returned by str_get_indexes(). Must return NULL safely. */
    {
        char *in = dup_payload("EPRT |2");
        char *out = ftp_get_data_client_addr_v6_from_EPRT(in, (uint32_t)strlen(in));
        CHECK(out == NULL, "truncated EPRT (one delimiter) returns NULL safely");
        free(out);
        free(in);
    }

    /* No delimiters at all: str_get_indexes returns NULL. */
    {
        char *in = dup_payload("EPRT 2");
        char *out = ftp_get_data_client_addr_v6_from_EPRT(in, (uint32_t)strlen(in));
        CHECK(out == NULL, "EPRT with no delimiter returns NULL safely");
        free(out);
        free(in);
    }
}

static void test_eprt_port(void)
{
    printf("[#35] EPRT port delimiter validation + well-formed decode\n");

    /* Well-formed EPRT IPv4: the port sits between the 3rd and 4th "|".
     * From the proto_ftp.c docstring example. Must still decode to 6275. */
    {
        char *in = dup_payload("EPRT |1|132.235.1.2|6275|");
        unsigned short port = ftp_get_data_client_port_from_EPRT(in, (uint32_t)strlen(in));
        CHECK(port == 6275, "well-formed EPRT extracts port 6275");
        free(in);
    }

    /* Truncated EPRT with a single "|": pre-fix read indexes[3]/indexes[2]
     * past the 2-element array returned by str_get_indexes(). Must return 0. */
    {
        char *in = dup_payload("EPRT |2");
        unsigned short port = ftp_get_data_client_port_from_EPRT(in, (uint32_t)strlen(in));
        CHECK(port == 0, "truncated EPRT (one delimiter) returns 0 safely");
        free(in);
    }

    /* Two delimiters only: indexes[2] == -1, so the indexes[3] read was OOB
     * pre-fix. Must be rejected by the delimiter-count guard. */
    {
        char *in = dup_payload("EPRT |1|132.235.1.2");
        unsigned short port = ftp_get_data_client_port_from_EPRT(in, (uint32_t)strlen(in));
        CHECK(port == 0, "EPRT missing the port delimiter returns 0 safely");
        free(in);
    }

    /* No delimiters at all: str_get_indexes returns NULL, so indexes[3] was a
     * NULL-deref pre-fix. */
    {
        char *in = dup_payload("EPRT 2");
        unsigned short port = ftp_get_data_client_port_from_EPRT(in, (uint32_t)strlen(in));
        CHECK(port == 0, "EPRT with no delimiter returns 0 safely");
        free(in);
    }

    /* Else branch: exactly three "|" (no trailing delimiter), port terminated
     * by CRLF. indexes[3]==-1 so len = strlen - indexes[2] - 2 strips the CRLF.
     * Must still decode to 6275 — covers the else branch's well-formed path. */
    {
        char *in = dup_payload("EPRT |1|132.235.1.2|6275\r\n");
        unsigned short port = ftp_get_data_client_port_from_EPRT(in, (uint32_t)strlen(in));
        CHECK(port == 6275, "EPRT without trailing '|' (CRLF) extracts port 6275");
        free(in);
    }

    /* Else branch, degenerate: the third "|" sits within two bytes of the end,
     * so len = strlen - indexes[2] - 2 <= 0. Exercises the new else-branch
     * len<=0 guard — must return 0 with no OOB malloc(0)/memcpy. */
    {
        char *in = dup_payload("EPRT |2|a|");
        unsigned short port = ftp_get_data_client_port_from_EPRT(in, (uint32_t)strlen(in));
        CHECK(port == 0, "EPRT with empty port field returns 0 safely");
        free(in);
    }
}

static void test_port_addr(void)
{
    printf("[#35] PORT parameter delimiter validation + well-formed decode\n");

    /* Well-formed PORT parameter (the substring after "PORT "): the IPv4 octets
     * end at the 4th comma, so indexes[3] is a real offset. Must decode to the
     * dotted address 192.168.1.2. */
    {
        char *in = dup_payload("192,168,1,2,7,138");
        unsigned int addr = ftp_get_addr_from_parameter(in, (unsigned int)strlen(in));
        CHECK(addr == inet_addr("192.168.1.2"),
              "well-formed PORT extracts 192.168.1.2");
        free(in);
    }

    /* No delimiter: str_get_indexes returns NULL, so indexes[3] was a NULL-deref
     * pre-fix. */
    {
        char *in = dup_payload("192");
        unsigned int addr = ftp_get_addr_from_parameter(in, (unsigned int)strlen(in));
        CHECK(addr == 0, "PORT with no delimiter returns 0 safely");
        free(in);
    }

    /* One delimiter: array is two ints, so the pre-fix indexes[3] read was OOB.
     * The guard short-circuits at indexes[1]==-1. */
    {
        char *in = dup_payload("192,168");
        unsigned int addr = ftp_get_addr_from_parameter(in, (unsigned int)strlen(in));
        CHECK(addr == 0, "PORT with one delimiter returns 0 safely");
        free(in);
    }

    /* Two delimiters: indexes[2]==-1, so indexes[3] was OOB pre-fix. Rejected by
     * the delimiter-count guard. */
    {
        char *in = dup_payload("192,168,1");
        unsigned int addr = ftp_get_addr_from_parameter(in, (unsigned int)strlen(in));
        CHECK(addr == 0, "PORT with two delimiters returns 0 safely");
        free(in);
    }

    /* Three delimiters, nothing after the last: indexes[3]==-1 (sentinel), so
     * len = indexes[3] <= 0. Exercises the len<=0 guard. */
    {
        char *in = dup_payload("192,168,1,");
        unsigned int addr = ftp_get_addr_from_parameter(in, (unsigned int)strlen(in));
        CHECK(addr == 0, "PORT ending at the delimiter returns 0 safely");
        free(in);
    }
}

static void test_bounded_buffers(void)
{
    printf("[#195] non-NUL-terminated buffers: parsers are bounded by payload_len\n");

    /* Raw (no-NUL) EPRT: three "|" delimiters, address between the 2nd and
     * 3rd. A strlen()-based search would run into the ASan redzone. */
    {
        const char *lit = "EPRT |2|2002:5183:4383::5183:4383|1031";
        char *in = raw_payload(lit, strlen(lit));
        char *out = ftp_get_data_client_addr_v6_from_EPRT(in, (uint32_t)strlen(lit));
        CHECK(out != NULL && strcmp(out, "2002:5183:4383::5183:4383") == 0,
              "raw EPRT (no NUL) extracts the IPv6 address");
        free(out);
        free(in);
    }

    /* Raw (no-NUL) EPRT port, CRLF-terminated else branch. */
    {
        const char *lit = "EPRT |1|132.235.1.2|6275\r\n";
        char *in = raw_payload(lit, strlen(lit));
        unsigned short port = ftp_get_data_client_port_from_EPRT(in, (uint32_t)strlen(lit));
        CHECK(port == 6275, "raw EPRT (no NUL) extracts port 6275");
        free(in);
    }

    /* Captured-length truncation: payload_len shorter than the C string — the
     * port field is cut mid-token; the parser must bound reads to payload_len
     * and reject rather than read the trailing bytes. */
    {
        const char *lit = "EPRT |1|132.235.1.2|6275";
        char *in = raw_payload(lit, strlen(lit));
        /* payload_len ends just after the third "|" (offset 19): the else
         * branch computes len = 20 - 19 - 2 <= 0 and must return 0 without
         * reading the digits that follow in the buffer. */
        unsigned short port = ftp_get_data_client_port_from_EPRT(in, 20);
        CHECK(port == 0, "truncated EPRT payload_len is bounded, returns 0");
        free(in);
    }

    /* Raw (no-NUL) PORT parameter. */
    {
        const char *lit = "192,168,1,2,7,138";
        char *in = raw_payload(lit, strlen(lit));
        unsigned int addr = ftp_get_addr_from_parameter(in, (unsigned int)strlen(lit));
        CHECK(addr == inet_addr("192.168.1.2"),
              "raw PORT parameter (no NUL) extracts 192.168.1.2");
        free(in);
    }

    /* Raw (no-NUL) LPRT: the parser internally makes a bounded NUL-terminated
     * copy before strtok — a strlen() on the raw buffer would hit the redzone. */
    {
        const char *lit =
            "LPRT 6,16,32,2,81,131,67,131,0,0,0,0,0,0,81,131,67,131,2,4,7";
        char *in = raw_payload(lit, strlen(lit));
        char *out = ftp_get_data_client_addr_v6_from_LPRT(in, (uint32_t)strlen(lit));
        CHECK(out != NULL && strcmp(out, "2002:5183:4383::5183:4383") == 0,
              "raw LPRT (no NUL) decodes to 2002:5183:4383::5183:4383");
        free(out);
        free(in);
    }
}

int main(void)
{
    printf("== ftp_lprt_eprt_test (issue #8, K4; issue #35; #195) ==\n");
    test_lprt_wellformed();
    test_lprt_overflow_inputs();
    test_eprt();
    test_eprt_port();
    test_port_addr();
    test_bounded_buffers();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures) {
        printf("RESULT: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
