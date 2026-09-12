/*
 * ssl_record_test — crafted-input regression test for the hardened TLS/SSL
 * record header check and record-walk loop.
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 2c (issue #5, H2).
 *
 * It drives the two record-walk entry points in
 * src/mmt_tcpip/lib/protocols/proto_ssl.c with deliberately truncated /
 * malformed records that, before the hardening, caused out-of-bounds reads:
 *
 *   - H2  ssl_is_tls_record_header() only rejected payload_len == 0, then read
 *         payload[0], get_u16(payload,1) and get_u16(payload,3) — i.e. up to
 *         5 bytes — so a 1..4 byte payload over-read past the buffer.
 *   - H2  tls_get_number_records() walked records by adding the record length
 *         field; with a truncated trailing record the loop read the 2-byte
 *         length at an offset with fewer than 5 bytes remaining.
 *
 * Each payload buffer is heap-allocated to EXACTLY payload_len bytes, so
 * AddressSanitizer brackets it tightly and flags any read past the last byte.
 * The library is built with BUILD=asan by the runner (run_ssl_record_test.sh).
 * With -fno-sanitize-recover=all any sanitizer hit aborts the process, so a
 * clean exit 0 with every assertion passing is the success condition.
 *
 * Build (see run_ssl_record_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -o ssl_record_test \
 *       ssl_record_test.c -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#include "mmt_core.h"
/*
 * tls_get_number_records() reads ipacket->internal_packet->{payload,
 * payload_packet_len}. mmt_tcpip_internal_packet_t is opaque in the installed
 * public headers, so we pull in its full definition from the (in-tree) plugin
 * header. The runner adds the matching -I paths; the layout is identical to the
 * one the library was compiled with, since both come from this same header.
 */
#include "mmt_tcpip_plugin_structs.h"

/*
 * Record-walk entry points under test. They are non-static (exported) in
 * src/mmt_tcpip/lib/protocols/proto_ssl.c but not declared in any public
 * header, so we declare them here.
 *
 * ssl_is_tls_record_header() takes a raw payload pointer + length, so it can be
 * exercised directly. tls_get_number_records() reads
 * ipacket->internal_packet->{payload,payload_packet_len}, so we build a minimal
 * internal packet for it.
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

/* Allocate an exactly-sized buffer (ASan brackets it) and copy in `len` bytes
 * from src (rest zeroed). Caller frees. */
static uint8_t *make_buf(const uint8_t *src, size_t len)
{
    uint8_t *b = (uint8_t *)malloc(len ? len : 1);
    if (!b) { perror("malloc"); exit(2); }
    if (len) {
        memset(b, 0, len);
        if (src) memcpy(b, src, len);
    }
    return b;
}

/* A well-formed 5-byte TLS record header: handshake (0x16), TLS 1.0 (0x0301),
 * length `body_len`. */
static void put_record_header(uint8_t *p, uint16_t body_len)
{
    p[0] = 0x16;                       /* content type: handshake (22) */
    p[1] = 0x03; p[2] = 0x01;          /* version 3.1 (TLS 1.0, 769)   */
    p[3] = (uint8_t)(body_len >> 8);   /* length high byte             */
    p[4] = (uint8_t)(body_len & 0xFF); /* length low byte              */
}

/* ---- ssl_is_tls_record_header: minimum 5-byte header guard (AC #1) ---- */
static void test_record_header_min_len(void)
{
    printf("[H2] ssl_is_tls_record_header minimum-length guard\n");

    /* payload_len 0..4 must all be rejected without reading past the buffer.
     * Each buffer is exactly payload_len bytes so ASan catches any over-read. */
    for (int n = 0; n <= 4; n++) {
        uint8_t seed[4] = {0x16, 0x03, 0x01, 0x00};
        uint8_t *b = make_buf(seed, (size_t)n);
        char msg[64];
        snprintf(msg, sizeof(msg),
                 "payload_len %d rejected without over-read", n);
        CHECK(ssl_is_tls_record_header(b, n) == 0, msg);
        free(b);
    }

    /* Exactly 5 bytes, well-formed header -> accepted (no regression). */
    uint8_t *b5 = make_buf(NULL, 5);
    put_record_header(b5, 0);
    CHECK(ssl_is_tls_record_header(b5, 5) == 1,
          "well-formed 5-byte record header still accepted (no regression)");
    free(b5);

    /* 5 bytes but bad content type / version -> still rejected. */
    uint8_t *bbad = make_buf(NULL, 5);
    put_record_header(bbad, 0);
    bbad[0] = 0x00; /* invalid content type */
    CHECK(ssl_is_tls_record_header(bbad, 5) == 0,
          "invalid content type rejected");
    free(bbad);
}

/* Build a minimal ipacket whose internal_packet carries `payload` of
 * `payload_len` bytes. tls_get_number_records() reads only those two fields. */
static void run_number_records(const uint8_t *payload, int payload_len,
                               int expected, const char *msg)
{
    ipacket_t pkt;
    struct mmt_tcpip_internal_packet_struct ip;
    memset(&pkt, 0, sizeof(pkt));
    memset(&ip, 0, sizeof(ip));
    ip.payload = payload;
    ip.payload_packet_len = (uint16_t)payload_len;
    pkt.internal_packet = &ip;
    int n = tls_get_number_records(&pkt);
    CHECK(n == expected, msg);
}

/* ---- tls_get_number_records: bounded record walk (AC #2) ---- */
static void test_number_records_walk(void)
{
    printf("[H2] tls_get_number_records bounded record walk\n");

    /* Two well-formed back-to-back records, each header + 3-byte body = 8
     * bytes, buffer exactly 16 bytes -> count 2, no over-read. */
    {
        uint8_t *b = make_buf(NULL, 16);
        put_record_header(b, 3);
        put_record_header(b + 8, 3);
        run_number_records(b, 16, 2,
            "two well-formed records counted as 2 (no regression)");
        free(b);
    }

    /* One well-formed record (8 bytes) followed by a truncated 3-byte trailing
     * fragment (a valid-looking header start but < 5 bytes left). Buffer is
     * exactly 11 bytes: the walk must count 1 and stop without reading the
     * 2-byte length of the trailing fragment past the end. */
    {
        uint8_t *b = make_buf(NULL, 11);
        put_record_header(b, 3);
        b[8] = 0x16; b[9] = 0x03; b[10] = 0x01; /* truncated next header */
        run_number_records(b, 11, 1,
            "trailing 3-byte fragment not over-read, counted as 1");
        free(b);
    }

    /* A record whose declared length overruns the buffer: header says body 100
     * but only 7 bytes are captured. The header check rejects it
     * (payload_len < length), so the walk counts 0 and never reads past the
     * 7-byte buffer. */
    {
        uint8_t *b = make_buf(NULL, 7);
        put_record_header(b, 100);
        run_number_records(b, 7, 0,
            "over-declared record length rejected without over-read");
        free(b);
    }

    /* A first well-formed record (header + 3-byte body = 8 bytes) followed by a
     * full second header (offset 8..12) that declares a 100-byte body. The walk
     * counts the first record, then the bottom-of-loop header re-check reads the
     * second header (5 bytes, in bounds) and rejects it because only 5 bytes
     * remain (< declared length) — stopping without reading past the 13-byte
     * buffer. */
    {
        uint8_t *b = make_buf(NULL, 13);
        put_record_header(b, 3);
        put_record_header(b + 8, 100);
        run_number_records(b, 13, 1,
            "over-declared trailing record stops walk safely");
        free(b);
    }

    /* Non-TLS payload of 4 bytes -> header check rejects, count 0, no read
     * past the 4-byte buffer. */
    {
        uint8_t seed[4] = {0x16, 0x03, 0x01, 0x00};
        uint8_t *b = make_buf(seed, 4);
        run_number_records(b, 4, 0,
            "sub-header-length payload yields 0 records without over-read");
        free(b);
    }
}

int main(void)
{
    printf("=== TLS/SSL record-walk hardening test (issue #5: H2) ===\n");
    test_record_header_min_len();
    test_number_records_walk();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
