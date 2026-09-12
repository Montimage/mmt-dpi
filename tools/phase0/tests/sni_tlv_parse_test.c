/*
 * sni_tlv_parse_test — crafted-input regression test for structural parsing of
 * the RFC 6066 server_name (SNI) extension in the SSL/TLS ClientHello parser
 * (issue #103).
 *
 * getServerNameFromClientHello() (src/mmt_tcpip/lib/protocols/proto_ssl.c) used
 * to locate the SNI hostname by scanning forward over the extension body,
 * skipping bytes that looked non-printable / punctuation / whitespace, then
 * copying the remainder. That heuristic misidentifies where the hostname starts
 * whenever the 2-byte server_name_list length (= 3 + hostname_length) or the
 * name_length field renders as printable ASCII: hostname lengths 45-54 push the
 * list-length low byte into '0'..'9', 62-87 into 'A'..'Z' and 94-119 into
 * 'a'..'z', so the scan stops on that byte and extracts a single-character (or
 * otherwise corrupted) "hostname". The fix parses the extension's actual wire
 * structure (server_name_list length, name_type, name_length) via a helper and
 * copies exactly name_length hostname bytes.
 *
 * This test drives getServerNameFromClientHello() directly (it is exported,
 * though undeclared in public headers) with hand-crafted ClientHello payloads
 * whose SNI extension body is built byte-by-byte, so the declared extension
 * length and the internal name_length can be controlled independently for the
 * adversarial cases.
 *
 * Each payload is heap-allocated to EXACTLY payload_packet_len bytes and placed
 * at an ODD address: the parser still contains pre-existing raw uint16 casts at
 * payload[3], payload[45] and payload[49] (out of scope for this issue), so the
 * payload is aligned such that those three casts land on even addresses. UBSan
 * (-fsanitize=alignment, part of -fsanitize=undefined) then stays focused on the
 * SNI parse under test; ASan brackets the hostname bytes tightly, so any read
 * past the declared name flags an out-of-bounds abort. A clean exit 0 with every
 * assertion passing is the success condition.
 *
 * Build (see run_sni_tlv_parse_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o sni_tlv_parse_test sni_tlv_parse_test.c \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "mmt_core.h"
/*
 * getServerNameFromClientHello() reads ipacket->internal_packet->{payload,
 * payload_packet_len, https_server_name, packet_id} and ipacket->packet_id.
 * The internal packet struct is opaque in the installed public headers, so pull
 * in its full definition from the in-tree plugin header (the runner adds the
 * matching -I paths; the layout matches the compiled library byte-for-byte).
 */
#include "mmt_tcpip_plugin_structs.h"
#include "mmt_tcpip_internal_defs_macros.h"

/*
 * Entry point under test. getServerNameFromClientHello() is exported
 * (non-static) in src/mmt_tcpip/lib/protocols/proto_ssl.c but not declared in
 * any public header — it comes from the shared internal header
 * (issue #186). Returns 2 when a hostname was
 * extracted, 0 otherwise.
 */
#include "internal_decls.h"

/* Matches MMT_SSL_CERTIFICATE_BUF_LEN in proto_ssl.c after the fix: the
 * production callers now feed a 256-byte thread-local buffer. */
#define BUF_LEN 256

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
 * Assemble a minimal TLS ClientHello record carrying exactly one server_name
 * (SNI) extension, wrapping the caller-supplied extension body blob `body`
 * (body_len bytes, placed verbatim at the server_name pointer the parser
 * computes). The record uses session_id_len = 1, a 1-byte cipher-suites list
 * and no compression methods; with those choices the parser's pre-existing raw
 * uint16 casts fall on payload offsets 3, 45 and 49.
 *
 * The declared extension length field is set to body_len, so a caller that puts
 * a shorter-than-declared TLV header inside `body` (e.g. name_length claiming
 * more bytes than the extension holds) exercises the helper's rejection path.
 *
 * The payload is malloc'd to exactly (55 + body_len) bytes plus one slack byte,
 * and returned at an ODD address so payload[3], payload[45], payload[49] are all
 * even (2-byte aligned). *raw receives the malloc base (free it), *out_len the
 * exact payload_packet_len. Multi-byte header fields are big-endian.
 *
 * Byte map (p = returned odd pointer):
 *   [3..4]   record length            = payload_len - 5
 *   [43]     session_id length         = 1
 *   [44]     session id (1 byte)       = 0
 *   [45..46] cipher_suites length      = 1
 *   [47]     cipher suite (1 byte)     = 0
 *   [48]     compression methods len   = 0
 *   [49..50] extensions length         = 6 + body_len
 *   [51..52] extension type            = 0x0000 (server_name)
 *   [53..54] extension length          = body_len
 *   [55..]   extension body            = `body` (body_len bytes)  <- server_name
 */
static uint8_t *build_client_hello(const uint8_t *body, size_t body_len,
                                   uint8_t **raw, size_t *out_len)
{
    size_t payload_len = 55 + body_len;
    uint8_t *base = (uint8_t *)malloc(payload_len + 1);
    if (!base) { perror("malloc"); exit(2); }
    memset(base, 0, payload_len + 1);
    /* Force an odd start address: base is malloc-aligned (even), so base|1
     * is base+1 and still inside the allocation. */
    uint8_t *p = (uint8_t *)(((uintptr_t)base) | (uintptr_t)1);

    uint16_t rec = (uint16_t)(payload_len - 5);
    p[3] = (uint8_t)(rec >> 8);
    p[4] = (uint8_t)(rec & 0xFF);
    p[43] = 1;                 /* session_id length */
    p[44] = 0;                 /* session id */
    p[45] = 0; p[46] = 1;      /* cipher_suites length = 1 */
    p[47] = 0;                 /* one cipher-suite byte */
    p[48] = 0;                 /* compression methods length = 0 */
    uint16_t exts = (uint16_t)(6 + body_len);
    p[49] = (uint8_t)(exts >> 8);
    p[50] = (uint8_t)(exts & 0xFF);
    p[51] = 0; p[52] = 0;      /* extension type = server_name (0) */
    p[53] = (uint8_t)(body_len >> 8);
    p[54] = (uint8_t)(body_len & 0xFF);
    memcpy(p + 55, body, body_len);

    *raw = base;
    *out_len = payload_len;
    return p;
}

/* Build a well-formed SNI extension body: server_name_list length, name_type
 * host_name (0), name_length, then `host_bytes` hostname bytes. `declared_name`
 * is written into the name_length field independently of host_bytes so the
 * "name_length overruns the extension" and "overlong name_length" cases can be
 * built. Returns the body length; caller supplies a buffer >= 5 + host_bytes. */
static size_t make_sni_body(uint8_t *out, uint16_t declared_name,
                            const uint8_t *host, size_t host_bytes)
{
    uint16_t snl = (uint16_t)(3 + host_bytes); /* name_type(1)+name_len(2)+name */
    out[0] = (uint8_t)(snl >> 8);
    out[1] = (uint8_t)(snl & 0xFF);
    out[2] = 0;                                 /* name_type = host_name */
    out[3] = (uint8_t)(declared_name >> 8);
    out[4] = (uint8_t)(declared_name & 0xFF);
    if (host_bytes) memcpy(out + 5, host, host_bytes);
    return 5 + host_bytes;
}

/* Deterministic hostname of `len` bytes drawn from [a-z] (all valid under
 * stripCertificateTrailer, so a correct parse round-trips exactly). */
static void fill_hostname(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)('a' + (int)(i % 26));
}

/* Drive getServerNameFromClientHello() on a payload of exactly payload_len
 * bytes. Returns the classifier result; on success `buffer` holds the extracted
 * hostname and *out_len its recorded length. */
static int run_client_hello(const uint8_t *payload, int payload_len,
                            char *buffer, int buffer_len, uint16_t *out_len)
{
    ipacket_t pkt;
    struct mmt_tcpip_internal_packet_struct ip;

    memset(&pkt, 0, sizeof(pkt));
    memset(&ip, 0, sizeof(ip));

    ip.payload = payload;
    ip.payload_packet_len = (uint16_t)payload_len;
    pkt.internal_packet = &ip;

    int rc = getServerNameFromClientHello(&pkt, buffer, buffer_len);
    if (out_len) *out_len = ip.https_server_name.len;
    return rc;
}

/* Extract a well-formed `host_len`-byte SNI hostname and assert it round-trips
 * exactly (content and recorded length). This is the direct evidence the old
 * printable-scan heuristic is gone: for host_len in the corruption bands the
 * pre-fix parser returned a single garbage character instead of the hostname. */
static void expect_hostname(size_t host_len, const char *label)
{
    uint8_t host[512];
    uint8_t body[512];
    fill_hostname(host, host_len);
    size_t body_len = make_sni_body(body, (uint16_t)host_len, host, host_len);

    uint8_t *raw; size_t plen;
    uint8_t *p = build_client_hello(body, body_len, &raw, &plen);

    char buffer[BUF_LEN];
    uint16_t rlen = 0;
    int rc = run_client_hello(p, (int)plen, buffer, BUF_LEN, &rlen);

    char expected[512];
    memcpy(expected, host, host_len);
    expected[host_len] = '\0';

    int ok = (rc == 2) && (rlen == host_len) && (strcmp(buffer, expected) == 0);
    printf("  [len=%zu] rc=%d recorded_len=%u extracted=\"%.*s%s\"\n",
           host_len, rc, rlen, buffer[0] ? (int)(strlen(buffer) > 40 ? 40 : strlen(buffer)) : 0,
           buffer, strlen(buffer) > 40 ? "..." : "");
    CHECK(ok, label);

    free(raw);
}

/* ---- corruption-band regression: the reported bug (AC #1) ---- */
static void test_corruption_bands(void)
{
    printf("[#103] hostnames in the reported corruption bands extract intact\n");
    /* short baseline: unaffected by the old heuristic, must stay correct */
    expect_hostname(10,  "baseline 10-byte hostname extracted intact");
    /* midpoints of each reported band (direct symptom witnesses) */
    expect_hostname(50,  "50-byte hostname (band 45-54) extracted intact");
    expect_hostname(75,  "75-byte hostname (band 62-87) extracted intact");
    expect_hostname(105, "105-byte hostname (band 94-119) extracted intact");
    /* exact band edges */
    expect_hostname(45,  "45-byte hostname (band edge) extracted intact");
    expect_hostname(54,  "54-byte hostname (band edge) extracted intact");
    expect_hostname(62,  "62-byte hostname (band edge) extracted intact");
    expect_hostname(87,  "87-byte hostname (band edge) extracted intact");
    expect_hostname(94,  "94-byte hostname (band edge) extracted intact");
    expect_hostname(119, "119-byte hostname (band edge) extracted intact");
}

/* ---- boundary sweep: lengths just outside each band stay correct ---- */
static void test_boundary_sweep(void)
{
    printf("[#103] boundary sweep just outside each reported band\n");
    expect_hostname(44,  "44-byte hostname (just below band) extracted intact");
    expect_hostname(55,  "55-byte hostname (just above band) extracted intact");
    expect_hostname(61,  "61-byte hostname (just below band) extracted intact");
    expect_hostname(88,  "88-byte hostname (just above band) extracted intact");
    expect_hostname(93,  "93-byte hostname (just below band) extracted intact");
    expect_hostname(120, "120-byte hostname (just above band) extracted intact");
}

/* ---- 255-byte hostname stored without truncation (AC #2) ---- */
static void test_max_length_hostname(void)
{
    printf("[#103] 255-byte hostname stored without truncation\n");
    expect_hostname(255, "255-byte hostname stored intact (buffer_len - 1)");
}

/* ---- overlong name_length is clamped to buffer_len-1, no OOB (ASan) ---- */
static void test_overlong_hostname_clamped(void)
{
    printf("[#103] overlong hostname (name_length 300) clamped to 255, no OOB\n");
    size_t host_len = 300;
    uint8_t host[512];
    uint8_t body[512];
    fill_hostname(host, host_len);
    /* declared name_length == 300 and 300 real hostname bytes are present, so
     * the copy is clamped to buffer_len-1 (255) with all bytes in bounds. */
    size_t body_len = make_sni_body(body, (uint16_t)host_len, host, host_len);

    uint8_t *raw; size_t plen;
    uint8_t *p = build_client_hello(body, body_len, &raw, &plen);

    char buffer[BUF_LEN];
    uint16_t rlen = 0;
    int rc = run_client_hello(p, (int)plen, buffer, BUF_LEN, &rlen);

    char expected[BUF_LEN];
    memcpy(expected, host, BUF_LEN - 1);
    expected[BUF_LEN - 1] = '\0';

    CHECK(rc == 2, "overlong name still classified as a hostname");
    CHECK(rlen == BUF_LEN - 1, "overlong name clamped to buffer_len - 1 (255)");
    CHECK(strcmp(buffer, expected) == 0,
          "clamped hostname equals the first 255 input bytes (not corrupted)");
    free(raw);
}

/* ---- adversarial malformed TLVs are safely rejected (return 0, no OOB) ---- */
static void test_malformed_rejected(void)
{
    printf("[#103] malformed SNI TLVs are rejected safely (no crash / OOB)\n");
    char buffer[BUF_LEN];
    uint16_t rlen;

    /* (a) extension body shorter than the 5-byte TLV header: 2 bytes. The helper
     * must reject on the length check BEFORE reading name_type at body[2] — that
     * byte is one past the tightly-bracketed allocation, so an early read aborts
     * under ASan. */
    {
        uint8_t body[2] = { 0x00, 0x35 };
        uint8_t *raw; size_t plen;
        uint8_t *p = build_client_hello(body, sizeof(body), &raw, &plen);
        int rc = run_client_hello(p, (int)plen, buffer, BUF_LEN, &rlen);
        CHECK(rc == 0, "extension_len 2 (< 5) rejected");
        free(raw);
    }

    /* (b) extension body of 4 bytes (still < 5): rejected. */
    {
        uint8_t body[4] = { 0x00, 0x36, 0x00, 0x00 };
        uint8_t *raw; size_t plen;
        uint8_t *p = build_client_hello(body, sizeof(body), &raw, &plen);
        int rc = run_client_hello(p, (int)plen, buffer, BUF_LEN, &rlen);
        CHECK(rc == 0, "extension_len 4 (< 5) rejected");
        free(raw);
    }

    /* (c) name_length claims 200 bytes but the extension holds only 10:
     * 5 + 200 > 10, so the helper must reject rather than read 200 bytes. */
    {
        uint8_t host[5];
        uint8_t body[10];
        fill_hostname(host, sizeof(host));
        size_t body_len = make_sni_body(body, 200, host, sizeof(host)); /* = 10 */
        uint8_t *raw; size_t plen;
        uint8_t *p = build_client_hello(body, body_len, &raw, &plen);
        int rc = run_client_hello(p, (int)plen, buffer, BUF_LEN, &rlen);
        CHECK(rc == 0, "name_length overrunning the extension is rejected");
        free(raw);
    }

    /* (d) name_type != host_name (0): a 20-byte name declared with name_type 1
     * must be rejected. */
    {
        uint8_t host[20];
        uint8_t body[64];
        fill_hostname(host, sizeof(host));
        size_t body_len = make_sni_body(body, (uint16_t)sizeof(host), host, sizeof(host));
        body[2] = 1; /* name_type = 1 (not host_name) */
        uint8_t *raw; size_t plen;
        uint8_t *p = build_client_hello(body, body_len, &raw, &plen);
        int rc = run_client_hello(p, (int)plen, buffer, BUF_LEN, &rlen);
        CHECK(rc == 0, "non-host_name name_type is rejected");
        free(raw);
    }
}

int main(void)
{
    printf("=== SNI extension TLV-parse test (issue #103) ===\n");
    test_corruption_bands();
    test_boundary_sweep();
    test_max_length_hostname();
    test_overlong_hostname_clamped();
    test_malformed_rejected();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
