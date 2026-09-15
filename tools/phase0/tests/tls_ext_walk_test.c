/*
 * tls_ext_walk_test — crafted-input regression test for two proto_ssl.c
 * defects fixed in issue #203:
 *
 *   F-BUG-064  getServerNameFromClientHello() walked the ClientHello
 *              extension list with a uint16_t cursor and added each
 *              extension's declared 16-bit length without checking it fit
 *              inside the enclosing extensions_len. A declared length of
 *              0xFFFC wraps the cursor (6 + 65532 -> 2), so the loop
 *              re-reads the same extension header forever — a hang on a
 *              single malformed packet.
 *   F-BUG-073  tls_content_type_extraction() / tls_version_extraction() /
 *              tls_length_extraction() used the values returned by
 *              get_packet_offset_at_index() — which returns -1 when the
 *              index is invalid — unchecked, then subtracted them from
 *              tcp_offset + payload_len. A wrapped/huge unsigned result
 *              passed the `ssl_payload_len >= 5` gate and the record header
 *              was then read at a wild offset far outside the capture.
 *
 * The ClientHello payloads are built the same way as sni_tlv_parse_test.c:
 * heap buffer sized EXACTLY to payload_packet_len, placed at an odd address
 * so the parser's pre-existing raw uint16 casts at payload[3], [45] and [49]
 * stay aligned and UBSan stays focused on the extension walk under test.
 * The hang case is bounded by alarm(): a cursor wrap turns into a loud
 * failure, not a stuck test.
 *
 * Build (see run_tls_ext_walk_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o tls_ext_walk_test tls_ext_walk_test.c \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#include "mmt_core.h"
#include "mmt_tcpip_plugin_structs.h"
#include "mmt_tcpip_internal_defs_macros.h"
#include "mmt_tcpip_protocols.h"      /* PROTO_TCP */
#include "internal_decls.h"

#define BUF_LEN 256
#define HANG_TIMEOUT_S 8

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

/* If the extension-walk cursor wraps, the loop never terminates — turn that
 * hang into an explicit failure instead of a stalled test. async-signal-safe:
 * write() + _exit() only. */
static void on_alarm(int sig)
{
    (void)sig;
    static const char msg[] =
        "  FAIL: extension walk did not terminate (F-BUG-064 cursor wrap)\n";
    ssize_t w = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)w;
    _exit(1);
}

/* -------------------------------------------------------------------------
 * F-BUG-064: ClientHello extension walk
 *
 * Same fixed ClientHello framing as sni_tlv_parse_test.c: session_id_len=1,
 * cipher_suites_len=1, compression_len=0 puts the parser's raw uint16 casts
 * at payload[3], [45] and [49]. The extension area starts at payload[51];
 * `exts` bytes are copied verbatim (exts_bytes_present may be shorter than
 * the declared extensions_len to model truncation).
 */
static uint8_t *build_hello_exts(const uint8_t *exts, size_t exts_bytes_present,
                                 uint16_t declared_exts_len,
                                 uint8_t **raw, size_t *out_len)
{
    /* The parser only walks when declared_exts_len + 49 <= total_len and
     * <= cap_total_len; total_len is derived from the record-length field,
     * which we set to payload_len - 5, so the allocation must cover the
     * larger of declared/present. */
    size_t region = exts_bytes_present > (size_t)declared_exts_len
                    ? exts_bytes_present : (size_t)declared_exts_len;
    size_t payload_len = 51 + region;
    uint8_t *base = (uint8_t *)malloc(payload_len + 1);
    if (!base) { perror("malloc"); exit(2); }
    memset(base, 0, payload_len + 1);
    /* Odd start: base is malloc-aligned (even) so base|1 lands the u16 casts
     * at payload[3], [45], [49] on even addresses. */
    uint8_t *p = (uint8_t *)(((uintptr_t)base) | (uintptr_t)1);

    uint16_t rec = (uint16_t)(payload_len - 5);
    p[3] = (uint8_t)(rec >> 8);
    p[4] = (uint8_t)(rec & 0xFF);
    p[43] = 1;                 /* session_id length */
    p[44] = 0;
    p[45] = 0; p[46] = 1;      /* cipher_suites length = 1 */
    p[47] = 0;
    p[48] = 0;                 /* compression methods length = 0 */
    p[49] = (uint8_t)(declared_exts_len >> 8);
    p[50] = (uint8_t)(declared_exts_len & 0xFF);
    memcpy(p + 51, exts, exts_bytes_present);

    *raw = base;
    *out_len = payload_len;
    return p;
}

static int run_client_hello(const uint8_t *payload, int payload_len,
                            char *buffer, int buffer_len)
{
    ipacket_t pkt;
    struct mmt_tcpip_internal_packet_struct ip;

    memset(&pkt, 0, sizeof(pkt));
    memset(&ip, 0, sizeof(ip));

    ip.payload = payload;
    ip.payload_packet_len = (uint16_t)payload_len;
    pkt.internal_packet = &ip;

    return getServerNameFromClientHello(&pkt, buffer, buffer_len);
}

/* A well-formed SNI extension body, same shape as sni_tlv_parse_test.c:
 * server_name_list length, name_type host_name(0), name_length, hostname. */
static size_t make_sni_body(uint8_t *out, const uint8_t *host, size_t host_bytes)
{
    uint16_t snl = (uint16_t)(3 + host_bytes);
    out[0] = (uint8_t)(snl >> 8);
    out[1] = (uint8_t)(snl & 0xFF);
    out[2] = 0;
    out[3] = (uint8_t)(host_bytes >> 8);
    out[4] = (uint8_t)(host_bytes & 0xFF);
    memcpy(out + 5, host, host_bytes);
    return 5 + host_bytes;
}

static void test_extension_len_overrun_no_hang(void)
{
    printf("[F-BUG-064] extension declaring 0xFFFC bytes terminates (no wrap)\n");

    /* One extension: id 0x0017 (not server_name), declared length 0xFFFC —
     * 65532 bytes, far beyond the 146-byte extensions region. Pre-fix the
     * uint16 cursor wraps 6 + 65532 -> 2 and the loop re-reads this header
     * forever; the alarm catches that. Post-fix the walk breaks and the
     * function returns 0 with no hostname. */
    const uint8_t exts[] = { 0x00, 0x17, 0xFF, 0xFC };
    uint8_t *raw; size_t plen;
    uint8_t *p = build_hello_exts(exts, sizeof(exts), 146, &raw, &plen);

    char buf[BUF_LEN];
    int rc = run_client_hello(p, (int)plen, buf, BUF_LEN);
    CHECK(rc == 0, "overrunning extension length breaks the walk, returns 0");
    free(raw);
}

static void test_truncated_last_extension(void)
{
    printf("[F-BUG-064] extension header claims more than extensions_len holds\n");

    /* extensions_len = 8: at cursor 2 the walk sees ext id 0x0017 len 0x0064
     * — 6 + 4 = 10 > 8, so the extension does not fit; must break cleanly. */
    const uint8_t exts[] = { 0x00, 0x17, 0x00, 0x64 };
    uint8_t *raw; size_t plen;
    uint8_t *p = build_hello_exts(exts, sizeof(exts), 8, &raw, &plen);

    char buf[BUF_LEN];
    int rc = run_client_hello(p, (int)plen, buf, BUF_LEN);
    CHECK(rc == 0, "extension not fitting extensions_len breaks the walk");
    free(raw);
}

static void test_valid_extensions_still_extract(void)
{
    printf("[F-BUG-064] regression: benign extension then SNI still extracts\n");

    /* ext 1: id 0x0017 len 4 "AAAA"; ext 2: id 0x0000 (server_name) with a
     * well-formed body. The walk must skip the first and parse the second. */
    const uint8_t host[] = "www.example.com";
    uint8_t body[64];
    size_t body_len = make_sni_body(body, host, sizeof(host) - 1);

    uint8_t exts[128];
    size_t n = 0;
    exts[n++] = 0x00; exts[n++] = 0x17;        /* type 0x0017 */
    exts[n++] = 0x00; exts[n++] = 0x04;        /* len 4 */
    exts[n++] = 'A'; exts[n++] = 'A'; exts[n++] = 'A'; exts[n++] = 'A';
    exts[n++] = 0x00; exts[n++] = 0x00;        /* type server_name */
    exts[n++] = (uint8_t)(body_len >> 8); exts[n++] = (uint8_t)(body_len & 0xFF);
    memcpy(exts + n, body, body_len);
    n += body_len;

    uint8_t *raw; size_t plen;
    uint8_t *p = build_hello_exts(exts, n, (uint16_t)n, &raw, &plen);

    char buf[BUF_LEN];
    int rc = run_client_hello(p, (int)plen, buf, BUF_LEN);
    CHECK(rc == 2 && strcmp(buf, "www.example.com") == 0,
          "SNI hostname still extracted after a benign leading extension");
    free(raw);
}

/* -------------------------------------------------------------------------
 * F-BUG-073: TLS field extractors must reject invalid packet offsets
 *
 * Wiring: proto_path[0] = PROTO_TCP so get_protocol_index_by_id() returns 0;
 * the extractor reads tcp_offset = offset at index 1 and ssl_offset = offset
 * at proto_index (1). proto_headers_offset.proto_path is cumulative, so
 * setting entry [1] = ssl_off gives tcp_offset = ssl_offset = ssl_off and
 * ssl_payload_len = payload_packet_len.
 */
static int run_tls_extractor(int (*fn)(const ipacket_t *, unsigned, attribute_t *),
                             uint16_t ssl_off, uint16_t payload_len,
                             uint16_t caplen, const uint8_t *buf,
                             int field_pos, void *out)
{
    ipacket_t pkt;
    proto_hierarchy_t hier, headers_offset;
    pkthdr_t p_hdr;
    struct mmt_tcpip_internal_packet_struct ip;
    attribute_t attr;

    memset(&pkt, 0, sizeof(pkt));
    memset(&hier, 0, sizeof(hier));
    memset(&headers_offset, 0, sizeof(headers_offset));
    memset(&p_hdr, 0, sizeof(p_hdr));
    memset(&ip, 0, sizeof(ip));
    memset(&attr, 0, sizeof(attr));

    hier.proto_path[0] = PROTO_TCP;              /* tcp_index = 0 */
    hier.len = 1;
    headers_offset.proto_path[0] = 0;
    headers_offset.proto_path[1] = ssl_off;      /* cumulative offset at idx 1 */
    ip.payload_packet_len = payload_len;

    p_hdr.len = caplen;
    p_hdr.caplen = caplen;
    pkt.p_hdr = &p_hdr;
    pkt.data = (const u_char *)buf;
    pkt.proto_hierarchy = &hier;
    pkt.proto_headers_offset = &headers_offset;
    pkt.internal_packet = &ip;

    attr.field_id = 1;
    attr.position_in_packet = field_pos;
    attr.data = out;

    return fn(&pkt, 1, &attr);
}

static void test_extractors_reject_bad_offsets(void)
{
    printf("[F-BUG-073] extractors reject offsets outside the capture\n");

    /* 100-byte capture, SSL offset pinned at 65000: ssl_payload_len underflows
     * the old unsigned math into a huge value, so the pre-fix code reads the
     * record header at data[65000] — ~64900 bytes past the end (ASan abort).
     * Post-fix: ssl_offset >= caplen -> return 0 without touching data. */
    const size_t caplen = 100;
    uint8_t *b = (uint8_t *)malloc(caplen);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, caplen);

    uint8_t ct = 0;
    int rc = run_tls_extractor(tls_content_type_extraction,
                               65000, 60000, (uint16_t)caplen, b, 0, &ct);
    CHECK(rc == 0, "content_type extractor rejects ssl_offset >= caplen");

    uint16_t v = 0;
    rc = run_tls_extractor(tls_version_extraction,
                           65000, 60000, (uint16_t)caplen, b, 1, &v);
    CHECK(rc == 0, "version extractor rejects ssl_offset >= caplen");

    uint16_t l = 0;
    rc = run_tls_extractor(tls_length_extraction,
                           65000, 60000, (uint16_t)caplen, b, 3, &l);
    CHECK(rc == 0, "length extractor rejects ssl_offset >= caplen");
    free(b);
}

static void test_extractors_reject_missing_tcp(void)
{
    printf("[F-BUG-073] extractors reject packets with no TCP in the hierarchy\n");

    /* No PROTO_TCP in proto_path -> get_protocol_index_by_id() returns -1;
     * the extractors must not turn that into a wild index. */
    ipacket_t pkt;
    proto_hierarchy_t hier, headers_offset;
    pkthdr_t p_hdr;
    struct mmt_tcpip_internal_packet_struct ip;
    attribute_t attr;
    uint8_t b[32];
    memset(b, 0, sizeof(b));

    memset(&pkt, 0, sizeof(pkt));
    memset(&hier, 0, sizeof(hier));
    memset(&headers_offset, 0, sizeof(headers_offset));
    memset(&p_hdr, 0, sizeof(p_hdr));
    memset(&ip, 0, sizeof(ip));
    memset(&attr, 0, sizeof(attr));

    hier.proto_path[0] = 9999;                   /* not PROTO_TCP */
    hier.len = 1;
    ip.payload_packet_len = 32;
    p_hdr.len = p_hdr.caplen = sizeof(b);
    pkt.p_hdr = &p_hdr;
    pkt.data = b;
    pkt.proto_hierarchy = &hier;
    pkt.proto_headers_offset = &headers_offset;
    pkt.internal_packet = &ip;

    uint8_t ct = 0;
    attr.field_id = 1; attr.data = &ct;
    int rc = tls_content_type_extraction(&pkt, 1, &attr);
    CHECK(rc == 0, "content_type extractor returns 0 with no TCP ancestor");
}

static void test_extractors_valid_record(void)
{
    printf("[F-BUG-073] regression: a real TLS record still extracts\n");

    /* 50-byte capture; TCP payload / SSL record at offset 19:
     * content_type 0x16 (handshake), version 0x0301, length 25.
     * Offset 19 is ODD on purpose: the shared extraction helpers do raw
     * uint16 casts at proto_offset + position (pre-existing, out of scope),
     * so 19 puts the version read at 20 and the length read at 22 — both
     * even, keeping UBSan focused on the offset guards under test. */
    const size_t caplen = 50;
    uint8_t *b = (uint8_t *)malloc(caplen);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, caplen);
    b[19] = 0x16; b[20] = 0x03; b[21] = 0x01;
    b[22] = 0x00; b[23] = 0x19;

    uint8_t ct = 0;
    int rc = run_tls_extractor(tls_content_type_extraction,
                               19, 31, (uint16_t)caplen, b, 0, &ct);
    CHECK(rc != 0 && ct == 0x16, "content type 0x16 extracted");

    uint16_t v = 0;
    rc = run_tls_extractor(tls_version_extraction,
                           19, 31, (uint16_t)caplen, b, 1, &v);
    CHECK(rc != 0 && v == 0x0301, "version 0x0301 extracted");

    uint16_t l = 0;
    rc = run_tls_extractor(tls_length_extraction,
                           19, 31, (uint16_t)caplen, b, 3, &l);
    CHECK(rc != 0 && l == 25, "record length 25 extracted");
    free(b);
}

int main(void)
{
    printf("=== TLS extension-walk / extractor-offset test (issue #203) ===\n");
    signal(SIGALRM, on_alarm);
    alarm(HANG_TIMEOUT_S);

    test_extension_len_overrun_no_hang();
    test_truncated_last_extension();
    test_valid_extensions_still_extract();
    test_extractors_reject_missing_tcp();
    test_extractors_valid_record();
    /* The wild-offset case aborts under ASan on a pre-fix build — keep it
     * last so the cleaner CHECK failures above still print. */
    test_extractors_reject_bad_offsets();

    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
