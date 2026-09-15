/*
 * quic_dtls_extractor_test — crafted-input regression test for the QUIC-IETF
 * and DTLS attribute extractors hardened in issue #203:
 *
 *   F-BUG-063  _extraction_quic_ietf_att() (src/mmt_tcpip/lib/protocols/
 *              proto_quic_ietf.c) overlaid a packed quic_ietf_long_header_t —
 *              whose members are POINTERS — directly on the packet bytes, then
 *              wrote three pointer values back through that overlay, silently
 *              corrupting 24 bytes of the captured packet. It also advanced
 *              its cursor on the wire-declared connection-id lengths without
 *              checking each step against the captured length, so a crafted
 *              dcid_len=255 forced reads far past the captured end.
 *   F-BUG-071  QUIC_IETF_DESTINATION_CONNECTION_ID extraction cast the
 *              attribute_t itself to mmt_string_data_t (instead of
 *              extracted_data->data), scribbling the string length and the
 *              %-formatted bytes over the attribute's protocol_index, status
 *              and data_type fields, and used %s on raw packet bytes.
 *   F-BUG-070  _dtls_client_hello_extract_attribute() (proto_dtls.c) set
 *              u16_arr->len = cipher_bytes / 2 — unbounded up to 32767 — while
 *              the backing mmt_u16_array_t holds only BINARY_64DATA_LEN (64)
 *              entries: any consumer trusting .len over-reads the array.
 *
 * Each test drives the (now non-static, internal_decls.h-declared) extractor
 * entry points directly with a heap buffer sized EXACTLY to caplen, so ASan
 * brackets every access: any read/write past the captured bytes aborts. The
 * packet-unchanged checks also catch the overlay write-back corruption, which
 * needs no OOB to be observable.
 *
 * Build (see run_quic_dtls_extractor_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o quic_dtls_extractor_test quic_dtls_extractor_test.c \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "mmt_core.h"
/*
 * The extractors read ipacket->{data, p_hdr->caplen, proto_headers_offset,
 * session->session_data[]}. The session struct is opaque in the installed
 * headers — pull the full definition from the in-tree private header (the
 * runner adds the matching -I paths; the layout matches the compiled library).
 */
#include "packet_processing.h"
#include "mmt_tcpip_plugin_structs.h"
#include "mmt_tcpip_internal_defs_macros.h"
#include "mmt_tcpip_attributes.h"   /* DTLS_CONTENT_TYPE_HANDSHAKE, DTLS_* attr ids */
#include "protocols/proto_quic_ietf.h" /* QUIC_IETF_* attribute ids */
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

/* ---------------------------------------------------------------- helpers */

/* Drive _extraction_quic_ietf_att(&pkt, 0, &attr) on a buffer of exactly
 * caplen bytes placed at packet offset 0. session_data[0] stays NULL so the
 * session-state block is skipped — this test exercises packet parsing only. */
static int run_quic_attr(uint32_t field_id, void *out,
                         const uint8_t *buf, uint16_t caplen)
{
    ipacket_t pkt;
    proto_hierarchy_t headers_offset;
    pkthdr_t p_hdr;
    struct mmt_tcpip_internal_packet_struct ip;
    mmt_session_t sess;
    attribute_t attr;

    memset(&pkt, 0, sizeof(pkt));
    memset(&headers_offset, 0, sizeof(headers_offset));
    memset(&p_hdr, 0, sizeof(p_hdr));
    memset(&ip, 0, sizeof(ip));
    memset(&sess, 0, sizeof(sess));
    memset(&attr, 0, sizeof(attr));

    headers_offset.proto_path[0] = 0;            /* index 0 -> offset 0 */
    pkt.proto_headers_offset = &headers_offset;
    pkt.internal_cumulative_offset_valid = 0;

    p_hdr.len = caplen;
    p_hdr.caplen = caplen;
    pkt.p_hdr = &p_hdr;
    pkt.data = (const u_char *)buf;
    pkt.session = &sess;
    pkt.internal_packet = &ip;

    attr.field_id = field_id;
    attr.data = out;
    attr.data_type = MMT_UNDEFINED_TYPE;

    return _extraction_quic_ietf_att(&pkt, 0, &attr);
}

/* Drive _dtls_extract_attribute(&pkt, 0, &attr) on a buffer of exactly caplen
 * bytes at packet offset 0. */
static int run_dtls_attr(uint32_t field_id, void *out,
                         const uint8_t *buf, uint16_t caplen)
{
    ipacket_t pkt;
    proto_hierarchy_t headers_offset;
    pkthdr_t p_hdr;
    struct mmt_tcpip_internal_packet_struct ip;
    attribute_t attr;

    memset(&pkt, 0, sizeof(pkt));
    memset(&headers_offset, 0, sizeof(headers_offset));
    memset(&p_hdr, 0, sizeof(p_hdr));
    memset(&ip, 0, sizeof(ip));
    memset(&attr, 0, sizeof(attr));

    headers_offset.proto_path[0] = 0;
    pkt.proto_headers_offset = &headers_offset;
    pkt.internal_cumulative_offset_valid = 0;

    p_hdr.len = caplen;
    p_hdr.caplen = caplen;
    pkt.p_hdr = &p_hdr;
    pkt.data = (const u_char *)buf;
    pkt.internal_packet = &ip;

    attr.field_id = field_id;
    attr.data = out;
    attr.data_type = MMT_UNDEFINED_TYPE;

    return _dtls_extract_attribute(&pkt, 0, &attr);
}

/* ------------------------------------------- QUIC long header (F-BUG-063) */

/* Byte map for a minimal Initial long-header packet at offset 0:
 *   [0]    flags 0xC0: header_form=1, fixed_bit=1, long_packet_type=0
 *   [1..4] version 0x00000001
 *   [5]    dcid_len, [6..] dcid, then scid_len, scid, then payload (token_len
 *          byte first for Initial).
 */
static uint8_t *build_quic_long(uint8_t dcid_len, uint8_t scid_len,
                                size_t payload_pad, size_t *out_len)
{
    size_t len = 6 + dcid_len + 1 + scid_len + payload_pad;
    uint8_t *b = (uint8_t *)malloc(len);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, len);
    b[0] = 0xC0;
    b[1] = 0; b[2] = 0; b[3] = 0; b[4] = 1;      /* version = 1 */
    b[5] = dcid_len;
    for (uint8_t i = 0; i < dcid_len && 6 + i < len; i++)
        b[6 + i] = (uint8_t)('A' + i);
    size_t off = 6 + dcid_len;
    if (off < len) b[off] = scid_len;
    off += 1;
    for (uint8_t i = 0; i < scid_len && off + i < len; i++)
        b[off + i] = (uint8_t)('a' + i);
    *out_len = len;
    return b;
}

static void test_quic_long_header_valid(void)
{
    printf("[F-BUG-063] valid QUIC long header: fields extracted, packet untouched\n");

    size_t len;
    uint8_t *b = build_quic_long(4, 2, 8, &len);   /* dcid="ABCD" scid="ab" */
    uint8_t *snapshot = (uint8_t *)malloc(len);
    memcpy(snapshot, b, len);

    uint32_t v = 0;
    int rc = run_quic_attr(QUIC_IETF_VERSION, &v, b, (uint16_t)len);
    CHECK(rc != 0 && v == 1, "version extracted (1)");

    uint8_t hf = 0;
    rc = run_quic_attr(QUIC_IETF_HEADER_FORM, &hf, b, (uint16_t)len);
    CHECK(rc != 0 && hf == 1, "header_form extracted (long=1)");

    uint8_t pt = 0xFF;
    rc = run_quic_attr(QUIC_IETF_LONG_PACKET_TYPE, &pt, b, (uint16_t)len);
    CHECK(rc != 0 && pt == 0, "long_packet_type extracted (Initial=0)");

    uint16_t dl = 0;
    rc = run_quic_attr(QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH, &dl, b, (uint16_t)len);
    CHECK(rc != 0 && dl == 4, "dcid_len extracted (4)");

    uint16_t sl = 0;
    rc = run_quic_attr(QUIC_IETF_SOURCE_CONNECTION_ID_LENGTH, &sl, b, (uint16_t)len);
    CHECK(rc != 0 && sl == 2, "scid_len extracted (2)");

    /* The old overlay wrote three 8-byte pointers back into the packet at
     * offsets 6, 15 and 16 — the capture buffer MUST come out byte-identical. */
    CHECK(memcmp(b, snapshot, len) == 0,
          "packet buffer byte-identical after extraction (no overlay write-back)");
    free(snapshot);
    free(b);
}

static void test_quic_long_header_truncated(void)
{
    printf("[F-BUG-063] truncated QUIC long header: every cursor step caplen-checked\n");

    /* dcid_len=255 in a 20-byte capture, allocated to EXACTLY 20 bytes: the
     * old cursor advanced to offset 6+255 and read scid_len ~240 bytes past
     * the captured end — an immediate ASan abort. */
    size_t len = 20;
    uint8_t *b = (uint8_t *)malloc(len);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, len);
    b[0] = 0xC0;                       /* long header, Initial */
    b[1] = 0; b[2] = 0; b[3] = 0; b[4] = 1;
    b[5] = 255;                        /* dcid_len far beyond the capture */
    uint8_t *snapshot = (uint8_t *)malloc(len);
    memcpy(snapshot, b, len);

    uint16_t dl = 0;
    int rc = run_quic_attr(QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH, &dl, b, 20);
    /* The declared dcid region does not fit the capture: the header is
     * malformed, so dependent fields must report UNSET — and nothing may
     * read past byte 20 (ASan) or write into the packet. */
    CHECK(rc == 0, "dcid_len=255 on a 20-byte capture reports UNSET, no over-read");
    CHECK(memcmp(b, snapshot, len) == 0,
          "truncated packet buffer byte-identical (no overlay write-back)");
    free(snapshot);
    free(b);

    /* Header cut mid-connection-id-area: 8 bytes only — even scid_len read is OOB. */
    b = build_quic_long(8, 8, 0, &len);
    uint8_t v = 0xFF;
    rc = run_quic_attr(QUIC_IETF_LONG_PACKET_TYPE, &v, b, 8);
    CHECK(rc == 0, "8-byte capture: dependent field reports UNSET, no over-read");
    free(b);
}

/* --------------------------------- QUIC short header conn-id (F-BUG-071) */

static void test_quic_short_header_conn_id(void)
{
    printf("[F-BUG-071] short-header destination connection id extraction\n");

    /* Short header: flags 0x40 (header_form=0, fixed_bit=1), 8-byte dcid
     * "ABCDEFGH", 4-byte packet number — 13 bytes exactly, so ASan brackets
     * the conn-id bytes tightly. */
    uint8_t *b = (uint8_t *)malloc(13);
    if (!b) { perror("malloc"); exit(2); }
    b[0] = 0x40;
    memcpy(b + 1, "ABCDEFGH", 8);
    b[9] = 1; b[10] = 2; b[11] = 3; b[12] = 4;

    mmt_string_data_t *out = (mmt_string_data_t *)calloc(1, sizeof(mmt_string_data_t));
    int rc = run_quic_attr(QUIC_IETF_DESTINATION_CONNECTION_ID, out, b, 13);

    CHECK(rc != 0, "connection id extraction reports SET");
    CHECK(out->len == 8 && memcmp(out->data, "ABCDEFGH", 8) == 0,
          "8-byte connection id copied byte-exact into extracted_data->data");
    CHECK(out->data[8] == '\0', "extracted id is NUL-terminated");
    free(out);
    free(b);
}

/* --------------------------------- DTLS cipher-suite array (F-BUG-070) */

/* Minimal DTLS record + client_hello at offset 0:
 *   [0]     content_type 22 (handshake)
 *   [1..2]  version 0xFEFD
 *   [3..4]  epoch 0, [5..10] seq 0, [11..12] record length
 *   [13]    handshake type 1 (client_hello)
 *   [14..16] hs length, [17..18] msg seq, [19..21] frag off, [22..24] frag len,
 *   [25..26] client version, [27..58] random  — 46-byte hello prefix ends at 58
 *   [59]    session_id_len = 0
 *   [60]    cookie_len = 0
 *   [61..62] cipher_suites_len = cipher_bytes
 *   [63..]  cipher suite bytes (2 bytes per suite, big-endian)
 */
static uint8_t *build_dtls_hello(uint16_t cipher_bytes_declared,
                               size_t cipher_bytes_present,
                               size_t *out_len)
{
    size_t len = 63 + cipher_bytes_present;
    uint8_t *b = (uint8_t *)malloc(len);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, len);
    b[0] = 22;                       /* DTLS_CONTENT_TYPE_HANDSHAKE */
    b[1] = 0xFE; b[2] = 0xFD;        /* DTLS 1.2 */
    uint16_t rec = (uint16_t)(len - 13);
    b[11] = (uint8_t)(rec >> 8); b[12] = (uint8_t)(rec & 0xFF);
    b[13] = 1;                       /* handshake type: client_hello */
    /* rest of the 46-byte hello header stays zero (len/seq/frag/version/random) */
    b[59] = 0;                       /* session_id_len */
    b[60] = 0;                       /* cookie_len */
    b[61] = (uint8_t)(cipher_bytes_declared >> 8);
    b[62] = (uint8_t)(cipher_bytes_declared & 0xFF);
    for (size_t i = 0; i + 1 < cipher_bytes_present; i += 2) {
        b[63 + i] = 0x00; b[63 + i + 1] = 0x2F;   /* TLS_RSA_WITH_AES_128_CBC_SHA */
    }
    *out_len = len;
    return b;
}

static void test_dtls_cipher_suite_clamped(void)
{
    printf("[F-BUG-070] oversized cipher-suite list clamps to the 64-entry array\n");

    /* 200 declared+present cipher bytes = 100 suites > BINARY_64DATA_LEN(64). */
    size_t len;
    uint8_t *b = build_dtls_hello(200, 200, &len);

    mmt_u16_array_t *arr = (mmt_u16_array_t *)calloc(1, sizeof(mmt_u16_array_t));
    int rc = run_dtls_attr(6 /* DTLS_CLIENT_HELLO_CIPHER_SUITE */, arr, b, (uint16_t)len);

    CHECK(rc != 0, "cipher-suite extraction reports SET");
    CHECK(arr->len <= BINARY_64DATA_LEN,
          "published len never exceeds the fixed 64-entry capacity");
    CHECK(arr->len == BINARY_64DATA_LEN,
          "len is clamped to 64 (not silently dropped)");
    CHECK(arr->data[0] == 0x002F && arr->data[arr->len - 1] == 0x002F,
          "first/last published suite values correct");
    free(arr);
    free(b);
}

static void test_dtls_cipher_suite_normal(void)
{
    printf("[F-BUG-070] well-formed small cipher-suite list unchanged\n");

    size_t len;
    uint8_t *b = build_dtls_hello(6, 6, &len);    /* 3 suites */
    b[63] = 0xC0; b[64] = 0x2B;                   /* mix in a real suite id */

    mmt_u16_array_t *arr = (mmt_u16_array_t *)calloc(1, sizeof(mmt_u16_array_t));
    int rc = run_dtls_attr(6, arr, b, (uint16_t)len);

    CHECK(rc != 0 && arr->len == 3, "3-suite list extracts len=3");
    CHECK(arr->data[0] == 0xC02B && arr->data[1] == 0x002F && arr->data[2] == 0x002F,
          "suite values decoded big-endian");
    free(arr);
    free(b);
}

static void test_dtls_cipher_suite_truncated(void)
{
    printf("[F-BUG-070] declared list longer than captured bytes is bounded\n");

    /* Declares 200 cipher bytes but only 20 are captured: the parse must clamp
     * to the bytes actually present (10 suites), not the declared count. */
    size_t len;
    uint8_t *b = build_dtls_hello(200, 20, &len);

    mmt_u16_array_t *arr = (mmt_u16_array_t *)calloc(1, sizeof(mmt_u16_array_t));
    int rc = run_dtls_attr(6, arr, b, (uint16_t)len);

    CHECK(rc != 0, "truncated list still reports SET on the bytes present");
    CHECK(arr->len == 10, "len follows captured bytes (10), not declared (100)");
    free(arr);
    free(b);
}

int main(void)
{
    printf("=== QUIC/DTLS extractor hardening test (issue #203) ===\n");
    test_quic_long_header_valid();
    test_quic_short_header_conn_id();
    test_dtls_cipher_suite_normal();
    test_dtls_cipher_suite_clamped();
    test_dtls_cipher_suite_truncated();
    /* Keep the ASan-aborting pre-fix case last so the diagnostic CHECKs above
     * still print on an unfixed build. */
    test_quic_long_header_truncated();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
