/*
 * ssl_tls12_version_test — crafted-input regression test for the TLS 1.2
 * record-version check in the mid-flow SSL/TLS classifier (issue #100).
 *
 * mmt_classify_ssl() (src/mmt_tcpip/lib/protocols/proto_ssl.c) recognizes
 * mid-flow TLS records — Application Data (0x17) and encrypted Alert (0x15) —
 * by content type, record version (payload[1..2], 0x03 0x00..0x03) and record
 * length, bumping flow->l4.tcp.ssl_stage toward SSL classification. Before the
 * fix, the two mid-flow checks tested `payload[10] == 0x03` where every
 * sibling check tests `payload[2] == 0x03`:
 *
 *   - a TLS 1.2 (0x0303) Application Data / Alert record only matched when
 *     payload[10] — the 6th ENCRYPTED body byte — happened to be 0x03, so
 *     mid-flow-captured TLS 1.2 flows classified by luck, and
 *   - a record with an invalid version (e.g. 0x0304) matched whenever that
 *     same encrypted byte happened to be 0x03 (luck-based false positive).
 *
 * The fix reads the record version at payload[2], matching the sibling
 * handshake-record check. This test drives mmt_classify_ssl() with exactly
 * sized TLS 1.2 records whose payload[10] is deterministically NOT 0x03 and
 * asserts the ssl_stage advance (and, over three records, that the flow
 * deterministically reaches ssl_stage 3, the "detected SSL" stage).
 *
 * Each payload buffer is heap-allocated to EXACTLY payload_packet_len bytes,
 * so AddressSanitizer brackets it tightly and flags any read past the last
 * byte. The runner (run_ssl_tls12_version_test.sh) builds the library and this
 * test with -fsanitize=address,undefined -fno-sanitize-recover=all, so any
 * over-read aborts; a clean exit 0 with every assertion passing is the
 * success condition.
 *
 * Build (see run_ssl_tls12_version_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -o ssl_tls12_version_test \
 *       ssl_tls12_version_test.c -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "mmt_core.h"
/*
 * mmt_classify_ssl() reads ipacket->internal_packet->{payload,
 * payload_packet_len, tcp, iph, flow} plus ipacket->session. The internal
 * packet and session structs are opaque in the installed public headers, so we
 * pull in their full definitions from the (in-tree) plugin header. The runner
 * adds the matching -I paths; the layout is identical to the one the library
 * was compiled with, since both come from this same header.
 */
#include "mmt_tcpip_plugin_structs.h"
#include "mmt_tcpip_internal_defs_macros.h"

/*
 * Entry point under test. mmt_classify_ssl() is exported (non-static) in
 * src/mmt_tcpip/lib/protocols/proto_ssl.c but not declared in any public
 * header, so declare it here. It is the classifier mmt_check_ssl() dispatches
 * to; calling it directly skips only the selection/detection bitmask gate,
 * which is unrelated to the record-version checks under test.
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

/*
 * mmt_classify_ssl() only READS ipacket->session — the "fewer than 8 data
 * packets seen, keep waiting" fall-through check at the bottom of the
 * classifier. struct mmt_session_struct is private to mmt_core
 * (private_include/packet_processing.h), so rather than reaching into private
 * core headers, hand it an over-sized zeroed blob: every field the classifier
 * reads is then 0 ("first packet, initiator direction"), which keeps the flow
 * under SSL consideration instead of excluding it.
 */
#define SESSION_BLOB_SIZE 65536
static mmt_session_t *g_session;

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

/* Build a complete TLS record of exactly 5 + body_len bytes: content type,
 * record version 0x03 <ver_minor>, 2-byte body length, body filled with
 * `fill`. A fill byte != 0x03 makes payload[10] (the 6th encrypted body byte
 * the pre-fix check consulted) deterministically NOT 0x03. Caller frees. */
static uint8_t *make_tls_record(uint8_t content_type, uint8_t ver_minor,
                                uint16_t body_len, uint8_t fill)
{
    uint8_t *b = make_buf(NULL, 5u + body_len);
    b[0] = content_type;
    b[1] = 0x03; b[2] = ver_minor;
    b[3] = (uint8_t)(body_len >> 8);
    b[4] = (uint8_t)(body_len & 0xFF);
    memset(b + 5, fill, body_len);
    return b;
}

/*
 * Drive mmt_classify_ssl() with `payload` of exactly `payload_len` bytes on
 * the given flow. The TCP ports are chosen so the WhatsApp (443), Viber
 * (5242/4244) and Gameforge (non-443/80 + IPv4) pre-checks all fall through:
 * Gameforge enters its branch on non-443/80 ports but requires packet->iph
 * (IPv4), which stays NULL here. The internal packet is zeroed except for the
 * fields the classifier actually reads, so the parse never touches
 * uninitialised state and ASan brackets the payload exactly.
 */
static int run_classify_ssl(struct mmt_internal_tcpip_session_struct *flow,
                            const uint8_t *payload, int payload_len)
{
    ipacket_t pkt;
    struct mmt_tcpip_internal_packet_struct ip;
    struct tcphdr tcp;

    memset(&pkt, 0, sizeof(pkt));
    memset(&ip, 0, sizeof(ip));
    memset(&tcp, 0, sizeof(tcp));

    tcp.source = htons(34567);
    tcp.dest = htons(8443);

    ip.flow = flow;
    ip.tcp = (const mmt_una_tcphdr_t *)&tcp;
    ip.payload = payload;
    ip.payload_packet_len = (uint16_t)payload_len;

    pkt.internal_packet = &ip;
    pkt.session = g_session;
    return mmt_classify_ssl(&pkt, 0);
}

/* ---- TLS 1.2 Application Data record advances the SSL stage (AC #1) ----
 *
 * 0x17 0x03 0x03, body 16 -> 21 bytes total (> the 12-byte minimum gate,
 * and 21 <= record length 16 + 5). payload[10] = 0xAA: before the fix the
 * version disjunct read payload[10] instead of payload[2], so this record
 * did not match and ssl_stage stayed 0. */
static void test_tls12_application_data(void)
{
    printf("[#100] mid-flow TLS 1.2 Application Data record (17 03 03)\n");

    struct mmt_internal_tcpip_session_struct flow;
    memset(&flow, 0, sizeof(flow));

    uint8_t *b = make_tls_record(0x17, 0x03, 16, 0xAA);
    int r = run_classify_ssl(&flow, b, 21);
    CHECK(flow.l4.tcp.ssl_stage == 1,
          "TLS 1.2 app-data record advances ssl_stage via record version at payload[2]");
    CHECK(r == 4, "classifier keeps the flow under SSL consideration (returns 4)");
    free(b);
}

/* ---- TLS 1.2 encrypted Alert record advances the SSL stage (AC #1) ----
 *
 * 0x15 0x03 0x03, body 26 -> 31 bytes total (payload_packet_len - record
 * length == 5, the exact-length condition of the alert check).
 * payload[10] = 0xAA as above. */
static void test_tls12_encrypted_alert(void)
{
    printf("[#100] mid-flow TLS 1.2 encrypted Alert record (15 03 03)\n");

    struct mmt_internal_tcpip_session_struct flow;
    memset(&flow, 0, sizeof(flow));

    uint8_t *b = make_tls_record(0x15, 0x03, 26, 0xAA);
    int r = run_classify_ssl(&flow, b, 31);
    CHECK(flow.l4.tcp.ssl_stage == 1,
          "TLS 1.2 encrypted alert record advances ssl_stage via record version at payload[2]");
    CHECK(r == 4, "classifier keeps the flow under SSL consideration (returns 4)");
    free(b);
}

/* ---- the decision is made on payload[2], not encrypted byte payload[10] ----
 *
 * (a) A TLS 1.2 app-data record whose encrypted byte payload[10] HAPPENS to be
 *     0x03 (the pre-fix "lucky" case) must still match after the fix.
 * (b) A record with an invalid record version 0x0304 (real TLS 1.3 keeps the
 *     legacy record version 0x0303 on the wire; the sibling handshake check
 *     accepts only 0x0300..0x0303) must NOT match even when payload[10] is
 *     0x03 — before the fix this was a luck-based false positive. */
static void test_decision_on_record_version_byte(void)
{
    printf("[#100] decision on payload[2], independent of encrypted payload[10]\n");

    struct mmt_internal_tcpip_session_struct flow;

    memset(&flow, 0, sizeof(flow));
    uint8_t *lucky = make_tls_record(0x17, 0x03, 16, 0xAA);
    lucky[10] = 0x03; /* encrypted byte the pre-fix check consulted */
    run_classify_ssl(&flow, lucky, 21);
    CHECK(flow.l4.tcp.ssl_stage == 1,
          "TLS 1.2 record still matches when payload[10] happens to be 0x03");
    free(lucky);

    memset(&flow, 0, sizeof(flow));
    uint8_t *bad = make_tls_record(0x17, 0x04, 16, 0xAA);
    bad[10] = 0x03; /* pre-fix: this byte alone made the record match */
    run_classify_ssl(&flow, bad, 21);
    CHECK(flow.l4.tcp.ssl_stage == 0,
          "invalid record version 0x0304 rejected regardless of payload[10]");
    free(bad);
}

/* ---- sibling record versions are unaffected (no regression) ----
 *
 * TLS 1.0 (0x0301) records match through the untouched payload[2] == 0x01
 * disjunct, with payload[10] != 0x03 to prove no dependence on it. */
static void test_sibling_versions_unaffected(void)
{
    printf("[#100] TLS 1.0 records still match (no regression)\n");

    struct mmt_internal_tcpip_session_struct flow;

    memset(&flow, 0, sizeof(flow));
    uint8_t *appdata = make_tls_record(0x17, 0x01, 16, 0xAA);
    run_classify_ssl(&flow, appdata, 21);
    CHECK(flow.l4.tcp.ssl_stage == 1,
          "TLS 1.0 app-data record still advances ssl_stage");
    free(appdata);

    memset(&flow, 0, sizeof(flow));
    uint8_t *alert = make_tls_record(0x15, 0x01, 26, 0xAA);
    run_classify_ssl(&flow, alert, 31);
    CHECK(flow.l4.tcp.ssl_stage == 1,
          "TLS 1.0 encrypted alert record still advances ssl_stage");
    free(alert);
}

/* ---- mid-flow TLS 1.2 flow reaches the "detected SSL" stage (AC #2) ----
 *
 * Three consecutive mid-flow TLS 1.2 Application Data records on one flow must
 * deterministically drive ssl_stage 0 -> 3. ssl_stage >= 3 is exactly the
 * "detected SSL like messages, process this as SSL" state: the next packet on
 * the flow is classified PROTO_SSL. Before the fix this progression only
 * happened when every record's payload[10] happened to be 0x03. */
static void test_tls12_flow_reaches_detected_stage(void)
{
    printf("[#100] three mid-flow TLS 1.2 records reach ssl_stage 3 deterministically\n");

    struct mmt_internal_tcpip_session_struct flow;
    memset(&flow, 0, sizeof(flow));

    uint8_t *b = make_tls_record(0x17, 0x03, 16, 0xAA);
    int r1 = run_classify_ssl(&flow, b, 21);
    int r2 = run_classify_ssl(&flow, b, 21);
    int r3 = run_classify_ssl(&flow, b, 21);
    CHECK(r1 == 4 && r2 == 4 && r3 == 4,
          "each mid-flow record keeps the flow under SSL consideration");
    CHECK(flow.l4.tcp.ssl_stage == 3,
          "flow reaches ssl_stage 3 (detected SSL) after three TLS 1.2 records");
    free(b);
}

int main(void)
{
    printf("=== TLS 1.2 record-version check test (issue #100) ===\n");
    g_session = (mmt_session_t *)calloc(1, SESSION_BLOB_SIZE);
    if (!g_session) { perror("calloc"); return 2; }
    test_tls12_application_data();
    test_tls12_encrypted_alert();
    test_decision_on_record_version_byte();
    test_sibling_versions_unaffected();
    test_tls12_flow_reaches_detected_stage();
    free(g_session);
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
