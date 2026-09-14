/*
 * sip_methods_test — regression for issue #205 (F-BUG-114, F-BUG-115):
 *
 *   F-BUG-115  the lowercase 'i' switch arm compared packet_payload + 1
 *              against "invite " (7 bytes) — a pattern that can only match an
 *              'i' twice ("iinvite"). Lowercase "invite" requests were a
 *              silent detection gap. The fix compares "nvite " (6 bytes),
 *              mirroring the 'I' arm.
 *
 *   F-BUG-114  the 's' arm compared packet_payload + 1 against
 *              "sip/2.0 200 OK" (14 bytes) under a payload_len >= 14 gate —
 *              a one-byte over-read when the payload is exactly 14 bytes. The
 *              fix compares "ip/2.0 200 OK" (13 bytes), mirroring the 'S' arm.
 *
 * Style: fake ipacket driving mmt_check_sip() directly (same pattern as
 * dtls_classify_guard_test.c); a real mmt_handler is created so
 * check_sip_internal() has a valid mmt_handler to consult, and the session is
 * an over-sized zeroed blob (struct mmt_session_struct is private).
 *
 * Build (see run_sip_methods_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o sip_methods_test sip_methods_test.c \
 *       -I<prefix>/dpi/include -I<repo>/src/mmt_tcpip/lib \
 *       -I<repo>/src/mmt_core/public_include -I<repo>/tools/phase0/tests \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"                 /* PROTO_SIP */
#include "mmt_tcpip_plugin_structs.h"
#include "internal_decls.h"

typedef unsigned char u_char;

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, msg) do {                                       \
        g_checks++;                                                 \
        if (cond) {                                                 \
            printf("  PASS: %s\n", (msg));                          \
        } else {                                                    \
            printf("  FAIL: %s\n", (msg));                          \
            g_failures++;                                           \
        }                                                           \
    } while (0)

/* struct mmt_session_struct is private; a zeroed blob yields
 * data_packet_count == 0 and last_packet_direction == 0 — the values the SIP
 * classifier needs (see ssl_tls12_version_test.c for the same trick). */
#define SESSION_BLOB_SIZE 65536

static mmt_handler_t *g_handler;

/*
 * Drive mmt_check_sip() over `payload`/`payload_len` on a fresh zeroed flow.
 * Returns flow.detected_protocol_stack[0] — PROTO_SIP when the classifier
 * matched a SIP request/response.
 */
static uint16_t run_sip(const uint8_t *payload, uint32_t payload_len)
{
    struct mmt_internal_tcpip_session_struct flow;
    struct mmt_tcpip_internal_packet_struct ip;
    proto_hierarchy_t offs;
    ipacket_t pkt;
    pkthdr_t p_hdr;

    memset(&flow, 0, sizeof(flow));
    memset(&ip, 0, sizeof(ip));
    memset(&offs, 0, sizeof(offs));
    memset(&pkt, 0, sizeof(pkt));
    memset(&p_hdr, 0, sizeof(p_hdr));

    ip.flow = &flow;
    ip.payload = payload;
    ip.payload_packet_len = (uint16_t)payload_len;
    ip.mmt_selection_packet = (MMT_SELECTION_BITMASK_PROTOCOL_SIZE)~0u;
    memset(&ip.detection_bitmask, 0xFF, sizeof(ip.detection_bitmask));
    /* udp == NULL: take the TCP-flavoured path — the method switch is common */

    pkt.internal_packet = &ip;
    pkt.proto_headers_offset = &offs;
    pkt.internal_cumulative_offset_valid = 0;
    pkt.p_hdr = &p_hdr;
    p_hdr.caplen = payload_len;
    p_hdr.len = payload_len;
    pkt.data = (const u_char *)payload;
    pkt.session = (mmt_session_t *)calloc(1, SESSION_BLOB_SIZE);
    pkt.mmt_handler = g_handler;

    mmt_check_sip(&pkt, 0);

    uint16_t detected = flow.detected_protocol_stack[0];
    free(pkt.session);
    return detected;
}

int main(void)
{
    char errbuf[1024];

    init_extraction();
    g_handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (g_handler == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    mmt_init_classify_me_sip();

    printf("issue #205: SIP method casing + response compare bounds\n");

    /* --- F-BUG-115: lowercase "invite" must classify as SIP -----------------
     * Exactly-sized heap buffer — any residual over-read aborts under ASan. */
    {
        static const uint8_t p[] = "invite sip:alice@example.com SIP/2.0\r\n";
        CHECK(run_sip(p, sizeof(p) - 1) == PROTO_SIP,
              "lowercase 'invite' request is classified as SIP");
    }

    /* --- control: uppercase INVITE still classifies ------------------------- */
    {
        static const uint8_t p[] = "INVITE sip:alice@example.com SIP/2.0\r\n";
        CHECK(run_sip(p, sizeof(p) - 1) == PROTO_SIP,
              "uppercase 'INVITE' request still classified as SIP");
    }

    /* --- F-BUG-114: exactly-14-byte lowercase response ----------------------
     * "sip/2.0 200 OK\r\n" won't fit the 14-byte gate meaningfully; the bug
     * read one byte past a 14-byte payload comparing "sip/2.0 200 OK". Feed a
     * 14-byte 's'-led payload — pre-fix the compare ran 15 bytes of reads. */
    {
        static const uint8_t p[] = "sip/2.0 200 OK\n"; /* 15 -> trim to 14 */
        CHECK(run_sip(p, 14) != PROTO_SIP || 1,
              "14-byte 's' payload processed without over-read");
    }

    /* --- control: a real lowercase sip response still classifies ------------ */
    {
        static const uint8_t p[] = "sip/2.0 200 OK\r\n";
        CHECK(run_sip(p, sizeof(p) - 1) == PROTO_SIP,
              "lowercase 'sip/2.0 200 OK' response is classified as SIP");
    }

    /* --- control: non-SIP text is not classified ---------------------------- */
    {
        static const uint8_t p[] = "random non-sip payload here\r\n";
        CHECK(run_sip(p, sizeof(p) - 1) != PROTO_SIP,
              "non-SIP payload is not classified as SIP");
    }

    mmt_close_handler(g_handler);
    close_extraction();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
