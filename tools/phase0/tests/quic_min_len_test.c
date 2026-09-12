/*
 * quic_min_len_test — crafted-input regression test for the QUIC public-header
 * minimum-length gate and per-access bounds re-checks.
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 2d (issue #6, H3).
 *
 * Before the hardening, mmt_check_quic() (src/mmt_tcpip/lib/protocols/proto_quic.c)
 * was reachable on any UDP-with-payload datagram to/from port 80 or 443, where
 * the UDP-with-payload selection mask only guarantees a single payload byte. It
 * then read up to ~15 payload bytes:
 *
 *   - payload[0] and payload[1]                       (public flags + 1 byte)
 *   - sequence(): connect_id() returns up to 9 (CID_LEN_8 + 1), then the SEQ
 *                 loop reads payload[cid_offs + i], i in 0..seq_lens-1 with
 *                 seq_lens up to 6 -> highest index 14 (15 bytes).
 *   - version path: connect_id() up to 9, then payload[ver_offs..ver_offs+3]
 *                   -> highest index 12 (13 bytes).
 *
 * A 1..14 byte datagram therefore over-read past the captured payload. The fix
 * gates the whole public-header parse on payload_packet_len >= 15 and re-checks
 * the remaining length before each multi-byte access.
 *
 * Each payload buffer is heap-allocated to EXACTLY payload_packet_len bytes, so
 * AddressSanitizer brackets it tightly and flags any read past the last byte.
 * The runner (run_quic_min_len_test.sh) builds the library and this test with
 * -fsanitize=address,undefined -fno-sanitize-recover=all, so any over-read
 * aborts; a clean exit 0 with every assertion passing is the success condition.
 *
 * Build (see run_quic_min_len_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -o quic_min_len_test \
 *       quic_min_len_test.c -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

#include "mmt_core.h"
/*
 * mmt_check_quic() reads ipacket->internal_packet->{payload, payload_packet_len,
 * udp, flow, mmt_selection_packet, detection_bitmask}. The internal packet and
 * session structs are opaque in the installed public headers, so we pull in
 * their full definitions from the (in-tree) plugin header. The runner adds the
 * matching -I paths; the layout is identical to the one the library was compiled
 * with, since both come from this same header.
 */
#include "mmt_tcpip_plugin_structs.h"
#include "mmt_tcpip_internal_defs_macros.h"

/*
 * Entry point under test. mmt_check_quic() is exported and declared in
 * mmt_common_internal_include.h, but that header is not installed; declare it
 * here. mmt_init_classify_me_quic() populates the file-scope selection /
 * detection / excluded bitmasks the gate at the top of mmt_check_quic() reads;
 * it is non-static but undeclared in any public header.
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

/*
 * Drive mmt_check_quic() with `payload` of exactly `payload_len` bytes over a
 * UDP/443 datagram that passes the selection / detection / excluded bitmask
 * gate, then assert the return value. The internal packet is zeroed except for
 * the fields mmt_check_quic() actually reads, so the parse never touches
 * uninitialised state and ASan brackets the payload exactly.
 */
static int run_check_quic(const uint8_t *payload, int payload_len)
{
    ipacket_t pkt;
    struct mmt_tcpip_internal_packet_struct ip;
    struct mmt_internal_tcpip_session_struct flow;
    struct udphdr udp;

    memset(&pkt, 0, sizeof(pkt));
    memset(&ip, 0, sizeof(ip));
    memset(&flow, 0, sizeof(flow));
    memset(&udp, 0, sizeof(udp));

    /* UDP to port 443 -> the QUIC-over-UDP branch is taken. */
    udp.source = htons(12345);
    udp.dest = htons(443);

    /* flow->excluded_protocol_bitmask is all-zero (memset), so
     * MMT_BITMASK_COMPARE(excluded, flow.excluded) == 0 -> gate not blocked. */
    ip.flow = &flow;
    ip.udp = &udp;
    ip.payload = payload;
    ip.payload_packet_len = (uint16_t)payload_len;

    /* Selection mask: all bits set so (selection_bitmask & this) == selection_bitmask. */
    ip.mmt_selection_packet = (MMT_SELECTION_BITMASK_PROTOCOL_SIZE)~0u;
    /* Detection bitmask: all bits set so it overlaps the QUIC detection bitmask. */
    memset(&ip.detection_bitmask, 0xFF, sizeof(ip.detection_bitmask));

    pkt.internal_packet = &ip;
    return mmt_check_quic(&pkt, 0);
}

/* ---- minimum-length gate: short datagrams rejected without over-read (AC #1 + #2) ----
 *
 * payload[0] = 0x3C (CID_LEN_8 | SEQ_LEN_6) takes the SEQ branch (0x3C & 0xC3 == 0),
 * which pre-fix walked payload[9..14] (index 14, 15 bytes).
 * payload[0] = 0x0D (CID_LEN_8 | VER_MASK) takes the version branch, which pre-fix
 * read payload[9..12] (index 12, 13 bytes).
 * With a 1..14 byte buffer both must now be rejected at the gate without any
 * read past the last byte. */
static void test_min_len_gate(void)
{
    printf("[H3] QUIC minimum-length gate rejects short datagrams\n");

    const uint8_t flags[2] = {0x3C, 0x0D};
    const char *flag_name[2] = {"SEQ-path flags 0x3C", "version-path flags 0x0D"};

    for (int f = 0; f < 2; f++) {
        for (int n = 1; n <= 14; n++) {
            uint8_t seed[14];
            memset(seed, 0, sizeof(seed));
            seed[0] = flags[f];
            uint8_t *b = make_buf(seed, (size_t)n);
            char msg[96];
            snprintf(msg, sizeof(msg),
                     "%s, payload_len %d rejected without over-read",
                     flag_name[f], n);
            CHECK(run_check_quic(b, n) == 0, msg);
            free(b);
        }
    }
}

/* ---- version path reads stay in bounds at exactly the gate length (AC #2) ----
 *
 * A 15-byte version-path datagram (>= QUIC_MIN_PAYLOAD_LEN) passes the gate; the
 * classifier reads payload[ver_offs..ver_offs+3] (indices 9..12, in bounds for a
 * 15-byte buffer) and, because the version bytes are not a known gQUIC version,
 * returns 0 via the reject path without calling into the connection-add core.
 * This exercises the multi-byte version read on an exactly-sized buffer. */
static void test_version_read_in_bounds(void)
{
    printf("[H3] QUIC version-path multi-byte read stays in bounds at len 15\n");

    uint8_t *b = make_buf(NULL, 15);
    b[0] = 0x0D;                 /* CID_LEN_8 | VER_MASK -> version path, ver_offs = 9 */
    /* payload[9..12] = "ZZZZ": a deliberately non-matching version so the parse
     * reads all four version bytes (in bounds) and then rejects. */
    b[9] = 'Z'; b[10] = 'Z'; b[11] = 'Z'; b[12] = 'Z';
    CHECK(run_check_quic(b, 15) == 0,
          "unknown version at len 15 read in bounds and rejected (no over-read)");
    free(b);
}

int main(void)
{
    printf("=== QUIC minimum-length gating test (issue #6: H3) ===\n");
    /* Populate the file-scope selection/detection/excluded bitmasks that the
     * gate at the top of mmt_check_quic() compares against. */
    mmt_init_classify_me_quic();
    test_min_len_gate();
    test_version_read_in_bounds();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
