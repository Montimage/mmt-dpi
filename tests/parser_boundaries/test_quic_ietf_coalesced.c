/*
 * test_quic_ietf_coalesced.c — packet/API-path regression test for issue #333
 * (QUIC-IETF version handling, coalesced packets and session state).
 *
 *   - QUIC version 2 (RFC 9369) long headers are classified like version 1,
 *     and their rotated long packet types are reported in RFC 9000 numbering;
 *     an unsupported version (draft-29) still abstains;
 *   - short-header packets are parsed with the destination connection ID
 *     length the receiving endpoint announced in its long headers (not a
 *     fixed 8 bytes), in both directions;
 *   - coalesced packets (RFC 9000 §12.2) are classified as QUIC after QUIC,
 *     the chained layer is dropped again on a later non-coalesced datagram,
 *     zero padding and a Length running past the capture add no layer, and
 *     a long chain stays bounded by the protocol path;
 *   - a chained packet must carry the destination connection ID of the
 *     datagram's first packet (RFC 9000 §12.2): a trailer with another DCID
 *     adds no layer (#458);
 *   - the chained tail never outlives its datagram: it is dropped when the
 *     checker finds no QUIC on a QUIC flow, and when the last classified
 *     datagram (the 40th, CFG_CLASSIFICATION_THRESHOLD * 2) was coalesced,
 *     later datagrams are walked again past the threshold (#458);
 *   - QUIC over INT starts at the INT shim Length, by the same rule as the
 *     INT dissector (type <= 1, at least 3 words, metadata header Ver 1;
 *     else the historical 56); DSCP 0x20 (CS4) traffic without a valid shim
 *     is not INT (#453), but a flow already classified as INT keeps the
 *     56-byte fallback for its later packets.
 *
 * Crafted Ethernet/IPv4/UDP frames go through mmt_init_handler +
 * packet_process; the packet handler reads the protocol path and the
 * attributes back with get_attribute_extracted_data_at_index(). Every frame
 * is a heap buffer of exactly caplen bytes and run_tests.sh builds with
 * sanitizers under SANITIZE=asan, so any over-read aborts the run.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "protocols/proto_quic_ietf.h"   /* QUIC_IETF_* ids — source tree, not installed */

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, msg) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: %s\n", (msg));                           \
        } else {                                                     \
            printf("  FAIL: %s\n", (msg));                           \
            g_failures++;                                            \
        }                                                            \
    } while (0)

#define MAX_LAYERS 16

/* Values observed on the last packet. */
static int      g_quic_layers;              /* number of quic_ietf layers */
static int      g_quic_index[MAX_LAYERS];   /* their protocol indexes */
static int      g_path_len;
static int      g_int_seen;                 /* PROTO_INT in the path */
static int      g_quic_off;                 /* header offset of the first quic layer */
static uint8_t  g_ip_tos;                   /* IPv4 TOS of the next frame */
static int      g_version_set[MAX_LAYERS];
static uint32_t g_version[MAX_LAYERS];
static int      g_type_set[MAX_LAYERS];
static uint8_t  g_type[MAX_LAYERS];
static int      g_dcid_set;
static uint32_t g_dcid_len;
static uint8_t  g_dcid[32];
static int      g_pn_set;
static uint32_t g_pn;

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    g_quic_layers = 0;
    g_int_seen = 0;
    g_path_len = ipacket->proto_hierarchy ? ipacket->proto_hierarchy->len : 0;
    for (int i = 0; i < g_path_len && i < PROTO_PATH_SIZE; i++) {
        if (ipacket->proto_hierarchy->proto_path[i] == PROTO_INT)
            g_int_seen = 1;
        if (ipacket->proto_hierarchy->proto_path[i] != PROTO_QUIC_IETF)
            continue;
        int n = g_quic_layers++;
        g_quic_index[n] = i;
        const uint32_t *v = get_attribute_extracted_data_at_index(ipacket,
                PROTO_QUIC_IETF, QUIC_IETF_VERSION, (unsigned) i);
        g_version_set[n] = (v != NULL);
        g_version[n] = v ? *v : 0;
        const uint8_t *t = get_attribute_extracted_data_at_index(ipacket,
                PROTO_QUIC_IETF, QUIC_IETF_LONG_PACKET_TYPE, (unsigned) i);
        g_type_set[n] = (t != NULL);
        g_type[n] = t ? *t : 0xff;
    }
    g_dcid_set = 0;
    g_pn_set = 0;
    g_quic_off = -1;
    if (g_quic_layers > 0) {
        unsigned i = (unsigned) g_quic_index[0];
        g_quic_off = get_packet_offset_at_index(ipacket, i);
        const mmt_string_data_t *s = get_attribute_extracted_data_at_index(
                ipacket, PROTO_QUIC_IETF, QUIC_IETF_DESTINATION_CONNECTION_ID, i);
        if (s != NULL) {
            g_dcid_set = 1;
            g_dcid_len = s->len;
            memcpy(g_dcid, s->data, s->len < sizeof(g_dcid) ? s->len : sizeof(g_dcid));
        }
        const uint32_t *pn = get_attribute_extracted_data_at_index(
                ipacket, PROTO_QUIC_IETF, QUIC_IETF_PACKET_NUMBER, i);
        g_pn_set = (pn != NULL);
        g_pn = pn ? *pn : 0;
    }
    return 0;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

/* QUIC long header: `ptype` is the raw 2-bit wire codepoint. `initial` adds
 * the Initial-only Token Length (0). The Length varint (2 bytes) covers a
 * 4-byte packet number plus `payload` bytes. Returns the packet size. */
static size_t quic_long(uint8_t *b, uint32_t version, uint8_t ptype, int initial,
        const uint8_t *dcid, uint8_t dcid_len,
        const uint8_t *scid, uint8_t scid_len, size_t payload) {
    size_t n = 0;
    b[n++] = 0xC0 | (uint8_t)(ptype << 4) | 0x03;
    put_be32(b + n, version); n += 4;
    b[n++] = dcid_len; memcpy(b + n, dcid, dcid_len); n += dcid_len;
    b[n++] = scid_len; memcpy(b + n, scid, scid_len); n += scid_len;
    if (initial)
        b[n++] = 0x00;
    put_be16(b + n, (uint16_t)(0x4000 | (4 + payload))); n += 2;
    put_be32(b + n, 1); n += 4;
    memset(b + n, 0x5a, payload); n += payload;
    return n;
}

/* Short header: fixed bit set, 2-byte packet number (pn length bits = 1). */
static size_t quic_short(uint8_t *b, const uint8_t *dcid, uint8_t dcid_len,
        uint16_t pn, size_t payload) {
    size_t n = 0;
    b[n++] = 0x41;
    memcpy(b + n, dcid, dcid_len); n += dcid_len;
    put_be16(b + n, pn); n += 2;
    memset(b + n, 0x5c, payload); n += payload;
    return n;
}

/* Wrap `quic` (qlen bytes) in Ethernet/IPv4/UDP into an exact-size heap
 * frame and run it. dir 0 = client 10.0.0.1:sport -> server 10.0.0.2:443. */
static void run_udp(mmt_handler_t *h, int dir, uint16_t sport,
        const uint8_t *quic, size_t qlen, uint32_t sec) {
    size_t len = 14 + 20 + 8 + qlen;
    uint8_t *f = malloc(len);
    if (!f) { perror("malloc"); exit(2); }
    static const uint8_t mac_a[6] = {0x02,0,0,0,0,1}, mac_b[6] = {0x02,0,0,0,0,2};
    memcpy(f, dir ? mac_a : mac_b, 6);
    memcpy(f + 6, dir ? mac_b : mac_a, 6);
    put_be16(f + 12, 0x0800);
    uint8_t *ip = f + 14;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    ip[1] = g_ip_tos;
    put_be16(ip + 2, (uint16_t)(20 + 8 + qlen));
    ip[8] = 64; ip[9] = 17;
    uint8_t cli[4] = {10,0,0,1}, srv[4] = {10,0,0,2};
    memcpy(ip + 12, dir ? srv : cli, 4);
    memcpy(ip + 16, dir ? cli : srv, 4);
    uint8_t *udp = ip + 20;
    put_be16(udp,     dir ? 443 : sport);
    put_be16(udp + 2, dir ? sport : 443);
    put_be16(udp + 4, (uint16_t)(8 + qlen));
    put_be16(udp + 6, 0);
    memcpy(udp + 8, quic, qlen);

    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = sec;
    hdr.caplen = (unsigned) len;
    hdr.len = (unsigned) len;
    g_quic_layers = 0;
    g_int_seen = 0;
    g_path_len = 0;
    packet_process(h, &hdr, f);
    free(f);
}

static const uint8_t CID_A[20] = {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,
                                  0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3};
static const uint8_t CID_B[20] = {0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,
                                  0xca,0xcb,0xcc,0xcd,0xce,0xcf,0xd0,0xd1,0xd2,0xd3};

int main(void) {
    char errbuf[1024];
    uint8_t q[2048];
    size_t n, n1;
    uint32_t t = 1;

    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);
    const uint32_t attrs[] = { QUIC_IETF_VERSION, QUIC_IETF_LONG_PACKET_TYPE,
        QUIC_IETF_DESTINATION_CONNECTION_ID, QUIC_IETF_PACKET_NUMBER };
    for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++)
        register_extraction_attribute(h, PROTO_QUIC_IETF, attrs[i]);

    printf("issue #333: QUIC-IETF versions, connection IDs and coalesced packets\n");

    /* --- 1. v1 handshake: client SCID 5 bytes, server SCID 12 bytes ------- */
    n = quic_long(q, 0x00000001, 0, 1, CID_B, 8, CID_A, 5, 1100);
    run_udp(h, 0, 50001, q, n, t++);
    CHECK(g_quic_layers == 1 && g_version_set[0] && g_version[0] == 1,
          "v1 client Initial: one quic_ietf layer, version 1");
    CHECK(g_type_set[0] && g_type[0] == QUIC_IETF_INITIAL_PACKET_TYPE,
          "v1 client Initial: long_packet_type = Initial");
    n = quic_long(q, 0x00000001, 2, 0, CID_A, 5, CID_B, 12, 60);
    run_udp(h, 1, 50001, q, n, t++);
    CHECK(g_quic_layers == 1 && g_type_set[0] && g_type[0] == QUIC_IETF_HANDSHAKE_PACKET_TYPE,
          "v1 server Handshake: long_packet_type = Handshake");

    /* --- 2. short headers use the peer-announced DCID length ------------- */
    n = quic_short(q, CID_B, 12, 0x0102, 30);
    run_udp(h, 0, 50001, q, n, t++);
    CHECK(g_quic_layers == 1, "client 1-RTT: classified as quic_ietf");
    CHECK(g_dcid_set && g_dcid_len == 12 && memcmp(g_dcid, CID_B, 12) == 0,
          "client 1-RTT: DCID is the server's 12-byte SCID, not 8 bytes");
    CHECK(g_pn_set && g_pn == 0x0102,
          "client 1-RTT: 2-byte packet number read after the 12-byte DCID");
    n = quic_short(q, CID_A, 5, 0x0304, 30);
    run_udp(h, 1, 50001, q, n, t++);
    CHECK(g_dcid_set && g_dcid_len == 5 && memcmp(g_dcid, CID_A, 5) == 0,
          "server 1-RTT: DCID is the client's 5-byte SCID");
    CHECK(g_pn_set && g_pn == 0x0304,
          "server 1-RTT: 2-byte packet number read after the 5-byte DCID");

    /* --- 3. QUIC version 2 (RFC 9369) ----------------------------------- */
    n = quic_long(q, 0x6b3343cf, 1 /* v2 Initial */, 1, CID_B, 8, CID_A, 8, 1100);
    run_udp(h, 0, 50002, q, n, t++);
    CHECK(g_quic_layers == 1 && g_version_set[0] && g_version[0] == 0x6b3343cf,
          "v2 client Initial: classified, version 0x6b3343cf");
    CHECK(g_type_set[0] && g_type[0] == QUIC_IETF_INITIAL_PACKET_TYPE,
          "v2 type 0b01 reported as Initial (RFC 9000 numbering)");
    n = quic_long(q, 0x6b3343cf, 3 /* v2 Handshake */, 0, CID_A, 8, CID_B, 8, 60);
    run_udp(h, 1, 50002, q, n, t++);
    CHECK(g_quic_layers == 1 && g_type_set[0] && g_type[0] == QUIC_IETF_HANDSHAKE_PACKET_TYPE,
          "v2 type 0b11 reported as Handshake");

    /* --- 4. unsupported version abstains -------------------------------- */
    n = quic_long(q, 0xff00001d, 0, 1, CID_B, 8, CID_A, 8, 1100);
    run_udp(h, 0, 50003, q, n, t++);
    CHECK(g_quic_layers == 0, "draft-29 Initial: not classified as quic_ietf");

    /* --- 5. coalesced packets ------------------------------------------- */
    n1 = quic_long(q, 0x00000001, 0, 1, CID_B, 8, CID_A, 8, 200);
    n = n1 + quic_long(q + n1, 0x00000001, 2, 0, CID_B, 8, CID_A, 8, 100);
    run_udp(h, 0, 50004, q, n, t++);
    CHECK(g_quic_layers == 2 && g_quic_index[1] == g_quic_index[0] + 1,
          "Initial + Handshake in one datagram: QUIC after QUIC");
    CHECK(g_quic_layers == 2 && g_type_set[0] && g_type[0] == QUIC_IETF_INITIAL_PACKET_TYPE
          && g_type_set[1] && g_type[1] == QUIC_IETF_HANDSHAKE_PACKET_TYPE,
          "coalesced: each layer reports its own packet type");

    n = quic_long(q, 0x00000001, 2, 0, CID_B, 8, CID_A, 8, 100);
    run_udp(h, 0, 50004, q, n, t++);
    CHECK(g_quic_layers == 1, "later single-packet datagram: chained layer dropped");

    n1 = quic_long(q, 0x00000001, 2, 0, CID_A, 8, CID_B, 8, 100);
    n = n1 + quic_short(q + n1, CID_A, 8, 7, 40);
    run_udp(h, 1, 50004, q, n, t++);
    CHECK(g_quic_layers == 2, "Handshake + 1-RTT in one datagram: QUIC after QUIC");

    /* zero padding after the last packet is not a packet */
    n1 = quic_long(q, 0x00000001, 0, 1, CID_B, 8, CID_A, 8, 200);
    memset(q + n1, 0, 900);
    run_udp(h, 0, 50004, q, n1 + 900, t++);
    CHECK(g_quic_layers == 1, "Initial + zero padding: one quic_ietf layer");

    /* a Length running past the capture adds no layer (no over-read) */
    n1 = quic_long(q, 0x00000001, 2, 0, CID_B, 8, CID_A, 8, 100);
    run_udp(h, 0, 50004, q, n1 - 1, t++);
    CHECK(g_quic_layers == 1, "Length past the capture: one quic_ietf layer");

    /* a Token Length varint cut by the capture adds no layer: 20-byte CIDs
     * put it at byte 47, it announces an 8-byte encoding, 5 bytes remain */
    n1 = quic_long(q, 0x00000001, 0, 1, CID_B, 20, CID_A, 20, 200);
    q[1 + 4 + 1 + 20 + 1 + 20] = 0xC0;
    run_udp(h, 0, 50004, q, 1 + 4 + 1 + 20 + 1 + 20 + 5, t++);
    CHECK(g_quic_layers == 1, "truncated Token Length varint: no chained layer");

    /* a long chain of tiny Handshake packets stays bounded by the path */
    n = 0;
    for (int i = 0; i < 40; i++)
        n += quic_long(q + n, 0x00000001, 2, 0, CID_B, 8, CID_A, 8, 16);
    run_udp(h, 0, 50004, q, n, t++);
    CHECK(g_quic_layers > 2 && g_path_len <= PROTO_PATH_SIZE,
          "40 coalesced packets: chain classified, path bounded");

    n = quic_long(q, 0x00000001, 2, 0, CID_B, 8, CID_A, 8, 100);
    run_udp(h, 0, 50004, q, n, t++);
    CHECK(g_quic_layers == 1, "after the long chain: back to one quic_ietf layer");

    /* --- 5b. chained packets must carry the first packet's DCID (#458) --- */
    n1 = quic_long(q, 0x00000001, 2, 0, CID_A, 8, CID_B, 8, 100);
    n = n1 + quic_short(q + n1, CID_B, 8, 7, 40);
    run_udp(h, 1, 50004, q, n, t++);
    CHECK(g_quic_layers == 1, "Handshake + 1-RTT with another DCID: no chained layer");

    n1 = quic_long(q, 0x00000001, 2, 0, CID_A, 8, CID_B, 8, 100);
    memset(q + n1, 0x5c, 40);                    /* fixed bit set, garbage */
    run_udp(h, 1, 50004, q, n1 + 40, t++);
    CHECK(g_quic_layers == 1, "Handshake + 40 garbage bytes with the fixed bit: no chained layer");

    n1 = quic_long(q, 0x00000001, 0, 1, CID_B, 8, CID_A, 8, 200);
    n = n1 + quic_long(q + n1, 0x00000001, 2, 0, CID_A, 8, CID_A, 8, 100);
    run_udp(h, 0, 50004, q, n, t++);
    CHECK(g_quic_layers == 1, "Initial + Handshake with another DCID: no chained layer");

    n1 = quic_long(q, 0x00000001, 0, 1, CID_B, 8, CID_A, 8, 200);
    n = n1 + quic_long(q + n1, 0x00000001, 2, 0, CID_B, 5, CID_A, 8, 100);
    run_udp(h, 0, 50004, q, n, t++);
    CHECK(g_quic_layers == 1, "Initial + Handshake with a shorter DCID prefix: no chained layer");

    /* --- 5c. a non-QUIC datagram on a QUIC flow drops the chain (#458) --- */
    n1 = quic_long(q, 0x00000001, 2, 0, CID_A, 8, CID_B, 8, 100);
    n = n1 + quic_short(q + n1, CID_A, 8, 7, 40);
    run_udp(h, 1, 50004, q, n, t++);
    CHECK(g_quic_layers == 2, "Handshake + 1-RTT, same DCID: QUIC after QUIC");
    memset(q, 0x01, 12);                         /* fixed bit clear: not QUIC */
    run_udp(h, 1, 50004, q, 12, t++);
    CHECK(g_quic_layers == 1, "non-QUIC datagram on the QUIC flow: chained layer dropped");
    n1 = quic_long(q, 0x00000001, 2, 0, CID_A, 8, CID_B, 8, 100);
    n = n1 + quic_short(q + n1, CID_A, 8, 8, 40);
    run_udp(h, 1, 50004, q, n, t++);
    CHECK(g_quic_layers == 2, "coalesced again: QUIC after QUIC");
    n = quic_short(q, CID_A, 8, 9, 4);           /* 15 bytes: too short */
    run_udp(h, 1, 50004, q, n, t++);
    CHECK(g_quic_layers == 1, "too-short short header on the QUIC flow: chained layer dropped");

    /* --- 5d. the 40th (last classified) datagram is coalesced (#458) ----- */
    {
        const uint16_t sport = 50005;
        int single_ok = 1;
        for (int i = 1; i < 40; i++) {
            n = quic_long(q, 0x00000001, i == 1 ? 0 : 2, i == 1, CID_B, 8, CID_A, 8, 100);
            run_udp(h, 0, sport, q, n, t++);
            if (g_quic_layers != 1)
                single_ok = 0;
        }
        CHECK(single_ok, "packets 1-39 of a new flow: one quic_ietf layer each");
        n1 = quic_long(q, 0x00000001, 2, 0, CID_B, 8, CID_A, 8, 100);
        n = n1 + quic_short(q + n1, CID_B, 8, 9, 40);
        run_udp(h, 0, sport, q, n, t++);
        CHECK(g_quic_layers == 2, "packet 40 coalesced: QUIC after QUIC");

        n = quic_long(q, 0x00000001, 2, 0, CID_B, 8, CID_A, 8, 100);
        run_udp(h, 0, sport, q, n, t++);
        CHECK(g_quic_layers == 1, "packet 41 (past the threshold), single packet: chain dropped");
        n1 = quic_long(q, 0x00000001, 2, 0, CID_B, 8, CID_A, 8, 100);
        n = n1 + quic_short(q + n1, CID_B, 8, 10, 40);
        run_udp(h, 0, sport, q, n, t++);
        CHECK(g_quic_layers == 2 && g_type_set[0] && g_type[0] == QUIC_IETF_HANDSHAKE_PACKET_TYPE,
              "packet 42 coalesced past the threshold: chain walked from this datagram");
        memset(q, 0x01, 12);
        run_udp(h, 0, sport, q, 12, t++);
        CHECK(g_quic_layers == 1, "packet 43 not QUIC past the threshold: no chained layer");
        n = quic_short(q, CID_B, 8, 11, 30);
        run_udp(h, 0, sport, q, n, t++);
        CHECK(g_quic_layers == 1, "packet 44, 1-RTT past the threshold: one quic_ietf layer");
    }

    /* --- 6. QUIC over INT (UDP carrier with DSCP 0x20) -------------------- */
    {
        const int l4 = 14 + 20 + 8;
        /* sport 0: a new flow per case; else the INT flow of 50110 */
        struct { uint8_t type, words; size_t bytes; uint16_t sport; int is_int, quic_at; const char *msg; } c[] = {
            { 1, 5,  20, 50100, 1, 20, "INT shim type 1, 5 words: QUIC at 20 bytes" },
            { 1, 2,  56, 50101, 0, -1, "CS4, shim length < 3 words: not INT" },
            { 2, 5,  56, 50102, 0, -1, "CS4, shim type 2: not INT" },
            { 1, 5,  20, 50110, 1, 20, "INT flow, valid shim: QUIC at 20 bytes" },
            { 1, 2,  56, 50110, 1, 56, "INT flow, shim length < 3 words: QUIC at the historical 56" },
            { 2, 5,  56, 50110, 1, 56, "INT flow, shim type 2: QUIC at the historical 56" },
        };
        g_ip_tos = 0x20 << 2;
        for (size_t k = 0; k < sizeof(c) / sizeof(c[0]); k++) {
            memset(q, 0, c[k].bytes);
            q[0] = c[k].type; q[2] = c[k].words;
            q[4] = 0x10;                                 /* metadata header Ver 1 */
            n = c[k].bytes + quic_long(q + c[k].bytes, 0x00000001, 0, 1, CID_B, 8, CID_A, 8, 300);
            run_udp(h, 0, c[k].sport, q, n, t++);
            if (c[k].is_int)
                CHECK(g_int_seen && g_quic_layers == 1 && g_quic_off == l4 + c[k].quic_at, c[k].msg);
            else
                CHECK(!g_int_seen && g_quic_layers == 0, c[k].msg);
        }

        /* a CS4-marked QUIC Initial is QUIC right after UDP, not INT */
        n = quic_long(q, 0x00000001, 0, 1, CID_B, 8, CID_A, 8, 300);
        run_udp(h, 0, 50120, q, n, t++);
        CHECK(!g_int_seen && g_quic_layers == 1 && g_quic_off == l4,
              "CS4 QUIC Initial without INT: QUIC right after UDP");
        g_ip_tos = 0;
    }

    mmt_close_handler(h);
    close_extraction();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
