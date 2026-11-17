/*
 * http2_multi_frame_test — regression test for the HTTP/2 frame walk
 * (montimage-projects/mmt-dpi#770).
 *
 * Before the fix the HTTP/2 dissector (src/mmt_tcpip/lib/protocols/http2.c)
 * read every attribute from the first 9 bytes of the TCP payload:
 *
 *   - a client's first segment opens with the 24-byte connection preface
 *     "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", which was read as a frame header:
 *     http2.type 32, http2.header_stream_id 541611092;
 *   - a segment carrying several frames (HEADERS + RST_STREAM, the HTTP/2
 *     Rapid Reset of CVE-2023-44487) showed only its first one, so no rule
 *     could see the resets.
 *
 * This test drives a crafted h2c flow through the full classification path
 * (packet_process) and checks, per segment, the header attributes of the
 * first frame and the two segment-wide counters http2.frame_count and
 * http2.rst_stream_count. The runner builds the SDK with BUILD=asan, so an
 * extractor writing past its attribute buffer, or a walk reading past the
 * capture, also aborts the run.
 *
 * Build (see run_http2_multi_frame_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o http2_multi_frame_test http2_multi_frame_test.c \
 *       -I<prefix>/dpi/include -L<prefix>/dpi/lib -lmmt_core -ldl -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "tcpip/http2.h"

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

/* What the packet handler saw for the last processed packet. */
typedef struct {
    int      is_http2;
    int      has_type, has_stream_id, has_length, has_frames, has_rst;
    uint8_t  type;
    uint32_t stream_id, length, frames, rst;
} seen_t;
static seen_t g;

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;
    for (int i = 0; ph != NULL && i < ph->len; i++)
        if (ph->proto_path[i] == PROTO_HTTP2)
            g.is_http2 = 1;

    const uint8_t *t = get_attribute_extracted_data(ipacket, PROTO_HTTP2, HTTP2_TYPE);
    const uint32_t *s = get_attribute_extracted_data(ipacket, PROTO_HTTP2, HTTP2_HEADER_STREAM_ID);
    const uint32_t *l = get_attribute_extracted_data(ipacket, PROTO_HTTP2, HTTP2_HEADER_LENGTH);
    const uint32_t *f = get_attribute_extracted_data(ipacket, PROTO_HTTP2, HTTP2_FRAME_COUNT);
    const uint32_t *r = get_attribute_extracted_data(ipacket, PROTO_HTTP2, HTTP2_RST_STREAM_COUNT);
    if ((g.has_type = (t != NULL)))      g.type = *t;
    if ((g.has_stream_id = (s != NULL))) g.stream_id = *s;
    if ((g.has_length = (l != NULL)))    g.length = *l;
    if ((g.has_frames = (f != NULL)))    g.frames = *f;
    if ((g.has_rst = (r != NULL)))       g.rst = *r;
    return 0;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

/* Append a 9-byte frame header plus `len` payload bytes (0x00) to b. */
static size_t put_frame(uint8_t *b, uint32_t len, uint8_t type, uint8_t flags,
                        uint32_t stream_id) {
    b[0] = (len >> 16) & 0xff; b[1] = (len >> 8) & 0xff; b[2] = len & 0xff;
    b[3] = type;
    b[4] = flags;
    put_be32(b + 5, stream_id);
    memset(b + 9, 0, len);
    return 9 + len;
}

static const char PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static uint32_t g_cseq = 1000, g_sseq = 5000;
static uint32_t g_sec  = 1;

/*
 * Send one Ethernet/IPv4/TCP frame client:40000 -> server:80 (or back when
 * to_client) with `plen` payload bytes, plus `trailer` bytes after the IP
 * datagram (Ethernet padding / FCS: captured but outside IP tot_len).
 */
static void send_tcp(mmt_handler_t *h, int to_client, uint8_t flags,
                     const uint8_t *payload, size_t plen,
                     const uint8_t *trailer, size_t tlen) {
    static uint8_t frame[2048];
    memset(frame, 0, sizeof(frame));
    static const uint8_t mac_c[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t mac_s[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(frame,     to_client ? mac_c : mac_s, 6);
    memcpy(frame + 6, to_client ? mac_s : mac_c, 6);
    put_be16(frame + 12, 0x0800);

    uint8_t *ip = frame + 14;
    ip[0] = 0x45;
    put_be16(ip + 2, (uint16_t) (20 + 20 + plen));
    ip[8] = 64;
    ip[9] = 6;
    uint8_t c[4] = {10, 0, 0, 1}, s[4] = {10, 0, 0, 2};
    memcpy(ip + 12, to_client ? s : c, 4);
    memcpy(ip + 16, to_client ? c : s, 4);

    uint8_t *tcp = ip + 20;
    put_be16(tcp,     to_client ? 80 : 40000);
    put_be16(tcp + 2, to_client ? 40000 : 80);
    put_be32(tcp + 4, to_client ? g_sseq : g_cseq);
    put_be32(tcp + 8, to_client ? g_cseq : g_sseq);
    tcp[12] = 0x50;
    tcp[13] = flags;
    put_be16(tcp + 14, 0xffff);
    if (plen) memcpy(tcp + 20, payload, plen);
    if (tlen) memcpy(tcp + 20 + plen, trailer, tlen);

    uint32_t adv = (uint32_t) plen + ((flags & 0x03) ? 1 : 0); /* SYN/FIN */
    if (to_client) g_sseq += adv; else g_cseq += adv;

    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = g_sec++;
    hdr.caplen = hdr.len = (unsigned int) (14 + 20 + 20 + plen + tlen);
    memset(&g, 0, sizeof(g));
    packet_process(h, &hdr, frame);
}

#define TCP_ACK 0x10
#define TCP_PSH_ACK 0x18

int main(void) {
    char errbuf[1024];
    uint8_t seg[1024];
    size_t n;

    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_extraction_attribute(h, PROTO_HTTP2, HTTP2_TYPE);
    register_extraction_attribute(h, PROTO_HTTP2, HTTP2_HEADER_STREAM_ID);
    register_extraction_attribute(h, PROTO_HTTP2, HTTP2_HEADER_LENGTH);
    register_extraction_attribute(h, PROTO_HTTP2, HTTP2_FRAME_COUNT);
    register_extraction_attribute(h, PROTO_HTTP2, HTTP2_RST_STREAM_COUNT);
    register_packet_handler(h, 1, packet_handler, NULL);

    printf("=== HTTP/2 frame walk (montimage-projects/mmt-dpi#770) ===\n");

    CHECK(get_attribute_id_by_protocol_and_attribute_names("http2", "frame_count")
              == HTTP2_FRAME_COUNT
          && get_attribute_id_by_protocol_and_attribute_names("http2", "rst_stream_count")
              == HTTP2_RST_STREAM_COUNT,
          "http2.frame_count and http2.rst_stream_count are registered");
    CHECK(get_attribute_data_type(PROTO_HTTP2, HTTP2_TYPE) == MMT_U8_DATA,
          "http2.type keeps its MMT_U8_DATA type");

    send_tcp(h, 0, 0x02 /*SYN*/, NULL, 0, NULL, 0);
    send_tcp(h, 1, 0x12 /*SYN-ACK*/, NULL, 0, NULL, 0);
    send_tcp(h, 0, TCP_ACK, NULL, 0, NULL, 0);

    /* 1. Preface + SETTINGS(6) + WINDOW_UPDATE(4): the preface is not a frame. */
    n = 0;
    memcpy(seg, PREFACE, 24); n += 24;
    n += put_frame(seg + n, 6, 0x4, 0, 0);
    n += put_frame(seg + n, 4, 0x8, 0, 0);
    send_tcp(h, 0, TCP_PSH_ACK, seg, n, NULL, 0);
    printf("[1] preface + SETTINGS + WINDOW_UPDATE\n");
    CHECK(g.is_http2, "preface segment classified as HTTP/2");
    CHECK(g.has_type && g.type == 0x4, "http2.type = 4 (SETTINGS), not 32 (the preface)");
    CHECK(g.has_stream_id && g.stream_id == 0,
          "http2.header_stream_id = 0, not 541611092 (the preface)");
    CHECK(g.has_length && g.length == 6, "http2.header_length = 6 (SETTINGS payload)");
    CHECK(g.has_frames && g.frames == 2, "http2.frame_count = 2");
    CHECK(g.has_rst && g.rst == 0, "http2.rst_stream_count = 0");

    /* 2. Server SETTINGS: one frame. */
    n = put_frame(seg, 0, 0x4, 0, 0);
    send_tcp(h, 1, TCP_PSH_ACK, seg, n, NULL, 0);
    printf("[2] server SETTINGS\n");
    CHECK(g.is_http2 && g.has_type && g.type == 0x4, "http2.type = 4");
    CHECK(g.has_frames && g.frames == 1 && g.has_rst && g.rst == 0,
          "frame_count = 1, rst_stream_count = 0");

    /* 2b. The segment of this test's first version: SETTINGS + HEADERS +
     *     RST_STREAM. Its two failing checks ("contains HEADERS", "contains
     *     RST_STREAM") asked that the frames after the first one be seen:
     *     all three are counted and the reset is visible. */
    n = 0;
    n += put_frame(seg + n, 0, 0x4, 0, 0);
    n += put_frame(seg + n, 0, 0x1, 0, 1);
    n += put_frame(seg + n, 4, 0x3, 0, 1);
    send_tcp(h, 0, TCP_PSH_ACK, seg, n, NULL, 0);
    printf("[2b] SETTINGS + HEADERS + RST_STREAM in one segment\n");
    CHECK(g.has_type && g.type == 0x4, "http2.type = 4 (SETTINGS, the first frame)");
    CHECK(g.has_frames && g.frames == 3,
          "http2.frame_count = 3: HEADERS and RST_STREAM after SETTINGS are seen");
    CHECK(g.has_rst && g.rst == 1, "http2.rst_stream_count = 1: the RST_STREAM is visible");

    /* 3. Rapid Reset: 3 x (HEADERS + RST_STREAM) in one segment. */
    n = 0;
    for (uint32_t sid = 1; sid <= 5; sid += 2) {
        n += put_frame(seg + n, 5, 0x1, 0x5, sid);
        n += put_frame(seg + n, 4, 0x3, 0, sid);
    }
    send_tcp(h, 0, TCP_PSH_ACK, seg, n, NULL, 0);
    printf("[3] 3 x (HEADERS + RST_STREAM) in one segment\n");
    CHECK(g.is_http2, "segment classified as HTTP/2");
    CHECK(g.has_type && g.type == 0x1 && g.has_stream_id && g.stream_id == 1,
          "header attributes still describe the first frame (HEADERS, stream 1)");
    CHECK(g.has_frames && g.frames == 6, "http2.frame_count = 6");
    CHECK(g.has_rst && g.rst == 3, "http2.rst_stream_count = 3 (the resets after the first frame)");

    /* 4. Invalid RST_STREAM shapes (RFC 9113 §6.4) do not count as resets:
     *    an 8-byte payload, and stream 0. A valid one closes the segment. */
    n = 0;
    n += put_frame(seg + n, 8, 0x3, 0, 7);
    n += put_frame(seg + n, 4, 0x3, 0, 0);
    n += put_frame(seg + n, 4, 0x3, 0, 9);
    send_tcp(h, 0, TCP_PSH_ACK, seg, n, NULL, 0);
    printf("[4] RST_STREAM shapes\n");
    CHECK(g.has_frames && g.frames == 3, "http2.frame_count = 3");
    CHECK(g.has_rst && g.rst == 1, "only the well-formed RST_STREAM is counted");

    /* 5. Bytes after the IP datagram are not walked: a well-formed
     *    RST_STREAM sits in an Ethernet trailer past IP tot_len. */
    uint8_t trailer[16];
    size_t tl = put_frame(trailer, 4, 0x3, 0, 11);
    n = put_frame(seg, 4, 0x8, 0, 0);
    send_tcp(h, 0, TCP_PSH_ACK, seg, n, trailer, tl);
    printf("[5] frame in the Ethernet trailer\n");
    CHECK(g.has_frames && g.frames == 1, "http2.frame_count = 1 (trailer not walked)");
    CHECK(g.has_rst && g.rst == 0, "http2.rst_stream_count = 0 (trailer not walked)");

    /* 6. A frame continued in the next segment still counts, then the walk
     *    stops; 5 trailing bytes (half a header) do not count. */
    n = 0;
    n += put_frame(seg + n, 4, 0x3, 0, 13);
    n += put_frame(seg + n, 0, 0x0, 0, 13);       /* a DATA header ... */
    seg[13 + 2] = 200;                             /* ... claiming 200 bytes */
    send_tcp(h, 0, TCP_PSH_ACK, seg, n, NULL, 0);
    printf("[6] last frame continued in the next segment\n");
    CHECK(g.has_frames && g.frames == 2 && g.has_rst && g.rst == 1,
          "frame_count = 2, rst_stream_count = 1");
    n = put_frame(seg, 4, 0x3, 0, 15);
    memset(seg + n, 0, 5); n += 5;
    send_tcp(h, 0, TCP_PSH_ACK, seg, n, NULL, 0);
    CHECK(g.has_frames && g.frames == 1 && g.has_rst && g.rst == 1,
          "a partial trailing header is not a frame");

    /* 7. A segment holding the preface alone has no frame. */
    n = 24;
    memcpy(seg, PREFACE, 24);
    send_tcp(h, 0, TCP_PSH_ACK, seg, n, NULL, 0);
    printf("[7] preface alone\n");
    CHECK(!g.has_type && !g.has_stream_id, "no header attribute is read from the preface");
    CHECK(!g.has_frames && !g.has_rst, "no frame counter is reported");

    /* 8. A pure ACK reports nothing, even with a trailer long enough to hold
     *    a frame header (6 bytes of padding + a 4-byte FCS). */
    send_tcp(h, 1, TCP_ACK, NULL, 0, NULL, 0);
    printf("[8] pure ACK\n");
    CHECK(!g.has_frames && !g.has_rst, "no frame counter on an empty segment");
    memset(trailer, 0, sizeof(trailer));
    send_tcp(h, 1, TCP_ACK, NULL, 0, trailer, 10);
    CHECK(!g.has_frames && !g.has_rst && !g.has_type,
          "no frame read from a 10-byte trailer after an empty segment");

    /* 8b. #107: http2.header_length reports a frame up to the initial
     *     SETTINGS_MAX_FRAME_SIZE (16384, RFC 9113 §4.2), not only up to 2000.
     *     Each segment holds the header of a DATA frame continued later. */
    printf("[8b] header_length bound\n");
    static const uint32_t lens[] = {3000, 16384, 16385};
    for (int k = 0; k < 3; k++) {
        n = put_frame(seg, 0, 0x0, 0, 17);
        seg[0] = (lens[k] >> 16) & 0xff; seg[1] = (lens[k] >> 8) & 0xff; seg[2] = lens[k] & 0xff;
        send_tcp(h, 0, TCP_PSH_ACK, seg, n, NULL, 0);
        if (lens[k] <= 16384)
            CHECK(g.has_length && g.length == lens[k],
                  "header_length up to 16384 is reported");
        else
            CHECK(!g.has_length, "header_length above 16384 is not reported");
        CHECK(g.has_frames && g.frames == 1 && g.has_rst && g.rst == 0,
              "frame_count = 1, rst_stream_count = 0");
    }

    /* 9. Random segments (fixed seed): the counters equal a reference walk
     *    of the TCP payload alone, whatever the frame lengths claim and
     *    whatever trailer follows the IP datagram. Under ASan this also
     *    proves the walk never reads past the capture. */
    printf("[9] 2000 random segments vs a reference walk\n");
    unsigned int seed = 770;
    int mismatches = 0, unclassified = 0, rst_seen = 0;
    for (int it = 0; it < 2000; it++) {
        size_t plen = 1 + (size_t) (rand_r(&seed) % 600);
        for (size_t i = 0; i < plen; i++)
            seg[i] = (uint8_t) rand_r(&seed);
        /* plant plausible frames: small lengths, types 0..9, some resets */
        for (size_t p = 0; p + 9 <= plen && rand_r(&seed) % 4; ) {
            uint32_t len = (uint32_t) (rand_r(&seed) % 4 ? rand_r(&seed) % 40 : 4);
            seg[p] = 0; seg[p + 1] = (uint8_t) (len >> 8); seg[p + 2] = (uint8_t) len;
            seg[p + 3] = (uint8_t) (rand_r(&seed) % 10);
            p += 9 + len;
        }
        size_t tlen = (size_t) (rand_r(&seed) % 16);
        for (size_t i = 0; i < tlen; i++)
            trailer[i] = (uint8_t) rand_r(&seed);

        uint32_t want_frames = 0, want_rst = 0;
        for (uint64_t p = 0; p + 9 <= plen; ) {
            uint32_t len = (uint32_t) seg[p] << 16 | (uint32_t) seg[p + 1] << 8 | seg[p + 2];
            uint32_t sid = ((uint32_t) seg[p + 5] << 24 | (uint32_t) seg[p + 6] << 16
                            | (uint32_t) seg[p + 7] << 8 | seg[p + 8]) & 0x7FFFFFFF;
            want_frames++;
            if (seg[p + 3] == 0x3 && len == 4 && sid != 0)
                want_rst++;
            p += 9 + (uint64_t) len;
        }
        rst_seen += (int) want_rst;

        send_tcp(h, 0, TCP_PSH_ACK, seg, plen, trailer, tlen);
        if (!g.is_http2) { unclassified++; continue; }
        uint32_t got_frames = g.has_frames ? g.frames : 0;
        uint32_t got_rst = g.has_rst ? g.rst : 0;
        if (got_frames != want_frames || got_rst != want_rst
                || g.has_frames != (want_frames > 0)) {
            if (mismatches++ < 5)
                printf("    it %d: plen %zu tlen %zu frames %u/%u rst %u/%u\n", it,
                       plen, tlen, got_frames, want_frames, got_rst, want_rst);
        }
    }
    CHECK(unclassified == 0, "every random segment stays in the HTTP/2 session");
    CHECK(rst_seen > 0, "the random segments include resets");
    CHECK(mismatches == 0, "frame_count and rst_stream_count match the reference walk");

    mmt_close_handler(h);
    close_extraction();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
