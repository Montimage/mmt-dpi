/*
 * http2_bounds_test — crafted-input regression test for the HTTP/2
 * packet-mutation helpers (issue #204, F-BUG-057).
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 2e.
 *
 * The mutation side of http2.c used to write at offsets derived from the
 * packet's attacker-controlled 24-bit frame length with no destination-size
 * argument at all (update_stream_id, update_window_update, fuzz_payload) or
 * with checks that verified only the write *start* — and with `>` where `>=`
 * was required (restore_http2_packet, modify_get, inject_http2_packet).
 * Every helper now takes the data_out size and proves the whole write window
 * via http2_can_write() before touching the buffer.
 *
 * Every destination buffer is heap-allocated to EXACTLY its size, so
 * AddressSanitizer brackets it tightly and aborts on any read/write past the
 * end — a clean exit plus all CHECKs passing is the success condition. The
 * companion checks also verify the helpers still write where the window fits
 * (no functional regression on the happy path).
 *
 * Build (done by run_http2_bounds_test.sh against an installed prefix):
 *   gcc -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o http2_bounds_test http2_bounds_test.c \
 *       -I <prefix>/dpi/include -L <prefix>/dpi/lib -lmmt_tcpip -lmmt_core
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"

/* Mutation helpers under test — declared in the shared internal header
 * (issue #186 convention). PROTO_HTTP2 + the HTTP2_* attribute ids come from
 * mmt_tcpip_protocols.h via the internal http2.h. */
#include "internal_decls.h"
/* PROTO_HTTP2 + HTTP2_* attribute ids — installed tcpip headers. */
#include "tcpip/mmt_tcpip_protocols.h"
#include "tcpip/http2.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do { \
        g_checks++; \
        if (!(cond)) { \
            g_failures++; \
            printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); \
        } \
    } while (0)

/* Minimal ipacket good enough for the helpers: ->data, ->p_hdr->caplen and,
 * for update_http2_data(), a one-entry proto path placing PROTO_HTTP2 at a
 * chosen offset. */
static void make_ipacket(ipacket_t *ip, uint8_t *data, uint32_t caplen,
        int http2_offset)
{
    memset(ip, 0, sizeof(*ip));
    ip->data = data;
    ip->p_hdr = &ip->internal_p_hdr;
    ip->p_hdr->caplen = caplen;
    ip->proto_hierarchy = &ip->internal_proto_hierarchy;
    ip->proto_headers_offset = &ip->internal_proto_headers_offset;
    ip->proto_hierarchy->len = 1;
    ip->proto_hierarchy->proto_path[0] = PROTO_HTTP2;
    /* get_packet_offset_at_index() sums proto_headers_offset->proto_path
     * [0..index] — one entry at index 0, so its value IS the offset. */
    ip->proto_headers_offset->proto_path[0] = http2_offset;
}

/* Snapshot check: a region of the buffer is unchanged. */
static int region_is(const uint8_t *buf, int off, int n, uint8_t v)
{
    int i;
    for (i = 0; i < n; i++)
        if (buf[off + i] != v) return 0;
    return 1;
}

static void test_update_stream_id(void)
{
    printf("[H2-1] update_stream_id bounds\n");

    /* proto_offset so near the end that the 4-byte stream-id write does not
     * fit: pre-fix wrote past the buffer; now must refuse and return 0. */
    {
        uint8_t *buf = (uint8_t *) malloc(16);
        memset(buf, 0xAA, 16);
        int r = update_stream_id((char *) buf, 13, 0x11223344, 16);
        CHECK(r == 0 && region_is(buf, 13, 3, 0xAA),
              "stream-id write window past the end is refused");
        free(buf);
    }

    /* Negative proto_offset: stream_id_offset = 2 is in range so the first
     * write is allowed, but the attacker header-length read at
     * proto_offset-1 = -4 must be refused before the payload write. ASan
     * flags any access outside [0,8). */
    {
        uint8_t *buf = (uint8_t *) malloc(8);
        memset(buf, 0xAA, 8);
        int r = update_stream_id((char *) buf, -3, 0x11223344, 8);
        CHECK(buf[0] == 0xAA && buf[6] == 0xAA && buf[7] == 0xAA,
              "negative proto_offset never touches bytes outside the write window");
        (void) r;
        free(buf);
    }

    /* Happy path: stream-id window fits, method byte 0x83 (131) selects the
     * payload branch, zero header length -> second write at +18..+21. */
    {
        uint8_t *buf = (uint8_t *) malloc(32);
        memset(buf, 0xAA, 32);
        buf[3] = buf[4] = buf[5] = buf[6] = 0x00; /* header_length = 0 */
        buf[13] = 0x83;                          /* method_offset value 131 */
        int r = update_stream_id((char *) buf, 4, 0x11223344, 32);
        CHECK(r == 1, "in-window stream-id update proceeds");
        CHECK(buf[9] == 0x11 && buf[10] == 0x22 && buf[11] == 0x33 && buf[12] == 0x44,
              "header stream-id written at proto_offset+5");
        CHECK(buf[18] == 0x11 && buf[19] == 0x22 && buf[20] == 0x33 && buf[21] == 0x44,
              "payload stream-id written at payload offset");
        free(buf);
    }

    /* Payload-branch stream-id window beyond the buffer: header_length is
     * attacker-controlled; the write at header_length+proto_offset+14 must
     * be refused. */
    {
        uint8_t *buf = (uint8_t *) malloc(32);
        memset(buf, 0xAA, 32);
        buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x20; /* header_length = 0x20 */
        buf[13] = 0x83;
        int r = update_stream_id((char *) buf, 4, 0x11223344, 32);
        /* payload write offset = 4+0x20+9+5 = 56 > 32 -> refused; header
         * stream-id write at 9..12 already happened and is in-bounds. */
        CHECK(buf[9] == 0x11 && region_is(buf, 28, 4, 0xAA),
              "out-of-window payload stream-id write is refused");
        (void) r;
        free(buf);
    }
}

static void test_update_window_update(void)
{
    printf("[H2-2] update_window_update bounds\n");

    /* window_size_offset = proto_offset + 9; with proto_offset 4 the 4-byte
     * write needs 17 bytes — a 13-byte buffer must refuse. */
    {
        uint8_t *buf = (uint8_t *) malloc(13);
        memset(buf, 0xAA, 13);
        int r = (int) update_window_update((char *) buf, 4, 1, 13);
        CHECK(r == 0 && region_is(buf, 0, 13, 0xAA),
              "window-update write past the end is refused");
        free(buf);
    }

    /* Exact-fit edge: offset+4 == size must succeed (the old > vs >= class
     * of bug); the four bytes become 00 00 00 FF. */
    {
        uint8_t *buf = (uint8_t *) malloc(13);
        memset(buf, 0xAA, 13);
        int r = (int) update_window_update((char *) buf, 0, 1, 13);
        CHECK(r == -9 && buf[9] == 0 && buf[10] == 0 && buf[11] == 0 && buf[12] == 0xFF,
              "exact-fit window-update writes 00 00 00 FF");
        free(buf);
    }
}

static void test_inject_http2_packet(void)
{
    uint8_t inject[] = {0x00,0x00,0x04,0x08,0x00,0x00,0x00,0x00,0x00,
                        0x0f,0xff,0x00,0x01};
    printf("[H2-3] inject_http2_packet bounds\n");

    /* proto_offset + len > size: the old `proto_offset > size` check missed
     * the length term entirely. */
    {
        uint8_t *buf = (uint8_t *) malloc(32);
        memset(buf, 0xAA, 32);
        int r = inject_http2_packet(buf, inject, 20, (int) sizeof(inject), 32);
        CHECK(r == 0 && region_is(buf, 20, 12, 0xAA),
              "injection overflowing the buffer tail is refused");
        free(buf);
    }

    /* In-window injection copies the frame. */
    {
        uint8_t *buf = (uint8_t *) malloc(32);
        memset(buf, 0xAA, 32);
        buf[3] = buf[4] = buf[5] = buf[6] = 0x00; /* header_length = 0 */
        int r = inject_http2_packet(buf, inject, 4, (int) sizeof(inject), 32);
        CHECK(r == (int) sizeof(inject) - 9 && memcmp(buf + 4, inject, sizeof(inject)) == 0,
              "in-window injection copies the frame");
        free(buf);
    }
}

static void test_restore_http2_packet(void)
{
    printf("[H2-4] restore_http2_packet bounds\n");
    ipacket_t ip;

    /* Frame length in the packet claims 0xFFFFFF bytes: both the read from
     * packet->data and the write into data_out must be refused. */
    {
        uint8_t *src = (uint8_t *) malloc(32);
        uint8_t *dst = (uint8_t *) malloc(32);
        memset(src, 0x55, 32); memset(dst, 0xAA, 32);
        src[0] = 0xFF; src[1] = 0xFF; src[2] = 0xFF; src[3] = 0x00;
        dst[0] = 0xFF; dst[1] = 0xFF; dst[2] = 0xFF; dst[3] = 0x00;
        make_ipacket(&ip, src, 32, 1);
        int r = restore_http2_packet(dst, &ip, 1, 32);
        CHECK(r == 0 && region_is(dst, 1, 31, 0xAA) == 0 || r == 0,
              "attacker 24-bit length restore is refused");
        CHECK(region_is(dst, 16, 16, 0xAA), "no tail bytes touched");
        free(src); free(dst);
    }

    /* Exact-boundary copy: new_length+9 == remaining room must succeed —
     * the `>` vs `>=` regression case. proto_offset 1, new_length 22 ->
     * copies bytes 1..31 of a 32-byte buffer. */
    {
        uint8_t *src = (uint8_t *) malloc(32);
        uint8_t *dst = (uint8_t *) malloc(32);
        memset(src, 0x55, 32); memset(dst, 0xAA, 32);
        /* 4-byte big-endian length field at [0..3]: 00 00 00 16 = 22 */
        src[0] = 0x00; src[1] = 0x00; src[2] = 0x00; src[3] = 0x16;
        dst[0] = 0x00; dst[1] = 0x00; dst[2] = 0x00; dst[3] = 0x16;
        make_ipacket(&ip, src, 32, 1);
        int r = restore_http2_packet(dst, &ip, 1, 32);
        CHECK(r == 0 && memcmp(dst + 1, src + 1, 31) == 0,
              "exact-fit restore copies the frame");
        free(src); free(dst);
    }

    /* proto_offset == 0: the length-field read starts at -1 -> refused. */
    {
        uint8_t *src = (uint8_t *) malloc(32);
        uint8_t *dst = (uint8_t *) malloc(32);
        memset(src, 0x55, 32); memset(dst, 0xAA, 32);
        make_ipacket(&ip, src, 32, 0);
        int r = restore_http2_packet(dst, &ip, 0, 32);
        CHECK(r == 0 && region_is(dst, 0, 32, 0xAA),
              "proto_offset 0 refuses the negative length read");
        free(src); free(dst);
    }
}

static void test_modify_get(void)
{
    printf("[H2-5] modify_get bounds\n");

    /* Attacker header_length pushes the authority write far past the end. */
    {
        uint8_t *buf = (uint8_t *) malloc(64);
        memset(buf, 0xAA, 64);
        buf[3] = 0x00; buf[4] = 0xFF; buf[5] = 0xFF; buf[6] = 0xFF; /* 0x00FFFFFF */
        int r = modify_get(buf, 4, 64);
        CHECK(r == 0 && region_is(buf, 40, 24, 0xAA),
              "huge header_length authority write is refused");
        free(buf);
    }

    /* Happy path: header_length 0 -> authority lands at proto_offset+7 and
     * the 24-bit length field is bumped by 18. */
    {
        uint8_t *buf = (uint8_t *) malloc(64);
        memset(buf, 0xAA, 64);
        buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x00;
        int r = modify_get(buf, 4, 64);
        CHECK(r == 18 && buf[4] == 0x00 && buf[5] == 0x00 && buf[6] == 18,
              "in-window modify_get writes authority and bumps length");
        free(buf);
    }
}

static void test_fuzz_payload(void)
{
    printf("[H2-6] fuzz_payload bounds\n");
    ipacket_t ip;

    /* Attacker header+payload lengths point the fuzz window far past the
     * buffer: pre-fix wrote at data_out[~33 MB]. Must refuse. */
    {
        uint8_t *buf = (uint8_t *) malloc(64);
        memset(buf, 0xAA, 64);
        make_ipacket(&ip, buf, 64, 4);
        buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x00; /* header_length = 0 */
        buf[12] = 0x00; buf[13] = 0xFF; buf[14] = 0xFF; buf[15] = 0xFF; /* payload_length = 0x00FFFFFF */
        int r = fuzz_payload(buf, &ip, 4, 64);
        CHECK(r == 0 && region_is(buf, 32, 32, 0xAA),
              "huge payload_length fuzz window is refused");
        free(buf);
    }

    /* Negative proto_offset: the length read starts before the buffer. */
    {
        uint8_t *buf = (uint8_t *) malloc(64);
        memset(buf, 0xAA, 64);
        make_ipacket(&ip, buf, 64, 0);
        int r = fuzz_payload(buf, &ip, 0, 64);
        CHECK(r == 0 && region_is(buf, 0, 64, 0xAA),
              "proto_offset 0 refuses the negative length read");
        free(buf);
    }

    /* In-window fuzz: header_length 0 -> payload hdr at 12; payload_length 16
     * -> fuzz writes into data_out[31..38]. */
    {
        uint8_t *buf = (uint8_t *) malloc(64);
        memset(buf, 0xAA, 64);
        make_ipacket(&ip, buf, 64, 4);
        buf[3] = buf[4] = buf[5] = buf[6] = 0x00;
        buf[12] = 0x00; buf[13] = 0x00; buf[14] = 0x00; buf[15] = 0x10; /* payload_length = 16 */
        int r = fuzz_payload(buf, &ip, 4, 64);
        CHECK(r == 0, "in-window fuzz completes");
        CHECK(!region_is(buf, 31, 8, 0xAA),
              "fuzz actually rewrote bytes in the window");
        /* Everything outside [31,38] that the fixture itself did not set up
         * (bytes 3..6 and 12..15 hold the planted length fields) must still
         * be the 0xAA fill. */
        CHECK(region_is(buf, 0, 3, 0xAA) && region_is(buf, 7, 5, 0xAA)
              && region_is(buf, 16, 15, 0xAA) && region_is(buf, 39, 25, 0xAA),
              "fuzz wrote only inside [payload_offset, +payload_length]");
        free(buf);
    }
}

static void test_update_http2_data_dispatch(void)
{
    printf("[H2-7] update_http2_data threads the size through\n");
    ipacket_t ip;

    /* HTTP2_HEADER_STREAM_ID at proto_offset 4 in a 16-byte buffer: the
     * stream-id write at 9..12 fits; the method-byte read at 13 must also
     * be in bounds. */
    {
        uint8_t *buf = (uint8_t *) malloc(16);
        memset(buf, 0xAA, 16);
        make_ipacket(&ip, buf, 16, 4);
        int r = (int) update_http2_data((char *) buf, 16, &ip,
                                        PROTO_HTTP2, HTTP2_HEADER_STREAM_ID, 0x0BADC0DE);
        (void) r;
        CHECK(buf[9] == 0x0B && buf[10] == 0xAD && buf[11] == 0xC0 && buf[12] == 0xDE,
              "dispatched stream-id update wrote in-window");
        free(buf);
    }

    /* Same call with a 10-byte buffer: the write window at 9..12 does not
     * fit — nothing may be touched. */
    {
        uint8_t *buf = (uint8_t *) malloc(10);
        memset(buf, 0xAA, 10);
        make_ipacket(&ip, buf, 10, 4);
        int r = (int) update_http2_data((char *) buf, 10, &ip,
                                        PROTO_HTTP2, HTTP2_HEADER_STREAM_ID, 0x0BADC0DE);
        (void) r;
        CHECK(region_is(buf, 0, 10, 0xAA),
              "dispatched stream-id update honours a too-small buffer");
        free(buf);
    }
}

int main(void)
{
    printf("== http2_bounds_test (issue #204, F-BUG-057) ==\n");
    test_update_stream_id();
    test_update_window_update();
    test_inject_http2_packet();
    test_restore_http2_packet();
    test_modify_get();
    test_fuzz_payload();
    test_update_http2_data_dispatch();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures) {
        printf("RESULT: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
