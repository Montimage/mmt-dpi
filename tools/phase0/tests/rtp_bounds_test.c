/*
 * rtp_bounds_test — regression for issue #205 (F-BUG-108, F-BUG-109):
 *
 *   F-BUG-108  rtp_csrc_list_extraction() treated the 4-bit CSRC count,
 *              multiplied by 4 (0-60), as an *element count* in a loop writing
 *              4 bytes per iteration — the last write landed at offset 243 of
 *              the 68-byte BINARY_64DATA buffer (176-byte heap overflow with
 *              attacker-controlled contents). The fix publishes cc*4 as the
 *              byte length, iterates cc elements (max write 4 + 15*4 = 64
 *              bytes), and validates proto_offset + 12 + cc*4 <= caplen.
 *
 *   F-BUG-109  mmt_rtp_search() read the sequence number from payload[2..3]
 *              before any length check — a 1-3 byte payload produced an
 *              out-of-bounds read. The read is now taken only after the
 *              12-byte minimum-length gate.
 *
 * Style: same fake-ipacket approach as dtls_classify_guard_test.c — the
 * extraction/classification entry points are driven directly on exactly-sized
 * heap buffers so any residual over-read or over-write aborts under ASan.
 *
 * Build (see run_rtp_bounds_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o rtp_bounds_test rtp_bounds_test.c \
 *       -I<prefix>/dpi/include -I<repo>/src/mmt_tcpip/lib \
 *       -I<repo>/src/mmt_core/public_include -I<repo>/tools/phase0/tests \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"                 /* PROTO_RTP */
#include "mmt_tcpip_plugin_structs.h"        /* struct mmt_tcpip_internal_packet_struct */
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

/* Allocate an exactly-sized buffer (ASan brackets it), zero-filled. */
static uint8_t *make_buf(size_t len)
{
    uint8_t *b = (uint8_t *)malloc(len ? len : 1);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, len ? len : 1);
    return b;
}

/* Offsets: eth=14, ip=20, udp=8 -> RTP header starts at 42. */
#define RTP_INDEX   3
#define RTP_OFFSET  42

/*
 * Fake ipacket whose data[] holds an RTP packet at RTP_OFFSET. The RTP header
 * byte 0 is 0x80 | cc (version 2, CSRC count = cc).
 */
static void make_rtp_ipacket(ipacket_t *pkt, proto_hierarchy_t *offs,
                             pkthdr_t *p_hdr, uint8_t *data, uint32_t caplen,
                             uint8_t cc)
{
    memset(pkt, 0, sizeof(*pkt));
    memset(offs, 0, sizeof(*offs));
    memset(p_hdr, 0, sizeof(*p_hdr));

    offs->proto_path[0] = 14;
    offs->proto_path[1] = 20;
    offs->proto_path[2] = 8;
    offs->len = 4;
    pkt->proto_headers_offset = offs;
    pkt->internal_cumulative_offset_valid = 0;

    p_hdr->caplen = caplen;
    p_hdr->len    = caplen;
    pkt->p_hdr    = p_hdr;
    pkt->data     = (const u_char *)data;

    data[RTP_OFFSET]     = 0x80 | (cc & 0x0f); /* V=2, CC=cc */
    data[RTP_OFFSET + 1] = 96;                 /* PT */
}

int main(void)
{
    printf("issue #205: RTP CSRC bounds + sequence-number length gate\n");

    /* --- F-BUG-108: cc = 15 (max) -------------------------------------------
     * Buffer: RTP header (12) + 15 CSRCs (60) = 72 bytes after RTP_OFFSET.
     * Pre-fix the loop wrote 60 *elements* -> 4 + 60*4 = 244 bytes into a
     * 68-byte attribute buffer; ASan aborts. Post-fix: 60 data bytes. */
    {
        uint32_t caplen = RTP_OFFSET + 12 + 15 * 4;
        uint8_t *frame = make_buf(caplen);
        ipacket_t pkt;
        proto_hierarchy_t offs;
        pkthdr_t p_hdr;
        attribute_t attr;
        uint8_t *abuf = make_buf(68);        /* BINARY_64DATA_TYPE_LEN */

        memset(&attr, 0, sizeof(attr));
        attr.position_in_packet = 12;
        attr.data = abuf;

        make_rtp_ipacket(&pkt, &offs, &p_hdr, frame, caplen, 15);
        int r = rtp_csrc_list_extraction(&pkt, RTP_INDEX, &attr);
        CHECK(r == 1, "cc=15 CSRC extraction returns 1");
        CHECK(*(uint32_t *)abuf == 60, "cc=15 publishes cc*4 = 60 as the length");
        free(abuf);
        free(frame);
    }

    /* --- F-BUG-108: declared CSRC list longer than the capture -------------
     * cc = 15 but only 8 CSRC bytes captured -> extraction must refuse. */
    {
        uint32_t caplen = RTP_OFFSET + 12 + 8;
        uint8_t *frame = make_buf(caplen);
        ipacket_t pkt;
        proto_hierarchy_t offs;
        pkthdr_t p_hdr;
        attribute_t attr;
        uint8_t *abuf = make_buf(68);

        memset(&attr, 0, sizeof(attr));
        attr.position_in_packet = 12;
        attr.data = abuf;

        make_rtp_ipacket(&pkt, &offs, &p_hdr, frame, caplen, 15);
        int r = rtp_csrc_list_extraction(&pkt, RTP_INDEX, &attr);
        CHECK(r == 0, "truncated CSRC list (caplen short) is rejected");
        free(abuf);
        free(frame);
    }

    /* --- F-BUG-109: 1-byte payload ------------------------------------------
     * mmt_check_rtp_udp -> mmt_rtp_search must not read payload[2..3]. With
     * the bug the seqnum read at function entry over-read the 1-byte heap
     * buffer and ASan aborts. */
    {
        mmt_init_classify_me_rtp();

        struct mmt_internal_tcpip_session_struct flow;
        struct mmt_tcpip_internal_packet_struct ip;
        ipacket_t pkt;
        uint8_t *payload = make_buf(1);      /* exactly 1 byte */
        payload[0] = 0;

        memset(&flow, 0, sizeof(flow));
        memset(&ip, 0, sizeof(ip));
        memset(&pkt, 0, sizeof(pkt));

        ip.flow = &flow;
        ip.payload = payload;
        ip.payload_packet_len = 1;
        ip.mmt_selection_packet = (MMT_SELECTION_BITMASK_PROTOCOL_SIZE)~0u;
        memset(&ip.detection_bitmask, 0xFF, sizeof(ip.detection_bitmask));
        pkt.internal_packet = &ip;

        int r = mmt_check_rtp_udp(&pkt, 0);
        CHECK(r == 4, "mmt_check_rtp_udp returns on a 1-byte payload (no OOB)");
        free(payload);
    }

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
