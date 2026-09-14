/*
 * smb_bounds_test — regression for issue #205 (F-BUG-110, F-BUG-111,
 * F-BUG-112):
 *
 *   F-BUG-110  smb_session_data_analysis() trusted the 16-bit NT_CREATE
 *              file_path_len: a declared 65535-byte filename drove an
 *              out-of-bounds walk of the captured buffer through an unchecked
 *              and under-sized allocation (odd lengths overflowed by one
 *              byte). The fix clamps the declared length to the captured
 *              remainder and sizes + NULL-checks the allocation.
 *
 *   F-BUG-111  get_smb_payload() read 4 signature bytes at the protocol
 *              offset (and 4 more after the NetBIOS skip) without a caplen
 *              check.
 *
 *   F-BUG-112  smb_padding_extraction() and the session analysis read SMB1
 *              command fields up to +81 bytes past the SMB header with no
 *              caplen check anywhere on the path.
 *
 * Style: fake ipacket + a real mmt_handler (mmt_init_handler) so
 * configured_protocols[] exists; session is an over-sized zeroed blob (the
 * same trick as ssl_tls12_version_test.c — struct mmt_session_struct is
 * private). Exactly-sized heap buffers let ASan bracket every read.
 *
 * Build (see run_smb_bounds_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o smb_bounds_test smb_bounds_test.c \
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
#include "tcpip/mmt_tcpip.h"                 /* PROTO_SMB */
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

/* struct mmt_session_struct is private (private_include/packet_processing.h);
 * a zeroed blob answers 0 / NULL for every field the SMB analysis reads —
 * session_id == 0 is consistent and fine here. */
#define SESSION_BLOB_SIZE 65536

static uint8_t *make_buf(size_t len)
{
    uint8_t *b = (uint8_t *)malloc(len ? len : 1);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, len ? len : 1);
    return b;
}

/* eth=14, ip=20, tcp=20 -> SMB record (NetBIOS + SMB1) starts at 54. */
#define SMB_INDEX   3
#define SMB_OFFSET  54

/*
 * Wire a fake ipacket: data[] carries the frame, proto_headers_offset sums to
 * SMB_OFFSET at SMB_INDEX, and proto_hierarchy names PROTO_SMB there so
 * smb_get_session_list() finds configured_protocols[PROTO_SMB].
 */
static void make_smb_ipacket(ipacket_t *pkt,
                             struct mmt_tcpip_internal_packet_struct *ip,
                             proto_hierarchy_t *hier, proto_hierarchy_t *offs,
                             pkthdr_t *p_hdr, mmt_session_t *session,
                             mmt_handler_t *h,
                             uint8_t *data, uint32_t caplen,
                             uint32_t payload_len)
{
    memset(pkt, 0, sizeof(*pkt));
    memset(ip, 0, sizeof(*ip));
    memset(hier, 0, sizeof(*hier));
    memset(offs, 0, sizeof(*offs));
    memset(p_hdr, 0, sizeof(*p_hdr));

    hier->proto_path[SMB_INDEX] = PROTO_SMB;
    hier->len = SMB_INDEX + 1;
    pkt->proto_hierarchy = hier;

    offs->proto_path[0] = 14;
    offs->proto_path[1] = 20;
    offs->proto_path[2] = 20;
    offs->len = 4;
    pkt->proto_headers_offset = offs;
    pkt->internal_cumulative_offset_valid = 0;

    p_hdr->caplen = caplen;
    p_hdr->len    = caplen;
    pkt->p_hdr    = p_hdr;
    pkt->data     = (const u_char *)data;

    ip->payload_packet_len = payload_len;
    pkt->internal_packet = ip;
    pkt->session = session;
    pkt->mmt_handler = h;
}

/*
 * Write a NetBIOS-wrapped SMB1 NT_CREATE AndX request at SMB_OFFSET:
 *   [54..57]  NBSS header, first byte 0x00 (message type + 3-byte length)
 *   [58..61]  0xff 'S' 'M' 'B' signature
 *   [62]      command 0xa2 (SMB1_CMD_NT_CREATE)
 *   [90..]    command payload; file_path_len (u16) at +6, name at +52
 * Returns the byte count written past SMB_OFFSET.
 */
static uint32_t put_smb_nt_create(uint8_t *data, uint16_t file_path_len)
{
    uint8_t *p = data + SMB_OFFSET;
    p[0] = 0x00;                    /* NetBIOS -> get_smb_payload skips 4 */
    p[4] = 0xff; p[5] = 'S'; p[6] = 'M'; p[7] = 'B';
    p[8] = 0xa2;                    /* smb_command() reads smb_payload[4] */
    /* command payload starts at p[36] == smb_payload + 32 */
    p[36 + 6] = (uint8_t)(file_path_len & 0xff);
    p[36 + 7] = (uint8_t)(file_path_len >> 8);
    return 4 + 32 + 60;             /* 96 bytes of SMB record */
}

int main(void)
{
    char errbuf[1024];
    mmt_handler_t *h;
    mmt_session_t *session;

    init_extraction();
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    session = (mmt_session_t *)make_buf(SESSION_BLOB_SIZE);

    printf("issue #205: SMB caplen bounds\n");

    /* --- F-BUG-110: NT_CREATE with a 65535-byte declared filename ----------
     * Only 8 name bytes are actually captured past the fixed fields. Pre-fix
     * the path builder walked all 65535 declared bytes past the heap buffer;
     * post-fix the declared length is clamped to the captured remainder. */
    {
        uint8_t *frame = make_buf(SMB_OFFSET + 96);
        uint32_t smb_len = put_smb_nt_create(frame, 0xffff);

        ipacket_t pkt;
        struct mmt_tcpip_internal_packet_struct ip;
        proto_hierarchy_t hier, offs;
        pkthdr_t p_hdr;
        make_smb_ipacket(&pkt, &ip, &hier, &offs, &p_hdr, session, h,
                         frame, SMB_OFFSET + smb_len, smb_len);

        int r = smb_session_data_analysis(&pkt, SMB_INDEX);
        CHECK(r == MMT_CONTINUE,
              "NT_CREATE with file_path_len=65535 survives under ASan");
        free(frame);
    }

    /* --- F-BUG-111: get_smb_payload with the signature cut by caplen -------
     * 2 bytes of data at the protocol offset — pre-fix read offset+1..+3
     * out of bounds. */
    {
        uint8_t *frame = make_buf(SMB_OFFSET + 2);
        ipacket_t pkt;
        struct mmt_tcpip_internal_packet_struct ip;
        proto_hierarchy_t hier, offs;
        pkthdr_t p_hdr;
        make_smb_ipacket(&pkt, &ip, &hier, &offs, &p_hdr, session, h,
                         frame, SMB_OFFSET + 2, 2);

        const uint8_t *r = get_smb_payload(&pkt, SMB_INDEX);
        CHECK(r == NULL, "get_smb_payload rejects a caplen-truncated record");
        free(frame);
    }

    /* --- F-BUG-112: NT_CREATE whose command payload is cut short -----------
     * The SMB header + 6 command bytes are captured; file_path_len sits at
     * command_payload[6..7] — one byte past caplen. Pre-fix the u16 read and
     * every later field access were unguarded. */
    {
        uint8_t *frame = make_buf(SMB_OFFSET + 4 + 32 + 6);
        /* Header only — file_path_len at command_payload[6..7] (smb_payload
         * +38) is deliberately NOT captured. */
        uint8_t *p = frame + SMB_OFFSET;
        p[0] = 0x00;
        p[4] = 0xff; p[5] = 'S'; p[6] = 'M'; p[7] = 'B';
        p[8] = 0xa2;

        ipacket_t pkt;
        struct mmt_tcpip_internal_packet_struct ip;
        proto_hierarchy_t hier, offs;
        pkthdr_t p_hdr;
        make_smb_ipacket(&pkt, &ip, &hier, &offs, &p_hdr, session, h,
                         frame, SMB_OFFSET + 4 + 32 + 6, 4 + 32 + 6);

        int r = smb_session_data_analysis(&pkt, SMB_INDEX);
        CHECK(r == MMT_CONTINUE,
              "truncated NT_CREATE (no room for file_path_len) survives");
        free(frame);
    }

    free(session);
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
