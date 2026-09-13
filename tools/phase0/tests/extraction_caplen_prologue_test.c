/*
 * extraction_caplen_prologue_test — regression + coverage test for issue
 * #202 (F-BUG-033, F-BUG-010).
 *
 * F-BUG-033: about 30 hand-written extraction callbacks in
 * src/mmt_tcpip/lib/protocols/proto_{ip,tcp,gre,gtp,icmp}.c indexed
 * packet->data at unvalidated offsets — the generic extractors in
 * extraction_lib.c were hardened but these were not. The fix gives every
 * callback the shared caplen prologue built on mmt_have_bytes()
 * (src/mmt_core/private_include/packet_processing.h, issue #193), so the
 * coverage stays greppable. It also fixes icmp_data_extraction() sizing its
 * payload copy from p_hdr->len (wire length) instead of p_hdr->caplen — a
 * truncated capture made it read past the end of the captured buffer.
 *
 * F-BUG-010: register_extraction_attribute() sized the attribute scratch
 * buffer from get_data_size_by_data_type() while every extractor bounds-
 * checks against the separately sourced data_len — a protocol declaring a
 * length above the type size yielded a heap overflow with packet bytes. The
 * scratch is now sized from max(type size, declared data_len), and
 * register_attribute_with_protocol() refuses the disagreement with a
 * diagnostic naming the attribute.
 *
 * Part 1 (unit) drives the extraction callbacks directly on crafted
 * truncated captures — a heap-allocated, exactly caplen-sized buffer so ASan
 * brackets every out-of-bounds read. On the pre-fix tree each refused case
 * either aborts under ASan or returns 1 where post-fix it returns 0.
 *
 * Part 2 (unit) registers an attribute whose declared length exceeds its
 * type size and asserts the registration is refused, then checks the
 * scratch-buffer sizing invariant on a real registered attribute.
 *
 * Part 3 (corpus) replays the vendored golden pcap subset
 * (tools/phase0/ci/pcaps/) through a handler that registers an attribute
 * handler for every attribute of every registered protocol — under
 * ASan/UBSan any residual out-of-bounds read in a callback aborts.
 *
 * Build (see run_extraction_caplen_prologue_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o extraction_caplen_prologue_test extraction_caplen_prologue_test.c \
 *       -I<prefix>/dpi/include -Isrc/mmt_core/public_include \
 *       -Isrc/mmt_core/private_include \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <dirent.h>

#include <pcap.h>            /* pcap_open_offline, pcap_datalink, pcap_next */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h" /* PROTO_ICMP, ICMP_DATA, TCP_TSVAL, ... */
/* attribute_internal_struct + mmt_handler_struct live in the in-tree private
 * header; the layout matches the compiled library byte-for-byte (same
 * headers, same flags). */
#include "packet_processing.h"
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

/* -------------------------------------------------------------------------
 * Shared fixture: a heap-allocated, exactly caplen-sized captured buffer
 * (ASan brackets it) plus the ipacket wiring the callbacks read: p_hdr,
 * data, proto_headers_offset (per-layer relative offsets —
 * get_packet_offset_at_index() prefix-sums them, so the protocol under test
 * at index `idx` starts at sum(layer_sizes[0..idx])), proto_hierarchy and a
 * zeroed mmt_handler.
 * ------------------------------------------------------------------------- */
typedef struct {
    ipacket_t pkt;
    proto_hierarchy_t offsets;
    proto_hierarchy_t hier;
    pkthdr_t hdr;
    mmt_handler_t *hdlr;
    u_char *buf;
} fixture_t;

static void fixture_init(fixture_t *f, const int *layer_sizes, int nlayers,
        unsigned caplen, unsigned wirelen) {
    memset(f, 0, sizeof(*f));
    f->buf = (u_char *)malloc(caplen ? caplen : 1);
    if (!f->buf) { perror("malloc"); exit(2); }
    memset(f->buf, 0, caplen ? caplen : 1);
    f->hdlr = (mmt_handler_t *)calloc(1, sizeof(mmt_handler_t));
    if (!f->hdlr) { perror("calloc"); exit(2); }
    int i;
    for (i = 0; i < nlayers && i < PROTO_PATH_SIZE; i++) {
        f->offsets.proto_path[i] = layer_sizes[i];
        f->hier.proto_path[i] = 1; /* any proto id — the callbacks never read it */
    }
    f->offsets.len = f->hier.len = nlayers;
    f->hdr.caplen = caplen;
    f->hdr.len = wirelen;
    f->pkt.p_hdr = &f->hdr;
    f->pkt.data = f->buf;
    f->pkt.proto_headers_offset = &f->offsets;
    f->pkt.proto_hierarchy = &f->hier;
    f->pkt.internal_cumulative_offset_valid = 0;
    f->pkt.mmt_handler = f->hdlr;
}

static void fixture_free(fixture_t *f) {
    free(f->buf);
    free(f->hdlr);
}

/* Extracted-data scratch: aligned so the u16/u32 stores callbacks make are
 * aligned too (the test binary itself is UBSan-instrumented). */
static uint8_t g_scratch[1100] __attribute__((aligned(8)));

static attribute_t mk_attr(int position, int data_len) {
    attribute_t a;
    memset(&a, 0, sizeof(a));
    a.data = g_scratch;
    a.data_len = data_len;
    a.position_in_packet = position;
    a.proto_id = 1;
    a.field_id = 7;
    return a;
}

/* -------------------------------------------------------------------------
 * Part 1 — F-BUG-033: each callback must refuse when the bytes it reads lie
 * outside caplen, and still extract when they are inside.
 * ------------------------------------------------------------------------- */

static void test_ip_callbacks(void) {
    printf("[#202] proto_ip.c extraction callbacks\n");
    /* IP header at index 1, absolute offset 14 + 20 = 34. */
    const int layers[2] = { 14, 20 };
    fixture_t f;
    attribute_t a;

    /* ip_version_extraction reads byte 0 of the IP header. */
    fixture_init(&f, layers, 2, 34, 60);
    a = mk_attr(0, 1);
    CHECK(ip_version_extraction(&f.pkt, 1, &a) == 0,
          "ip_version refused when the IP header is not captured");
    fixture_free(&f);

    fixture_init(&f, layers, 2, 54, 54);
    f.buf[34] = 0x45; /* version 4, ihl 5 */
    a = mk_attr(0, 1);
    CHECK(ip_version_extraction(&f.pkt, 1, &a) == 1 && g_scratch[0] == 4,
          "ip_version extracted inside caplen");
    CHECK(ip_ihl_extraction(&f.pkt, 1, &a) == 1 && g_scratch[0] == 20,
          "ip_ihl extracted inside caplen");
    fixture_free(&f);

    /* ip_rf/df/mf read the flags byte at position 6. */
    fixture_init(&f, layers, 2, 40, 60); /* 34 + 6 = 40: flag byte absent */
    a = mk_attr(6, 1);
    CHECK(ip_rf_extraction(&f.pkt, 1, &a) == 0
          && ip_df_extraction(&f.pkt, 1, &a) == 0
          && ip_mf_extraction(&f.pkt, 1, &a) == 0,
          "ip_{rf,df,mf} refused when the flags byte is not captured");
    fixture_free(&f);

    fixture_init(&f, layers, 2, 54, 54);
    f.buf[34 + 6] = 0xE0; /* RF|DF|MF all set */
    a = mk_attr(6, 1);
    CHECK(ip_rf_extraction(&f.pkt, 1, &a) == 1 && g_scratch[0] == 1
          && ip_df_extraction(&f.pkt, 1, &a) == 1 && g_scratch[0] == 1
          && ip_mf_extraction(&f.pkt, 1, &a) == 1 && g_scratch[0] == 1,
          "ip_{rf,df,mf} extracted inside caplen");
    fixture_free(&f);

    /* ip_frag_offset reads two bytes at position 6. */
    fixture_init(&f, layers, 2, 41, 60); /* 34 + 6 + 1: half the field absent */
    a = mk_attr(6, 2);
    CHECK(ip_frag_offset_extraction(&f.pkt, 1, &a) == 0,
          "ip_frag_offset refused when the field is half captured");
    fixture_free(&f);

    fixture_init(&f, layers, 2, 54, 54);
    f.buf[34 + 6] = 0x20;
    f.buf[34 + 7] = 0x01; /* frag field 0x2001 -> offset (0x2001 & 0x1fff) << 3 = 8 */
    a = mk_attr(6, 2);
    CHECK(ip_frag_offset_extraction(&f.pkt, 1, &a) == 1
          && *(uint16_t *)g_scratch == 8,
          "ip_frag_offset extracted inside caplen");
    fixture_free(&f);

    /* ip_options: ihl > 5 promises (ihl-5)*4 option bytes at +20. */
    fixture_init(&f, layers, 2, 57, 60); /* ihl = 6 but the 4 option bytes are cut */
    f.buf[34] = 0x46;
    a = mk_attr(-2, sizeof(void *));
    CHECK(ip_options_extraction(&f.pkt, 1, &a) == 0 && a.data == NULL,
          "ip_options refused when the options area is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 2, 58, 58);
    f.buf[34] = 0x46;
    a = mk_attr(-2, sizeof(void *));
    CHECK(ip_options_extraction(&f.pkt, 1, &a) == 1
          && a.data == &f.buf[34 + 20],
          "ip_options returns the captured options area");
    fixture_free(&f);

    /* ip_opts_type: reads ihl at byte 0, then the byte at position 20. */
    fixture_init(&f, layers, 2, 34, 60);
    a = mk_attr(20, 1);
    CHECK(ip_opts_type_extraction(&f.pkt, 1, &a) == 0,
          "ip_opts_type refused when the IP header is not captured");
    fixture_free(&f);

    fixture_init(&f, layers, 2, 55, 55);
    f.buf[34] = 0x46; /* ihl 6 -> options exist */
    f.buf[34 + 20] = 0x07;
    a = mk_attr(20, 1);
    CHECK(ip_opts_type_extraction(&f.pkt, 1, &a) == 1 && g_scratch[0] == 0x07,
          "ip_opts_type extracted inside caplen");
    fixture_free(&f);

    /* ip_padding_check walks the options area: EOL followed by non-zero
     * padding reports 1; a header truncated inside the options refuses. */
    fixture_init(&f, layers, 2, 53, 60); /* shorter than a full IPv4 header */
    a = mk_attr(POSITION_NOT_KNOWN, 1);
    CHECK(ip_padding_check_extraction(&f.pkt, 1, &a) == 0,
          "ip_padding_check refused when the IP header is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 2, 58, 58);
    f.buf[34] = 0x46;      /* ihl 6 -> 4 option bytes at 54..57 */
    f.buf[54] = 0x00;      /* EOL */
    f.buf[55] = 0x07;      /* non-zero padding after EOL */
    a = mk_attr(POSITION_NOT_KNOWN, 1);
    CHECK(ip_padding_check_extraction(&f.pkt, 1, &a) == 1 && g_scratch[0] == 1,
          "ip_padding_check flags non-zero padding inside caplen");
    fixture_free(&f);
}

static void test_tcp_callbacks(void) {
    printf("[#202] proto_tcp.c extraction callbacks\n");
    /* TCP header at index 2, absolute offset 14 + 20 + 20 = 54. */
    const int layers[3] = { 14, 20, 20 };
    fixture_t f;
    attribute_t a;

    /* tcp_data_offset reads the data-offset nibble at byte 12. */
    fixture_init(&f, layers, 3, 66, 80); /* 54 + 12 = 66: byte absent */
    a = mk_attr(12, 1);
    CHECK(tcp_data_offset_extraction(&f.pkt, 2, &a) == 0,
          "tcp_data_offset refused when byte 12 is not captured");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 80, 80);
    f.buf[54 + 12] = 0x50; /* doff = 5 */
    a = mk_attr(12, 1);
    CHECK(tcp_data_offset_extraction(&f.pkt, 2, &a) == 1 && g_scratch[0] == 5,
          "tcp_data_offset extracted inside caplen");
    fixture_free(&f);

    /* The flag extractors read the flags byte at offset 13. */
    fixture_init(&f, layers, 3, 67, 80); /* 54 + 13 = 67: flags byte absent */
    a = mk_attr(13, 1);
    CHECK(tcp_fin_flag_extraction(&f.pkt, 2, &a) == 0
          && tcp_syn_flag_extraction(&f.pkt, 2, &a) == 0
          && tcp_rst_flag_extraction(&f.pkt, 2, &a) == 0
          && tcp_psh_flag_extraction(&f.pkt, 2, &a) == 0
          && tcp_ack_flag_extraction(&f.pkt, 2, &a) == 0
          && tcp_urg_flag_extraction(&f.pkt, 2, &a) == 0
          && tcp_ece_flag_extraction(&f.pkt, 2, &a) == 0
          && tcp_cwr_flag_extraction(&f.pkt, 2, &a) == 0
          && tcp_flags_extraction(&f.pkt, 2, &a) == 0,
          "tcp flag extractors refused when the flags byte is not captured");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 80, 80);
    f.buf[54 + 13] = 0x3F; /* fin|syn|rst|psh|ack|urg */
    a = mk_attr(13, 1);
    CHECK(tcp_fin_flag_extraction(&f.pkt, 2, &a) == 1 && g_scratch[0] == 1
          && tcp_syn_flag_extraction(&f.pkt, 2, &a) == 1 && g_scratch[0] == 1
          && tcp_ack_flag_extraction(&f.pkt, 2, &a) == 1 && g_scratch[0] == 1
          && tcp_flags_extraction(&f.pkt, 2, &a) == 1 && g_scratch[0] == 0x3F,
          "tcp flag extractors extracted inside caplen");
    fixture_free(&f);

    /* tcp_option walks the options area: craft a timestamp option
     * (kind 8, len 10) in a doff=8 header — the option area then spans
     * 74..86 and the whole option is captured at caplen 86. */
    fixture_init(&f, layers, 3, 74, 84); /* fixed header only, options cut */
    f.buf[54 + 12] = 0x60; /* doff = 6 -> 24-byte header */
    a = mk_attr(POSITION_NOT_KNOWN, 4);
    a.field_id = TCP_TSVAL;
    CHECK(tcp_option_extraction(&f.pkt, 2, &a) == 0,
          "tcp_option returns 0 when the header overruns caplen");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 86, 86);
    f.buf[54 + 12] = 0x80; /* doff = 8 -> 32-byte header, options at 74..85 */
    f.buf[74] = 8;  /* timestamp kind */
    f.buf[75] = 10; /* option length */
    f.buf[76] = 0xDE; f.buf[77] = 0xAD; f.buf[78] = 0xBE; f.buf[79] = 0xEF;
    a = mk_attr(POSITION_NOT_KNOWN, 4);
    a.field_id = TCP_TSVAL;
    CHECK(tcp_option_extraction(&f.pkt, 2, &a) == 1
          && *(uint32_t *)g_scratch == 0xDEADBEEFu,
          "tcp_option extracts the timestamp inside caplen");
    fixture_free(&f);
}

static void test_gre_callbacks(void) {
    printf("[#202] proto_gre.c extraction callbacks\n");
    /* GRE header at index 2, absolute offset 14 + 20 + 4 = 38. */
    const int layers[3] = { 14, 20, 4 };
    fixture_t f;
    attribute_t a;

    /* The flag extractors read the flags/version half-word at offset 0. */
    fixture_init(&f, layers, 3, 39, 60); /* one byte of the flags word */
    a = mk_attr(0, 2);
    CHECK(gre_c_flag_extraction(&f.pkt, 2, &a) == 0
          && gre_k_flag_extraction(&f.pkt, 2, &a) == 0
          && gre_s_flag_extraction(&f.pkt, 2, &a) == 0
          && gre_version_extraction(&f.pkt, 2, &a) == 0,
          "gre flag extractors refused when the flags word is half captured");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 60, 60);
    f.buf[38] = 0x20; /* key bit (little-endian bitfield, bit 5) */
    a = mk_attr(0, 2);
    CHECK(gre_k_flag_extraction(&f.pkt, 2, &a) == 1 && g_scratch[0] != 0,
          "gre_k_flag extracted inside caplen");
    fixture_free(&f);

    /* gre_csum reads flags then the checksum byte at offset 4 when C is set
     * (the callback reads grehdr->data — a single byte — via ntohs). */
    fixture_init(&f, layers, 3, 42, 60); /* byte at offset 4 (absolute 42) cut */
    f.buf[38] = 0x80; /* csum bit (bit 7) */
    a = mk_attr(4, 2);
    CHECK(gre_csum_extraction(&f.pkt, 2, &a) == 0,
          "gre_csum refused when the checksum byte is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 60, 60);
    f.buf[38] = 0x80;
    f.buf[42] = 0x12;
    a = mk_attr(4, 2);
    CHECK(gre_csum_extraction(&f.pkt, 2, &a) == 1
          && *(uint16_t *)g_scratch == 0x1200,
          "gre_csum extracted inside caplen");
    fixture_free(&f);

    /* gre_key: key present, no csum -> 4-byte key at offset 4. */
    fixture_init(&f, layers, 3, 45, 60);
    f.buf[38] = 0x20;
    a = mk_attr(POSITION_NOT_KNOWN, 4);
    CHECK(gre_key_extraction(&f.pkt, 2, &a) == 0,
          "gre_key refused when the key field is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 60, 60);
    f.buf[38] = 0x20;
    f.buf[42] = 0xCA; f.buf[43] = 0xFE; f.buf[44] = 0xBA; f.buf[45] = 0xBE;
    a = mk_attr(POSITION_NOT_KNOWN, 4);
    CHECK(gre_key_extraction(&f.pkt, 2, &a) == 1
          && *(uint32_t *)g_scratch == 0xCAFEBABEu,
          "gre_key extracted inside caplen");
    fixture_free(&f);

    /* gre_seqnb: seq + key present -> seq at offset 4 + 4 = 8. */
    fixture_init(&f, layers, 3, 49, 60);
    f.buf[38] = 0x30; /* seq | key */
    a = mk_attr(POSITION_NOT_KNOWN, 4);
    CHECK(gre_seqnb_extraction(&f.pkt, 2, &a) == 0,
          "gre_seqnb refused when the sequence field is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 60, 60);
    f.buf[38] = 0x30;
    f.buf[46] = 0x01; f.buf[47] = 0x02; f.buf[48] = 0x03; f.buf[49] = 0x04;
    a = mk_attr(POSITION_NOT_KNOWN, 4);
    CHECK(gre_seqnb_extraction(&f.pkt, 2, &a) == 1
          && *(uint32_t *)g_scratch == 0x01020304u,
          "gre_seqnb extracted inside caplen");
    fixture_free(&f);
}

static void test_gtp_callbacks(void) {
    printf("[#202] proto_gtp.c extraction callbacks\n");
    /* GTP header at index 2, absolute offset 14 + 20 + 8 = 42. */
    const int layers[3] = { 14, 20, 8 };
    fixture_t f;
    attribute_t a;

    /* The flag extractors read the flags byte at offset 0. */
    fixture_init(&f, layers, 3, 42, 60); /* no GTP byte captured */
    a = mk_attr(0, 1);
    CHECK(gtp_version_flag_extraction(&f.pkt, 2, &a) == 0
          && gtp_protocol_type_flag_extraction(&f.pkt, 2, &a) == 0
          && gtp_reserved_flag_extraction(&f.pkt, 2, &a) == 0
          && gtp_extension_header_flag_extraction(&f.pkt, 2, &a) == 0
          && gtp_seq_check_flag_extraction(&f.pkt, 2, &a) == 0
          && gtp_npdu_number_flag_extraction(&f.pkt, 2, &a) == 0,
          "gtp flag extractors refused when the flags byte is not captured");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 60, 60);
    f.buf[42] = 0x34; /* version 1 | proto_type | extension_header */
    a = mk_attr(0, 1);
    CHECK(gtp_version_flag_extraction(&f.pkt, 2, &a) == 1 && g_scratch[0] == 1
          && gtp_extension_header_flag_extraction(&f.pkt, 2, &a) == 1
              && g_scratch[0] == 1,
          "gtp flag extractors extracted inside caplen");
    fixture_free(&f);

    /* gtp_seq_num gates on message_type (offset 1) 0x10/0x12, then reads the
     * 16-bit sequence number at position 8. */
    fixture_init(&f, layers, 3, 51, 60); /* seq field at 50..51 half captured */
    f.buf[43] = 0x10;
    a = mk_attr(8, 2);
    CHECK(gtp_seq_num_extraction(&f.pkt, 2, &a) == 0,
          "gtp_seq_num refused when the sequence field is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 60, 60);
    f.buf[43] = 0x10;
    f.buf[50] = 0xAB; f.buf[51] = 0xCD;
    a = mk_attr(8, 2);
    CHECK(gtp_seq_num_extraction(&f.pkt, 2, &a) == 1
          && *(uint16_t *)g_scratch == 0xABCDu,
          "gtp_seq_num extracted inside caplen");
    fixture_free(&f);

    /* gtp_imsi_mmc gates on message_type 0x10 then delegates to the hardened
     * generic extractor at position 13. */
    fixture_init(&f, layers, 3, 56, 60); /* field at 55..56 half captured */
    f.buf[43] = 0x10;
    a = mk_attr(13, 2);
    CHECK(gtp_imsi_mmc_extraction(&f.pkt, 2, &a) == 0,
          "gtp_imsi_mmc refused when the field is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 60, 60);
    f.buf[43] = 0x10;
    f.buf[55] = 0x02; f.buf[56] = 0x42;
    a = mk_attr(13, 2);
    CHECK(gtp_imsi_mmc_extraction(&f.pkt, 2, &a) == 1
          && *(uint16_t *)g_scratch == 0x0242u,
          "gtp_imsi_mmc extracted inside caplen");
    fixture_free(&f);

    /* _gtp_extract_next_extension_header_type reads the flags byte then the
     * next-extension-header byte at offset 11. */
    fixture_init(&f, layers, 3, 53, 60); /* byte at 53 cut */
    f.buf[42] = 0x04; /* extension_header bit */
    a = mk_attr(0, 1);
    CHECK(_gtp_extract_next_extension_header_type(&f.pkt, 2, &a) == 0,
          "gtp next-ext-header refused when the field byte is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 3, 60, 60);
    f.buf[42] = 0x04;
    f.buf[53] = 0x85;
    a = mk_attr(0, 1);
    CHECK(_gtp_extract_next_extension_header_type(&f.pkt, 2, &a) == 1
          && g_scratch[0] == 0x85,
          "gtp next-ext-header extracted inside caplen");
    fixture_free(&f);
}

static void test_icmp_callbacks(void) {
    printf("[#202] proto_icmp.c extraction callbacks\n");
    /* ICMP message at index 1, absolute offset 14 + 20 = 34. */
    const int layers[2] = { 14, 20 };
    fixture_t f;
    attribute_t a;

    /* identifier/seq_nb reads the type byte then delegates at position 4. */
    fixture_init(&f, layers, 2, 34, 60); /* no ICMP byte captured */
    a = mk_attr(4, 2);
    CHECK(icmp_identifier_and_seq_nb_extraction(&f.pkt, 1, &a) == 0,
          "icmp_identifier refused when the type byte is not captured");
    fixture_free(&f);

    fixture_init(&f, layers, 2, 39, 60); /* type captured, field cut */
    f.buf[34] = 8; /* ICMP_ECHO */
    a = mk_attr(4, 2);
    CHECK(icmp_identifier_and_seq_nb_extraction(&f.pkt, 1, &a) == 0,
          "icmp_identifier refused when the field is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 2, 60, 60);
    f.buf[34] = 8;
    f.buf[38] = 0x12; f.buf[39] = 0x34;
    a = mk_attr(4, 2);
    CHECK(icmp_identifier_and_seq_nb_extraction(&f.pkt, 1, &a) == 1
          && *(uint16_t *)g_scratch == 0x1234u,
          "icmp_identifier extracted inside caplen");
    fixture_free(&f);

    /* gateway reads the type byte then delegates (int at position 4). */
    fixture_init(&f, layers, 2, 41, 60);
    f.buf[34] = 5; /* ICMP_REDIRECT */
    a = mk_attr(4, 4);
    CHECK(icmp_gateway_extraction(&f.pkt, 1, &a) == 0,
          "icmp_gateway refused when the gateway field is truncated");
    fixture_free(&f);

    fixture_init(&f, layers, 2, 60, 60);
    f.buf[34] = 5;
    f.buf[38] = 192; f.buf[39] = 168; f.buf[40] = 0; f.buf[41] = 1;
    a = mk_attr(4, 4);
    CHECK(icmp_gateway_extraction(&f.pkt, 1, &a) == 1,
          "icmp_gateway extracted inside caplen");
    fixture_free(&f);

    /* F-BUG-033 headliner: icmp_data sized its memcpy from p_hdr->len (the
     * wire length) — a truncated capture made it read past the captured
     * buffer. caplen = 46 captured bytes of a 142-byte wire packet: only 4
     * payload bytes exist after position 8, so the copy must be 4, not the
     * 100 the wire length claims. */
    fixture_init(&f, layers, 2, 46, 142);
    f.buf[34] = 8; /* ICMP_ECHO */
    f.buf[42] = 0xAA; f.buf[43] = 0xBB; f.buf[44] = 0xCC; f.buf[45] = 0xDD;
    memset(g_scratch, 0, sizeof(g_scratch));
    a = mk_attr(8, 1028);
    CHECK(icmp_data_extraction(&f.pkt, 1, &a) == 1
          && *(uint32_t *)g_scratch == 4
          && g_scratch[4] == 0xAA && g_scratch[7] == 0xDD,
          "icmp_data copies only the captured payload bytes, not the wire length");
    fixture_free(&f);
}

/* -------------------------------------------------------------------------
 * Part 2 — F-BUG-010: a declared data_len above the type size must be
 * refused at registration; the per-handler scratch buffer must cover the
 * declared length.
 * ------------------------------------------------------------------------- */

static void test_registration(void) {
    printf("[#202] attribute registration — data_len vs type size\n");

    protocol_t *icmp = get_protocol_struct_by_protocol_id(PROTO_ICMP);
    CHECK(icmp != NULL, "PROTO_ICMP registered after init_extraction");
    if (icmp == NULL) return;

    /* Declared data_len (64) over the MMT_U8_DATA type size (1) — the
     * extractor could bound-check against 64 while the scratch held 1:
     * refused. */
    attribute_metadata_t bad = {
        .id = 990, .alias = "caplen_probe_bad",
        .data_type = MMT_U8_DATA, .data_len = 64,
        .position_in_packet = 0, .scope = SCOPE_PACKET,
        .extraction_function = silent_extraction,
    };
    CHECK(register_attribute_with_protocol(icmp, &bad) == 0,
          "registration refused when declared data_len exceeds the type size");

    attribute_metadata_t good = {
        .id = 991, .alias = "caplen_probe_ok",
        .data_type = MMT_U8_DATA, .data_len = 1,
        .position_in_packet = 0, .scope = SCOPE_PACKET,
        .extraction_function = silent_extraction,
    };
    CHECK(register_attribute_with_protocol(icmp, &good) == 1,
          "consistent attribute still registers (control)");

    /* The scratch buffer attached to a registered attribute must cover the
     * declared data_len — ICMP_DATA declares BINARY_1024DATA_TYPE_LEN
     * (1028) on MMT_BINARY_VAR_DATA. Registering it exercises the
     * register_extraction_attribute() allocation path; the corpus leg then
     * extracts it under ASan, so an undersized scratch would abort. */
    char errbuf[1024];
    mmt_handler_t *hdlr = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    CHECK(hdlr != NULL, "mmt_init_handler for the extraction-registration check");
    if (hdlr == NULL) return;
    CHECK(register_extraction_attribute(hdlr, PROTO_ICMP, ICMP_DATA) == 1,
          "ICMP_DATA extraction attribute registered");
    mmt_close_handler(hdlr);
}

/* -------------------------------------------------------------------------
 * Part 3 — corpus: every attribute of every protocol over the golden pcaps
 * (any residual out-of-bounds read aborts under ASan).
 * ------------------------------------------------------------------------- */

static void noop_attr_handler(const ipacket_t *ipacket, attribute_t *attribute,
        void *user_args) {
    (void)ipacket; (void)attribute; (void)user_args;
}

typedef struct {
    mmt_handler_t *hdlr;
    unsigned long registered;      /* attribute handlers successfully registered */
    unsigned long skipped_null_fn; /*   skipped: metadata has no extraction_function */
} reg_ctx_t;

static void reg_attr_cb(attribute_metadata_t *attr, uint32_t proto_id, void *args) {
    reg_ctx_t *c = (reg_ctx_t *)args;
    if (attr == NULL) return;
    /* Some metadata entries declare no extraction_function at all — skip
     * them like position_unknown_guard_test does. */
    if (attr->extraction_function == NULL) {
        c->skipped_null_fn++;
        return;
    }
    if (register_attribute_handler(c->hdlr, proto_id, (uint32_t)attr->id,
            noop_attr_handler, NULL, NULL) == 1) {
        c->registered++;
    }
}

static void reg_proto_cb(uint32_t proto_id, void *args) {
    iterate_through_protocol_attributes(proto_id, reg_attr_cb, args);
}

static int g_pcaps_seen = 0;
static int g_pcaps_replayed = 0;
static unsigned long g_packets = 0;
static reg_ctx_t g_reg;

static int replay_pcap(const char *path) {
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    char mmt_errbuf[1024];
    pcap_t *pcap;
    mmt_handler_t *hdlr;
    const u_char *data;
    struct pcap_pkthdr p_pkthdr;
    struct pkthdr header;
    int datalink;

    g_pcaps_seen++;
    pcap = pcap_open_offline(path, pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", path, pcap_errbuf);
        return -1;
    }
    datalink = pcap_datalink(pcap);

    hdlr = mmt_init_handler((uint32_t)datalink, 0, mmt_errbuf);
    if (hdlr == NULL) {
        fprintf(stderr, "<unsupported link-type %s: %s>\n", path, mmt_errbuf);
        pcap_close(pcap);
        return 0;
    }

    memset(&g_reg, 0, sizeof(g_reg));
    g_reg.hdlr = hdlr;
    iterate_through_protocols(reg_proto_cb, &g_reg);

    memset(&header, 0, sizeof(header));
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        header.ts = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len = p_pkthdr.len;
        packet_process(hdlr, &header, data);
        g_packets++;
    }

    mmt_close_handler(hdlr);
    pcap_close(pcap);
    g_pcaps_replayed++;
    return 0;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int replay_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (d == NULL) {
        fprintf(stderr, "opendir(%s) failed\n", dir);
        return -1;
    }
    char **names = NULL;
    size_t n = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t len = strlen(de->d_name);
        if (len < 5 || strcmp(de->d_name + len - 5, ".pcap") != 0) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            names = (char **)realloc(names, cap * sizeof(char *));
            if (!names) { perror("realloc"); closedir(d); exit(2); }
        }
        names[n++] = strdup(de->d_name);
    }
    closedir(d);
    qsort(names, n, sizeof(char *), cmp_str);

    int rc = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        size_t pathlen = strlen(dir) + strlen(names[i]) + 2;
        char *path = (char *)malloc(pathlen);
        if (!path) { perror("malloc"); exit(2); }
        snprintf(path, pathlen, "%s/%s", dir, names[i]);
        if (replay_pcap(path) != 0) rc = -1;
        free(path);
        free(names[i]);
    }
    free(names);
    return rc;
}

static void test_corpus(const char *pcap_dir) {
    printf("[#202] golden-corpus coverage — every registered attribute extracted\n");

    int rc = replay_dir(pcap_dir);

    CHECK(rc == 0, "every golden pcap replayed without harness error");
    CHECK(g_pcaps_replayed > 0 && g_pcaps_replayed == g_pcaps_seen,
          "all vendored golden pcaps replayed");
    CHECK(g_packets > 0, "corpus produced packets");
    CHECK(g_reg.registered > 0,
          "attribute handlers registered (extraction actually exercised)");
}

int main(int argc, char **argv) {
    printf("=== extraction caplen-prologue test (issue #202) ===\n");
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <golden-pcap-dir>\n", argv[0]);
        return 2;
    }

    /* init_extraction() loads the protocol plugins and registers every tcpip
     * protocol; it must run from the install prefix so the CWD-relative
     * "plugins/" lookup resolves (see the runner script). */
    if (!init_extraction()) {
        fprintf(stderr, "init_extraction failed\n");
        return 2;
    }

    test_ip_callbacks();
    test_tcp_callbacks();
    test_gre_callbacks();
    test_gtp_callbacks();
    test_icmp_callbacks();
    test_registration();
    test_corpus(argv[1]);

    close_extraction();

    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
