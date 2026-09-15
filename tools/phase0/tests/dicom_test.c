/*
 * dicom_test.c — crafted-input test for the DICOM dissector
 * (src/mmt_dicom/dicom.c), issue #215.
 *
 * Coverage per the issue acceptance criteria:
 *   - AE-title copy:   DICOM_CALLED_AE_TITLE / DICOM_CALLING_AE_TITLE are
 *                      extracted on the real packet path and asserted
 *                      byte-for-byte — the exact write that commit 396bc63a
 *                      bounded to 16 bytes (reverting it turns the positive
 *                      extraction into an ASan heap-buffer-overflow).
 *   - Item-length walk: the A-ASSOCIATE variable-item area is exercised with
 *                      well-formed items, an overrunning declared length, a
 *                      zero-length item, an unknown item type, a presentation
 *                      context missing its abstract-syntax sub-item, and a
 *                      user-info item cut mid-sub-item.
 *   - Truncated PDUs:  capture-length cuts at several mid-PDU points on the
 *                      real packet path, plus tight-buffer boundary cuts via
 *                      internal_extract_attribute() on a fabricated ipacket.
 *
 * Layout:
 *   Part 1 — unit: mmt_check_dicom_hdr/payload/mmt_check_dicom on crafted
 *            headers (all PDU types, all length edges).
 *   Part 2 — full path: crafted Eth/IPv4/TCP frames through packet_process()
 *            with reassembly enabled (so ipacket->data is a right-sized
 *            heap buffer ASan brackets), then per-attribute extraction via
 *            get_attribute_extracted_data_at_index().
 *   Part 3 — fixture: fabricated ipacket + real registered attribute via
 *            get_registered_attribute_internal_struct() +
 *            internal_extract_attribute() for tight-caplen boundaries.
 *   Part 4 — pending-#210 inputs behind MMT_PENDING_FIXES=1 (see below).
 *
 * Deferred to issue #210 (Task 3.4, PR #294 — not yet merged): the u32
 * attribute reads at dicom.c:99/203/226 cast &data[odd] to uint32_t* and
 * trip UBSan on any input whose absolute field address is not 4-aligned,
 * and mmt_check_dicom_tcp() dereferences the header at data[dicom_offset]
 * without checking dicom_offset <= caplen. The positive extractions below
 * keep every u32 field 4-aligned on purpose (pad item in the PDU, standard
 * 14+20+20 transport so the DICOM payload starts at offset 54); the gated
 * block arms the misaligned variants — green only on a tree carrying the
 * #210 fix, red on a revert.
 *
 * Exit 0 == clean. Any ASan/UBSan report aborts under -fno-sanitize-recover.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mmt_tcpip_plugin_structs.h"   /* mmt_tcpip_internal_packet_struct — in-tree header */
#include "packet_processing.h"        /* struct attribute_internal_struct — in-tree header */
#include "dicom/dicom.h"              /* installed: DICOM_* ids, struct dicomhdr */
#include "internal_decls.h"

#include "../../../src/mmt_dicom/dicom.c" /* TU include: reach static _extraction_att (#210) */

#define PROTO_DICOM 701

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

static void put_u16be(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_u32be(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

/* htonl without pulling in <arpa/inet.h> ordering surprises on packed fields */
static uint32_t htonl_local(uint32_t v) {
    uint32_t r; uint8_t *p = (uint8_t *)&r;
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
    return r;
}

/* ------------------------------------------------------------------ */
/* PDU builders — all offsets are PDU-relative (the dissector sees the  */
/* PDU at absolute offset dicom_offset inside the packet).              */
/* ------------------------------------------------------------------ */

/* Canonical A-ASSOCIATE-RQ/AC. Layout (all sizes include the 4-byte item
 * header):
 *   74: 0x10 app-ctx   len 21 "1.2.840.10008.3.1.1.1"      -> next @ 99
 *   99: 0x60 pad item  len 1  (unknown type — skipped)      -> next @ 104
 *  104: 0x20/0x21 pres-ctx len 46:
 *         ctx-id(4) + 0x30 abstract(21) + 0x40 transfer(21) -> next @ 154
 *  154: 0x50 user-info len 25:
 *         0x51 max-pdu @158 -> u32 value @162 (PDU-rel),
 *         0x52 impl-uid @166 len 13 "1.2.3.4.5.6.7"          -> end @ 183
 * With the transport stack below (eth14+ip20+tcp20) the DICOM payload sits
 * at absolute offset 54, so the 0x51 value lands at 54+162 = 216 — 4-byte
 * aligned. That parity is deliberate: the u32 field reads at
 * dicom.c:99/203/226 are only defined for aligned addresses until #210
 * lands; the MMT_PENDING_FIXES block arms the misaligned variant. */
static int build_assoc(uint8_t *b, uint8_t pdu_type) {
    int n = 0;
    b[n++] = pdu_type; b[n++] = 0x00; n += 4;          /* pdu_len filled below */
    b[n++] = 0x00; b[n++] = 0x01; b[n++] = 0x00; b[n++] = 0x00; /* proto ver */
    memcpy(b + n, "CALLED_AE       ", 16); n += 16;
    memcpy(b + n, "CALLING_AE      ", 16); n += 16;
    memset(b + n, 0, 32); n += 32;
    b[n++] = 0x10; b[n++] = 0x00; put_u16be(b + n, 21); n += 2;
    memcpy(b + n, "1.2.840.10008.3.1.1.1", 21); n += 21;
    b[n++] = 0x60; b[n++] = 0x00; put_u16be(b + n, 1); n += 2;
    b[n++] = 0x00;                                     /* pad item, len 1 */
    int pc_at = n;
    b[n++] = (pdu_type == A_ASSOCIATE_RQ) ? 0x20 : 0x21;
    b[n++] = 0x00; n += 2; int pc_start = n;
    b[n++] = 0x01; b[n++] = 0; b[n++] = 0; b[n++] = 0;  /* context id 1 */
    b[n++] = 0x30; b[n++] = 0x00; put_u16be(b + n, 17); n += 2;
    memcpy(b + n, "1.2.840.10008.1.1", 17); n += 17;
    b[n++] = 0x40; b[n++] = 0x00; put_u16be(b + n, 17); n += 2;
    memcpy(b + n, "1.2.840.10008.1.2", 17); n += 17;
    put_u16be(b + pc_at + 2, (uint16_t)(n - pc_start));
    int ui_at = n;
    b[n++] = 0x50; b[n++] = 0x00; n += 2; int ui_start = n;
    b[n++] = 0x51; b[n++] = 0x00; put_u16be(b + n, 4); n += 2;
    put_u32be(b + n, 16384); n += 4;                    /* max pdu = 16384 */
    b[n++] = 0x52; b[n++] = 0x00; put_u16be(b + n, 13); n += 2;
    memcpy(b + n, "1.2.3.4.5.6.7", 13); n += 13;
    put_u16be(b + ui_at + 2, (uint16_t)(n - ui_start));
    put_u32be(b + 2, (uint32_t)(n - 6));                /* pdu_len */
    return n;
}

/* Fixed 4-byte-body PDUs: A-ASSOCIATE-RJ(3), A-RELEASE-RQ(5)/RP(6), A-ABORT(7). */
static int build_fixed(uint8_t *b, uint8_t pdu_type) {
    b[0] = pdu_type; b[1] = 0x00; put_u32be(b + 2, 4);
    b[6] = 0; b[7] = 0; b[8] = 0; b[9] = 0;
    return 10;
}

/* P-DATA-TF: 04 00 len32 | pdv_len32 ctx(1) flags(1) | dimse bytes.
 * flags bit0: 1 = command PDV, 0 = dataset PDV. */
static int build_pdata(uint8_t *b, uint8_t flags, const uint8_t *dimse, int dimse_len) {
    int n = 0;
    b[n++] = 0x04; b[n++] = 0x00; n += 4;               /* pdu_len below */
    int pdv_at = n; n += 4;                             /* pdv_len below */
    b[n++] = 0x01;                                      /* context id */
    b[n++] = flags;
    memcpy(b + n, dimse, dimse_len); n += dimse_len;
    put_u32be(b + pdv_at, (uint32_t)(n - pdv_at - 4));  /* pdv_len = ctx+flags+data */
    put_u32be(b + 2, (uint32_t)(n - 6));                /* pdu_len */
    return n;
}

/* Implicit-VR DIMSE tag writer: group/elem little-endian, 4-byte LE length,
 * then `vlen` value bytes. */
static int put_tag(uint8_t *b, uint16_t group, uint16_t elem,
        const uint8_t *val, int vlen) {
    b[0] = group & 0xff; b[1] = group >> 8;
    b[2] = elem & 0xff; b[3] = elem >> 8;
    b[4] = vlen & 0xff; b[5] = (vlen >> 8) & 0xff;
    b[6] = (vlen >> 16) & 0xff; b[7] = (vlen >> 24) & 0xff;
    memcpy(b + 8, val, vlen);
    return 8 + vlen;
}

/* DIMSE command set: group-length, command-field, message-id, status,
 * data-set-type, affected-SOP-class-uid. */
static int build_dimse_command(uint8_t *b) {
    int n = 0;
    uint8_t u32v[4] = { 0x60, 0, 0, 0 };            /* group length 96 */
    n += put_tag(b + n, 0x0000, 0x0000, u32v, 4);
    uint8_t u16v[2] = { 0x30, 0x00 };               /* C-STORE-RQ 0x0030 */
    n += put_tag(b + n, 0x0000, 0x0100, u16v, 2);
    uint8_t mid[2] = { 0x07, 0x00 };                /* message id 7 */
    n += put_tag(b + n, 0x0000, 0x0110, mid, 2);
    uint8_t st[2] = { 0x00, 0x00 };                 /* status success */
    n += put_tag(b + n, 0x0000, 0x0900, st, 2);
    uint8_t dst[2] = { 0x01, 0x01 };                /* data set type 0x0101 */
    n += put_tag(b + n, 0x0000, 0x0800, dst, 2);
    n += put_tag(b + n, 0x0000, 0x0002,
            (const uint8_t *)"1.2.840.10008.5.1.4.1.1.7", 24); /* affected SOP */
    return n;
}

/* Dataset PDV carrying the patient name tag (0010,0010) with explicit VR 'PN',
 * followed by a 32-byte pixel-data element: the whole PDU must reach
 * caplen >= dicom_offset+68 = 122 or the central guard refuses the string
 * attribute (registered data_len is the 68-byte binary blob) before the
 * extractor runs. */
static int build_dimse_dataset(uint8_t *b) {
    int n = 0;
    b[n++] = 0x10; b[n++] = 0x00; b[n++] = 0x10; b[n++] = 0x00;  /* (0010,0010) */
    b[n++] = 'P'; b[n++] = 'N';                                  /* VR */
    b[n++] = 8; b[n++] = 0;                                      /* len LE */
    memcpy(b + n, "DOE^JOHN", 8); n += 8;
    b[n++] = 0xE0; b[n++] = 0x7F; b[n++] = 0x10; b[n++] = 0x00;  /* (7FE0,0010) */
    memset(b + n, 0, 4); n += 4;                                 /* implicit len */
    b[n - 4] = 32;
    memset(b + n, 0, 32); n += 32;                               /* 32B value */
    return n;
}

/* Item-walk edge PDUs (header always stays classify-valid: type 1, a
 * pdu_len inside [68,65535]). `variant` selects the variable area shape. */
static int build_assoc_edge(uint8_t *b, int variant) {
    int n = 0;
    b[n++] = 0x01; b[n++] = 0x00; n += 4;
    b[n++] = 0x00; b[n++] = 0x01; b[n++] = 0x00; b[n++] = 0x00;
    memcpy(b + n, "CALLED_AE       ", 16); n += 16;
    memcpy(b + n, "CALLING_AE      ", 16); n += 16;
    memset(b + n, 0, 32); n += 32;
    switch (variant) {
    case 0:  /* single item whose declared len overruns the PDU */
        b[n++] = 0x10; b[n++] = 0x00; put_u16be(b + n, 200); n += 2;
        memcpy(b + n, "1.2.840", 7); n += 7;
        break;
    case 1:  /* zero-length app-ctx item */
        b[n++] = 0x10; b[n++] = 0x00; put_u16be(b + n, 0); n += 2;
        break;
    case 2:  /* unknown item type only */
        b[n++] = 0x60; b[n++] = 0x00; put_u16be(b + n, 3); n += 2;
        b[n++] = 'x'; b[n++] = 'y'; b[n++] = 'z';
        break;
    case 3:  /* pres-ctx item with ctx-id but no 0x30 sub-item */
        b[n++] = 0x20; b[n++] = 0x00; put_u16be(b + n, 4); n += 2;
        b[n++] = 0x01; b[n++] = 0; b[n++] = 0; b[n++] = 0;
        break;
    case 4:  /* user-info item cut mid-sub-item: 0x51 declares 4 but PDU ends */
        b[n++] = 0x50; b[n++] = 0x00; put_u16be(b + n, 25); n += 2;
        b[n++] = 0x51; b[n++] = 0x00;                      /* len bytes cut */
        break;
    case 5:  /* variable area holds only a 2-byte item header fragment */
        b[n++] = 0x10; b[n++] = 0x00;
        break;
    }
    put_u32be(b + 2, (uint32_t)(n - 6));
    /* pdu_len must stay inside [68, 65535] for classification to pass;
     * pad the declared region with a trailing unknown item if too small. */
    while (n < 74) { b[n++] = 0x00; }
    put_u32be(b + 2, (uint32_t)(n - 6));
    return n;
}

static unsigned g_sport = 40000;    /* unique sport per packet => fresh flow */

/* Eth/IPv4/TCP frame carrying a DICOM PDU. Returns the frame length.
 * dport is deliberately NOT DICOM's well-known port (104): port-based
 * classification would accept the frame regardless of payload and the
 * negative cases below would never reach the payload check. */
static int build_frame(uint8_t *pkt, const uint8_t *pdu, int pdu_len) {
    int off = 0;
    memset(pkt, 0, 14);
    pkt[12] = 0x08; pkt[13] = 0x00; off = 14;                      /* eth */
    memset(pkt + off, 0, 20);
    pkt[off] = 0x45;
    put_u16be(pkt + off + 2, (uint16_t)(20 + 20 + pdu_len));
    put_u16be(pkt + off + 4, 0x1234);
    pkt[off + 8] = 64; pkt[off + 9] = 6;
    pkt[off + 12] = 10; pkt[off + 15] = 1;
    pkt[off + 16] = 10; pkt[off + 19] = 2;
    off += 20;                                                     /* ipv4 */
    put_u16be(pkt + off, g_sport); put_u16be(pkt + off + 2, 22222);  /* unregistered */
    memset(pkt + off + 4, 0, 8);
    pkt[off + 12] = 0x50; pkt[off + 13] = 0x18;
    put_u16be(pkt + off + 14, 0xffff);
    off += 20;                                                     /* tcp */
    memcpy(pkt + off, pdu, pdu_len); off += pdu_len;
    return off;
}

/* ------------------------------------------------------------------ */
/* Part 1 — unit checks on the classification helpers                  */
/* ------------------------------------------------------------------ */
static void test_check_functions(void) {
    printf("mmt_check_dicom_* unit checks:\n");
    struct dicomhdr h;
    memset(&h, 0, sizeof(h));

    /* hdr gate: types 1..7 */
    for (int t = 0; t <= 8; t++) {
        h.pdu_type = (uint8_t)t;
        char d[64]; snprintf(d, sizeof(d), "hdr type %d -> %s", t,
                (t >= 1 && t <= 7) ? "accept" : "reject");
        CHECK(mmt_check_dicom_hdr(&h) == (t >= 1 && t <= 7), d);
    }

    /* payload gate: minimum captured length is HDRLEN(6)+MIN_LEN(4) = 10 */
    h.pdu_type = A_ASSOCIATE_RQ; h.pdu_len = htonl_local(68);
    CHECK(mmt_check_dicom_payload(&h, 9) == 0, "packet_len 9 < 10 rejected");
    CHECK(mmt_check_dicom_payload(&h, 10) == 1, "packet_len 10 accepted (assoc len 68)");

    /* A-ASSOCIATE length window */
    h.pdu_len = htonl_local(67);
    CHECK(mmt_check_dicom_payload(&h, 100) == 0, "assoc pdu_len 67 rejected");
    h.pdu_len = htonl_local(68);
    CHECK(mmt_check_dicom_payload(&h, 100) == 1, "assoc pdu_len 68 accepted");
    h.pdu_len = htonl_local(65535);
    CHECK(mmt_check_dicom_payload(&h, 100) == 1, "assoc pdu_len 65535 accepted");
    h.pdu_len = htonl_local(65536);
    CHECK(mmt_check_dicom_payload(&h, 100) == 0, "assoc pdu_len 65536 rejected");

    /* fixed-body PDUs require exactly 4 */
    const uint8_t fixed[] = { A_ASSOCIATE_RJ, A_RELEASE_RQ, A_RELEASE_RP, A_ABORT };
    for (unsigned i = 0; i < sizeof(fixed); i++) {
        h.pdu_type = fixed[i]; h.pdu_len = htonl_local(4);
        char d[64]; snprintf(d, sizeof(d), "type %u pdu_len 4 accepted", fixed[i]);
        CHECK(mmt_check_dicom_payload(&h, 10) == 1, d);
        h.pdu_len = htonl_local(5);
        snprintf(d, sizeof(d), "type %u pdu_len 5 rejected", fixed[i]);
        CHECK(mmt_check_dicom_payload(&h, 10) == 0, d);
    }

    /* P-DATA-TF requires pdu_len >= 6 */
    h.pdu_type = P_DATA_TF; h.pdu_len = htonl_local(5);
    CHECK(mmt_check_dicom_payload(&h, 20) == 0, "p-data pdu_len 5 rejected");
    h.pdu_len = htonl_local(6);
    CHECK(mmt_check_dicom_payload(&h, 20) == 1, "p-data pdu_len 6 accepted");

    /* combined check */
    h.pdu_type = 9; h.pdu_len = htonl_local(4);
    CHECK(mmt_check_dicom(&h, 20) == 0, "combined check rejects bad type");
    h.pdu_type = P_DATA_TF; h.pdu_len = htonl_local(6);
    CHECK(mmt_check_dicom(&h, 20) == 1, "combined check accepts p-data");
}

/* ------------------------------------------------------------------ */
/* Part 2 — full packet path                                           */
/* ------------------------------------------------------------------ */

/* Per-packet observations collected inside the packet handler (the ipacket
 * is recycled/freed once packet_process returns — extraction must happen
 * there). */
static int g_last_proto = -1;
static const int *g_attr_plan = NULL;      /* fids to extract this packet */
static int g_attr_plan_len = 0;
static int g_dicom_index = -1;
static int g_extract_seen[32];             /* fid -> get_attribute_.. != NULL */
static mmt_binary_data_t g_extract_str[32]; /* captured string blobs */
static uint32_t g_extract_u32[32];         /* captured ints */

/* Field-id value widths — the returned data blob is only as large as the
 * field's registered data_len, so copy exactly the right number of bytes. */
static int fid_is_string(int fid) {
    switch (fid) {
    case 4: case 5: case 6: case 7: case 9: case 15: case 17: case 19: case 20:
        return 1;
    default:
        return 0;
    }
}
static int fid_int_size(int fid) {
    switch (fid) {
    case 2: case 8: case 10: case 13: return 4;
    case 3: case 14: case 16: case 18: case 21: return 2;
    case 1: case 11: case 12: return 1;
    default: return 0;
    }
}

static int ph_collect(const ipacket_t *ipacket, void *u) {
    (void)u;
    if (!ipacket->proto_hierarchy || ipacket->proto_hierarchy->len <= 0)
        return 0;
    int idx = ipacket->proto_hierarchy->len - 1;
    g_last_proto = ipacket->proto_hierarchy->proto_path[idx];
    g_dicom_index = (g_last_proto == PROTO_DICOM) ? idx : -1;
    if (g_dicom_index < 0 || !g_attr_plan) return 0;
    for (int i = 0; i < g_attr_plan_len; i++) {
        int fid = g_attr_plan[i];
        if (fid <= 0 || fid >= 32) continue;
        void *d = get_attribute_extracted_data_at_index(ipacket,
                PROTO_DICOM, fid, (unsigned)g_dicom_index);
        g_extract_seen[fid] = (d != NULL);
        if (!d) continue;
        if (fid_is_string(fid)) {
            memcpy(&g_extract_str[fid], d, sizeof(mmt_binary_data_t));
        } else {
            switch (fid_int_size(fid)) {
            case 4: g_extract_u32[fid] = *(uint32_t *)d; break;
            case 2: g_extract_u32[fid] = *(uint16_t *)d; break;
            case 1: g_extract_u32[fid] = *(uint8_t *)d; break;
            default: break;
            }
        }
    }
    return 0;
}

static mmt_handler_t *g_handler = NULL;

/* Feed a crafted frame; `cut` truncates the captured tail if > 0 (wire len
 * stays full). Every call uses a fresh source port so each packet opens a
 * new flow — otherwise an established flow inherits the earlier packet's
 * classification and the negative cases would never reach the payload
 * check. Returns the classified tail proto (or -1). */
static int feed_pdu(const uint8_t *pdu, int pdu_len, int cut,
        const int *attr_plan, int plan_len) {
    uint8_t pkt[14 + 20 + 20 + 512];
    g_sport++;
    int flen = build_frame(pkt, pdu, pdu_len);
    struct pkthdr hdr; memset(&hdr, 0, sizeof hdr);
    hdr.len = flen;
    hdr.caplen = (cut > 0 && cut < flen) ? cut : flen;
    g_last_proto = -1; g_dicom_index = -1;
    g_attr_plan = attr_plan; g_attr_plan_len = plan_len;
    memset(g_extract_seen, 0, sizeof(g_extract_seen));
    packet_process(g_handler, &hdr, pkt);
    g_attr_plan = NULL; g_attr_plan_len = 0;
    return g_last_proto;
}

static const int ASSOC_ATTRS[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 19, 20 };
static const int PDATA_ATTRS[] = { 1, 2, 10, 11, 12, 13, 14, 16, 17, 18, 21 };
static const int DS_ATTRS[]   = { 15 };

static void test_full_path(void) {
    printf("full-path classification + extraction:\n");
    char errbuf[1024];
    g_handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (!g_handler) {
        printf("  info: mmt_init_handler failed (%s) — skipping part 2\n", errbuf);
        return;
    }
    /* on-demand extraction requires the attributes registered */
    const int all_fids[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21 };
    for (unsigned i = 0; i < sizeof(all_fids)/sizeof(all_fids[0]); i++)
        (void)register_extraction_attribute(g_handler, PROTO_DICOM, all_fids[i]);
    enable_mmt_reassembly(g_handler);   /* right-sized heap packet buffer */
    register_packet_handler(g_handler, 1, ph_collect, NULL);

    uint8_t pdu[512];

    /* --- A-ASSOCIATE-RQ ------------------------------------------ */
    int plen = build_assoc(pdu, A_ASSOCIATE_RQ);
    int tail = feed_pdu(pdu, plen, 0, ASSOC_ATTRS, (int)(sizeof(ASSOC_ATTRS)/sizeof(int)));
    CHECK(tail == PROTO_DICOM, "A-ASSOCIATE-RQ classified as DICOM");
    CHECK(g_extract_seen[1] && g_extract_u32[1] == 1, "pdu_type = 1");
    CHECK(g_extract_seen[2] && g_extract_u32[2] == (uint32_t)(plen - 6),
            "pdu_len extracted (aligned u32 read)");
    CHECK(g_extract_seen[3] && g_extract_u32[3] == 1, "proto_version = 1");
    CHECK(g_extract_seen[4] && g_extract_str[4].len == 16
            && memcmp(g_extract_str[4].data, "CALLED_AE       ", 16) == 0,
            "called AE title 'CALLED_AE       '");
    CHECK(g_extract_seen[5] && g_extract_str[5].len == 16
            && memcmp(g_extract_str[5].data, "CALLING_AE      ", 16) == 0,
            "calling AE title 'CALLING_AE      '");
    CHECK(g_extract_seen[6] && g_extract_str[6].len == 21
            && memcmp(g_extract_str[6].data, "1.2.840.10008.3.1.1.1", 21) == 0,
            "application context UID");
    CHECK(g_extract_seen[7] && g_extract_str[7].len == 17
            && memcmp(g_extract_str[7].data, "1.2.840.10008.1.1", 17) == 0,
            "presentation context abstract syntax");
    CHECK(g_extract_seen[8] && g_extract_u32[8] == 16384,
            "max pdu length = 16384 (aligned u32 sub-item read)");
    CHECK(g_extract_seen[9] && g_extract_str[9].len == 13
            && memcmp(g_extract_str[9].data, "1.2.3.4.5.6.7", 13) == 0,
            "implementation class UID");
    CHECK(g_extract_seen[19] && g_extract_str[19].len == 17
            && memcmp(g_extract_str[19].data, "1.2.840.10008.1.1", 17) == 0,
            "abstract syntax via 0x30 sub-item");
    CHECK(g_extract_seen[20] && g_extract_str[20].len == 17
            && memcmp(g_extract_str[20].data, "1.2.840.10008.1.2", 17) == 0,
            "transfer syntax via 0x40 sub-item");

    /* --- A-ASSOCIATE-AC (0x21 pres-ctx path) ------------------------ */
    plen = build_assoc(pdu, A_ASSOCIATE_AC);
    tail = feed_pdu(pdu, plen, 0, ASSOC_ATTRS, (int)(sizeof(ASSOC_ATTRS)/sizeof(int)));
    CHECK(tail == PROTO_DICOM, "A-ASSOCIATE-AC classified as DICOM");
    CHECK(g_extract_seen[7] && g_extract_str[7].len == 17
            && memcmp(g_extract_str[7].data, "1.2.840.10008.1.1", 17) == 0,
            "AC presentation context via 0x21 item");

    /* --- fixed-body PDUs ------------------------------------------- */
    const uint8_t fixed_types[] = { A_ASSOCIATE_RJ, A_RELEASE_RQ, A_RELEASE_RP, A_ABORT };
    for (unsigned i = 0; i < sizeof(fixed_types); i++) {
        plen = build_fixed(pdu, fixed_types[i]);
        tail = feed_pdu(pdu, plen, 0, ASSOC_ATTRS, (int)(sizeof(ASSOC_ATTRS)/sizeof(int)));
        char d[64]; snprintf(d, sizeof(d), "type %u classified as DICOM", fixed_types[i]);
        CHECK(tail == PROTO_DICOM, d);
        snprintf(d, sizeof(d), "type %u pdu_type extracted = %u", fixed_types[i], fixed_types[i]);
        CHECK(g_extract_seen[1] && g_extract_u32[1] == fixed_types[i], d);
    }

    /* --- P-DATA-TF command PDV ------------------------------------- */
    uint8_t dimse[256];
    int dlen = build_dimse_command(dimse);
    plen = build_pdata(pdu, 0x03, dimse, dlen);   /* command + last fragment */
    tail = feed_pdu(pdu, plen, 0, PDATA_ATTRS, (int)(sizeof(PDATA_ATTRS)/sizeof(int)));
    CHECK(tail == PROTO_DICOM, "P-DATA-TF classified as DICOM");
    CHECK(g_extract_seen[10] && g_extract_u32[10] == (uint32_t)(dlen + 2),
            "pdv_length extracted (aligned u32 read)");
    CHECK(g_extract_seen[11] && g_extract_u32[11] == 1, "pdv context id = 1");
    CHECK(g_extract_seen[12] && g_extract_u32[12] == 0x03, "pdv flags = 0x03");
    CHECK(g_extract_seen[13] && g_extract_u32[13] == 96, "command group length = 96");
    CHECK(g_extract_seen[14] && g_extract_u32[14] == 0x0030, "command field = C-STORE-RQ");
    CHECK(g_extract_seen[16] && g_extract_u32[16] == 0, "status = success(0)");
    CHECK(g_extract_seen[17] && g_extract_str[17].len == 24
            && memcmp(g_extract_str[17].data, "1.2.840.10008.5.1.4.1.1.7", 24) == 0,
            "affected SOP class UID");
    CHECK(g_extract_seen[18] && g_extract_u32[18] == 7, "message id = 7");
    CHECK(g_extract_seen[21] && g_extract_u32[21] == 0x0101, "data set type = 0x0101");

    /* --- P-DATA-TF dataset PDV (flags bit0 clear -> patient name) ---- */
    dlen = build_dimse_dataset(dimse);
    plen = build_pdata(pdu, 0x02, dimse, dlen);
    tail = feed_pdu(pdu, plen, 0, DS_ATTRS, 1);
    CHECK(tail == PROTO_DICOM, "dataset P-DATA classified as DICOM");
    CHECK(g_extract_seen[15] && g_extract_str[15].len == 8
            && memcmp(g_extract_str[15].data, "DOE^JOHN", 8) == 0,
            "patient name via explicit-VR PN tag");

    /* --- item-walk edge cases ---------------------------------------- */
    const char *edge_desc[] = {
        "overrunning declared item length",
        "zero-length item",
        "unknown item type only",
        "pres-ctx without 0x30 sub-item",
        "user-info cut mid-sub-item",
        "2-byte item header fragment",
    };
    for (int v = 0; v <= 5; v++) {
        plen = build_assoc_edge(pdu, v);
        tail = feed_pdu(pdu, plen, 0, ASSOC_ATTRS, (int)(sizeof(ASSOC_ATTRS)/sizeof(int)));
        char d[96]; snprintf(d, sizeof(d), "edge[%d] %s: still classified", v, edge_desc[v]);
        CHECK(tail == PROTO_DICOM, d);
        snprintf(d, sizeof(d), "edge[%d] %s: app-ctx bounded", v, edge_desc[v]);
        if (v == 1)
            CHECK(g_extract_seen[6] && g_extract_str[6].len == 0, d);
        else
            CHECK(!g_extract_seen[6], d);
        /* AE-title needs the central guard's 132 captured bytes (54+10+68);
         * edge[5] captures only 76 payload bytes, so refusal is expected. */
        snprintf(d, sizeof(d), "edge[%d] %s: AE-title extraction bounded", v, edge_desc[v]);
        if (54 + plen < 132)
            CHECK(!g_extract_seen[4], d);
        else
            CHECK(g_extract_seen[4] && g_extract_str[4].len == 16, d);
    }

    /* --- truncated PDUs ----------------------------------------------
     * The canonical assoc is 183 bytes at payload offset 54. Cuts inside
     * the header (<10 payload bytes) must not classify; cuts at/after the
     * item area must classify but bound every extraction by caplen. */
    plen = build_assoc(pdu, A_ASSOCIATE_RQ);
    const int cuts[] = { 54 + 5, 54 + 10, 54 + 25, 54 + 74, 54 + 99, 54 + 150, 54 + 182 };
    for (unsigned i = 0; i < sizeof(cuts)/sizeof(cuts[0]); i++) {
        int k = cuts[i] - 54;   /* captured payload bytes */
        tail = feed_pdu(pdu, plen, cuts[i], ASSOC_ATTRS,
                (int)(sizeof(ASSOC_ATTRS)/sizeof(int)));
        char d[96];
        if (k < 10) {
            snprintf(d, sizeof(d), "cut at %d payload bytes: not classified", k);
            CHECK(tail != PROTO_DICOM, d);
        } else {
            snprintf(d, sizeof(d), "cut at %d payload bytes: classified", k);
            CHECK(tail == PROTO_DICOM, d);
            /* AE-title: the registered data_len is the 68-byte binary blob, so
             * the central guard needs offset+pos+68 <= caplen (54+10+68=132)
             * before the extractor even runs; below that it refuses cleanly. */
            snprintf(d, sizeof(d), "cut at %d: AE-title extraction bounded", k);
            if (cuts[i] < 132)
                CHECK(!g_extract_seen[4], d);
            else
                CHECK(g_extract_seen[4] && g_extract_str[4].len == 16, d);
        }
    }

    /* --- non-DICOM payload ------------------------------------------- */
    uint8_t junk[64]; memset(junk, 0, sizeof(junk));
    tail = feed_pdu(junk, sizeof(junk), 0, NULL, 0);
    CHECK(tail != PROTO_DICOM, "zero payload not classified as DICOM");

    /* bad PDU type inside an otherwise-well-formed packet */
    plen = build_assoc(pdu, A_ASSOCIATE_RQ);
    pdu[0] = 0x09;                                    /* invalid type */
    tail = feed_pdu(pdu, plen, 0, NULL, 0);
    CHECK(tail != PROTO_DICOM, "pdu_type 9 not classified as DICOM");

    mmt_close_handler(g_handler);
    g_handler = NULL;
}

/* ------------------------------------------------------------------ */
/* Part 3 — fixture: internal_extract_attribute on tight buffers        */
/* ------------------------------------------------------------------ */

typedef struct {
    ipacket_t pkt;
    proto_hierarchy_t offsets;
    proto_hierarchy_t hier;
    pkthdr_t hdr;
    mmt_handler_t *hdlr;   /* borrowed — the real handler that registered attrs */
    u_char *buf;
} dicom_fixture_t;

/* `captured` is the number of DICOM payload bytes captured; the buffer holds
 * a 54-byte wire prefix (layers {0,0,14,20,20} -> offset(4) = 54, the DICOM
 * position the real path produces) followed by the payload, so all offsets
 * and alignments match part 2. */
static void dicom_fixture_init(dicom_fixture_t *f, mmt_handler_t *hdlr,
        const uint8_t *pdu, unsigned captured) {
    memset(f, 0, sizeof(*f));
    unsigned caplen = 54 + captured;
    f->buf = (u_char *)malloc(caplen ? caplen : 1);
    if (!f->buf) { perror("malloc"); exit(2); }
    memset(f->buf, 0, caplen);
    if (pdu && captured) memcpy(f->buf + 54, pdu, captured);
    const int sizes[5] = { 0, 0, 14, 20, 20 };
    for (int i = 0; i < 5; i++) {
        f->offsets.proto_path[i] = sizes[i];
        f->hier.proto_path[i] = 701;
    }
    f->offsets.len = f->hier.len = 5;
    f->hdr.caplen = caplen;
    f->hdr.len = caplen;
    f->pkt.p_hdr = &f->hdr;
    f->pkt.data = f->buf;
    f->pkt.proto_headers_offset = &f->offsets;
    f->pkt.proto_hierarchy = &f->hier;
    f->pkt.internal_cumulative_offset_valid = 0;
    f->pkt.mmt_handler = hdlr;
}

static void dicom_fixture_free(dicom_fixture_t *f) {
    free(f->buf);
}

static void test_fixture_extraction(void) {
    printf("fixture extraction via internal_extract_attribute:\n");
    char errbuf[1024];
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (!h) { printf("  info: mmt_init_handler failed — skipping\n"); return; }

    /* register the fields we drive so their real attribute structs exist */
    const int fids[] = { 1, 2, 4, 5, 6, 7, 13 };
    for (unsigned i = 0; i < sizeof(fids)/sizeof(fids[0]); i++)
        (void)register_extraction_attribute(h, PROTO_DICOM, fids[i]);

    uint8_t pdu[512];
    int plen = build_assoc(pdu, A_ASSOCIATE_RQ);

    /* positive extraction on a right-sized buffer — the copy that commit
     * 396bc63a bounded to 16 bytes; reverting it writes 68 into a 64-byte
     * data[] inside the attribute blob and ASan aborts here. */
    dicom_fixture_t f;
    dicom_fixture_init(&f, h, pdu, (unsigned)plen);
    struct attribute_internal_struct *attr =
        get_registered_attribute_internal_struct(&f.pkt, PROTO_DICOM,
                DICOM_CALLED_AE_TITLE, 4);
    CHECK(attr != NULL, "registered CALLED_AE_TITLE attr found");
    if (attr) {
        int r = internal_extract_attribute(&f.pkt, attr, 4);
        CHECK(r == 1 && attr->status == ATTRIBUTE_SET,
                "fixture AE-title extraction succeeds");
        if (r == 1) {
            mmt_binary_data_t *bd = (mmt_binary_data_t *)attr->data;
            CHECK(bd->len == 16 && memcmp(bd->data, "CALLED_AE       ", 16) == 0,
                    "fixture AE-title value correct");
        }
    }
    dicom_fixture_free(&f);

    /* AE-title cut below the declared extent: the central guard needs
     * offset+pos+68 <= caplen (54+10+68=132) — 46 captured payload bytes
     * (caplen 100) refuses before the extractor runs. */
    dicom_fixture_init(&f, h, pdu, 46);
    if (attr) {
        int r = internal_extract_attribute(&f.pkt, attr, 4);
        CHECK(r == 0, "caplen 100: AE-title refused by central guard");
    }
    dicom_fixture_free(&f);

    /* zero-captured-payload boundary: caplen == dicom_offset -> the
     * extractor's `caplen - dicom_offset == 0` early return. */
    dicom_fixture_init(&f, h, pdu, 0);
    attr = get_registered_attribute_internal_struct(&f.pkt, PROTO_DICOM,
            DICOM_PDU_TYPE, 4);
    if (attr) {
        int r = internal_extract_attribute(&f.pkt, attr, 4);
        CHECK(r == 0, "caplen == dicom_offset: extraction refused");
    }
    dicom_fixture_free(&f);

    /* tight boundary for the item walk: PDU cut so the variable area holds
     * a 2-byte item header fragment — find_assoc_subitem's `pos <= end-4`
     * edge — extraction of the app-ctx attr must refuse cleanly. */
    uint8_t edge[512];
    (void)build_assoc_edge(edge, 5);            /* 2-byte fragment after hdr */
    dicom_fixture_init(&f, h, edge, 76);        /* fragment inside capture */
    attr = get_registered_attribute_internal_struct(&f.pkt, PROTO_DICOM,
            DICOM_APPLICATION_CONTEXT, 4);
    if (attr) {
        int r = internal_extract_attribute(&f.pkt, attr, 4);
        CHECK(r == 0, "item header fragment at end: app-ctx extraction refused");
    }
    dicom_fixture_free(&f);

    mmt_close_handler(h);
}

/* ------------------------------------------------------------------ */
/* Part 4 — pending-#210 inputs (env-gated; red on main today)           */
/* ------------------------------------------------------------------ */
static void test_pending_210(void) {
    /* The #210 fix is in the tree — these cases run unconditionally. */
    printf("pending-#210 cases (issue #210 fix present):\n");

    char errbuf[1024];
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (!h) return;
    const int fids[] = { 2, 8 };
    for (unsigned i = 0; i < sizeof(fids)/sizeof(fids[0]); i++)
        (void)register_extraction_attribute(h, PROTO_DICOM, fids[i]);

    /* Misaligned u32 reads: put the DICOM payload at an odd absolute offset
     * inside the captured buffer (proto_path {0,0,14,20,21} -> offset(4)=55),
     * so the uint32_t* casts at dicom.c:99/203/226 take unaligned addresses.
     * Post-#210 these must extract the correct values; on main UBSan aborts. */
    uint8_t pdu[512];
    int plen = build_assoc(pdu, A_ASSOCIATE_RQ);
    dicom_fixture_t f;
    memset(&f, 0, sizeof(f));
    f.buf = (u_char *)malloc(55 + plen);
    memcpy(f.buf + 55, pdu, plen);
    const int sizes[5] = { 0, 0, 14, 20, 21 };
    for (int i = 0; i < 5; i++) {
        f.offsets.proto_path[i] = sizes[i];
        f.hier.proto_path[i] = 701;
    }
    f.offsets.len = f.hier.len = 5;
    f.hdr.caplen = 55 + plen; f.hdr.len = 55 + plen;
    f.pkt.p_hdr = &f.hdr; f.pkt.data = f.buf;
    f.pkt.proto_headers_offset = &f.offsets;
    f.pkt.proto_hierarchy = &f.hier;
    f.pkt.mmt_handler = h;

    struct attribute_internal_struct *attr =
        get_registered_attribute_internal_struct(&f.pkt, PROTO_DICOM,
                DICOM_PDU_LEN, 4);
    if (attr) {
        int r = internal_extract_attribute(&f.pkt, attr, 4);
        CHECK(r == 1 && *(uint32_t *)attr->data == (uint32_t)(plen - 6),
                "pdu_len extracts at unaligned absolute offset");
    }
    attr = get_registered_attribute_internal_struct(&f.pkt, PROTO_DICOM,
            DICOM_MAX_PDU_LENGTH, 4);
    if (attr) {
        int r = internal_extract_attribute(&f.pkt, attr, 4);
        CHECK(r == 1 && *(uint32_t *)attr->data == 16384,
                "max-pdu u32 extracts at unaligned absolute offset");
    }
    free(f.buf);

    /* mmt_check_dicom_tcp with dicom_offset > caplen — no bounds check on
     * the header dereference on main. Post-fix must return 0 cleanly. */
    dicom_fixture_init(&f, h, pdu, 0);
    f.hdr.caplen = 40;                          /* only 40 bytes captured */
    const int big[5] = { 0, 0, 14, 20, 60 };    /* offset(4) = 94 > caplen 40 */
    for (int i = 0; i < 5; i++) f.offsets.proto_path[i] = big[i];
    f.pkt.internal_cumulative_offset_valid = 0;
    int rc = mmt_check_dicom_tcp(&f.pkt, 3);
    CHECK(rc == 0, "check_dicom_tcp offset>caplen refused cleanly");
    dicom_fixture_free(&f);

    mmt_close_handler(h);
}

/* -----------------------------------------------------------------------
 * Issue #210 (F-BUG-099) truncated-PDU / out-of-capture offset guards.
 * dicom.c is #included below so the static _extraction_att() entry point
 * is reachable and ASan/UBSan-instrumented in this TU.
 * -------------------------------------------------------------------- */
typedef struct {
    ipacket_t pkt;
    proto_hierarchy_t offsets;
    proto_hierarchy_t hier;
    proto_hierarchy_t classif;
    pkthdr_t hdr;
    u_char *buf;
} fixture_t;

/* caplen captured bytes; dicom_offset is absolute (the l3 base is
 * proto_path[0] = 14, so proto_path[1] = dicom_offset - 14). */
static void fixture_init(fixture_t *f, unsigned caplen, int dicom_offset) {
    memset(f, 0, sizeof(*f));
    f->buf = (u_char *) malloc(caplen ? caplen : 1);
    if (!f->buf) { perror("malloc"); exit(2); }
    memset(f->buf, 0, caplen ? caplen : 1);

    f->offsets.proto_path[0] = 14;                    /* ethernet */
    f->offsets.proto_path[1] = dicom_offset - 14;     /* l3+l4 -> dicom */
    f->offsets.len = 2;
    f->hier.proto_path[0] = 6;                        /* any proto id */
    f->hier.len = 1;
    f->classif.len = 1;

    f->hdr.caplen = caplen;
    f->hdr.len = caplen;
    f->pkt.p_hdr = &f->hdr;
    f->pkt.data = f->buf;
    f->pkt.proto_headers_offset = &f->offsets;
    f->pkt.proto_hierarchy = &f->hier;
    f->pkt.proto_classif_status = &f->classif;
    f->pkt.internal_cumulative_offset_valid = 0;
    f->pkt.session = NULL;
    f->pkt.mmt_handler = NULL;
}

static void fixture_free(fixture_t *f) {
    free(f->buf);
}

/* Stamp a valid A-ASSOCIATE-RQ DICOM header (type 1, pdu_len 68) at the
 * given absolute offset inside the captured buffer. */
static void stamp_assoc_rq(fixture_t *f, int off) {
    f->buf[off]     = 0x01;            /* A_ASSOCIATE_RQ */
    f->buf[off + 1] = 0x00;            /* reserved */
    f->buf[off + 2] = 0x00;
    f->buf[off + 3] = 0x00;
    f->buf[off + 4] = 0x00;
    f->buf[off + 5] = 0x44;            /* pdu_len = 68 (BE) */
}

static void test_210_offset_guards(void) {
    fixture_t f;
    attribute_t attr;
    uint8_t out8;
    int r;

    printf("[#210] DICOM truncated-PDU / out-of-capture offset guard\n");

    /* --- refused cases: all read past the capture on the pre-fix tree --- */

    /* dicom_offset past caplen entirely: packet_len wraps to ~2^32, the
     * minimum-length check passed trivially and hdr->pdu_type was read
     * out of bounds. Must now be refused before any subtraction. */
    fixture_init(&f, 60, 74);
    r = mmt_check_dicom_tcp(&f.pkt, 0);
    CHECK(r == 0, "classify refuses dicom_offset past caplen");
    fixture_free(&f);

    /* dicom_offset == caplen: zero bytes of the header captured;
     * pre-fix read hdr->pdu_type one byte out of bounds. */
    fixture_init(&f, 60, 60);
    r = mmt_check_dicom_tcp(&f.pkt, 0);
    CHECK(r == 0, "classify refuses dicom_offset == caplen");
    fixture_free(&f);

    /* dicom_offset inside the capture but without the 6-byte fixed
     * header: only 2 captured bytes remain. */
    fixture_init(&f, 60, 58);
    r = mmt_check_dicom_tcp(&f.pkt, 0);
    CHECK(r == 0, "classify refuses a truncated fixed header");
    fixture_free(&f);

    /* Same three offsets through the attribute-extraction entry point
     * (_extraction_att), which had its own zero-only guard. proto_index
     * is the DICOM layer's own index (1: ethernet/TCP then DICOM). */
    memset(&attr, 0, sizeof(attr));
    attr.proto_id = PROTO_DICOM;
    attr.field_id = DICOM_PDU_TYPE;
    attr.position_in_packet = 0;
    attr.data = &out8;

    fixture_init(&f, 60, 74);
    r = _extraction_att(&f.pkt, 1, &attr);
    CHECK(r == 0, "extraction refuses dicom_offset past caplen");
    fixture_free(&f);

    fixture_init(&f, 60, 60);
    r = _extraction_att(&f.pkt, 1, &attr);
    CHECK(r == 0, "extraction refuses dicom_offset == caplen");
    fixture_free(&f);

    fixture_init(&f, 60, 58);
    r = _extraction_att(&f.pkt, 1, &attr);
    CHECK(r == 0, "extraction refuses a truncated fixed header");
    fixture_free(&f);

    /* --- allowed cases: full header + payload inside the capture --- */

    /* 74 captured bytes, DICOM A-ASSOCIATE-RQ at offset 34 (40 bytes of
     * captured DICOM, pdu_len = 68 -> sane per mmt_check_dicom_payload).
     * Classification must reach set_classified_proto() and return its
     * non-zero status. */
    fixture_init(&f, 74, 34);
    stamp_assoc_rq(&f, 34);
    r = mmt_check_dicom_tcp(&f.pkt, 0);
    CHECK(r != 0, "classify accepts a valid A-ASSOCIATE-RQ PDU");
    CHECK(f.hier.proto_path[1] == PROTO_DICOM,
          "classified proto recorded in the hierarchy");
    fixture_free(&f);

    /* Extraction of DICOM_PDU_TYPE from the same valid PDU. */
    fixture_init(&f, 74, 34);
    stamp_assoc_rq(&f, 34);
    out8 = 0xAA;
    r = _extraction_att(&f.pkt, 1, &attr);
    CHECK(r == 1 && out8 == 0x01,
          "extraction returns DICOM_PDU_TYPE from a valid PDU");
    fixture_free(&f);

}

int main(void) {
    printf("=== DICOM dissector crafted-input test (issues #210 + #215) ===\n");
    test_210_offset_guards();
    test_check_functions();
    /* init_extraction()/close_extraction() own process-global plugin state:
     * calling them more than once trips a use-after-free inside the library,
     * so the whole run shares a single init/close pair. */
    if (init_extraction()) {
        test_full_path();
        test_fixture_extraction();
        test_pending_210();
        close_extraction();
    } else {
        printf("  info: init_extraction unavailable — parts 2-4 skipped\n");
    }

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
