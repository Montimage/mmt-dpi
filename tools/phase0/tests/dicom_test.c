/*
 * dicom_test — regression test for issue #210 (F-BUG-099): both DICOM
 * entry points computed the DICOM payload length as an unsigned
 * subtraction guarded only against zero:
 *
 *   unsigned int packet_len = ipacket->p_hdr->caplen - dicom_offset;
 *
 * When dicom_offset (the protocol offset handed down by the parent TCP
 * dissector) lies beyond the captured bytes, the subtraction wraps to
 * ~2^32, the minimum-length check inside mmt_check_dicom() passes
 * trivially, and the parser dereferences a header pointer that points
 * past the end of the captured buffer. The two sites are
 * _extraction_att() (attribute extraction) and mmt_check_dicom_tcp()
 * (classification) in src/mmt_dicom/dicom.c.
 *
 * The fix validates the offset and requires the fixed 6-byte DICOM
 * header (PROTO_DICOM_HDRLEN) before subtracting, so a truncated or
 * out-of-capture offset is refused up front.
 *
 * This test compiles dicom.c into the test binary (the static
 * _extraction_att() is otherwise unreachable) and builds both with
 * -fsanitize=address,undefined -fno-sanitize-recover=all, so on the
 * pre-fix tree every "refused" case below aborts with a sanitizer
 * report instead of returning 0.
 *
 * Build (see run_dicom_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o dicom_test dicom_test.c \
 *       -I<prefix>/dpi/include -Isrc/mmt_core/public_include \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"           /* ipacket_t, attribute_t, pkthdr_t ... */

/* Pull the implementation into this TU so the static _extraction_att()
 * is reachable and ASan-instrumented. Its own includes resolve relative
 * to src/mmt_dicom/. */
#include "../../../src/mmt_dicom/dicom.c"

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

/* -----------------------------------------------------------------------
 * Fixture: an ipacket_t whose captured buffer is an exactly-sized heap
 * allocation (ASan brackets it), with the three proto_hierarchy_t arrays
 * the DICOM entry points touch (offsets, hierarchy, classif status).
 *
 * get_packet_offset_at_index() returns the inclusive prefix sum of
 * proto_headers_offset->proto_path[], so with index = 0:
 *   l3_offset    = proto_path[0]            (parent TCP ends)
 *   dicom_offset = proto_path[0] + proto_path[1]
 * proto_path[1] is chosen per case to place the DICOM start where the
 * scenario needs it — inside, at the boundary, or past caplen.
 * --------------------------------------------------------------------- */
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

int main(void) {
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

    printf("----------------------------------------\n");
    printf("%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures) {
        printf("✗ DICOM caplen-guard test FAILED\n");
        return 1;
    }
    printf("✓ DICOM caplen-guard test PASSED\n");
    return 0;
}
