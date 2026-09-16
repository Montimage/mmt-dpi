/*
 * Coverage driver for the DICOM dissector (src/mmt_dicom/dicom.c), issue #215.
 *
 * The dissector source is included directly so that gcov attributes the
 * exercised lines to the real file and so the static _extraction_att()
 * attribute extractor is reachable. The few mmt_core registration/packet
 * helpers it references are stubbed with compatible signatures; all parsing
 * logic under test is the real code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../../src/mmt_dicom/dicom.c"

static int checks;
static int failures;
#define CHECK(cond, msg) do { \
		checks++; \
		if (!(cond)) { \
			failures++; \
			fprintf(stderr, "FAIL %d: %s\n", __LINE__, msg); \
		} \
	} while (0)

/* ---- stubs for mmt_core registration / packet helpers ---- */

protocol_t *init_protocol_struct_for_registration(uint32_t proto_id,
		const char *protocol_name) {
	(void) proto_id;
	(void) protocol_name;
	return (protocol_t *) calloc(1, 1);
}

bool register_attribute_with_protocol(protocol_t *protocol_struct,
		attribute_metadata_t *attribute_meta_data) {
	(void) protocol_struct;
	(void) attribute_meta_data;
	return 1;
}

bool register_protocol(protocol_t *protocol_struct, uint32_t proto_id) {
	(void) proto_id;
	free(protocol_struct); /* stub allocation from init_protocol_struct_* */
	return 1;
}

bool register_classification_function_with_parent_protocol(uint32_t proto_id,
		generic_classification_function classification_fct, int weight) {
	(void) proto_id;
	(void) classification_fct;
	(void) weight;
	return 1;
}

int set_classified_proto(ipacket_t *ipacket, unsigned index,
		classified_proto_t classified_proto) {
	if (!ipacket || !ipacket->proto_hierarchy
			|| index >= (unsigned) ipacket->proto_hierarchy->len)
		return 0;
	ipacket->proto_hierarchy->proto_path[index] = classified_proto.proto_id;
	return 1;
}

int get_packet_offset_at_index(const ipacket_t *ipacket, unsigned index) {
	int off = 0;
	unsigned i;
	if (!ipacket || !ipacket->proto_headers_offset
			|| index >= (unsigned) ipacket->proto_headers_offset->len)
		return -1;
	for (i = 0; i <= index; i++)
		off += ipacket->proto_headers_offset->proto_path[i];
	return off;
}

/* ---- packet fixture ---- */

#define PKT_BUF 1024

struct test_pkt {
	ipacket_t ipacket;
	proto_hierarchy_t proto_offset;
	proto_hierarchy_t proto_h;
	pkthdr_t pcap_hdr;
	unsigned char buffer[PKT_BUF];
};

/* proto_path: META(1) -> ETHERNET(99) -> IP(178) -> TCP(354) -> DICOM(701)
 * header lengths: 0,0,14,20,20  -> DICOM payload starts at offset 54. */
#define DICOM_INDEX 4
#define DICOM_OFF 54

static struct test_pkt *pkt_with_pdu(const unsigned char *pdu, unsigned pdu_len,
		unsigned caplen) {
	struct test_pkt *t = calloc(1, sizeof(*t));
	memcpy(&t->buffer[DICOM_OFF], pdu, pdu_len);
	t->proto_h.proto_path[0] = 1;
	t->proto_h.proto_path[1] = 99;
	t->proto_h.proto_path[2] = 178;
	t->proto_h.proto_path[3] = 354;
	t->proto_h.proto_path[4] = PROTO_DICOM;
	t->proto_h.len = 5;
	t->ipacket.proto_hierarchy = &t->proto_h;
	t->proto_offset.proto_path[0] = 0;
	t->proto_offset.proto_path[1] = 0;
	t->proto_offset.proto_path[2] = 14;
	t->proto_offset.proto_path[3] = 20;
	t->proto_offset.proto_path[4] = 20;
	t->proto_offset.len = 5;
	t->ipacket.proto_headers_offset = &t->proto_offset;
	t->ipacket.data = t->buffer;
	t->ipacket.p_hdr = &t->pcap_hdr;
	t->ipacket.p_hdr->caplen = caplen;
	t->ipacket.packet_id = 1;
	return t;
}

static void free_pkt(struct test_pkt *t) {
	free(t);
}

/* ---- DICOM fixtures (PDU-relative layout) ---- */

/* A-ASSOCIATE-RQ: fixed part 68B, then variable items from offset 74:
 *   0x10 app-ctx len 21 "1.2.840.10008.3.1.1.1"
 *   0x20 pres-ctx len 46: ctx-id(4) + 0x30 abstract(4+17) + 0x40 transfer(4+17)
 *   0x50 user-info len 25: 0x51 max-pdu(8) + 0x52 impl-uid(4+13)
 * PDU length field = 204 (payload after the 6-byte header). */
static unsigned char assoc_pdu[224];
static unsigned assoc_pdu_len;

static void put_u16be(unsigned char *p, unsigned v) {
	p[0] = (v >> 8) & 0xff;
	p[1] = v & 0xff;
}

static void build_assoc(unsigned char *b, unsigned char pdu_type) {
	unsigned n = 0;
	memset(b, 0, 224);
	b[n++] = pdu_type;
	b[n++] = 0x00;
	n += 4; /* pdu_len filled below */
	b[n++] = 0x00; b[n++] = 0x01; b[n++] = 0x00; b[n++] = 0x00;
	memcpy(b + n, "CALLED_AE       ", 16); n += 16;
	memcpy(b + n, "CALLING_AE      ", 16); n += 16;
	memset(b + n, 0, 32); n += 32;
	b[n++] = 0x10; b[n++] = 0x00; put_u16be(b + n, 21); n += 2;
	memcpy(b + n, "1.2.840.10008.3.1.1.1", 21); n += 21;
	/* pad item (unknown type, skipped by the item walk): keeps the 0x51
	 * max-PDU u32 value at PDU offset 162 so the dicom.c:203 read at
	 * absolute 54+162 is 4-aligned — the misaligned variant is the
	 * pending-#210 case, armed in the phase0 harness only. */
	b[n++] = 0x60; b[n++] = 0x00; put_u16be(b + n, 1); n += 2;
	b[n++] = 0x00;
	b[n++] = (pdu_type == A_ASSOCIATE_RQ) ? 0x20 : 0x21;
	b[n++] = 0x00;
	put_u16be(b + n, 46); n += 2;
	b[n++] = 0x01; b[n++] = 0; b[n++] = 0; b[n++] = 0;
	b[n++] = 0x30; b[n++] = 0x00; put_u16be(b + n, 17); n += 2;
	memcpy(b + n, "1.2.840.10008.1.1", 17); n += 17;
	b[n++] = 0x40; b[n++] = 0x00; put_u16be(b + n, 17); n += 2;
	memcpy(b + n, "1.2.840.10008.1.2", 17); n += 17;
	b[n++] = 0x50; b[n++] = 0x00; put_u16be(b + n, 25); n += 2;
	b[n++] = 0x51; b[n++] = 0x00; put_u16be(b + n, 4); n += 2;
	b[n++] = 0x00; b[n++] = 0x00; b[n++] = 0x30; b[n++] = 0x00; /* 12288 */
	b[n++] = 0x52; b[n++] = 0x00; put_u16be(b + n, 13); n += 2;
	memcpy(b + n, "1.2.3.4.5.6.7", 13); n += 13;
	put_u16be(b + 4, n - 6); /* pdu_len low 16 bits @ bytes 4-5 */
	assoc_pdu_len = n;
}

/* P-DATA-TF: one PDV with flags 0x02 (dataset, bit0 clear) so the
 * patient-name path (which refuses command data) is reachable; the DIMSE
 * tag region carries every searched tag so all tag-scan cases hit.
 * pdu_len field = pdv hdr (6) + tags region. */
static unsigned char pdata_pdu[256];
static unsigned pdata_pdu_len;

static void build_pdata(void) {
	unsigned n = 0;
	static const unsigned char tags[] = {
		/* (0000,0000) group length, implicit VR: len4 + val4 = 88 */
		0x00,0x00,0x00,0x00, 0x04,0x00,0x00,0x00, 0x58,0x00,0x00,0x00,
		/* (0000,0002) affected SOP class UID: len 17 + "1.2.840.10008.5.1" */
		0x00,0x00,0x02,0x00, 0x11,0x00,0x00,0x00,
		'1','.','2','.','8','4','0','.','1','0','0','0','8','.','5','.','1',' ',
		/* (0000,0100) command field = C-ECHO-RQ 0x0030 */
		0x00,0x00,0x00,0x01, 0x02,0x00,0x00,0x00, 0x30,0x00,
		/* (0000,0110) message id = 7 */
		0x00,0x00,0x10,0x01, 0x02,0x00,0x00,0x00, 0x07,0x00,
		/* (0000,0800) data set type = 0x0101 */
		0x00,0x00,0x00,0x08, 0x02,0x00,0x00,0x00, 0x01,0x01,
		/* (0000,0900) status = 0 */
		0x00,0x00,0x00,0x09, 0x02,0x00,0x00,0x00, 0x00,0x00,
		/* (0010,0010) patient name "DOE^JOHN" implicit VR */
		0x10,0x00,0x10,0x00, 0x08,0x00,0x00,0x00,
		'D','O','E','^','J','O','H','N'
	};
	memset(pdata_pdu, 0, sizeof(pdata_pdu));
	pdata_pdu[n++] = P_DATA_TF;
	pdata_pdu[n++] = 0x00;
	n += 4; /* pdu_len filled below */
	/* PDV: length(4 BE) = 2 + sizeof(tags); ctx=1; flags=0x02 (dataset) */
	pdata_pdu[n++] = 0x00; pdata_pdu[n++] = 0x00; pdata_pdu[n++] = 0x00;
	pdata_pdu[n++] = (unsigned char)(2 + sizeof(tags));
	pdata_pdu[n++] = 0x01;
	pdata_pdu[n++] = 0x02;
	memcpy(pdata_pdu + n, tags, sizeof(tags));
	n += sizeof(tags);
	put_u16be(pdata_pdu + 4, n - 6); /* low 16 bits of pdu_len @ bytes 4-5 */
	pdata_pdu[2] = 0x00; pdata_pdu[3] = 0x00;
	pdata_pdu_len = n;
}

static void drive_extraction(struct test_pkt *t, uint32_t field_id,
		uint16_t position, void *data) {
	attribute_t attr;
	memset(&attr, 0, sizeof(attr));
	attr.proto_id = PROTO_DICOM;
	attr.field_id = field_id;
	attr.position_in_packet = position;
	attr.data = data;
	_extraction_att(&t->ipacket, DICOM_INDEX, &attr);
}

int main(void) {
	/* registration plumbing */
	CHECK(init_dicom_proto_struct() == 1, "init_dicom_proto_struct registers");
	{
		classified_proto_t cp = dicom_stack_classification(NULL);
		CHECK(cp.proto_id == PROTO_DICOM && cp.status == Classified,
				"dicom_stack_classification returns classified dicom");
	}

	/* header / payload validators */
	build_assoc(assoc_pdu, A_ASSOCIATE_RQ);
	build_pdata();
	CHECK(mmt_check_dicom_hdr((struct dicomhdr *)assoc_pdu) == 1,
			"valid hdr type accepted");
	{
		unsigned char bad[10] = {0x09, 0x00, 0x00, 0x00, 0x00, 0x44};
		CHECK(mmt_check_dicom_hdr((struct dicomhdr *)bad) == 0,
				"hdr type >7 refused");
		bad[0] = 0x00;
		CHECK(mmt_check_dicom_hdr((struct dicomhdr *)bad) == 0,
				"hdr type 0 refused");
	}
	CHECK(mmt_check_dicom_payload((struct dicomhdr *)assoc_pdu,
			assoc_pdu_len) == 1, "assoc payload accepted");
	CHECK(mmt_check_dicom_payload((struct dicomhdr *)assoc_pdu, 9) == 0,
			"packet_len < hdr+min refused");
	{
		unsigned char rj[10] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x04,
				0, 0, 0, 0};
		CHECK(mmt_check_dicom_payload((struct dicomhdr *)rj,
				sizeof(rj)) == 1, "A-ASSOCIATE-RJ len 4 accepted");
		rj[5] = 0x05;
		CHECK(mmt_check_dicom_payload((struct dicomhdr *)rj,
				sizeof(rj)) == 0, "A-ASSOCIATE-RJ len !=4 refused");
	}
	{
		unsigned char rel[10] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x04,
				0, 0, 0, 0};
		CHECK(mmt_check_dicom_payload((struct dicomhdr *)rel,
				sizeof(rel)) == 1, "A-RELEASE-RQ accepted");
		rel[0] = 0x06;
		CHECK(mmt_check_dicom_payload((struct dicomhdr *)rel,
				sizeof(rel)) == 1, "A-RELEASE-RP accepted");
		rel[0] = 0x07;
		CHECK(mmt_check_dicom_payload((struct dicomhdr *)rel,
				sizeof(rel)) == 1, "A-ABORT accepted");
	}
	CHECK(mmt_check_dicom_payload((struct dicomhdr *)pdata_pdu,
			pdata_pdu_len) == 1, "P-DATA-TF payload accepted");
	{
		unsigned char pd[10] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x05,
				0, 0, 0, 0};
		CHECK(mmt_check_dicom_payload((struct dicomhdr *)pd,
				sizeof(pd)) == 0, "P-DATA-TF pdu_len<6 refused");
	}
	{
		unsigned char bad[10] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x43,
				0, 0, 0, 0};
		CHECK(mmt_check_dicom_payload((struct dicomhdr *)bad,
				sizeof(bad)) == 0, "assoc pdu_len<68 refused");
	}
	CHECK(mmt_check_dicom((struct dicomhdr *)assoc_pdu, assoc_pdu_len) == 1,
			"mmt_check_dicom accepts assoc req");

	/* per-attribute extraction over association + P-DATA packets */
	{
		struct test_pkt *ta = pkt_with_pdu(assoc_pdu, assoc_pdu_len,
				DICOM_OFF + assoc_pdu_len);
		struct test_pkt *td = pkt_with_pdu(pdata_pdu, pdata_pdu_len,
				DICOM_OFF + pdata_pdu_len);
		uint8_t i8 = 0;
		uint16_t i16 = 0;
		uint32_t i32 = 0;
		mmt_binary_data_t blob;

		drive_extraction(ta, DICOM_PDU_TYPE, 0, &i8);
		CHECK(i8 == A_ASSOCIATE_RQ, "PDU_TYPE extracted");
		drive_extraction(ta, DICOM_PDU_LEN, 2, &i32);
		CHECK(i32 == assoc_pdu_len - 6, "PDU_LEN extracted");
		drive_extraction(ta, DICOM_PROTO_VERSION, 6, &i16);
		CHECK(i16 == 1, "PROTO_VERSION extracted");
		memset(&blob, 0, sizeof(blob));
		drive_extraction(ta, DICOM_CALLED_AE_TITLE, 10, &blob);
		CHECK(blob.len == 16 && memcmp(blob.data, "CALLED_AE", 9) == 0,
				"CALLED_AE extracted");
		memset(&blob, 0, sizeof(blob));
		drive_extraction(ta, DICOM_CALLING_AE_TITLE, 26, &blob);
		CHECK(blob.len == 16 && memcmp(blob.data, "CALLING_AE", 10) == 0,
				"CALLING_AE extracted");
		memset(&blob, 0, sizeof(blob));
		drive_extraction(ta, DICOM_APPLICATION_CONTEXT, 0, &blob);
		CHECK(blob.len == 21 && memcmp(blob.data, "1.2.840.10008.3.1.1.1",
				21) == 0, "APPLICATION_CONTEXT extracted");
		memset(&blob, 0, sizeof(blob));
		drive_extraction(ta, DICOM_PRESENTATION_CONTEXT, 0, &blob);
		CHECK(blob.len == 17 && memcmp(blob.data, "1.2.840.10008.1.1",
				17) == 0, "PRESENTATION_CONTEXT (abstract) extracted");
		i32 = 0;
		drive_extraction(ta, DICOM_MAX_PDU_LENGTH, 0, &i32);
		CHECK(i32 == 12288, "MAX_PDU_LENGTH extracted");
		memset(&blob, 0, sizeof(blob));
		drive_extraction(ta, DICOM_IMPLEMENTATION_CLASS_UID, 0, &blob);
		CHECK(blob.len == 13 && memcmp(blob.data, "1.2.3.4.5.6.7",
				13) == 0, "IMPLEMENTATION_CLASS_UID extracted");
		memset(&blob, 0, sizeof(blob));
		drive_extraction(ta, DICOM_ABSTRACT_SYNTAX, 0, &blob);
		CHECK(blob.len == 17, "ABSTRACT_SYNTAX extracted");
		memset(&blob, 0, sizeof(blob));
		drive_extraction(ta, DICOM_TRANSFER_SYNTAX, 0, &blob);
		CHECK(blob.len == 17 && memcmp(blob.data, "1.2.840.10008.1.2",
				17) == 0, "TRANSFER_SYNTAX extracted");

		i32 = 0;
		drive_extraction(td, DICOM_PDV_LENGTH, 6, &i32);
		CHECK(i32 > 0, "PDV_LENGTH extracted");
		i8 = 0;
		drive_extraction(td, DICOM_PDV_CONTEXT, 10, &i8);
		CHECK(i8 == 1, "PDV_CONTEXT extracted");
		i8 = 0;
		drive_extraction(td, DICOM_PDV_FLAGS, 11, &i8);
		CHECK(i8 == 2, "PDV_FLAGS extracted");
		i32 = 0;
		drive_extraction(td, DICOM_COMMAND_GROUP_LENGTH, 0, &i32);
		CHECK(i32 == 88, "COMMAND_GROUP_LENGTH extracted");
		i16 = 0;
		drive_extraction(td, DICOM_COMMAND_FIELD, 0, &i16);
		CHECK(i16 == DICOM_C_ECHO_RQ, "COMMAND_FIELD extracted");
		memset(&blob, 0, sizeof(blob));
		drive_extraction(td, DICOM_PATIENT_NAME, 0, &blob);
		CHECK(blob.len == 8 && memcmp(blob.data, "DOE^JOHN", 8) == 0,
				"PATIENT_NAME extracted");
		i16 = 0;
		drive_extraction(td, DICOM_STATUS, 0, &i16);
		CHECK(i16 == 0, "STATUS extracted");
		memset(&blob, 0, sizeof(blob));
		drive_extraction(td, DICOM_AFFECTED_SOP_CLASS_UID, 0, &blob);
		CHECK(blob.len == 17, "AFFECTED_SOP_CLASS_UID extracted");
		i16 = 0;
		drive_extraction(td, DICOM_MESSAGE_ID, 0, &i16);
		CHECK(i16 == 7, "MESSAGE_ID extracted");
		i16 = 0;
		drive_extraction(td, DICOM_DATA_SET_TYPE, 0, &i16);
		CHECK(i16 == 0x0101, "DATA_SET_TYPE extracted");

		/* A-ASSOCIATE-AC exercises the 0x21 presentation-context branch */
		{
			unsigned char ac[224];
			struct test_pkt *tc;
			memcpy(ac, assoc_pdu, assoc_pdu_len);
			build_assoc(ac, A_ASSOCIATE_AC);
			tc = pkt_with_pdu(ac, assoc_pdu_len, DICOM_OFF + assoc_pdu_len);
			i16 = 0;
			drive_extraction(tc, DICOM_PROTO_VERSION, 6, &i16);
			memset(&blob, 0, sizeof(blob));
			drive_extraction(tc, DICOM_PRESENTATION_CONTEXT, 0, &blob);
			drive_extraction(tc, DICOM_ABSTRACT_SYNTAX, 0, &blob);
			drive_extraction(tc, DICOM_TRANSFER_SYNTAX, 0, &blob);
			free_pkt(tc);
		}

		/* wrong-pdu-type negatives hit the else-return-0 branches */
		i16 = 0;
		drive_extraction(td, DICOM_PROTO_VERSION, 6, &i16);
		memset(&blob, 0, sizeof(blob));
		drive_extraction(td, DICOM_CALLED_AE_TITLE, 10, &blob);
		drive_extraction(td, DICOM_APPLICATION_CONTEXT, 0, &blob);
		drive_extraction(ta, DICOM_PDV_LENGTH, 6, &i32);
		drive_extraction(ta, DICOM_COMMAND_FIELD, 0, &i16);
		drive_extraction(ta, DICOM_PATIENT_NAME, 0, &blob);
		drive_extraction(ta, DICOM_DATA_SET_TYPE, 0, &i16);
		/* unknown field id -> default branch */
		drive_extraction(ta, 999, 0, &i32);

		/* truncated packets exercise every bounds guard */
		{
			struct test_pkt *tt = pkt_with_pdu(assoc_pdu, assoc_pdu_len,
					DICOM_OFF + 90);
			drive_extraction(tt, DICOM_APPLICATION_CONTEXT, 0, &blob);
			drive_extraction(tt, DICOM_PRESENTATION_CONTEXT, 0, &blob);
			drive_extraction(tt, DICOM_MAX_PDU_LENGTH, 0, &i32);
			drive_extraction(tt, DICOM_IMPLEMENTATION_CLASS_UID, 0, &blob);
			drive_extraction(tt, DICOM_ABSTRACT_SYNTAX, 0, &blob);
			drive_extraction(tt, DICOM_TRANSFER_SYNTAX, 0, &blob);
			free_pkt(tt);
		}
		{
			struct test_pkt *tt = pkt_with_pdu(assoc_pdu, assoc_pdu_len,
					DICOM_OFF + 80);
			drive_extraction(tt, DICOM_APPLICATION_CONTEXT, 0, &blob);
			free_pkt(tt);
		}
		{
			struct test_pkt *tt = pkt_with_pdu(pdata_pdu, pdata_pdu_len,
					DICOM_OFF + 30);
			drive_extraction(tt, DICOM_PDV_LENGTH, 6, &i32);
			drive_extraction(tt, DICOM_PDV_CONTEXT, 10, &i8);
			drive_extraction(tt, DICOM_PDV_FLAGS, 11, &i8);
			drive_extraction(tt, DICOM_COMMAND_GROUP_LENGTH, 0, &i32);
			drive_extraction(tt, DICOM_PATIENT_NAME, 0, &blob);
			drive_extraction(tt, DICOM_AFFECTED_SOP_CLASS_UID, 0, &blob);
			drive_extraction(tt, DICOM_MESSAGE_ID, 0, &i16);
			drive_extraction(tt, DICOM_DATA_SET_TYPE, 0, &i16);
			free_pkt(tt);
		}
		{
			/* caplen == dicom_offset: early return */
			struct test_pkt *tt = pkt_with_pdu(assoc_pdu, 0, DICOM_OFF);
			drive_extraction(tt, DICOM_PDU_TYPE, 0, &i8);
			free_pkt(tt);
		}
		{
			/* invalid pdu in the packet: mmt_check_dicom refuses */
			unsigned char inv[16] = {0x0f, 0, 0, 0, 0, 0x0a};
			struct test_pkt *tt = pkt_with_pdu(inv, sizeof(inv),
					DICOM_OFF + sizeof(inv));
			drive_extraction(tt, DICOM_PDU_TYPE, 0, &i8);
			free_pkt(tt);
		}
		/* command-data PDV (flags bit0 set): PATIENT_NAME refuses */
		{
			unsigned char pc[64];
			struct test_pkt *tt;
			memcpy(pc, pdata_pdu, 40);
			pc[11] = 0x03; /* flags: command */
			tt = pkt_with_pdu(pc, 40, DICOM_OFF + 40);
			memset(&blob, 0, sizeof(blob));
			drive_extraction(tt, DICOM_PATIENT_NAME, 0, &blob);
			CHECK(blob.len == 0, "PATIENT_NAME refuses command PDV");
			free_pkt(tt);
		}

		free_pkt(ta);
		free_pkt(td);
	}

	/* mmt_check_dicom_tcp over a fabricated TCP->DICOM packet.
	 * index is the TCP layer index; DICOM sits at index+1. */
	{
		struct test_pkt *t = pkt_with_pdu(assoc_pdu, assoc_pdu_len,
				DICOM_OFF + assoc_pdu_len);
		CHECK(mmt_check_dicom_tcp(&t->ipacket, 3) == 1,
				"mmt_check_dicom_tcp classifies valid assoc");
		free_pkt(t);
	}
	{
		struct test_pkt *t = pkt_with_pdu(pdata_pdu, pdata_pdu_len,
				DICOM_OFF + pdata_pdu_len);
		CHECK(mmt_check_dicom_tcp(&t->ipacket, 3) == 1,
				"mmt_check_dicom_tcp classifies P-DATA");
		free_pkt(t);
	}
	{
		unsigned char inv[16] = {0x0f, 0, 0, 0, 0, 0x0a};
		struct test_pkt *t = pkt_with_pdu(inv, sizeof(inv),
				DICOM_OFF + sizeof(inv));
		CHECK(mmt_check_dicom_tcp(&t->ipacket, 3) == 0,
				"mmt_check_dicom_tcp refuses bad type");
		free_pkt(t);
	}
	{
		/* dicom offset past caplen: refused (in-allocation garbage) */
		struct test_pkt *t = pkt_with_pdu(assoc_pdu, assoc_pdu_len,
				DICOM_OFF + assoc_pdu_len);
		t->proto_offset.proto_path[4] = 900;
		t->ipacket.p_hdr->caplen = 60;
		CHECK(mmt_check_dicom_tcp(&t->ipacket, 3) == 0,
				"mmt_check_dicom_tcp refuses out-of-caplen offset");
		free_pkt(t);
	}

#ifndef CORE
	CHECK(init_proto() == 1, "init_proto delegates to registration");
	CHECK(cleanup_proto() == 0, "cleanup_proto returns 0");
#endif

	printf("=== %d checks, %d failures ===\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
