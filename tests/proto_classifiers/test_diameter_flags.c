/*
 * test_diameter_flags.c — crafted-input regression test for the Diameter
 * command-flag extraction (issue #504, F-BUG-202).
 *
 * The Diameter header's flags byte is R P E T r r r r, most significant bit
 * first (RFC 6733 §3). struct diameter_header used to declare one bitfield
 * per flag in wire order; GCC allocates bitfields LSB-first on little-endian
 * hosts, so flag_r/p/e/t read the four reserved bits. A CER (flags 0x80)
 * reported R=0 and an error answer (flags 0x20) reported E=0. The extractor
 * now decodes the byte with masks; reverting to the bitfields fails the
 * R/E/P/T checks below.
 *
 * proto_diameter.c is included directly so the static extractor is reachable
 * and gcov attributes the exercised lines to the real file; the mmt_core
 * helpers it references are stubbed (same convention as the other tests in
 * this suite).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/mmt_mobile/proto_diameter.c"

static int checks;
static int failures;
#define CHECK(cond, msg) do { \
		checks++; \
		if (!(cond)) { \
			failures++; \
			fprintf(stderr, "FAIL %d: %s\n", __LINE__, msg); \
		} \
	} while (0)

/* ---- stubs for the mmt_core helpers proto_diameter.c references ---- */

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
	free(protocol_struct);
	return 1;
}

bool register_classification_function_with_parent_protocol(uint32_t proto_id,
		generic_classification_function classification_fct, int weight) {
	(void) proto_id;
	(void) classification_fct;
	(void) weight;
	return 1;
}

unsigned get_protocol_index_by_id(const ipacket_t *ipacket, uint32_t proto_id) {
	(void) ipacket;
	(void) proto_id;
	return (unsigned) -1;
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

uint32_t get_attr_protocol_id(attribute_t *attr) {
	return attr ? attr->proto_id : 0;
}

int set_classified_proto(ipacket_t *ipacket, unsigned index,
		classified_proto_t classified_proto) {
	(void) ipacket;
	(void) index;
	(void) classified_proto;
	return 0;
}

/* ---- packet fixture: a Diameter header at offset 0 ---- */

struct test_pkt {
	ipacket_t ipacket;
	proto_hierarchy_t proto_offset;
	pkthdr_t pcap_hdr;
	unsigned char buffer[64];
};

/* Fabricate a 20-byte Diameter header: version 1, message length 20, the
 * given flags byte and command code, application id 0, fixed hop-by-hop and
 * end-to-end identifiers. */
static void pkt_diameter(struct test_pkt *t, uint8_t flags,
		uint32_t command_code, unsigned caplen) {
	static const unsigned char tail[12] = {
		0x00, 0x00, 0x00, 0x00, /* application id */
		0x11, 0x22, 0x33, 0x44, /* hop-by-hop id */
		0x55, 0x66, 0x77, 0x88, /* end-to-end id */
	};
	memset(t, 0, sizeof(*t));
	t->buffer[0] = 1;               /* version */
	t->buffer[1] = 0x00;            /* message length = 20 */
	t->buffer[2] = 0x00;
	t->buffer[3] = 20;
	t->buffer[4] = flags;           /* R P E T r r r r */
	t->buffer[5] = (uint8_t) (command_code >> 16);
	t->buffer[6] = (uint8_t) (command_code >> 8);
	t->buffer[7] = (uint8_t) command_code;
	memcpy(&t->buffer[8], tail, sizeof(tail));
	t->proto_offset.proto_path[0] = 0;
	t->proto_offset.len = 1;
	t->ipacket.proto_headers_offset = &t->proto_offset;
	t->ipacket.data = t->buffer;
	t->ipacket.p_hdr = &t->pcap_hdr;
	t->ipacket.p_hdr->caplen = caplen;
}

/* Extract one attribute; returns the extractor's verdict, value in *out. */
static int extract(struct test_pkt *t, unsigned field_id, uint32_t *out) {
	uint32_t value = 0xdeadbeef;
	attribute_t attr;
	memset(&attr, 0, sizeof(attr));
	attr.proto_id = PROTO_DIAMETER;
	attr.field_id = field_id;
	attr.data = &value;
	int ret = _extraction_att(&t->ipacket, 0, &attr);
	*out = value;
	return ret;
}

/* Extract a 1-byte flag attribute (MMT_U8_DATA). */
static int flag(struct test_pkt *t, unsigned field_id) {
	uint8_t value = 0xff;
	attribute_t attr;
	memset(&attr, 0, sizeof(attr));
	attr.proto_id = PROTO_DIAMETER;
	attr.field_id = field_id;
	attr.data = &value;
	if (_extraction_att(&t->ipacket, 0, &attr) != 1)
		return -1;
	return value;
}

int main(void) {
	struct test_pkt t;
	uint32_t v;

	printf("=== Diameter command-flag test (issue #504) ===\n");

	CHECK(sizeof(struct diameter_header) == 20,
			"diameter_header is the 20-byte wire header");

	/* CER: Capabilities-Exchange-Request, flags 0x80 (R only). */
	pkt_diameter(&t, 0x80, 257, 20);
	CHECK(flag(&t, DIAMETER_FLAG_R) == 1, "CER (flags 0x80) reports R=1");
	CHECK(flag(&t, DIAMETER_FLAG_P) == 0, "CER reports P=0");
	CHECK(flag(&t, DIAMETER_FLAG_E) == 0, "CER reports E=0");
	CHECK(flag(&t, DIAMETER_FLAG_T) == 0, "CER reports T=0");
	/* The fields around the flags byte decode unchanged. */
	CHECK(flag(&t, DIAMETER_VERSION) == 1, "version is 1");
	CHECK(extract(&t, DIAMETER_MESSAGE_LENGTH, &v) == 1 && v == 20,
			"message length is 20");
	CHECK(extract(&t, DIAMETER_COMMAND_CODE, &v) == 1 && v == 257,
			"command code is 257 (CER)");
	CHECK(extract(&t, DIAMETER_HOP_TO_HOP_ID, &v) == 1 && v == 0x11223344,
			"hop-by-hop id decodes");
	CHECK(extract(&t, DIAMETER_END_TO_END_ID, &v) == 1 && v == 0x55667788,
			"end-to-end id decodes");

	/* Error answer: R clear, E set (flags 0x20). */
	pkt_diameter(&t, 0x20, 257, 20);
	CHECK(flag(&t, DIAMETER_FLAG_E) == 1, "answer with E set reports E=1");
	CHECK(flag(&t, DIAMETER_FLAG_R) == 0, "answer reports R=0");

	/* Proxiable and re-transmitted bits map to P and T. */
	pkt_diameter(&t, 0x40, 316, 20);
	CHECK(flag(&t, DIAMETER_FLAG_P) == 1, "flags 0x40 reports P=1");
	CHECK(flag(&t, DIAMETER_FLAG_R) == 0, "flags 0x40 reports R=0");
	pkt_diameter(&t, 0x10, 316, 20);
	CHECK(flag(&t, DIAMETER_FLAG_T) == 1, "flags 0x10 reports T=1");
	CHECK(flag(&t, DIAMETER_FLAG_E) == 0, "flags 0x10 reports E=0");

	/* All four flags at once (0xF0). */
	pkt_diameter(&t, 0xF0, 272, 20);
	CHECK(flag(&t, DIAMETER_FLAG_R) == 1 && flag(&t, DIAMETER_FLAG_P) == 1
			&& flag(&t, DIAMETER_FLAG_E) == 1 && flag(&t, DIAMETER_FLAG_T) == 1,
			"flags 0xF0 reports R=P=E=T=1");

	/* Only the reserved bits set (0x0F): no flag may read them — this is
	 * exactly what the wire-order bitfields used to report. */
	pkt_diameter(&t, 0x0F, 272, 20);
	CHECK(flag(&t, DIAMETER_FLAG_R) == 0 && flag(&t, DIAMETER_FLAG_P) == 0
			&& flag(&t, DIAMETER_FLAG_E) == 0 && flag(&t, DIAMETER_FLAG_T) == 0,
			"reserved bits (0x0F) report no flag");

	/* A capture shorter than the 20-byte header extracts nothing. */
	pkt_diameter(&t, 0x80, 257, 19);
	CHECK(flag(&t, DIAMETER_FLAG_R) == -1,
			"19-byte capture is too short to extract");

	printf("=== %d checks, %d failures ===\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
