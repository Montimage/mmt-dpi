/*
 * Coverage driver for the NDN dissector
 * (src/mmt_tcpip/lib/protocols/ndn.c), issue #215.
 *
 * The dissector source is included directly so that gcov attributes the
 * exercised lines to the real file. mmt_core helpers it calls are stubbed
 * with compatible signatures (packet offsets, protocol-id lookup, attribute
 * events); memory.c and mmt_utils.c are compiled alongside so the real
 * mmt_malloc()/str_* helpers run. All parsing logic under test is real.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "packet_processing.h" /* mmt_handler_struct, protocol_instance_t */

#include "../../src/mmt_tcpip/lib/protocols/ndn.c"

static int checks;
static int failures;
#define CHECK(cond, msg) do { \
		checks++; \
		if (!(cond)) { \
			failures++; \
			fprintf(stderr, "FAIL %d: %s\n", __LINE__, msg); \
		} \
	} while (0)

/* ---- stubs for mmt_core symbols ndn.c references ---- */

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

uint32_t get_protocol_id_at_index(const ipacket_t *ipacket, unsigned index) {
	if (!ipacket || !ipacket->proto_hierarchy
			|| index >= (unsigned) ipacket->proto_hierarchy->len)
		return (uint32_t) -1;
	return (uint32_t) ipacket->proto_hierarchy->proto_path[index];
}

void fire_attribute_event(ipacket_t *ipacket, uint32_t proto_id,
		uint32_t attribute_id, unsigned index, void *data) {
	(void) ipacket;
	(void) proto_id;
	(void) attribute_id;
	(void) index;
	(void) data;
}

/* ---- helpers ---- */

/* Heap buffer holding exactly `len` payload bytes plus a trailing NUL: the
 * extra byte bounds str_sub()'s strlen() scan inside ndn_TLV_get_string. */
static char *dup_payload(const uint8_t *src, int len) {
	char *p = malloc(len + 1);
	memcpy(p, src, len);
	p[len] = '\0';
	return p;
}

static void put_u16be(uint8_t *p, uint16_t v) {
	p[0] = v >> 8;
	p[1] = v & 0xff;
}
static void put_u32be(uint8_t *p, uint32_t v) {
	p[0] = v >> 24;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >> 8) & 0xff;
	p[3] = v & 0xff;
}

/* ---- TLV type gate + parser length forms ---- */

static void test_tlv_basics(void) {
	CHECK(ndn_TLV_check_type(1) == 1, "type 1 accepted");
	CHECK(ndn_TLV_check_type(4) == 0, "type 4 rejected");
	CHECK(ndn_TLV_check_type(5) == 1, "type 5 accepted");
	CHECK(ndn_TLV_check_type(11) == 0, "type 11 rejected");
	CHECK(ndn_TLV_check_type(29) == 1, "type 29 accepted");
	CHECK(ndn_TLV_check_type(30) == 0, "type 30 rejected");
	CHECK(ndn_TLV_check_type(0) == 0, "type 0 rejected");
	CHECK(ndn_TLV_check_type(-1) == 0, "negative type rejected");

	/* 1-octet length form */
	{
		uint8_t wire[] = { 0x05, 0x03, 0x07, 0x01, 0x08 };
		char *p = dup_payload(wire, sizeof(wire));
		ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
		CHECK(n && n->type == 5 && n->length == 3 && n->data_offset == 2
				&& n->nb_octets == 0, "1-octet length form parses");
		ndn_TLV_free(n);
		free(p);
	}
	/* 0xfd 2-octet length */
	{
		uint8_t wire[260];
		memset(wire, 0, sizeof(wire));
		wire[0] = 0x05; wire[1] = 0xfd; put_u16be(wire + 2, 256);
		char *p = dup_payload(wire, sizeof(wire));
		ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
		CHECK(n && n->length == 256 && n->nb_octets == 2
				&& n->data_offset == 4, "0xfd length form parses");
		ndn_TLV_free(n);
		free(p);
	}
	{
		uint8_t wire[8];
		memset(wire, 0, sizeof(wire));
		wire[0] = 0x05; wire[1] = 0xfd; put_u16be(wire + 2, 256);
		char *p = dup_payload(wire, sizeof(wire));
		CHECK(ndn_TLV_parser(p, 0, sizeof(wire)) == NULL,
				"0xfd length overrun -> NULL");
		free(p);
	}
	/* 0xfe 4-octet length */
	{
		uint8_t wire[9];
		memset(wire, 0, sizeof(wire));
		wire[0] = 0x05; wire[1] = 0xfe; put_u32be(wire + 2, 3);
		wire[6] = 0x07; wire[7] = 0x01; wire[8] = 0x08;
		char *p = dup_payload(wire, sizeof(wire));
		ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
		CHECK(n && n->length == 3 && n->nb_octets == 4
				&& n->data_offset == 6, "0xfe length form parses");
		ndn_TLV_free(n);
		free(p);
	}
	{
		uint8_t wire[9];
		memset(wire, 0, sizeof(wire));
		wire[0] = 0x05; wire[1] = 0xfe; put_u32be(wire + 2, 0x00010000);
		char *p = dup_payload(wire, sizeof(wire));
		CHECK(ndn_TLV_parser(p, 0, sizeof(wire)) == NULL,
				"0xfe length overrun -> NULL");
		free(p);
	}
	/* 0xff 8-octet length */
	{
		uint8_t wire[13];
		memset(wire, 0, sizeof(wire));
		wire[0] = 0x05; wire[1] = 0xff;
		put_u32be(wire + 2, 0); put_u32be(wire + 6, 3);
		wire[10] = 0x07; wire[11] = 0x01; wire[12] = 0x08;
		char *p = dup_payload(wire, sizeof(wire));
		ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
		CHECK(n && n->length == 3 && n->nb_octets == 8
				&& n->data_offset == 10, "0xff length form parses");
		ndn_TLV_free(n);
		free(p);
	}
	/* zero-length node at exact end parses; not-at-end refused */
	{
		uint8_t wire[] = { 0x05, 0x00 };
		char *p = dup_payload(wire, sizeof(wire));
		ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
		CHECK(n && n->length == 0, "zero-length node at end parses");
		ndn_TLV_free(n);
		free(p);
	}
	{
		uint8_t wire[] = { 0x05, 0x00, 0xAA };
		char *p = dup_payload(wire, sizeof(wire));
		CHECK(ndn_TLV_parser(p, 0, sizeof(wire)) == NULL,
				"zero-length node not at end -> NULL");
		free(p);
	}
	{
		uint8_t wire[] = { 0x03, 0x01, 0x00 };
		char *p = dup_payload(wire, sizeof(wire));
		CHECK(ndn_TLV_parser(p, 0, sizeof(wire)) == NULL,
				"invalid type -> NULL");
		free(p);
	}
	{
		uint8_t wire[] = { 0x05, 0x10, 0x07 };
		char *p = dup_payload(wire, sizeof(wire));
		CHECK(ndn_TLV_parser(p, 0, sizeof(wire)) == NULL,
				"declared len over captured -> NULL");
		free(p);
	}
	CHECK(ndn_TLV_parser(NULL, 0, 10) == NULL, "NULL payload -> NULL");

	/* get_int / get_string bounds */
	{
		uint8_t wire[] = { 0x05, 0x03, 0x07, 0x01, 0x08 };
		char *p = dup_payload(wire, sizeof(wire));
		ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
		char *s = ndn_TLV_get_string(n, p, sizeof(wire));
		CHECK(s != NULL, "get_string in-bounds returns value");
		free(s);
		ndn_tlv_t evil = { 0 };
		evil.type = 5; evil.data_offset = 2; evil.length = 64;
		CHECK(ndn_TLV_get_int(&evil, p, sizeof(wire)) == -1,
				"get_int overrun node -> -1");
		CHECK(ndn_TLV_get_string(&evil, p, sizeof(wire)) == NULL,
				"get_string overrun node -> NULL");
		CHECK(ndn_TLV_get_int(NULL, p, sizeof(wire)) == -1,
				"get_int NULL node -> -1");
		CHECK(ndn_TLV_get_string(NULL, p, sizeof(wire)) == NULL,
				"get_string NULL node -> NULL");
		CHECK(ndn_TLV_get_int(n, NULL, sizeof(wire)) == -1,
				"get_int NULL payload -> -1");
		ndn_TLV_free(n);
		free(p);
	}

	/* TLV_init */
	{
		ndn_tlv_t *n = ndn_TLV_init();
		CHECK(n && n->type == 0 && n->next == NULL, "TLV_init zeroed");
		ndn_TLV_free(n);
	}
}

/* ---- classifier ---- */

static void test_check_payload(void) {
	char b1[2] = { 0x05, 0x00 };
	CHECK(mmt_check_ndn_payload(b1, 2) == 0, "len < 3 rejected");
	char b2[4] = { 0x04, 0x02, 0x07, 0x00 };
	CHECK(mmt_check_ndn_payload(b2, 4) == 0, "first byte not 5/6 rejected");
	char b3[10] = { 0x05, 0x08, 0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't' };
	CHECK(mmt_check_ndn_payload(b3, 10) == 1, "well-formed Interest accepted");
	char b4[10] = { 0x06, 0x08, 0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't' };
	CHECK(mmt_check_ndn_payload(b4, 10) == 1, "well-formed Data accepted");
	char b5[11] = { 0x05, 0x08, 0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't', 0 };
	CHECK(mmt_check_ndn_payload(b5, 11) == 0, "len mismatch rejected");
	char b6[10] = { 0x05, 0x08, 0x09, 0x06, 0x08, 0x04, 't', 'e', 's', 't' };
	CHECK(mmt_check_ndn_payload(b6, 10) == 0, "missing Name rejected");
}

/* ---- find_node + name components + recursion ---- */

static void test_find_and_names(void) {
	uint8_t wire[] = {
		0x05, 0x0E,
		0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
		0x0A, 0x04, 0x01, 0x02, 0x03, 0x04
	};
	char *p = dup_payload(wire, sizeof(wire));
	ndn_tlv_t *root = ndn_TLV_parser(p, 0, sizeof(wire));
	CHECK(root && root->type == 5, "interest root parses");
	ndn_tlv_t *nonce = ndn_find_node(p, sizeof(wire), root, NDN_INTEREST_NONCE);
	CHECK(nonce && nonce->type == NDN_INTEREST_NONCE && nonce->length == 4,
			"find_node locates Nonce");
	CHECK(ndn_TLV_get_int(nonce, p, sizeof(wire)) == 0x01020304,
			"nonce decodes big-endian");
	ndn_TLV_free(nonce);
	CHECK(ndn_find_node(p, sizeof(wire), root, NDN_INTEREST_LIFETIME) == NULL,
			"absent node -> NULL");
	CHECK(ndn_find_node(p, sizeof(wire), NULL, NDN_INTEREST_NONCE) == NULL,
			"NULL root -> NULL");
	CHECK(ndn_find_node(NULL, sizeof(wire), root, NDN_INTEREST_NONCE) == NULL,
			"NULL payload -> NULL");
	ndn_TLV_free(root);
	free(p);

	/* name components */
	uint8_t nw[] = {
		0x05, 0x10,
		0x07, 0x0E,
		0x08, 0x04, 't', 'e', 's', 't',
		0x08, 0x03, 'a', 'b', 'c',
		0x08, 0x01, 'x'
	};
	char *np = dup_payload(nw, sizeof(nw));
	char *c0 = ndn_name_components_at_index(np, sizeof(nw), 0);
	char *c1 = ndn_name_components_at_index(np, sizeof(nw), 1);
	char *c2 = ndn_name_components_at_index(np, sizeof(nw), 2);
	CHECK(c0 && c1 && c2, "components 0-2 present");
	CHECK(ndn_name_components_at_index(np, sizeof(nw), 9) == NULL,
			"out-of-range component -> NULL");
	free(c0); free(c1); free(c2);
	char *all = ndn_name_components_extraction_payload(np, sizeof(nw));
	CHECK(all != NULL, "joined name components present");
	free(all);
	free(np);

	/* deep chain: 200 components inside one Name — recursion in
	 * ndn_TLV_parser_name_comp() and in ndn_TLV_free() on ->next. */
	{
		enum { DEPTH = 200 };
		int name_len = DEPTH * 3;
		int total = 8 + name_len;
		uint8_t *deep = malloc(total);
		int n = 0, i;
		deep[n++] = 0x05; deep[n++] = 0xfd;
		put_u16be(deep + n, (uint16_t)(4 + name_len)); n += 2;
		deep[n++] = 0x07; deep[n++] = 0xfd;
		put_u16be(deep + n, (uint16_t)name_len); n += 2;
		for (i = 0; i < DEPTH; i++) {
			deep[n++] = 0x08; deep[n++] = 0x01; deep[n++] = 'c';
		}
		char *dp = dup_payload(deep, n);
		free(deep);
		ndn_tlv_t *chain = ndn_TLV_parser_name_comp(dp, n, 8, name_len);
		CHECK(chain != NULL, "200-deep chain parses");
		{
			int counted = 0;
			ndn_tlv_t *t;
			for (t = chain; t; t = t->next) counted++;
			CHECK(counted == DEPTH, "chain holds all components");
		}
		ndn_TLV_free(chain);
		free(dp);
	}
}

/* ---- *_extraction_payload functions ---- */

static void test_extraction_payloads(void) {
	uint8_t interest[] = {
		0x05, 0x1A,
		0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
		0x0A, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x0C, 0x02, 0x03, 0xE8,
		0x09, 0x06,
		0x0D, 0x01, 0x02,
		0x0E, 0x01, 0x05
	};
	char *ip = dup_payload(interest, sizeof(interest));
	CHECK(ndn_packet_length_extraction_payload(ip, sizeof(interest)) == 26,
			"packet_length = 26");
	CHECK(ndn_interest_nonce_extraction_payload(ip, sizeof(interest))
			== 0x01020304, "nonce = 0x01020304");
	CHECK(ndn_interest_lifetime_extraction_payload(ip, sizeof(interest))
			== 1000, "lifetime = 1000");
	CHECK(ndn_interest_min_suffix_component_extraction_payload(ip,
			sizeof(interest)) == 2, "min suffix = 2");
	CHECK(ndn_interest_max_suffix_component_extraction_payload(ip,
			sizeof(interest)) == 5, "max suffix = 5");
	free(ip);

	uint8_t bare[] = { 0x05, 0x08, 0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't' };
	char *ib = dup_payload(bare, sizeof(bare));
	CHECK(ndn_interest_nonce_extraction_payload(ib, sizeof(bare)) == -1,
			"absent nonce -> -1");
	CHECK(ndn_interest_lifetime_extraction_payload(ib, sizeof(bare)) == -1,
			"absent lifetime -> -1");
	CHECK(ndn_interest_min_suffix_component_extraction_payload(ib,
			sizeof(bare)) == -1, "absent min suffix -> -1");
	CHECK(ndn_interest_max_suffix_component_extraction_payload(ib,
			sizeof(bare)) == -1, "absent max suffix -> -1");
	free(ib);

	/* Data packet: MetaInfo{ContentType,Freshness,FinalBlock} + SigInfo */
	uint8_t data[] = {
		0x06, 0x1B,
		0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
		0x14, 0x0C,
		0x18, 0x01, 0x00,
		0x19, 0x02, 0x13, 0x88,
		0x1A, 0x03, 'a', 'b', 'c',
		0x16, 0x03, 0x1B, 0x01, 0x01
	};
	char *dp = dup_payload(data, sizeof(data));
	CHECK(ndn_data_content_type_extraction_payload(dp, sizeof(data)) == 0,
			"content type = BLOB");
	CHECK(ndn_data_freshness_period_extraction_payload(dp, sizeof(data))
			== 5000, "freshness = 5000");
	CHECK(ndn_data_signature_type_extraction_payload(dp, sizeof(data)) == 1,
			"sig type = Sha256WithRsa");
	free(dp);

	/* NUL-free data packet for the string-based extractors */
	uint8_t data_c[] = {
		0x06, 0x0E,
		0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
		0x15, 0x04, 'D', 'A', 'T', 'A'
	};
	char *dcp = dup_payload(data_c, sizeof(data_c));
	char *content = ndn_data_content_extraction_payload(dcp, sizeof(data_c));
	CHECK(content && memcmp(content, "DATA", 4) == 0, "content = 'DATA'");
	free(content);
	free(dcp);

	/* key-locator + signature-value data packet (string paths) */
	uint8_t data_k[] = {
		0x06, 0x1E,
		0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
		0x16, 0x10,                          /* SigInfo len 16 */
		0x1B, 0x01, 0x01,                    /* SigType */
		0x1C, 0x0B,                          /* KeyLocator len 11 */
		0x07, 0x09, 0x08, 0x07, 'k', 'e', 'y', 'n', 'a', 'm', 'e',
		0x17, 0x04, 'S', 'I', 'G', 'V'       /* SignatureValue */
	};
	char *dkp = dup_payload(data_k, sizeof(data_k));
	char *kl = ndn_data_key_locator_extraction_payload(dkp, sizeof(data_k));
	if (kl) free(kl);
	char *sv = ndn_data_signature_value_extraction_payload(dkp, sizeof(data_k));
	if (sv) free(sv);
	free(dkp);
	CHECK(1, "key-locator/sig-value paths ran");

	/* selectors variants: child-selector + must-be-fresh + any
	 * Interest value = Name(8) + Nonce(6) + Selectors(2+7) = 23 */
	uint8_t sel[] = {
		0x05, 0x17,
		0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
		0x0A, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x09, 0x07,
		0x11, 0x01, 0x01,                    /* ChildSelector = 1 */
		0x12, 0x00,                          /* MustBeFresh */
		0x13, 0x00                           /* Any */
	};
	char *sp = dup_payload(sel, sizeof(sel));
	{
		attribute_t a; int v = 0;
		/* payload-level probes exist only for some; exercise the parser path */
		ndn_tlv_t *r = ndn_TLV_parser(sp, 0, sizeof(sel));
		ndn_tlv_t *sn = r ? ndn_find_node(sp, sizeof(sel), r, 9) : NULL;
		CHECK(sn != NULL, "selectors node found");
		if (sn) ndn_TLV_free(sn);
		if (r) ndn_TLV_free(r);
		(void) a; (void) v;
	}
	free(sp);

	/* NDN-over-HTTP */
	{
		uint8_t http_name[] = {
			0x05, 0x10,
			0x07, 0x0E,
			0x08, 0x03, 'r', 'e', 'q',
			0x08, 0x07, 'G', 'E', 'T', ' ', '/', ' ', ' '
		};
		char *hn = dup_payload(http_name, sizeof(http_name));
		CHECK(mmt_check_payload_ndn_http(hn, sizeof(http_name)) == 1
				|| mmt_check_payload_ndn_http(hn, sizeof(http_name)) == 0,
				"ndn_http verdict returns");
		free(hn);
	}
	CHECK(mmt_check_payload_ndn_http(NULL, 10) == 0, "ndn_http NULL -> 0");
	CHECK(mmt_check_payload_ndn_http((char *)"", 0) == 0,
			"ndn_http len<=0 -> 0");
	CHECK(is_supported_method("GET") == 1, "GET supported");
	CHECK(is_supported_method("BOGUS") == 0, "BOGUS refused");
}

/* ---- ipacket-typed *_extraction ---- */

typedef struct {
	ipacket_t pkt;
	proto_hierarchy_t offsets;
	proto_hierarchy_t hier;
	pkthdr_t hdr;
	mmt_tcpip_internal_packet_t internal;
	mmt_handler_t *hdlr;
	uint8_t *buf;
} ndn_fixture_t;

static void fixture_init(ndn_fixture_t *f, const int *layer_sizes,
		const int *layer_protos, int nlayers, const uint8_t *payload,
		unsigned caplen) {
	int i;
	memset(f, 0, sizeof(*f));
	/* +1 NUL backstop: str_sub() strlen()s the payload past the component
	 * window — same latent over-read the phase0 harness documents. */
	f->buf = malloc(caplen + 1);
	memset(f->buf, 0, caplen + 1);
	if (payload) memcpy(f->buf, payload, caplen);
	f->hdlr = calloc(1, sizeof(mmt_handler_t));
	for (i = 0; i < nlayers && i < PROTO_PATH_SIZE; i++) {
		f->offsets.proto_path[i] = layer_sizes[i];
		f->hier.proto_path[i] = layer_protos ? layer_protos[i] : 1;
	}
	f->offsets.len = f->hier.len = nlayers;
	f->hdr.caplen = caplen;
	f->hdr.len = caplen;
	f->pkt.p_hdr = &f->hdr;
	f->pkt.data = f->buf;
	f->pkt.proto_headers_offset = &f->offsets;
	f->pkt.proto_hierarchy = &f->hier;
	f->pkt.internal_packet = &f->internal;
	f->pkt.mmt_handler = f->hdlr;
}

static void fixture_free(ndn_fixture_t *f) {
	free(f->buf);
	free(f->hdlr);
}

static void test_ipacket_extraction(void) {
	uint8_t interest[] = {
		0x05, 0x0E,
		0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
		0x0A, 0x04, 0x01, 0x02, 0x03, 0x04
	};
	uint8_t frame[14 + sizeof(interest)];
	int layers[3] = { 0, 0, 14 };
	int protos[3] = { 1, 99, PROTO_NDN };
	ndn_fixture_t f;
	attribute_t attr;
	uint8_t u8v;
	uint32_t u32v;
	int iv;

	memset(frame, 0, 14);
	memcpy(frame + 14, interest, sizeof(interest));

	/* proto_index == 2: NDN over Ethernet, payload_len = caplen - offset */
	fixture_init(&f, layers, protos, 3, frame, sizeof(frame));
	memset(&attr, 0, sizeof(attr)); attr.data = &u8v; u8v = 0;
	CHECK(ndn_packet_type_extraction(&f.pkt, 2, &attr) == 1 && u8v == 5,
			"packet_type = Interest(5)");
	memset(&attr, 0, sizeof(attr)); attr.data = &u32v; u32v = 0;
	CHECK(ndn_packet_length_extraction(&f.pkt, 2, &attr) == 1 && u32v == 14,
			"packet_length = 14");
	memset(&attr, 0, sizeof(attr)); attr.data = &iv; iv = 0;
	CHECK(ndn_interest_nonce_extraction(&f.pkt, 2, &attr) == 1
			&& iv == 0x01020304, "nonce extracted via ipacket");
	memset(&attr, 0, sizeof(attr)); attr.data = &iv; iv = 0;
	CHECK(ndn_interest_lifetime_extraction(&f.pkt, 2, &attr) == 0,
			"absent lifetime via ipacket -> 0");
	memset(&attr, 0, sizeof(attr)); attr.data = NULL;
	CHECK(ndn_name_components_extraction(&f.pkt, 2, &attr) == 1
			&& attr.data != NULL, "name components extracted");
	free(attr.data);
	memset(&attr, 0, sizeof(attr)); attr.data = &iv;
	CHECK(ndn_interest_min_suffix_component_extraction(&f.pkt, 2, &attr) == 0,
			"absent min-suffix via ipacket -> 0");
	memset(&attr, 0, sizeof(attr)); attr.data = &iv;
	CHECK(ndn_interest_max_suffix_component_extraction(&f.pkt, 2, &attr) == 0,
			"absent max-suffix via ipacket -> 0");
	memset(&attr, 0, sizeof(attr)); attr.data = &iv;
	ndn_interest_publisher_publickey_locator_extraction(&f.pkt, 2, &attr);
	ndn_interest_exclude_extraction(&f.pkt, 2, &attr);
	ndn_interest_child_selector_extraction(&f.pkt, 2, &attr);
	ndn_interest_must_be_fresh_extraction(&f.pkt, 2, &attr);
	ndn_interest_any_extraction(&f.pkt, 2, &attr);
	memset(&attr, 0, sizeof(attr)); attr.data = &iv;
	ndn_data_content_type_extraction(&f.pkt, 2, &attr);
	ndn_data_freshness_period_extraction(&f.pkt, 2, &attr);
	ndn_data_final_block_id_extraction(&f.pkt, 2, &attr);
	ndn_data_signature_type_extraction(&f.pkt, 2, &attr);
	memset(&attr, 0, sizeof(attr)); attr.data = NULL;
	ndn_data_content_extraction(&f.pkt, 2, &attr);
	free(attr.data);
	memset(&attr, 0, sizeof(attr)); attr.data = NULL;
	ndn_data_key_locator_extraction(&f.pkt, 2, &attr);
	free(attr.data);
	memset(&attr, 0, sizeof(attr)); attr.data = NULL;
	ndn_data_signature_value_extraction(&f.pkt, 2, &attr);
	free(attr.data);
	fixture_free(&f);

	/* proto_index != 2: NDN over TCP, payload_len from internal_packet */
	{
		uint8_t tcpbuf[80];
		int tlayers[5] = { 0, 0, 14, 20, 20 };
		int tprotos[5] = { 1, 99, 178, 354, PROTO_NDN };
		memset(tcpbuf, 0, sizeof(tcpbuf));
		memcpy(tcpbuf + 54, interest, sizeof(interest));
		fixture_init(&f, tlayers, tprotos, 5, tcpbuf, sizeof(tcpbuf));
		f.internal.payload_packet_len = sizeof(interest);
		memset(&attr, 0, sizeof(attr)); attr.data = &u8v; u8v = 0;
		CHECK(ndn_packet_type_extraction(&f.pkt, 4, &attr) == 1 && u8v == 5,
				"packet_type over TCP path = Interest(5)");
		memset(&attr, 0, sizeof(attr)); attr.data = &u32v; u32v = 0;
		CHECK(ndn_packet_length_extraction(&f.pkt, 4, &attr) == 1,
				"packet_length over TCP path");
		fixture_free(&f);
	}

	/* offset > caplen: refused before data[offset] is dereferenced */
	{
		int deep_layers[3] = { 0, 0, 4000 };
		fixture_init(&f, deep_layers, protos, 3, frame, sizeof(frame));
		memset(&attr, 0, sizeof(attr)); attr.data = &u8v; u8v = 0;
		CHECK(ndn_packet_type_extraction(&f.pkt, 2, &attr) == 0,
				"packet_type offset>caplen refused");
		memset(&attr, 0, sizeof(attr)); attr.data = &u32v; u32v = 0;
		CHECK(ndn_packet_length_extraction(&f.pkt, 2, &attr) == 0,
				"packet_length offset>caplen refused");
		memset(&attr, 0, sizeof(attr)); attr.data = NULL;
		CHECK(ndn_name_components_extraction(&f.pkt, 2, &attr) == 0,
				"name_components offset>caplen refused");
		fixture_free(&f);
	}
}

/* ---- sessions: tuple3, list, analysis, timed-out, cleanup ---- */

static void test_sessions(void) {
	/* pure allocation/compare paths */
	ndn_tuple3_t *a = ndn_new_tuple3();
	ndn_tuple3_t *b = ndn_new_tuple3();
	CHECK(a && b, "tuple3 allocation");
	a->name = strdup("x");
	a->src_MAC = mmt_malloc(3); strcpy(a->src_MAC, "m1");
	a->dst_MAC = mmt_malloc(3); strcpy(a->dst_MAC, "m2");
	b->name = strdup("x");
	b->src_MAC = mmt_malloc(3); strcpy(b->src_MAC, "m1");
	b->dst_MAC = mmt_malloc(3); strcpy(b->dst_MAC, "m2");
	CHECK(ndn_compare_tupe3(a, b) == 1, "identical tuples -> 1");
	mmt_free(b->src_MAC); mmt_free(b->dst_MAC);
	b->src_MAC = mmt_malloc(3); strcpy(b->src_MAC, "m2");
	b->dst_MAC = mmt_malloc(3); strcpy(b->dst_MAC, "m1");
	CHECK(ndn_compare_tupe3(a, b) == 2, "mirrored MACs -> 2");
	b->src_MAC[0] = 'z';
	CHECK(ndn_compare_tupe3(a, b) == 0, "mismatched MACs -> 0");
	CHECK(ndn_compare_tupe3(NULL, NULL) == 3, "two NULLs -> 3");
	CHECK(ndn_compare_tupe3(a, NULL) == 0, "tuple vs NULL -> 0");

	ndn_session_t *s = ndn_new_session();
	CHECK(s != NULL, "session allocation");
	s->tuple3 = a;
	CHECK(ndn_find_session_by_tuple3(a, s) == s, "find_session locates");
	CHECK(ndn_find_session_by_tuple3(NULL, s) == NULL, "NULL tuple -> NULL");
	CHECK(ndn_find_session_by_tuple3(a, NULL) == NULL, "NULL list -> NULL");
	ndn_free_session(s);
	ndn_free_tuple3(b);

	/* full session data analysis over a fabricated packet: Interest then
	 * the matching Data so the RTT branch runs. */
	uint8_t interest[] = {
		0x05, 0x12,
		0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
		0x0A, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x0C, 0x02, 0x03, 0xE8
	};
	uint8_t data_pkt[] = {
		0x06, 0x10,
		0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
		0x14, 0x06,
		0x19, 0x02, 0x13, 0x88,
		0x18, 0x00
	};
	uint8_t frame_i[14 + sizeof(interest)];
	uint8_t frame_d[14 + sizeof(data_pkt)];
	int layers[3] = { 0, 0, 14 };
	int protos[3] = { 1, 99, PROTO_NDN };
	ndn_fixture_t f;
	attribute_t attr;
	ndn_proto_context_t *ctx;

	memset(frame_i, 0, 14);
	memcpy(frame_i + 14, interest, sizeof(interest));
	memset(frame_d, 0, 14);
	memcpy(frame_d + 14, data_pkt, sizeof(data_pkt));

	fixture_init(&f, layers, protos, 3, frame_i, sizeof(frame_i));
	ctx = setup_ndn_context(NULL, NULL);
	CHECK(ctx != NULL && ctx->dummy_session != NULL, "setup_ndn_context");
	f.hdlr->configured_protocols[PROTO_NDN].args = ctx;
	f.hdr.ts.tv_sec = 1000;
	f.hdr.ts.tv_usec = 0;

	CHECK(ndn_session_data_analysis(&f.pkt, 2) == MMT_CONTINUE,
			"interest session analysis");
	CHECK(ctx->dummy_session->next != NULL, "session created");
	CHECK(ctx->dummy_session->next->nb_interest_packet[0] == 1,
			"interest counter incremented");

	/* data packet in the other direction -> RTT bookkeeping path */
	free(f.buf);
	f.buf = malloc(sizeof(frame_d) + 1);
	memcpy(f.buf, frame_d, sizeof(frame_d));
	f.buf[sizeof(frame_d)] = 0;
	f.pkt.data = f.buf;
	f.hdr.caplen = f.hdr.len = sizeof(frame_d);
	f.hdr.ts.tv_sec = 1000;
	f.hdr.ts.tv_usec = 5000;
	/* reverse the MACs so direction computes as 1 */
	{
		uint8_t tmp[6];
		memcpy(tmp, f.buf, 6);
		memcpy(f.buf, f.buf + 6, 6);
		memcpy(f.buf + 6, tmp, 6);
	}
	CHECK(ndn_session_data_analysis(&f.pkt, 2) == MMT_CONTINUE,
			"data session analysis");

	/* second interest same direction */
	free(f.buf);
	f.buf = malloc(sizeof(frame_i) + 1);
	memcpy(f.buf, frame_i, sizeof(frame_i));
	f.buf[sizeof(frame_i)] = 0;
	f.pkt.data = f.buf;
	f.hdr.caplen = f.hdr.len = sizeof(frame_i);
	CHECK(ndn_session_data_analysis(&f.pkt, 2) == MMT_CONTINUE,
			"repeat interest updates session");

	/* list_sessions extraction surfaces the live session list */
	memset(&attr, 0, sizeof(attr)); attr.data = NULL;
	CHECK(ndn_list_sessions_extraction(&f.pkt, 2, &attr) == 1
			&& attr.data == ctx->dummy_session->next,
			"list_sessions returns first session");

	/* delay time helper */
	CHECK(ndn_session_get_delay_time(ctx->dummy_session->next) > 0,
			"delay time positive");

	/* expiry path: age the session and re-run timed-out processing
	 * (delay_time is max(interest lifetime, data freshness) = 5000, so the
	 * packet clock must sit > 5000 + last-activity). */
	ctx->dummy_session->next->s_last_activity_time->tv_sec = 1;
	f.hdr.ts.tv_sec = 6000;
	ndn_process_timed_out_session(&f.pkt, 2, ctx->dummy_session->next,
			ctx->dummy_session, ctx->proto_id);
	CHECK(ctx->dummy_session->next == NULL, "expired session reaped");

	/* cleanup frees the context, its dummy session and dummy packet */
	cleanup_ndn_context(&f.hdlr->configured_protocols[PROTO_NDN], NULL);
	fixture_free(&f);

	/* analysis on a non-NDN payload: root type not 5/6 -> CONTINUE */
	{
		uint8_t junk[] = { 0x04, 0x02, 0x07, 0x00 };
		uint8_t fr[14 + sizeof(junk)];
		ndn_fixture_t fj;
		memset(fr, 0, 14);
		memcpy(fr + 14, junk, sizeof(junk));
		fixture_init(&fj, layers, protos, 3, fr, sizeof(fr));
		fj.hdlr->configured_protocols[PROTO_NDN].args = ctx = NULL;
		CHECK(ndn_session_data_analysis(&fj.pkt, 2) == MMT_CONTINUE,
				"non-NDN payload -> CONTINUE");
		fixture_free(&fj);
	}
}

int main(void) {
	test_tlv_basics();
	test_check_payload();
	test_find_and_names();
	test_extraction_payloads();
	test_ipacket_extraction();
	test_sessions();
	printf("=== %d checks, %d failures ===\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
