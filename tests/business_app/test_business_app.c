/*
 * test_business_app.c — coverage driver for the business-app plugin
 * (src/mmt_business_app/), issue #243 (F-TEST-015).
 *
 * The plugin is a shipped, installed library (libmmt_business_app.so,
 * PROTO_IPS_DATA = 801) that had no test of any kind: the only one of five
 * shipped libraries with neither direct nor indirect coverage. The pcap
 * harness (tools/phase0/tests/tcpip_pcap_harness.c) already loads the plugin
 * .so and registers its extraction attributes, so registration + dissect run
 * under the sanitizers there; this suite makes the same paths visible to the
 * library coverage report by compiling the plugin sources into the test
 * binary — gcov attributes the exercised lines to the real files in
 * coverage.info, and the static classifier/extractor entry points stay
 * reachable (same convention as tests/dicom_dissector, issue #215).
 *
 * Paths under test:
 *   mmt_business_app.c   — init_proto()/cleanup_proto() plugin entry points:
 *                          the registration path dlopen() runs under the pcap
 *                          harness; here it runs against stubbed core helpers.
 *   proto_ips_data.c     — _ips_data_classify_next_proto() ("TrolleyPos"
 *                          frame opener over the PROTO_IPS_DATA stack),
 *                          _ips_data_stack_classification() and
 *                          _extraction_att() for every registered attribute
 *                          (float/u16/u32/u64 assignments, missing-key and
 *                          truncated-capture guards).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/mmt_business_app/mmt_business_app.c"
#include "../../src/mmt_business_app/proto_ips_data.c"

static int checks;
static int failures;
#define CHECK(cond, msg) do { \
		checks++; \
		if (!(cond)) { \
			failures++; \
			fprintf(stderr, "FAIL %d: %s\n", __LINE__, msg); \
		} \
	} while (0)

/* ---- stubs for the mmt_core registration / packet helpers ----
 * Compatible signatures, no real registry: registration functions record the
 * calls so the test can assert the plugin's init sequence, and the packet
 * helpers reproduce the real semantics the plugin relies on. */

static int g_protocol_struct_calls;
static int g_register_protocol_calls;
static int g_register_stack_calls;
static int g_register_classify_calls;
static int g_register_attr_calls;
static uint32_t g_last_stack_id;
static int g_attr_registration_fail_at = -1; /* index to fail, -1 = never */

protocol_t *init_protocol_struct_for_registration(uint32_t proto_id,
		const char *protocol_name) {
	(void) proto_id;
	(void) protocol_name;
	g_protocol_struct_calls++;
	return (protocol_t *) calloc(1, 1);
}

bool register_attribute_with_protocol(protocol_t *protocol_struct,
		attribute_metadata_t *attribute_meta_data) {
	(void) protocol_struct;
	(void) attribute_meta_data;
	g_register_attr_calls++;
	return (g_attr_registration_fail_at < 0
			|| g_register_attr_calls - 1 != g_attr_registration_fail_at);
}

bool register_protocol(protocol_t *protocol_struct, uint32_t proto_id) {
	(void) proto_id;
	g_register_protocol_calls++;
	free(protocol_struct); /* stub allocation from init_protocol_struct_* */
	return 1;
}

bool register_protocol_stack(uint32_t s_id, char *s_name,
		generic_stack_classification_function fct) {
	(void) s_name;
	(void) fct;
	g_register_stack_calls++;
	g_last_stack_id = s_id;
	return 1;
}

bool register_classification_function(protocol_t *protocol_struct,
		generic_classification_function classification_fct) {
	(void) protocol_struct;
	(void) classification_fct;
	g_register_classify_calls++;
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

int set_classified_proto(ipacket_t *ipacket, unsigned index,
		classified_proto_t classified_proto) {
	if (!ipacket || !ipacket->proto_hierarchy
			|| index >= PROTO_PATH_SIZE)
		return 0;
	if ((int) index >= ipacket->proto_hierarchy->len)
		ipacket->proto_hierarchy->len = (int) index + 1;
	ipacket->proto_hierarchy->proto_path[index] = classified_proto.proto_id;
	return 1;
}

/* ---- packet fixture ---- */

#define PKT_BUF 512

struct test_pkt {
	ipacket_t ipacket;
	proto_hierarchy_t proto_offset;
	proto_hierarchy_t proto_h;
	pkthdr_t pcap_hdr;
	unsigned char buffer[PKT_BUF];
};

/* An IPS_DATA record lives at the start of the capture: the plugin's stack
 * classification puts META at index 0 and IPS_DATA at index 1 (the pcap
 * harness prints "meta.lps_data"), so the classifier is invoked at index 0
 * and sets index 1. */
static struct test_pkt *pkt_with_data(const char *data, unsigned caplen) {
	struct test_pkt *t = calloc(1, sizeof(*t));
	memcpy(t->buffer, data, caplen);
	t->proto_h.proto_path[0] = 1; /* META */
	t->proto_h.len = 1;
	t->ipacket.proto_hierarchy = &t->proto_h;
	t->proto_offset.proto_path[0] = 0;
	t->proto_offset.len = 1;
	t->ipacket.proto_headers_offset = &t->proto_offset;
	t->ipacket.data = t->buffer;
	t->ipacket.p_hdr = &t->pcap_hdr;
	t->ipacket.p_hdr->caplen = caplen;
	t->ipacket.packet_id = 7;
	return t;
}

static void free_pkt(struct test_pkt *t) {
	free(t);
}

/* A full CSV record as emitted by the protocol (see ips_data.h). */
static const char IPS_RECORD[] =
	"TrolleyPos: 32.981, Hoistpos: 38.042, NoOfMarkers: 3, "
	"m1: (58901,70912) , m2: (72175,70950) , m3: (65803,71939) , "
	"m4: (46930,65566) , m5: (65795,72047) , m6: (70644,58001)";

/* ---- registration path (init_proto -> init_proto_ips_data) ---- */
static void test_registration(void) {
	printf("[1] plugin registration (init_proto -> init_proto_ips_data)\n");

	g_protocol_struct_calls = g_register_protocol_calls = 0;
	g_register_stack_calls = g_register_classify_calls = g_register_attr_calls = 0;

	CHECK(init_proto() == 1, "init_proto registers the plugin successfully");
	CHECK(g_protocol_struct_calls == 1, "protocol struct initialised once");
	CHECK(g_register_attr_calls == 16, "all 16 IPS_DATA attributes registered");
	CHECK(g_register_classify_calls == 1, "classifier registered on the stack");
	CHECK(g_register_stack_calls == 1, "protocol stack registered");
	CHECK(g_last_stack_id == PROTO_IPS_DATA,
			"registered stack id is PROTO_IPS_DATA (801)");
	CHECK(g_register_protocol_calls == 1, "protocol registered");

	CHECK(cleanup_proto() == 0, "cleanup_proto returns cleanly");
}

/* ---- classification path (_ips_data_classify_next_proto) ---- */
static void test_classification(void) {
	printf("[2] IPS_DATA frame classification\n");

	struct test_pkt *t = pkt_with_data(IPS_RECORD, sizeof(IPS_RECORD) - 1);
	CHECK(_ips_data_classify_next_proto(&t->ipacket, 0) == 1,
			"TrolleyPos frame is classified");
	CHECK(t->proto_h.proto_path[1] == PROTO_IPS_DATA,
			"next protocol in path is PROTO_IPS_DATA");
	CHECK(_ips_data_stack_classification(&t->ipacket).proto_id == PROTO_IPS_DATA,
			"stack classification reports PROTO_IPS_DATA");
	free_pkt(t);

	/* A payload that does not open with "TrolleyPos" is not IPS_DATA. */
	static const char other[] = "Hoistpos: 38.042, NoOfMarkers: 3";
	t = pkt_with_data(other, sizeof(other) - 1);
	CHECK(_ips_data_classify_next_proto(&t->ipacket, 0) == 0,
			"non-TrolleyPos payload is not classified");
	free_pkt(t);

	/* A capture shorter than the 10-byte "TrolleyPos" opener must not
	 * over-read the captured buffer (issue #195 guard). */
	t = pkt_with_data("TrolleyPo", 9);
	CHECK(_ips_data_classify_next_proto(&t->ipacket, 0) == 0,
			"truncated opener is not classified");
	free_pkt(t);

	/* Offset beyond caplen: the classify guard returns 0. */
	t = pkt_with_data(IPS_RECORD, sizeof(IPS_RECORD) - 1);
	t->proto_offset.proto_path[0] = PKT_BUF; /* offset == caplen bound */
	CHECK(_ips_data_classify_next_proto(&t->ipacket, 0) == 0,
			"offset past caplen is not classified");
	free_pkt(t);
}

/* ---- extraction path (_extraction_att over every registered field) ---- */
static uint8_t attr_storage[16];
static void extract_check(struct test_pkt *t, uint32_t field_id,
		const char *msg, int check_value, double expected) {
	attribute_t attr;
	memset(&attr, 0, sizeof(attr));
	memset(attr_storage, 0xAA, sizeof(attr_storage));
	attr.proto_id = PROTO_IPS_DATA;
	attr.field_id = field_id;
	attr.data = attr_storage;
	CHECK(_extraction_att(&t->ipacket, 0, &attr) == 1, msg);
	if (check_value) {
		double got = 0;
		switch (field_id) {
		case IPS_DATA_TROLLEY_POS:
		case IPS_DATA_HOIST_POS: {
			/* float storage vs double literal — compare with tolerance */
			float f = *(float *) attr.data;
			CHECK(f > (float) expected - 0.001f
					&& f < (float) expected + 0.001f, msg);
			return;
		}
		case IPS_DATA_NO_OF_MARKERS:
			got = *(uint16_t *) attr.data;
			break;
		case IPS_DATA_ORDER:
			got = (double) *(uint64_t *) attr.data;
			break;
		default:
			got = *(uint32_t *) attr.data;
			break;
		}
		CHECK(got == expected, msg);
	}
}

static void test_extraction(void) {
	printf("[3] IPS_DATA attribute extraction on a full record\n");

	struct test_pkt *t = pkt_with_data(IPS_RECORD, sizeof(IPS_RECORD) - 1);

	extract_check(t, IPS_DATA_TROLLEY_POS, "trolley_pos float extracted",
			1, 32.981);
	extract_check(t, IPS_DATA_HOIST_POS, "hoist_pos float extracted",
			1, 38.042);
	extract_check(t, IPS_DATA_NO_OF_MARKERS, "no_of_marker u16 extracted",
			1, 3);
	extract_check(t, IPS_DATA_M1_X, "m1_x u32 extracted", 1, 58901);
	extract_check(t, IPS_DATA_M1_Y, "m1_y u32 extracted", 1, 70912);
	extract_check(t, IPS_DATA_M2_X, "m2_x u32 extracted", 1, 72175);
	extract_check(t, IPS_DATA_M2_Y, "m2_y u32 extracted", 1, 70950);
	extract_check(t, IPS_DATA_M3_X, "m3_x u32 extracted", 1, 65803);
	extract_check(t, IPS_DATA_M3_Y, "m3_y u32 extracted", 1, 71939);
	extract_check(t, IPS_DATA_M4_X, "m4_x u32 extracted", 1, 46930);
	extract_check(t, IPS_DATA_M4_Y, "m4_y u32 extracted", 1, 65566);
	extract_check(t, IPS_DATA_M5_X, "m5_x u32 extracted", 1, 65795);
	extract_check(t, IPS_DATA_M5_Y, "m5_y u32 extracted", 1, 72047);
	extract_check(t, IPS_DATA_M6_X, "m6_x u32 extracted", 1, 70644);
	extract_check(t, IPS_DATA_M6_Y, "m6_y u32 extracted", 1, 58001);
	extract_check(t, IPS_DATA_ORDER, "order mirrors packet_id", 1, 7);
	free_pkt(t);

	/* Missing keys: every converter sees an empty token and stores 0 —
	 * the F-BUG-098 token-copy bound must keep the parse in-capture. */
	static const char partial[] = "TrolleyPos: 1.5";
	t = pkt_with_data(partial, sizeof(partial) - 1);
	extract_check(t, IPS_DATA_TROLLEY_POS, "trolley_pos on sparse record",
			1, 1.5);
	extract_check(t, IPS_DATA_HOIST_POS, "absent hoist_pos yields 0", 1, 0);
	/* no_of_marker has no else-store on an absent key — the field is simply
	 * not written; exercise the NULL-ptr branch only (F-BUG-107 guard). */
	extract_check(t, IPS_DATA_NO_OF_MARKERS, "absent no_of_marker returns 1",
			0, 0);
	extract_check(t, IPS_DATA_M1_X, "absent m1_x yields 0", 1, 0);
	extract_check(t, IPS_DATA_M1_Y, "absent m1_y yields 0", 1, 0);
	free_pkt(t);
}

int main(void) {
	test_registration();
	test_classification();
	test_extraction();
	printf("=== %d checks, %d failures ===\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
