/*
 * test_dcerpc_offset.c — crafted-input regression test for the 1.8.0 DCERPC
 * packet-type offset fix (issue #243, F-TEST-014; fix #86, commit 6782d7da).
 *
 * The 1.8.0 fix corrected two reads in mmt_check_dcerpc()
 * (src/mmt_tcpip/lib/protocols/proto_dcerpc.c):
 *
 *   1. packet-type offset: the DCERPC RPC header carries pkt_type at
 *      payload[1], but the classifier read payload[2] < 16 — excluding ~93%
 *      of real DCERPC traffic;
 *   2. payload threshold: valid DCERPC packets can be as small as the
 *      16-byte minimum RPC header, but the classifier required > 64 bytes.
 *
 * The crafted packets below pin both reads: reverting payload[1] back to
 * payload[2], or >= 16 back to > 64, fails the corresponding CHECK.
 *
 * proto_dcerpc.c is included directly so gcov attributes the exercised lines
 * to the real file and so the file-scope classifier bitmasks are reachable;
 * the mmt_core helpers it calls are stubbed with compatible signatures
 * (same convention as tests/dicom_dissector, issue #215).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../../src/mmt_tcpip/lib/protocols/proto_dcerpc.c"

static int checks;
static int failures;
#define CHECK(cond, msg) do { \
		checks++; \
		if (!(cond)) { \
			failures++; \
			fprintf(stderr, "FAIL %d: %s\n", __LINE__, msg); \
		} \
	} while (0)

/* ---- stubs for the mmt_core helpers ---- */

static uint16_t g_last_detected;

protocol_t *init_protocol_struct_for_registration(uint32_t proto_id,
		const char *protocol_name) {
	(void) proto_id;
	(void) protocol_name;
	return (protocol_t *) calloc(1, 1);
}

bool register_protocol(protocol_t *protocol_struct, uint32_t proto_id) {
	(void) proto_id;
	free(protocol_struct);
	return 1;
}

/* Mirrors the observable effect of the real mmt_internal_add_connection():
 * the detected protocol lands on the flow's stack. */
void mmt_internal_add_connection(ipacket_t *ipacket,
		uint16_t detected_protocol, mmt_protocol_type_t protocol_type) {
	(void) protocol_type;
	g_last_detected = detected_protocol;
	ipacket->internal_packet->flow->detected_protocol_stack[0] =
			detected_protocol;
}

/* ---- packet fixture ---- */

struct test_pkt {
	ipacket_t ipacket;
	struct mmt_tcpip_internal_packet_struct ip;
	struct mmt_internal_tcpip_session_struct flow;
	struct tcphdr tcp;
	proto_hierarchy_t proto_h;
	unsigned char payload[128];
};

static struct test_pkt *pkt_with_dcerpc(uint16_t dport, const uint8_t *pl,
		unsigned pl_len) {
	struct test_pkt *t = calloc(1, sizeof(*t));
	memset(&t->tcp, 0, sizeof(t->tcp));
	t->tcp.dest = htons(dport);
	t->ip.tcp = &t->tcp;
	memcpy(t->payload, pl, pl_len);
	t->ip.payload = t->payload;
	t->ip.payload_packet_len = pl_len;
	t->ip.flow = &t->flow;
	/* Force the classifier's selection/exclusion/detection guard open — the
	 * bitmasks were populated by init_proto_dcerpc_struct() below. */
	t->ip.mmt_selection_packet = (MMT_SELECTION_BITMASK_PROTOCOL_SIZE) ~0u;
	memset(&t->ip.detection_bitmask, 0xFF, sizeof(t->ip.detection_bitmask));
	t->ipacket.internal_packet = &t->ip;
	t->ipacket.proto_hierarchy = &t->proto_h;
	return t;
}

static void free_pkt(struct test_pkt *t) {
	free(t);
}

/* A minimal DCERPC request: version 5, pkt_type at [1] < 16, and a byte at
 * [2] that is NOT < 16 — so the pre-fix payload[2] check rejects it. */
static int run_dcerpc(uint8_t pkt_type, uint8_t frag_attr, unsigned pl_len,
		uint16_t dport) {
	/* pl must cover the largest pl_len passed below (128): memcpy into the
	 * fixture reads pl_len bytes — a smaller source is a stack over-read. */
	uint8_t pl[128];
	memset(pl, 0, sizeof(pl));
	pl[0] = 0x05;        /* RPC version 5 */
	pl[1] = pkt_type;    /* pkt_type at offset 1 (the fix) */
	pl[2] = frag_attr;   /* frag_attr — must NOT be consulted as pkt_type */
	struct test_pkt *t = pkt_with_dcerpc(dport, pl, pl_len);
	int r = mmt_check_dcerpc(&t->ipacket, 0);
	int detected = (g_last_detected == PROTO_DCERPC
			&& t->flow.detected_protocol_stack[0] == PROTO_DCERPC);
	g_last_detected = 0;
	free_pkt(t);
	return r && detected;
}

int main(void) {
	printf("=== DCERPC offset/threshold fix test (1.8.0, issue #86) ===\n");
	CHECK(init_proto_dcerpc_struct() == 1,
			"init_proto_dcerpc_struct registers");

	/* The fix: pkt_type is read at payload[1]. A packet whose payload[2]
	 * carries a non-type byte (>= 16) still classifies — the pre-fix
	 * payload[2] < 16 read rejects it. */
	CHECK(run_dcerpc(0x00, 0xFF, 32, 135) == 1,
			"pkt_type read at payload[1], not payload[2]");
	CHECK(run_dcerpc(0x0B, 0xFF, 32, 135) == 1,
			"pkt_type 11 (CALL) at payload[1] classifies");

	/* The fix: payload_packet_len >= 16. A 16..64-byte RPC frame still
	 * classifies — the pre-fix > 64 threshold rejects it. */
	CHECK(run_dcerpc(0x00, 0x03, 16, 135) == 1,
			"minimum 16-byte RPC header classifies");
	CHECK(run_dcerpc(0x00, 0x03, 40, 135) == 1,
			"sub-64-byte RPC frame classifies");
	CHECK(run_dcerpc(0x00, 0x03, 128, 135) == 1,
			"large RPC frame still classifies (no upper bound)");

	/* Source port 135 is accepted too (server-to-client direction). */
	{
		uint8_t pl[32];
		memset(pl, 0, sizeof(pl));
		pl[0] = 0x05; pl[1] = 0x02; pl[2] = 0xFF;
		struct test_pkt *t = pkt_with_dcerpc(0, pl, 32);
		t->tcp.source = htons(135);
		CHECK(mmt_check_dcerpc(&t->ipacket, 0) == 1
				&& t->flow.detected_protocol_stack[0] == PROTO_DCERPC,
				"source port 135 classifies (either direction)");
		free_pkt(t);
	}

	/* Non-DCERPC inputs must be excluded, not classified. */
	{
		uint8_t pl[32];
		memset(pl, 0, sizeof(pl));
		pl[0] = 0x06; pl[1] = 0x00; pl[2] = 0x03; /* wrong version */
		struct test_pkt *t = pkt_with_dcerpc(135, pl, 32);
		CHECK(mmt_check_dcerpc(&t->ipacket, 0) == 0
				&& t->flow.detected_protocol_stack[0] != PROTO_DCERPC,
				"non-0x05 version byte is not classified");
		free_pkt(t);
	}
	{
		uint8_t pl[32];
		memset(pl, 0, sizeof(pl));
		pl[0] = 0x05; pl[1] = 0x00; pl[2] = 0x03;
		struct test_pkt *t = pkt_with_dcerpc(9999, pl, 32); /* wrong port */
		CHECK(mmt_check_dcerpc(&t->ipacket, 0) == 0
				&& t->flow.detected_protocol_stack[0] != PROTO_DCERPC,
				"non-135 port is not classified");
		free_pkt(t);
	}
	{
		uint8_t pl[32];
		memset(pl, 0, sizeof(pl));
		pl[0] = 0x05; pl[1] = 0x00; pl[2] = 0x03;
		struct test_pkt *t = pkt_with_dcerpc(135, pl, 8); /* too short */
		CHECK(mmt_check_dcerpc(&t->ipacket, 0) == 0,
				"sub-16-byte payload is not classified");
		free_pkt(t);
	}

	printf("=== %d checks, %d failures ===\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
