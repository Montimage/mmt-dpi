/*
 * test_ptp_classify.c — crafted-input regression test for the 1.8.0 PTP
 * classifier (issue #243, F-TEST-014; "add classification for PTP
 * (Precision Time Protocol) packets", CHANGELOG 1.8.0).
 *
 * _classify_ptp_from_udp() (src/mmt_tcpip/lib/protocols/proto_ptp.c)
 * accepts a UDP flow only when:
 *   - an endpoint port is 319 (PTP event) or 320 (PTP general), and
 *   - the capture holds the full UDP header plus a 44-byte PTP body
 *     (next_offset + 44 <= caplen — the bounds gate).
 *
 * The crafted packets below pin both reads: reverting the port match to a
 * no-op, or dropping the caplen gate, fails the corresponding CHECK.
 *
 * proto_ptp.c is included directly so the static classifier is reachable
 * and gcov attributes the exercised lines to the real file; the mmt_core
 * helpers it calls are stubbed with compatible signatures (same convention
 * as tests/dicom_dissector, issue #215).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../../src/mmt_tcpip/lib/protocols/proto_ptp.c"

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

static uint32_t g_last_registered_parent;
static int g_register_classify_calls;

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

bool register_classification_function_with_parent_protocol(uint32_t proto_id,
		generic_classification_function classification_fct, int weight) {
	(void) classification_fct;
	(void) weight;
	g_last_registered_parent = proto_id;
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

/* Mirrors the observable effect of the real set_classified_proto(): the
 * classified protocol lands at `index` in the packet's proto path. */
int set_classified_proto(ipacket_t *ipacket, unsigned index,
		classified_proto_t classified_proto) {
	if (!ipacket || !ipacket->proto_hierarchy || index >= PROTO_PATH_SIZE)
		return 0;
	if ((int) index >= ipacket->proto_hierarchy->len)
		ipacket->proto_hierarchy->len = (int) index + 1;
	ipacket->proto_hierarchy->proto_path[index] = classified_proto.proto_id;
	return 1;
}

/* ---- packet fixture ---- */

struct test_pkt {
	ipacket_t ipacket;
	struct mmt_tcpip_internal_packet_struct ip;
	struct mmt_internal_tcpip_session_struct flow;
	struct udphdr udp;
	proto_hierarchy_t proto_offset;
	proto_hierarchy_t proto_h;
	pkthdr_t pcap_hdr;
	unsigned char buffer[128];
};

/* Fabricate a UDP datagram: UDP header at offset 0 (proto_headers_offset[0]
 * = 0), `caplen` captured bytes, src/dst ports as given. */
static struct test_pkt *pkt_udp(uint16_t sport, uint16_t dport,
		unsigned caplen) {
	struct test_pkt *t = calloc(1, sizeof(*t));
	memset(&t->udp, 0, sizeof(t->udp));
	t->udp.source = htons(sport);
	t->udp.dest = htons(dport);
	t->ip.udp = &t->udp;
	t->ip.flow = &t->flow;
	t->proto_offset.proto_path[0] = 0;
	t->proto_offset.len = 1;
	t->ipacket.proto_headers_offset = &t->proto_offset;
	t->ipacket.proto_hierarchy = &t->proto_h;
	t->ipacket.internal_packet = &t->ip;
	t->ipacket.data = t->buffer;
	t->ipacket.p_hdr = &t->pcap_hdr;
	t->ipacket.p_hdr->caplen = caplen;
	return t;
}

static void free_pkt(struct test_pkt *t) {
	free(t);
}

int main(void) {
	printf("=== PTP classifier test (1.8.0) ===\n");

	CHECK(init_proto_ptp_struct() == 1,
			"init_proto_ptp_struct registers");
	CHECK(g_register_classify_calls == 1
			&& g_last_registered_parent == PROTO_UDP,
			"classifier registered under PROTO_UDP");

	/* Ports 319 and 320, either direction, classify when the capture holds
	 * the UDP header + a full 44-byte PTP datagram (8 + 44 = 52 bytes). */
	const uint16_t port_pairs[][2] = {
		{319, 9000}, {9000, 319}, {320, 9000}, {9000, 320}, {319, 320},
	};
	for (size_t i = 0; i < sizeof(port_pairs) / sizeof(port_pairs[0]); i++) {
		struct test_pkt *t = pkt_udp(port_pairs[i][0], port_pairs[i][1], 60);
		int r = _classify_ptp_from_udp(&t->ipacket, 0);
		char msg[80];
		snprintf(msg, sizeof(msg), "ports %u/%u classify as PTP",
				port_pairs[i][0], port_pairs[i][1]);
		CHECK(r == 1, msg);
		CHECK(t->proto_h.proto_path[1] == PROTO_PTP,
				"PTP lands at index 1 in the proto path");
		free_pkt(t);
	}

	/* A UDP flow with neither port 319 nor 320 must not classify — the
	 * port match is the classifier's first gate. */
	struct test_pkt *t = pkt_udp(123, 456, 60);
	CHECK(_classify_ptp_from_udp(&t->ipacket, 0) == 0,
			"non-319/320 ports do not classify");
	CHECK(t->proto_h.len == 0, "proto path untouched on port mismatch");
	free_pkt(t);

	/* The caplen gate: next_offset(8) + 44 > caplen must not classify —
	 * fewer than 52 captured bytes cannot hold a PTP datagram. */
	t = pkt_udp(319, 320, 51);
	CHECK(_classify_ptp_from_udp(&t->ipacket, 0) == 0,
			"51-byte capture is too short for a PTP datagram");
	free_pkt(t);

	/* Exactly 52 bytes: the boundary case (8 + 44 <= caplen) classifies. */
	t = pkt_udp(319, 320, 52);
	CHECK(_classify_ptp_from_udp(&t->ipacket, 0) == 1,
			"52-byte capture is the exact PTP minimum");
	free_pkt(t);

	/* No UDP header at all: the defensive NULL guard returns 0. */
	t = pkt_udp(319, 320, 60);
	t->ip.udp = NULL;
	CHECK(_classify_ptp_from_udp(&t->ipacket, 0) == 0,
			"NULL udp pointer does not classify");
	free_pkt(t);

	printf("=== %d checks, %d failures ===\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
