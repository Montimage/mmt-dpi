/*
 * test_udp_bounds_unit.c — helper reproducer for issue #375 (F-BUG-002):
 * udp_pre_classification_function() (src/mmt_tcpip/lib/protocols/proto_udp.c)
 * must bound the UDP payload by BOTH the UDP header's own length field and
 * the enclosing IP payload (l4_packet_len):
 *
 *   - UDP length 8 with 32 captured L4 bytes exposes zero payload — trailing
 *     captured bytes are not payload;
 *   - a UDP length smaller than the IP payload clamps to it;
 *   - a UDP length larger than the IP payload clamps to the enclosing bound;
 *   - UDP length below 8 (and IPv6 non-jumbo length 0) exposes zero payload;
 *   - IPv6 payload_len bounds the L4 segment (extension-header aware), while
 *     a zero IPv6 payload_len is a jumbogram (RFC 2675) and keeps the
 *     captured bound.
 *
 * proto_udp.c is included directly so the function under test is reachable
 * and gcov attributes the exercised lines to the real file; the mmt_core
 * helpers it calls are stubbed with compatible signatures (same convention
 * as tests/proto_classifiers and tests/dicom_dissector, issues #215/#243).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../../src/mmt_tcpip/lib/protocols/proto_udp.c"

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
	if (!ipacket || !ipacket->proto_hierarchy || index >= PROTO_PATH_SIZE)
		return 0;
	if ((int) index >= ipacket->proto_hierarchy->len)
		ipacket->proto_hierarchy->len = (int) index + 1;
	ipacket->proto_hierarchy->proto_path[index] = classified_proto.proto_id;
	return 1;
}

uint32_t get_proto_id_from_address(ipacket_t *ipacket) {
	(void) ipacket;
	return PROTO_UNKNOWN;
}

unsigned int mmt_guess_protocol_by_port_number(ipacket_t *ipacket) {
	(void) ipacket;
	return PROTO_UNKNOWN;
}

void fire_attribute_event(ipacket_t *ipacket, mmt_proto_id_t proto_id,
		uint32_t attribute_id, unsigned index, mmt_opaque_t data) {
	(void) ipacket; (void) proto_id; (void) attribute_id;
	(void) index; (void) data;
}

void set_session_timeout_delay(mmt_session_t *session, uint32_t timeout_delay) {
	(void) session; (void) timeout_delay;
}

void *mmt_malloc(size_t size) {
	return malloc(size);
}

void mmt_free(void *ptr) {
	free(ptr);
}

int general_short_extraction_with_ordering_change(const ipacket_t *packet,
		unsigned proto_index, attribute_t *extracted_data) {
	(void) packet; (void) proto_index; (void) extracted_data;
	return 0;
}

protocol_t *init_protocol_struct_for_registration(uint32_t proto_id,
		const char *protocol_name) {
	(void) proto_id; (void) protocol_name;
	return (protocol_t *) calloc(1, 1);
}

bool register_protocol(protocol_t *protocol_struct, uint32_t proto_id) {
	(void) proto_id;
	free(protocol_struct);
	return 1;
}

bool register_attribute_with_protocol(protocol_t *protocol_struct,
		attribute_metadata_t *attribute_metadata) {
	(void) protocol_struct; (void) attribute_metadata;
	return 1;
}

bool register_pre_post_classification_functions(protocol_t *protocol_struct,
		generic_classification_function pre_classification,
		generic_classification_function post_classification) {
	(void) protocol_struct; (void) pre_classification;
	(void) post_classification;
	return 1;
}

/* ---- packet fixture ---- */

struct test_pkt {
	ipacket_t ipacket;
	struct mmt_tcpip_internal_packet_struct ip;
	struct mmt_internal_tcpip_session_struct flow;
	struct mmt_session_struct session;
	proto_hierarchy_t proto_offset;
	proto_hierarchy_t proto_h;
	pkthdr_t pcap_hdr;
	mmt_una_iphdr_t iph;
	unsigned char buffer[256];
};

/* Fabricate the state udp_pre_classification_function() sees for an IPv4
 * packet: index 1, L4 (UDP) header at `l4_off` in buffer, l4_packet_len as
 * computed by proto_ip.c, `caplen` captured bytes total, UDP len field
 * `udp_len`. The UDP header is written into the buffer at l4_off. */
static void pkt_udp4(struct test_pkt *t, int l4_off, uint16_t l4_len,
		uint16_t udp_len, uint32_t caplen) {
	memset(t, 0, sizeof(*t));
	t->ip.iph = &t->iph;
	t->ip.iphv6 = NULL;
	t->ip.l4_packet_len = l4_len;
	t->ip.flow = &t->flow;
	t->iph.tot_len = htons(20 + l4_len);
	t->proto_offset.proto_path[0] = 14;         /* ethernet */
	t->proto_offset.proto_path[1] = l4_off - 14; /* ipv4 header */
	t->proto_offset.len = 2;
	t->ipacket.proto_headers_offset = &t->proto_offset;
	t->ipacket.proto_hierarchy = &t->proto_h;
	t->ipacket.internal_packet = &t->ip;
	t->ipacket.session = &t->session;
	t->ipacket.data = t->buffer;
	t->ipacket.p_hdr = &t->pcap_hdr;
	t->ipacket.p_hdr->caplen = caplen;
	t->session.packet_count = 1;
	t->session.internal_data = &t->flow;
	/* UDP header at l4_off: only the length field matters here. */
	memset(&t->buffer[l4_off], 0, sizeof(struct udphdr));
	t->buffer[l4_off + 4] = (uint8_t) (udp_len >> 8);
	t->buffer[l4_off + 5] = (uint8_t) (udp_len & 0xff);
}

/* Same for IPv6: the 40-byte base header lives at buffer[ip6_off] (the code
 * locates it through packet->iphv6), `ext_len` extension bytes follow it and
 * the UDP header sits at l4_off = ip6_off + 40 + ext_len. `ip6_plen` is the
 * declared payload_len field (0 == jumbogram). */
static void pkt_udp6(struct test_pkt *t, int ip6_off, int l4_off,
		uint16_t ip6_plen, uint16_t udp_len, uint32_t caplen) {
	memset(t, 0, sizeof(*t));
	t->buffer[ip6_off] = 0x60; /* version 6 */
	t->buffer[ip6_off + 4] = (uint8_t) (ip6_plen >> 8);
	t->buffer[ip6_off + 5] = (uint8_t) (ip6_plen & 0xff);
	t->ip.iph = NULL;
	t->ip.iphv6 = (const struct mmt_ipv6hdr *) &t->buffer[ip6_off];
	t->ip.flow = &t->flow;
	t->proto_offset.proto_path[0] = l4_off; /* everything before UDP */
	t->proto_offset.len = 1;
	t->ipacket.proto_headers_offset = &t->proto_offset;
	t->ipacket.proto_hierarchy = &t->proto_h;
	t->ipacket.internal_packet = &t->ip;
	t->ipacket.session = &t->session;
	t->ipacket.data = t->buffer;
	t->ipacket.p_hdr = &t->pcap_hdr;
	t->ipacket.p_hdr->caplen = caplen;
	t->session.packet_count = 1;
	t->session.internal_data = &t->flow;
	memset(&t->buffer[l4_off], 0, sizeof(struct udphdr));
	t->buffer[l4_off + 4] = (uint8_t) (udp_len >> 8);
	t->buffer[l4_off + 5] = (uint8_t) (udp_len & 0xff);
}

/* Expected outcome bundle for one fixture run. */
static void run_case(struct test_pkt *t, unsigned index, int l4_off,
		uint32_t expect_payload_len, const char *what) {
	int ret = udp_pre_classification_function(&t->ipacket, index);
	char msg[160];
	snprintf(msg, sizeof(msg), "%s: classify continues", what);
	CHECK(ret == MMT_CLASSIFY_CONTINUE, msg);
	snprintf(msg, sizeof(msg), "%s: payload_packet_len == %u (got %u)",
			what, expect_payload_len, t->ip.payload_packet_len);
	CHECK(t->ip.payload_packet_len == expect_payload_len, msg);
	snprintf(msg, sizeof(msg), "%s: payload points past the UDP header", what);
	CHECK(t->ip.payload == t->buffer + l4_off + (int) sizeof(struct udphdr),
			msg);
	snprintf(msg, sizeof(msg), "%s: HAS_PAYLOAD flag follows payload len", what);
	CHECK(((t->ip.mmt_selection_packet
			& MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) != 0)
			== (expect_payload_len != 0), msg);
	snprintf(msg, sizeof(msg), "%s: session data volume counts payload only",
			what);
	CHECK(t->session.data_byte_volume == expect_payload_len, msg);
}

int main(void) {
	struct test_pkt *t = calloc(1, sizeof(*t));

	printf("=== UDP payload bounds unit test (issue #375) ===\n");

	CHECK(init_proto_udp_struct() == 1,
			"init_proto_udp_struct registers");

	/* --- IPv4 --- */

	/* The finding: UDP length 8 with 32 captured L4 bytes exposes zero
	 * payload; the 24 trailing captured bytes are not payload. */
	pkt_udp4(t, 34, 32, 8, 34 + 32);
	run_case(t, 1, 34, 0, "IPv4 udp_len=8 of 32 captured");

	/* UDP length smaller than the enclosing IP payload: declared wins. */
	pkt_udp4(t, 34, 32, 20, 34 + 32);
	run_case(t, 1, 34, 12, "IPv4 udp_len=20 of 32 captured");

	/* UDP length larger than the enclosing IP payload: enclosing wins. */
	pkt_udp4(t, 34, 32, 60, 34 + 32);
	run_case(t, 1, 34, 24, "IPv4 udp_len=60 oversized vs l4=32");

	/* UDP length 0 over IPv4 means "rest of the datagram" — enclosing bound. */
	pkt_udp4(t, 34, 32, 0, 34 + 32);
	run_case(t, 1, 34, 24, "IPv4 udp_len=0 keeps enclosing bound");

	/* UDP length below the header size carries no payload. */
	pkt_udp4(t, 34, 32, 4, 34 + 32);
	run_case(t, 1, 34, 0, "IPv4 udp_len=4 malformed");

	/* Truncated capture: IP declared 32 L4 bytes but only 12 captured —
	 * the caplen clamp exposes only what was captured. */
	pkt_udp4(t, 34, 32, 32, 34 + 12);
	run_case(t, 1, 34, 4, "IPv4 truncated capture");

	/* l4_packet_len too small for a UDP header: classification is skipped. */
	pkt_udp4(t, 34, 4, 8, 34 + 32);
	CHECK(udp_pre_classification_function(&t->ipacket, 1)
			== MMT_CLASSIFY_SKIP,
			"IPv4 l4_len<8 skips classification");

	/* --- IPv6 --- */

	/* Same headline case over IPv6: UDP length 8, 32 captured L4 bytes. */
	pkt_udp6(t, 0, 40, 32, 8, 40 + 32);
	run_case(t, 0, 40, 0, "IPv6 udp_len=8 of 32 captured");

	/* IPv6 payload_len smaller than the capture: enclosing bound wins and
	 * the over-captured tail is excluded. */
	pkt_udp6(t, 0, 40, 20, 20, 40 + 32);
	run_case(t, 0, 40, 12, "IPv6 plen=20 over-captured 32");

	/* IPv6 extension headers: 8 ext bytes sit between the base header and
	 * UDP — payload_len counts them too. */
	pkt_udp6(t, 0, 48, 48, 40, 48 + 40);
	run_case(t, 0, 48, 32, "IPv6 8B ext hdr, plen=48, udp_len=40");

	/* IPv6 jumbogram: payload_len 0 with UDP length 0 keeps the captured
	 * bound (RFC 2675 — the real length lives in the Jumbo Payload option). */
	pkt_udp6(t, 0, 40, 0, 0, 40 + 32);
	run_case(t, 0, 40, 24, "IPv6 jumbo plen=0 udp_len=0");

	/* A non-jumbo IPv6 packet declaring UDP length 0 is malformed: no
	 * payload is exposed. */
	pkt_udp6(t, 0, 40, 32, 0, 40 + 32);
	run_case(t, 0, 40, 0, "IPv6 non-jumbo udp_len=0 malformed");

	/* Oversized IPv6 payload_len vs captured bytes: captured bound wins. */
	pkt_udp6(t, 0, 40, 100, 24, 40 + 32);
	run_case(t, 0, 40, 16, "IPv6 plen=100 oversized vs 32 captured");

	free(t);

	printf("=== %d checks, %d failures ===\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
