/*
 * test_stun_attribution.c — the STUN classifier keeps a STUN flow STUN
 * (issue #564, F-BUG-304).
 *
 * mmt_check_stun_udp() (src/mmt_tcpip/lib/protocols/proto_stun.c) used to
 * relabel a valid STUN flow from its server address: the hard-coded LINE
 * range 103.2.28.0/22, and — with ip_address_classify on — the IP-range
 * table's GOOGLE -> GTALK, YAHOO -> YAHOOMSG or any other hit, all as
 * correlated protocols. Nothing in a STUN message names an application, so
 * the classifier now records PROTO_STUN and nothing else.
 *
 * The packets below are STUN Binding requests to a LINE address and to an
 * address the stubbed table maps to PROTO_GOOGLE, with ip_address_classify
 * on: reverting the fix records PROTO_LINE / PROTO_GTALK through
 * mmt_internal_add_connection_by() and fails the CHECKs. A non-STUN payload
 * must not record PROTO_STUN. The rest pins what #564 left alone: the
 * attribute walk (padded and unpadded attributes), the Viber, Tango and
 * FaceTime fallbacks a non-STUN datagram still takes, and RFC 4571-framed
 * STUN over TCP.
 *
 * proto_stun.c is included directly so gcov attributes the exercised lines
 * to the real file; the mmt_core helpers it calls are stubbed (same
 * convention as test_ptp_classify.c).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../../src/mmt_tcpip/lib/protocols/proto_stun.c"

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

static uint32_t g_added[8];
static int g_nadded;
static int g_ip_lookups;

static void record(uint32_t proto) {
	if (g_nadded < (int) (sizeof(g_added) / sizeof(g_added[0])))
		g_added[g_nadded] = proto;
	g_nadded++;
}

void mmt_internal_add_connection(ipacket_t *ipacket,
		uint16_t detected_protocol, mmt_protocol_type_t protocol_type) {
	(void) ipacket;
	(void) protocol_type;
	record(detected_protocol);
}

void mmt_internal_add_connection_by(ipacket_t *ipacket,
		uint16_t detected_protocol, mmt_protocol_type_t protocol_type,
		uint8_t method) {
	(void) ipacket;
	(void) protocol_type;
	(void) method;
	record(detected_protocol);
}

/* the IP-range table: every address is Google's (the pre-#564 classifier
 * relabelled such a STUN flow GTALK) */
uint32_t get_proto_id_from_address(ipacket_t *ipacket) {
	(void) ipacket;
	g_ip_lookups++;
	return PROTO_GOOGLE;
}

void *mmt_malloc(size_t size) {
	return malloc(size);
}

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

/* ---- packet fixture ---- */

struct test_pkt {
	ipacket_t ipacket;
	struct mmt_tcpip_internal_packet_struct ip;
	struct mmt_internal_tcpip_session_struct flow;
	struct mmt_internal_tcpip_id_struct src, dst;
	mmt_session_t session;
	mmt_handler_t handler;
	struct iphdr iph;
	struct udphdr udp;
	uint8_t payload[64];
};

/* UDP datagram 192.0.2.1:49451 -> daddr:3478 carrying `len` payload bytes */
static struct test_pkt *pkt_udp(uint32_t daddr, const uint8_t *payload,
		uint16_t len) {
	struct test_pkt *t = calloc(1, sizeof(*t));
	t->iph.saddr = htonl(0xC0000201);
	t->iph.daddr = htonl(daddr);
	t->udp.source = htons(49451);
	t->udp.dest = htons(3478);
	memcpy(t->payload, payload, len);
	t->ip.iph = (const mmt_una_iphdr_t *) &t->iph;
	t->ip.udp = (const mmt_una_udphdr_t *) &t->udp;
	t->ip.flow = &t->flow;
	t->ip.src = &t->src;
	t->ip.dst = &t->dst;
	t->ip.payload = t->payload;
	t->ip.payload_packet_len = len;
	t->handler.ip_address_classify = 1;
	t->ipacket.internal_packet = &t->ip;
	t->ipacket.session = &t->session;
	t->ipacket.mmt_handler = &t->handler;
	g_nadded = 0;
	g_ip_lookups = 0;
	return t;
}

static void free_pkt(struct test_pkt *t) {
	free(t->src.ext);   /* host records insert_to_local_protos() grew */
	free(t->dst.ext);
	free(t);
}

/* RFC 8489 Binding request: type 0x0001, length 0, magic cookie, txid */
static const uint8_t BINDING_REQUEST[20] = {
	0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
};

int main(void) {
	printf("=== STUN attribution test (issue #564) ===\n");

	CHECK(init_proto_stun_struct() == 1, "init_proto_stun_struct registers");

	/* 74.125.250.129 (stun.l.google.com); the stubbed table says GOOGLE */
	struct test_pkt *t = pkt_udp(0x4A7DFA81, BINDING_REQUEST,
			sizeof(BINDING_REQUEST));
	CHECK(mmt_check_stun_udp(&t->ipacket, 0) == 4,
			"Binding request to a Google address is STUN");
	CHECK(g_nadded == 1 && g_added[0] == PROTO_STUN,
			"only PROTO_STUN is recorded (no GTALK relabel)");
	CHECK(g_ip_lookups == 0, "the IP-range table is not consulted");
	CHECK(t->session.content_flags & MMT_CONTENT_CONVERSATIONAL,
			"the session is marked conversational");
	free_pkt(t);

	/* 103.2.28.1: the hard-coded LINE /22 used to win over STUN */
	t = pkt_udp(0x67021C01, BINDING_REQUEST, sizeof(BINDING_REQUEST));
	CHECK(mmt_check_stun_udp(&t->ipacket, 0) == 4,
			"Binding request to a LINE address is STUN");
	CHECK(g_nadded == 1 && g_added[0] == PROTO_STUN,
			"only PROTO_STUN is recorded (no LINE relabel)");
	free_pkt(t);

	/* not STUN: the length field does not match the datagram */
	{
		uint8_t bad[24];
		memcpy(bad, BINDING_REQUEST, sizeof(BINDING_REQUEST));
		memset(bad + 20, 0x5a, 4);
		t = pkt_udp(0xC6336402, bad, sizeof(bad));
		mmt_check_stun_udp(&t->ipacket, 0);
		int stun = 0;
		for (int i = 0; i < g_nadded && i < 8; i++)
			stun |= g_added[i] == PROTO_STUN;
		CHECK(!stun, "a length-mismatched header is not STUN");
		free_pkt(t);
	}

	/* the attribute walk: a Binding success response (type 0x0101) with
	 * XOR-MAPPED-ADDRESS, and a request whose USERNAME (5 bytes, so 3
	 * bytes of padding) is followed by FINGERPRINT -- the padded branch */
	{
		static const uint8_t resp[32] = {
			0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xA4, 0x42,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
			0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xe1, 0x39, 0xe1, 0x12, 0xa6, 0x43,
		};
		static const uint8_t user[40] = {
			0x00, 0x01, 0x00, 0x14, 0x21, 0x12, 0xA4, 0x42,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
			0x00, 0x06, 0x00, 0x05, 'a', 'b', 'c', 'd', 'e', 0x00, 0x00, 0x00,
			0x80, 0x28, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78,
		};
		static const uint8_t odd[29] = {     /* SOFTWARE, 5 bytes, unpadded end */
			0x01, 0x11, 0x00, 0x09, 0x21, 0x12, 0xA4, 0x42,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
			0x80, 0x22, 0x00, 0x05, 'a', 'c', 'c', 'u', 'r',
		};
		static const uint8_t unknown_attr[28] = {   /* attribute 0x7777 */
			0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
			0x77, 0x77, 0x00, 0x04, 0, 0, 0, 0,
		};
		const struct { const uint8_t *p; uint16_t len; int stun; const char *what; } m[] = {
			{ resp, sizeof(resp), 1, "Binding response with XOR-MAPPED-ADDRESS is STUN" },
			{ user, sizeof(user), 1, "padded USERNAME then FINGERPRINT is STUN" },
			{ odd, sizeof(odd), 1, "unpadded trailing SOFTWARE is STUN" },
			{ unknown_attr, sizeof(unknown_attr), 0, "an unknown attribute is not STUN" },
		};
		for (size_t i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
			t = pkt_udp(0xC6336402, m[i].p, m[i].len);
			int r = mmt_check_stun_udp(&t->ipacket, 0);
			CHECK((r == 4 && g_nadded == 1 && g_added[0] == PROTO_STUN) == (m[i].stun == 1),
					m[i].what);
			free_pkt(t);
		}
	}

	/* not STUN: the address-keyed fallbacks for other conversational apps
	 * still run (unchanged by #564) and keep their own labels */
	{
		static const uint8_t junk[24] = { 0x5a, 0x5a, 0x5a, 0x5a };
		const uint32_t viber[] = {
			0x36A93FA1, 0x3400FC01, 0x365DFF41, 0x32100001, 0x6B140001,
			0x17140001, 0x36E00001, 0x2E330001, 0x2E890001, 0xB0220001,
		};
		for (size_t i = 0; i < sizeof(viber) / sizeof(viber[0]); i++) {
			t = pkt_udp(viber[i], junk, sizeof(junk));
			t->udp.source = htons(5243);
			CHECK(mmt_check_stun_udp(&t->ipacket, 0) == 4
					&& g_nadded == 1 && g_added[0] == PROTO_VIBER,
					"Viber range on port 5243 labels VIBER");
			free_pkt(t);
		}
		/* Viber port, unlisted address: falls through to Tango/FaceTime */
		t = pkt_udp(0xC6336402, junk, sizeof(junk));
		t->udp.dest = htons(7985);
		CHECK(mmt_check_stun_udp(&t->ipacket, 0) == 0 && g_nadded == 0,
				"Viber port without a Viber address is nothing");
		free_pkt(t);

		const uint32_t tango[] = { 0xC753A801, 0x48FBF371 };
		for (size_t i = 0; i < 2; i++) {
			t = pkt_udp(tango[i], junk, sizeof(junk));
			CHECK(mmt_check_stun_udp(&t->ipacket, 0) == 4
					&& g_nadded == 1 && g_added[0] == PROTO_TANGO,
					"Tango range labels TANGO");
			free_pkt(t);
		}

		/* Tango pattern; then a new flow to the same host and port is
		 * Tango by the port the first one recorded */
		uint8_t tp[40] = { 0x03, 0, 0, 0, 0, 0, 0x09, 0x54, 0x41, 0x4e, 0x47, 0x4f };
		t = pkt_udp(0xC6336402, tp, sizeof(tp));
		CHECK(mmt_check_stun_udp(&t->ipacket, 0) == 4
				&& g_nadded == 1 && g_added[0] == PROTO_TANGO,
				"Tango pattern labels TANGO");
		struct mmt_internal_tcpip_id_struct dst = t->dst, src = t->src;
		t->dst.ext = NULL;   /* handed to the next two flows */
		t->src.ext = NULL;
		free_pkt(t);
		t = pkt_udp(0xC6336402, junk, sizeof(junk));
		t->dst = dst;
		CHECK(mmt_check_stun_udp(&t->ipacket, 0) == 4
				&& g_nadded == 1 && g_added[0] == PROTO_TANGO,
				"server port recorded by the pattern labels TANGO");
		free_pkt(t);
		t = pkt_udp(0xC6336402, junk, sizeof(junk));
		t->src = src;
		CHECK(mmt_check_stun_udp(&t->ipacket, 0) == 4
				&& g_nadded == 1 && g_added[0] == PROTO_TANGO,
				"client port recorded by the pattern labels TANGO");
		free_pkt(t);

		static const uint8_t ft[16] = { 0 };
		t = pkt_udp(0x11000001, ft, sizeof(ft));
		CHECK(mmt_check_stun_udp(&t->ipacket, 0) == 4
				&& g_nadded == 1 && g_added[0] == PROTO_FACETIME,
				"16 bytes to 17.0.0.0/8 label FACETIME");
		free_pkt(t);
	}

	/* STUN over TCP: RFC 4571 framing must cover the whole segment */
	{
		uint8_t framed[22] = { 0x00, 0x14 };
		memcpy(framed + 2, BINDING_REQUEST, sizeof(BINDING_REQUEST));
		t = pkt_udp(0xC6336402, framed, sizeof(framed));
		CHECK(mmt_check_stun_tcp(&t->ipacket, 0) == 1
				&& g_nadded == 1 && g_added[0] == PROTO_STUN,
				"framed Binding request over TCP is STUN");
		free_pkt(t);
		framed[1] = 0x15;
		t = pkt_udp(0xC6336402, framed, sizeof(framed));
		CHECK(mmt_check_stun_tcp(&t->ipacket, 0) == 0 && g_nadded == 0,
				"a frame length that misses the segment is not STUN");
		free_pkt(t);
	}

	printf("=== %d checks, %d failures ===\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
