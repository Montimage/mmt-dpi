/*
 * test_syslog_format.c — crafted-input regression test for the 1.8.0 syslog
 * dual-format parser (issue #243, F-TEST-014; "add syslog protocol parser
 * supporting both RFC 3164 and RFC 5424 message formats", #80, commit
 * 8844d6fb).
 *
 * mmt_int_is_syslog_packet() (src/mmt_tcpip/lib/protocols/proto_syslog.c)
 * splits the post-PRI payload between the two syslog formats:
 *
 *   - RFC 5424 branch: version digit '1', a space, then a 4-digit ISO-8601
 *     year ('2' or '1' followed by three digits);
 *   - RFC 3164 branch: a 3-letter month abbreviation (Jan–Dec);
 *   - hostname/tag branch: an alphanumeric token ending in ' ', ':', '=',
 *     '[' or '-' (with ':' requiring a following space);
 *   - plus the "last message" / "snort: " compat prefixes and the UDP-514
 *     lenient fallback (a valid <PRI> alone suffices on port 514).
 *
 * The crafted packets below pin the format split: dropping either format
 * branch — or the whole parser down to the pre-1.8.0 "port-only" shape —
 * fails the corresponding CHECK. A frame that matches neither format must
 * be excluded off port 514.
 *
 * proto_syslog.c is included directly so the static parse helpers are
 * reachable and gcov attributes the exercised lines to the real file; the
 * mmt_core helpers it calls are stubbed with compatible signatures (same
 * convention as tests/dicom_dissector, issue #215).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../../src/mmt_tcpip/lib/protocols/proto_syslog.c"

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
	struct udphdr udp;
	struct tcphdr tcp;
	proto_hierarchy_t proto_h;
	pkthdr_t pcap_hdr;
	unsigned char buffer[1100];
};

/* Fabricate a packet carrying `msg` as its L4 payload. use_udp514 selects
 * the UDP-514 lenient path; otherwise the strict (TCP-like) path runs. */
static struct test_pkt *pkt_syslog(const char *msg, int use_udp514) {
	struct test_pkt *t = calloc(1, sizeof(*t));
	size_t len = strlen(msg);
	memcpy(t->buffer, msg, len);
	t->ipacket.data = t->buffer;
	t->ipacket.p_hdr = &t->pcap_hdr;
	t->ipacket.p_hdr->caplen = (unsigned int) len;
	t->ip.payload = t->buffer;
	t->ip.payload_packet_len = (uint16_t) len;
	t->ip.flow = &t->flow;
	if (use_udp514) {
		memset(&t->udp, 0, sizeof(t->udp));
		t->udp.dest = htons(514);
		t->ip.udp = &t->udp;
	}
	t->ip.mmt_selection_packet = (MMT_SELECTION_BITMASK_PROTOCOL_SIZE) ~0u;
	memset(&t->ip.detection_bitmask, 0xFF, sizeof(t->ip.detection_bitmask));
	t->ipacket.internal_packet = &t->ip;
	t->ipacket.proto_hierarchy = &t->proto_h;
	return t;
}

static void free_pkt(struct test_pkt *t) {
	free(t);
}

static int run_syslog(const char *msg, int use_udp514) {
	struct test_pkt *t = pkt_syslog(msg, use_udp514);
	g_last_detected = 0;
	int r = mmt_check_syslog(&t->ipacket, 0);
	int detected = (g_last_detected == PROTO_SYSLOG
			&& t->flow.detected_protocol_stack[0] == PROTO_SYSLOG);
	free_pkt(t);
	return r && detected;
}

int main(void) {
	printf("=== syslog dual-format parser test (1.8.0, issue #80) ===\n");
	CHECK(init_proto_syslog_struct() == 1,
			"init_proto_syslog_struct registers");

	/* --- RFC 3164: <PRI> + 3-letter month + timestamp + tag --- */
	CHECK(run_syslog("<34>Oct 11 22:14:15 myhost su[123]: msg", 0) == 1,
			"RFC 3164 (BSD) format classifies");
	CHECK(run_syslog("<13>Jan  1 00:00:01 host tag: x", 0) == 1,
			"RFC 3164 single-digit day classifies");
	CHECK(run_syslog("<191>Dec 31 23:59:59 h app: m", 0) == 1,
			"RFC 3164 December edge month classifies");

	/* --- RFC 5424: <PRI> + version '1' + space + ISO-8601 timestamp --- */
	CHECK(run_syslog(
			"<13>1 2003-10-11T22:14:15.003Z host app 1234 msg",
			0) == 1,
			"RFC 5424 (structured) format classifies");
	CHECK(run_syslog("<165>1 2026-01-01T00:00:00Z h a - - m", 0) == 1,
			"RFC 5424 with NILVALUE fields classifies");

	/* --- compat prefixes --- */
	CHECK(run_syslog("<13>last message repeated 4 times", 0) == 1,
			"'last message' compat prefix classifies");
	CHECK(run_syslog("<13>snort: [1:1234] alert text here", 0) == 1,
			"'snort: ' compat prefix classifies");

	/* --- hostname/tag branch: alnum token then delimiter --- */
	CHECK(run_syslog("<13>myhost: something after colon", 0) == 1,
			"hostname: tag pattern classifies");
	CHECK(run_syslog("<13>myhost daemon[42]: event text", 0) == 1,
			"hostname + tag + pid pattern classifies");

	/* --- UDP 514 lenient: a valid <PRI> alone suffices --- */
	CHECK(run_syslog("<13>anything at all goes here ok", 1) == 1,
			"UDP/514 accepts a bare PRI frame");

	/* --- strict-path rejections: excluded, not classified --- */
	CHECK(run_syslog("no angle bracket anywhere at all...", 0) == 0,
			"missing '<' opener is not classified");
	CHECK(run_syslog("<13 no closing angle bracket at all", 0) == 0,
			"missing '>' after PRI is not classified");
	CHECK(run_syslog("<x>not digits inside the PRI field.", 0) == 0,
			"non-digit PRI is not classified");
	CHECK(run_syslog("<13>", 0) == 0,
			"payload <= 20 bytes is not classified");
	CHECK(run_syslog("<13>!!! not-a-syslog token here !!!", 0) == 0,
			"non-alnum token off port 514 is not classified");
	CHECK(run_syslog("<13>host:colon-without-space-then-x", 0) == 0,
			"tag colon not followed by space is not classified");

	/* --- the lenient path accepts a valid PRI even when no strict
	 * format branch matches — on UDP/514 only --- */
	CHECK(run_syslog("<13>!!xx not a strict format but udp", 1) == 1,
			"UDP/514 still accepts minimal PRI frame (lenient)");

	/* PRI up to 3 digits; a 4-digit PRI has no '>' where expected. */
	CHECK(run_syslog("<1234>Oct 11 22:14:15 h t: m longgg", 0) == 0,
			"4-digit PRI is rejected (PRI is 1-3 digits)");

	printf("=== %d checks, %d failures ===\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
