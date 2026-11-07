/*
 * test_ddl_host_port_unit.c — helper reproducer for issue #749 (CodeQL
 * cpp/comparison-with-wider-type, proto_direct_download_link.c):
 * search_ddl_domains() strips a ":port" suffix from the Host line by walking
 * back over its trailing digits with a counter compared against the
 * uint16_t host length. A uint8_t counter wrapped to 0 after 255 digits, read
 * host[len] (one byte past the Host value) and never reached the ':', so a
 * direct-download host followed by a port of 255+ digits was not recognised.
 *
 *   - "x.megaupload.com:80" strips the port and matches (unchanged path);
 *   - "x.megaupload.com:" + 300 digits strips the port and matches (red on
 *     the uint8_t counter: it returned 0);
 *   - "x.example.org:" + 300 digits still does not match.
 *
 * proto_direct_download_link.c is included directly so the function under
 * test is reachable; the core and tcpip helpers it calls are stubbed (same
 * convention as test_udp_bounds_unit.c). The Host value is followed by the
 * '\r' a header line ends with: on the old counter that byte stopped the
 * wrapped walk (a digit there looped forever), so the red run fails the
 * checks instead of hanging.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/mmt_tcpip/lib/protocols/proto_direct_download_link.c"

static int checks;
static int failures;
#define CHECK(cond, msg) do { \
		checks++; \
		if (!(cond)) { \
			failures++; \
			fprintf(stderr, "FAIL %d: %s\n", __LINE__, msg); \
		} \
	} while (0)

/* ---- stubs for the helpers the dissector file references ---- */

static int added;

void mmt_internal_add_connection(ipacket_t *ipacket, uint16_t detected_protocol,
		mmt_protocol_type_t protocol_type) {
	(void) ipacket; (void) protocol_type;
	if (detected_protocol == PROTO_DIRECT_DOWNLOAD_LINK)
		added++;
}

/* The fixture fills line[0] and host_line itself. */
void mmt_parse_packet_line_info(ipacket_t *ipacket) {
	(void) ipacket;
}

protocol_t *init_protocol_struct_for_registration(mmt_proto_id_t proto_id,
		const char *protocol_name) {
	(void) proto_id; (void) protocol_name;
	return NULL;
}

bool register_protocol(protocol_t *proto, mmt_proto_id_t proto_id) {
	(void) proto; (void) proto_id;
	return 0;
}

/* ---- fixture ---- */

static const char request_line[] = "GET /file.bin HTTP/1.1";

/* Runs search_ddl_domains() over a Host value made of `prefix` followed by
 * `digits` '0'..'9' characters, then the line's '\r' (not part of the value). */
static int run_host(const char *prefix, size_t digits) {
	static uint8_t payload[128];
	static struct mmt_tcpip_internal_packet_struct packet;
	static struct mmt_internal_tcpip_session_struct flow;
	static mmt_session_t session;
	ipacket_t ipacket;
	size_t plen = strlen(prefix);
	size_t hlen = plen + digits;
	uint8_t *host = malloc(hlen + 1);
	int ret;

	if (host == NULL)
		return -1;
	memcpy(host, prefix, plen);
	for (size_t k = 0; k < digits; k++)
		host[plen + k] = (uint8_t) ('0' + k % 10);
	host[hlen] = '\r';

	memset(payload, 'A', sizeof(payload));
	memcpy(payload, request_line, sizeof(request_line) - 1);
	memset(&packet, 0, sizeof(packet));
	memset(&flow, 0, sizeof(flow));
	memset(&session, 0, sizeof(session));
	memset(&ipacket, 0, sizeof(ipacket));

	packet.payload = payload;
	packet.payload_packet_len = sizeof(payload);
	packet.flow = &flow;
	packet.line[0].ptr = payload;
	packet.line[0].len = sizeof(request_line) - 1;
	packet.parsed_lines = 1;
	packet.host_line.ptr = host;
	packet.host_line.len = (uint16_t) hlen;
	ipacket.internal_packet = &packet;
	ipacket.session = &session;

	added = 0;
	ret = search_ddl_domains(&ipacket);
	free(host);
	return ret;
}

int main(void) {
	CHECK(run_host("x.megaupload.com:80", 0) == 1 && added == 1,
		"a short :port is stripped and the host matches");
	CHECK(run_host("x.megaupload.com", 0) == 1 && added == 1,
		"a host without a port matches");
	CHECK(run_host("x.megaupload.com:", 300) == 1 && added == 1,
		"a 300-digit :port is stripped and the host matches");
	CHECK(run_host("x.megaupload.com:", 255) == 1 && added == 1,
		"a 255-digit :port is stripped and the host matches");
	CHECK(run_host("x.example.org:", 300) == 0 && added == 0,
		"a non-DDL host with a 300-digit port does not match");

	printf("ddl host :port strip: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
