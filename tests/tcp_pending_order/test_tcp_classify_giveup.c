/*
 * test_tcp_classify_giveup.c — issue #526 (F-TEST-009): pin the issue #99
 * unknown-TCP classification give-up at its packet boundary.
 *
 * Issue #99 made tcp_pre_classification_function() and its reassembling
 * twin (src/mmt_tcpip/lib/protocols/proto_tcp.c) return MMT_CLASSIFY_SKIP
 * once a flow that is still PROTO_UNKNOWN has seen more than
 * 2 * CFG_CLASSIFICATION_THRESHOLD (= 40) packets, so the checker walk and
 * post-classification stop for the rest of the flow. Nothing executed that
 * boundary before; this test calls the SHIPPED functions (proto_tcp.c is
 * included, as in test_tcp_pending_order.c) on a crafted IPv4/TCP segment:
 *
 *   - unknown flow: CONTINUE for packets 1..40, SKIP on packet 41 (and on a
 *     much later packet, 1000) — for both entry points;
 *   - classified flow (PROTO_FTP): CONTINUE on packets 41 and 1000, so the
 *     give-up never drops a classified flow's per-packet path.
 *
 * The session's packet_count is set to N for "packet N": packet_session.c
 * increments it before the pipeline runs pre_classify on that packet. The
 * SDK-path counterpart — 41 packets of one unknown TCP flow through
 * packet_process, checker walk observed per packet — is the asan-profile
 * phase0 harness tools/phase0/tests/classified_flow_fastpath_test.c.
 *
 * The segment carries ACK only (no SYN/FIN/RST) and a 16-byte payload; the
 * frame is an exactly-sized heap buffer so ASan brackets it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/mmt_tcpip/lib/protocols/proto_tcp.c"
#include "../../src/mmt_tcpip/lib/protocols/tcp_segment.c"

#include "tcp_alloc_count.h"
#include "tcp_reasm_stubs.h"

static int checks;
static int failures;
#define CHECK(cond, ...) do {                                        \
		checks++;                                                    \
		if (!(cond)) {                                               \
			failures++;                                              \
			fprintf(stderr, "FAIL %d: ", __LINE__);                  \
			fprintf(stderr, __VA_ARGS__);                            \
			fprintf(stderr, "\n");                                   \
		}                                                            \
	} while (0)

/* The literal boundary issue #99 documents; CFG_CLASSIFICATION_THRESHOLD is
 * printed, not used, so a changed threshold or multiplier fails here. */
#define LAST_CLASSIFIED_PACKET 40u

#define IP_LEN      20u
#define TCP_LEN     20u
#define PAYLOAD_LEN 16u
#define FRAME_LEN   (IP_LEN + TCP_LEN + PAYLOAD_LEN)

typedef int (*pre_classify_fn)(ipacket_t *, unsigned);

typedef struct {
	mmt_handler_t handler;
	mmt_session_t session;
	struct mmt_internal_tcpip_session_struct flow;
	mmt_tcpip_internal_packet_t internal;
	proto_hierarchy_t offsets;
	struct pkthdr hdr;
	ipacket_internal_t ipacket;
	uint8_t *frame;
} fixture_t;

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
	p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

/* A fresh session/flow whose next packet is packet `n` of the flow. */
static void fixture_open(fixture_t *f, uint64_t n, uint32_t detected) {
	memset(f, 0, sizeof(*f));
	f->frame = malloc(FRAME_LEN);
	if (f->frame == NULL) { perror("malloc"); exit(2); }
	memset(f->frame, 0, FRAME_LEN);
	uint8_t *ip = f->frame, *tcp = f->frame + IP_LEN;
	ip[0] = 0x45; put_be16(ip + 2, FRAME_LEN); ip[8] = 64; ip[9] = 6;
	ip[12] = 10; ip[15] = 1; ip[16] = 10; ip[19] = 2;
	put_be16(tcp, 40001); put_be16(tcp + 2, 47123);       /* unassigned ports */
	put_be32(tcp + 4, 1000u + (uint32_t) n * PAYLOAD_LEN); /* seq */
	put_be32(tcp + 8, 5000u);                              /* ack_seq */
	tcp[12] = 0x50;                                        /* doff 5 */
	tcp[13] = 0x10;                                        /* ACK only */
	memset(tcp + TCP_LEN, 0xa5, PAYLOAD_LEN);

	f->handler.tcp_reassembly_limit = 4u * 1024u * 1024u;
	f->session.mmt_handler = &f->handler;
	f->session.packet_count = n;
	f->flow.detected_protocol_stack[0] = detected;
	f->internal.flow = &f->flow;
	f->internal.iph = (struct iphdr *) ip;
	f->internal.l4_packet_len = TCP_LEN + PAYLOAD_LEN;
	f->hdr.caplen = FRAME_LEN;
	f->hdr.len = FRAME_LEN;
	f->hdr.ts.tv_sec = 1;
	f->ipacket.data = f->frame;
	f->ipacket.p_hdr = &f->hdr;
	f->ipacket.session = &f->session;
	f->ipacket.mmt_handler = &f->handler;
	f->ipacket.internal_packet = &f->internal;
	f->ipacket.proto_headers_offset = &f->offsets;
	f->ipacket.packet_id = n;
	g_stub_packet_offset = (int) IP_LEN;   /* the TCP header offset */
}

static void fixture_close(fixture_t *f) {
	clean_session_payload(&f->session, 0);
	free(f->frame);
	g_stub_packet_offset = -1;
}

static int run(pre_classify_fn fn, uint64_t n, uint32_t detected) {
	fixture_t f;
	fixture_open(&f, n, detected);
	int rc = fn(&f.ipacket.pub, 0);
	fixture_close(&f);
	return rc;
}

static void sweep(const char *name, pre_classify_fn fn) {
	for (uint64_t n = 1; n <= LAST_CLASSIFIED_PACKET + 1; n++) {
		int rc = run(fn, n, PROTO_UNKNOWN);
		if (n <= LAST_CLASSIFIED_PACKET)
			CHECK(rc == MMT_CLASSIFY_CONTINUE,
			      "%s: unknown flow packet %llu returned %d, want CONTINUE (%d)",
			      name, (unsigned long long) n, rc, MMT_CLASSIFY_CONTINUE);
		else
			CHECK(rc == MMT_CLASSIFY_SKIP,
			      "%s: unknown flow packet %llu returned %d, want SKIP (%d)",
			      name, (unsigned long long) n, rc, MMT_CLASSIFY_SKIP);
	}
	int rc = run(fn, 1000, PROTO_UNKNOWN);
	CHECK(rc == MMT_CLASSIFY_SKIP,
	      "%s: unknown flow packet 1000 returned %d, want SKIP", name, rc);
	rc = run(fn, LAST_CLASSIFIED_PACKET + 1, PROTO_FTP);
	CHECK(rc == MMT_CLASSIFY_CONTINUE,
	      "%s: classified (FTP) flow packet 41 returned %d, want CONTINUE", name, rc);
	rc = run(fn, 1000, PROTO_FTP);
	CHECK(rc == MMT_CLASSIFY_CONTINUE,
	      "%s: classified (FTP) flow packet 1000 returned %d, want CONTINUE", name, rc);
}

int main(void) {
	int64_t outstanding0 = tcm_outstanding;
	printf("issue #99 / #526: unknown-TCP give-up after packet %u"
	       " (2 x CFG_CLASSIFICATION_THRESHOLD = %d)\n",
	       LAST_CLASSIFIED_PACKET, CFG_CLASSIFICATION_THRESHOLD * 2);
	sweep("tcp_pre_classification_function", tcp_pre_classification_function);
	sweep("tcp_pre_classification_function_with_reassemble",
	      tcp_pre_classification_function_with_reassemble);
	CHECK(tcm_outstanding == outstanding0, "%lld allocation(s) outstanding",
	      (long long) (tcm_outstanding - outstanding0));
	printf("%d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
