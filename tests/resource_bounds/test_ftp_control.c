/*
 * test_ftp_control.c — issue #563 (F-PERF-106): the per-handler FTP
 * control-session state stays bounded by the live control flows.
 *
 * Before the fix every control session ever seen stayed in a per-handler
 * singly linked list, appended after an O(N) tail walk and never unlinked
 * (FTP registered no session-data cleanup), so N sessions cost N(N-1)/2
 * list visits to open and the list only shrank at handler close, where a
 * recursive free took one stack frame per session.
 *
 *   A. Flat per-session cost — 1,000 and then 100,000 control flows each
 *      receive a server greeting through ftp_session_data_analysis(). Every
 *      open is an O(1) tail append (0 list visits; the old walk visited
 *      4,999,950,000 nodes at 100k), and the large scale makes exactly 100x
 *      the small scale's allocator calls.
 *   B. Expiry — ftp_session_data_cleanup(), the cleanup the core calls when
 *      a flow times out, unlinks each control session, in a fixed-seed
 *      shuffled order (splitmix64 + Fisher-Yates, so interior nodes leave
 *      the list, not only its head or tail): the live list holds
 *      100,000 sessions after the opens, and 0 (walked and counted) after
 *      the expiries; a data-connection lookup visits 100,000 nodes before
 *      and 0 after; every allocation is returned.
 *   C. Data-flow lifetime — 1,000 passive transfers (227 reply, then a data
 *      flow that attaches to the control session's data session). For half
 *      the control flow expires first: its session moves to the retired
 *      list, the data flow's next packet still reads it (ASan would flag a
 *      use after free), and the data flow's expiry frees it — or, for every
 *      fourth transfer, a non-matching packet detaches the data flow and the
 *      analysis frees it. For the other half the data flow expires first.
 *      Both lists end empty, nothing leaks.
 *   D. Teardown — 100,000 live sessions are released by cleanup_ftp_context()
 *      iteratively, with every allocation returned.
 *
 * Expiry goes through the cleanup init_proto_ftp_struct() registers (the
 * registration stub records it), as cleanup_timedout_sessions() would.
 * The proto_ftp*.c units are compiled beside this TU with -DMMT_FTP_LIST_STATS
 * (the lookup visit counter) and the counted allocator of the tcp-memory
 * fixture (-Dmalloc=tcm_malloc ...); the mmt_core and plugin symbols they
 * reference are stubbed below — only the FTP session code is driven.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "plugin_defs.h"
#include "mmt_core.h"
#include "extraction_lib.h"
#include "../../src/mmt_tcpip/lib/mmt_common_internal_include.h"
#include "../../src/mmt_tcpip/lib/protocols/ftp.h"

#include "tcp_alloc_count.h"
#include "rb_result.h"

#define RB "ftp-control"   /* results.json fixture id */

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

#define SMALL     1000u
#define LARGE     100000u
#define TRANSFERS 1000u
#define IDX       4u            /* FTP's position in the protocol path */
#define ORDER_SEED 0x5eed0563f7c0de00ULL /* expiry-order shuffle */

extern uint64_t mmt_ftp_list_visits;
void *setup_ftp_context(void *proto_context, void *args);
void cleanup_ftp_context(void *proto_context, void *args);
int ftp_session_data_analysis(ipacket_t *ipacket, unsigned index);
int init_proto_ftp_struct(void);

/* ---- stubs: the core/plugin symbols the FTP units reference ---- */

int get_packet_offset_at_index(const ipacket_t *ipacket, unsigned index) {
	(void) ipacket; (void) index;
	return 0;                   /* the crafted packets hold only the payload */
}
static protocol_t g_protocol;
protocol_t *init_protocol_struct_for_registration(mmt_proto_id_t proto_id, const char *protocol_name) {
	(void) proto_id; (void) protocol_name;
	return &g_protocol;
}
bool register_attribute_with_protocol(protocol_t *p, attribute_metadata_t *m) {
	(void) p; (void) m;
	return 0;
}
void register_proto_context_init_cleanup_function(protocol_t *p, generic_proto_context_init_function i,
		generic_proto_context_cleanup_function c, mmt_opaque_t a) {
	(void) p; (void) i; (void) c; (void) a;
}
bool register_session_data_analysis_function(protocol_t *p, generic_session_data_analysis_function f) {
	(void) p; (void) f;
	return 0;
}
static generic_session_data_cleanup_function g_registered_cleanup;
void register_session_data_cleanup_function(protocol_t *p, generic_session_data_cleanup_function f) {
	(void) p;
	g_registered_cleanup = f;   /* what the core's expiry would call */
}
bool register_protocol(protocol_t *p, mmt_proto_id_t proto_id) {
	(void) p; (void) proto_id;
	return 0;
}
uint32_t mmt_bytestream_to_number(const uint8_t *str, uint16_t max_chars_to_read, uint16_t *bytes_read) {
	(void) str; (void) max_chars_to_read;
	if (bytes_read) *bytes_read = 0;
	return 0;
}
void mmt_internal_add_connection(ipacket_t *ipacket, uint16_t detected_protocol, mmt_protocol_type_t t) {
	(void) ipacket; (void) detected_protocol; (void) t;
}
bool mmt_packet_scratch_adopt(const ipacket_t *ipacket, mmt_opaque_t value,
		mmt_packet_scratch_release_function release) {
	(void) ipacket; (void) value; (void) release;
	return 0;
}

/* ---- one crafted packet at a time, on a borrowed session ---- */

static mmt_handler_t g_handler;
static mmt_session_t g_sess;
static ipacket_t g_pkt;
static mmt_tcpip_internal_packet_t g_ip;
static struct tcphdr g_tcp;
static struct iphdr g_iph;
static pkthdr_t g_hdr;
static proto_hierarchy_t g_hier;
static uint8_t g_buf[256];

static ftp_context_t *ctx(void) {
	return (ftp_context_t *) g_handler.configured_protocols[PROTO_FTP].args;
}

static void handler_open(void) {
	g_handler.configured_protocols[PROTO_FTP].args =
		setup_ftp_context(&g_handler.configured_protocols[PROTO_FTP], NULL);
	g_hier.len = IDX + 1;
	g_hier.proto_path[IDX] = PROTO_FTP;
	g_ip.tcp = &g_tcp;
	g_ip.iph = &g_iph;
	g_ip.payload = g_buf;
	g_pkt.mmt_handler = &g_handler;
	g_pkt.session = &g_sess;
	g_pkt.internal_packet = &g_ip;
	g_pkt.proto_hierarchy = &g_hier;
	g_pkt.p_hdr = &g_hdr;
	g_pkt.data = g_buf;
}

static void handler_close(void) {
	cleanup_ftp_context(&g_handler.configured_protocols[PROTO_FTP], NULL);
}

/* Each flow owns only its FTP session_data slot; the packet borrows the
 * one session record and swaps the slot in and out. */
static void packet(void **slot, uint64_t flow_id, uint32_t saddr, uint16_t sport,
		uint32_t daddr, uint16_t dport, const char *payload) {
	size_t len = strlen(payload);
	memcpy(g_buf, payload, len);
	g_buf[len] = '\0';
	g_ip.payload_packet_len = (uint16_t) len;
	g_hdr.caplen = (unsigned) len;
	g_iph.saddr = saddr;
	g_iph.daddr = daddr;
	g_tcp.source = htons(sport);
	g_tcp.dest = htons(dport);
	g_sess.session_id = flow_id;
	g_sess.session_data[IDX] = *slot;
	ftp_session_data_analysis(&g_pkt, IDX);
	*slot = g_sess.session_data[IDX];
	g_sess.session_data[IDX] = NULL;
}

/* What the core's expiry does for the FTP slot of a timed-out flow. */
static void expire(void **slot) {
	g_sess.session_data[IDX] = *slot;
	g_registered_cleanup(&g_sess, IDX);
	*slot = g_sess.session_data[IDX];
	g_sess.session_data[IDX] = NULL;
}

static uint64_t walk(const ftp_control_session_t *head) {
	uint64_t n = 0;
	for (const ftp_control_session_t *c = head->next; c != head; c = c->next) n++;
	return n;
}

#define SERVER    htonl(0xc0000201u)    /* 192.0.2.1 */
#define CLIENT(k) htonl(0x0a000000u + (uint32_t) (k))
#define CPORT     40000

/* Returns how many opens were O(1) tail appends: the new session is the
 * live list's tail and the count grew by one (a walk is not needed for
 * either, so this is structural rather than a visit count). */
static uint32_t open_controls(void **slots, uint32_t n) {
	uint32_t tail_appends = 0;
	for (uint32_t k = 0; k < n; k++) {
		uint64_t before = ctx()->live_count;
		packet(&slots[k], k + 1, SERVER, 21, CLIENT(k), CPORT, "220 ready\r\n");
		tail_appends += (slots[k] != NULL && ctx()->live.prev == slots[k]
		                 && ctx()->live_count == before + 1);
	}
	return tail_appends;
}

/* An unmatched data-connection packet: its lookup examines every live
 * control session. Returns the nodes it visited. */
static uint64_t probe_visits(void) {
	void *slot = NULL;
	uint64_t v0 = mmt_ftp_list_visits;
	packet(&slot, 0xffffffffu, htonl(0xc6336401u), 5555, htonl(0xc6336402u), 6666, "x");
	CHECK(slot == NULL, "the probe flow matched no control session");
	return mmt_ftp_list_visits - v0;
}

static uint64_t splitmix64(uint64_t *state) {
	uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

/* ---- A + B: flat per-session cost, the lists empty after expiry ---- */

static uint64_t open_and_expire(uint32_t n, const char *scale) {
	void **slots = calloc(n, sizeof(void *));
	uint32_t *order = calloc(n, sizeof(uint32_t));
	CHECK(slots != NULL && order != NULL, "slot and order arrays");
	if (slots == NULL || order == NULL) { free(slots); free(order); return 0; }
	uint64_t state = ORDER_SEED;
	for (uint32_t k = 0; k < n; k++) order[k] = k;
	for (uint32_t k = n - 1; k > 0; k--) {
		uint32_t j = (uint32_t) (splitmix64(&state) % (k + 1u));
		uint32_t t = order[k]; order[k] = order[j]; order[j] = t;
	}
	int64_t out0 = tcm_outstanding;
	uint64_t calls0 = tcm_calls, v0 = mmt_ftp_list_visits;
	uint32_t tail_appends = open_controls(slots, n);
	uint64_t calls = tcm_calls - calls0;
	uint64_t open_visits = mmt_ftp_list_visits - v0;
	uint32_t opened = 0;
	for (uint32_t k = 0; k < n; k++) opened += (slots[k] != NULL);
	uint64_t live = ctx()->live_count, walked = walk(&ctx()->live);
	uint64_t probe_open = probe_visits();
	for (uint32_t k = 0; k < n; k++) expire(&slots[order[k]]);
	uint64_t probe_expired = probe_visits();
	uint64_t live_after = ctx()->live_count + walk(&ctx()->live);
	uint64_t retired_after = ctx()->retired_count + walk(&ctx()->retired);
	int64_t leaked = tcm_outstanding - out0;

	CHECK(opened == n, "%s: %u of %u control flows hold a session", scale, opened, n);
	CHECK(live == n && walked == n, "%s: live %llu, walked %llu", scale,
	      (unsigned long long) live, (unsigned long long) walked);
	CHECK(open_visits == 0, "%s: opening visited %llu list nodes", scale, (unsigned long long) open_visits);
	CHECK(tail_appends == n, "%s: %u of %u opens were tail appends", scale, tail_appends, n);
	CHECK(probe_open == n, "%s: lookup over the open list visited %llu", scale, (unsigned long long) probe_open);
	CHECK(probe_expired == 0 && live_after == 0 && retired_after == 0,
	      "%s: after expiry probe %llu, live %llu, retired %llu", scale,
	      (unsigned long long) probe_expired, (unsigned long long) live_after,
	      (unsigned long long) retired_after);
	CHECK(leaked == 0, "%s: %lld allocations outstanding after expiry", scale, (long long) leaked);
	printf("    %s: %u sessions, %llu allocator calls to open, %llu open visits, "
	       "probe %llu -> %llu visits, live %llu -> %llu\n", scale, n,
	       (unsigned long long) calls, (unsigned long long) open_visits,
	       (unsigned long long) probe_open, (unsigned long long) probe_expired,
	       (unsigned long long) live, (unsigned long long) live_after);

	char key[64];
#define M(name, v) do { snprintf(key, sizeof(key), "%s." name, scale); rb_metric(RB, key, (v)); } while (0)
	M("sessions", n);
	M("opened", opened);
	M("alloc_calls", calls);
	M("open_visits", open_visits);
	M("tail_appends", tail_appends);
	M("live_peak", live);
	M("probe_visits_open", probe_open);
	M("probe_visits_expired", probe_expired);
	M("live_after_expiry", live_after);
	M("retired_after_expiry", retired_after);
	M("leaked_allocations", (uint64_t) (leaked < 0 ? -leaked : leaked));
#undef M
	free(slots);
	free(order);
	return calls;
}

/* ---- C: data flows outliving their control flow ---- */

static void data_lifetime(void) {
	static void *ctl[TRANSFERS], *dat[TRANSFERS];
	int64_t out0 = tcm_outstanding;
	uint32_t attached = 0, read_retired = 0;
	for (uint32_t k = 0; k < TRANSFERS; k++) {
		char reply[96];
		uint32_t port = 2000u + k;
		snprintf(reply, sizeof(reply), "227 Entering Passive Mode (192,0,2,1,%u,%u)\r\n",
		         port >> 8, port & 0xffu);
		packet(&ctl[k], k + 1, SERVER, 21, CLIENT(k), CPORT, "220 ready\r\n");
		packet(&ctl[k], k + 1, SERVER, 21, CLIENT(k), CPORT, reply);
		packet(&dat[k], 1000000u + k, SERVER, (uint16_t) port, CLIENT(k), 50000, "data");
		attached += (dat[k] != NULL && ((ftp_data_session_t *) dat[k])->control_session
		             == (ftp_control_session_t *) ctl[k]);
	}
	CHECK(attached == TRANSFERS, "%u of %u data flows attached to their control session",
	      attached, TRANSFERS);

	/* Even transfers: the control flow expires first. */
	for (uint32_t k = 0; k < TRANSFERS; k += 2) expire(&ctl[k]);
	uint64_t retired_peak = ctx()->retired_count, retired_walk = walk(&ctx()->retired);
	uint64_t live_mid = ctx()->live_count;
	for (uint32_t k = 0; k < TRANSFERS; k += 2) {
		uint32_t port = 2000u + k;
		void *before = dat[k];
		packet(&dat[k], 1000000u + k, SERVER, (uint16_t) port, CLIENT(k), 50000, "more");
		read_retired += (dat[k] == before && before != NULL);
	}
	/* Every fourth transfer: the data flow's next packet no longer matches
	 * its retired data session and no live one (a new transfer's tuple), so
	 * the analysis detaches it — dropping the last reference frees the
	 * retired control session there, not at expiry. */
	uint64_t retired_before_detach = ctx()->retired_count;
	uint32_t detached = 0;
	for (uint32_t k = 0; k < TRANSFERS; k += 4) {
		packet(&dat[k], 1000000u + k, SERVER, 9, CLIENT(k), 50001, "other");
		detached += (dat[k] == NULL);
	}
	uint64_t freed_by_detach = retired_before_detach - ctx()->retired_count;
	for (uint32_t k = 0; k < TRANSFERS; k += 2) expire(&dat[k]);
	/* Odd transfers: the data flow expires first. */
	for (uint32_t k = 1; k < TRANSFERS; k += 2) expire(&dat[k]);
	for (uint32_t k = 1; k < TRANSFERS; k += 2) expire(&ctl[k]);
	uint64_t live_after = ctx()->live_count + walk(&ctx()->live);
	uint64_t retired_after = ctx()->retired_count + walk(&ctx()->retired);
	int64_t leaked = tcm_outstanding - out0;

	CHECK(retired_peak == TRANSFERS / 2 && retired_walk == TRANSFERS / 2,
	      "retired %llu (walked %llu) after the even control flows expired",
	      (unsigned long long) retired_peak, (unsigned long long) retired_walk);
	CHECK(live_mid == TRANSFERS / 2, "live %llu after the even control flows expired",
	      (unsigned long long) live_mid);
	CHECK(read_retired == TRANSFERS / 2, "%u data flows kept their retired data session", read_retired);
	CHECK(detached == TRANSFERS / 4 && freed_by_detach == TRANSFERS / 4,
	      "%u data flows detached, %llu retired sessions freed by the detach", detached,
	      (unsigned long long) freed_by_detach);
	CHECK(live_after == 0 && retired_after == 0, "lists end with live %llu, retired %llu",
	      (unsigned long long) live_after, (unsigned long long) retired_after);
	CHECK(leaked == 0, "%lld allocations outstanding after the transfers", (long long) leaked);
	printf("    transfers: %u attached, retired peak %llu, %u data packets on retired sessions, "
	       "live/retired after %llu/%llu, leaked %lld\n", attached,
	       (unsigned long long) retired_peak, read_retired, (unsigned long long) live_after,
	       (unsigned long long) retired_after, (long long) leaked);
	rb_metric(RB, "transfers.sessions", TRANSFERS);
	rb_metric(RB, "transfers.attached", attached);
	rb_metric(RB, "transfers.retired_peak", retired_peak);
	rb_metric(RB, "transfers.read_retired", read_retired);
	rb_metric(RB, "transfers.detached", detached);
	rb_metric(RB, "transfers.freed_by_detach", freed_by_detach);
	rb_metric(RB, "transfers.lists_after", live_after + retired_after);
	rb_metric(RB, "transfers.leaked_allocations", (uint64_t) (leaked < 0 ? -leaked : leaked));
}

/* ---- D: teardown of a full list, without recursion ---- */

static void teardown(int64_t out_before_open) {
	void **slots = calloc(LARGE, sizeof(void *));
	CHECK(slots != NULL, "slot array");
	if (slots == NULL) return;
	(void) open_controls(slots, LARGE);
	uint64_t live = ctx()->live_count;
	handler_close();
	free(slots);
	int64_t leaked = tcm_outstanding - out_before_open;
	CHECK(live == LARGE, "teardown: %llu live sessions", (unsigned long long) live);
	CHECK(leaked == 0, "teardown: %lld allocations outstanding", (long long) leaked);
	printf("    teardown: %llu live sessions released, leaked %lld\n",
	       (unsigned long long) live, (long long) leaked);
	rb_metric(RB, "teardown.sessions", live);
	rb_metric(RB, "teardown.leaked_allocations", (uint64_t) (leaked < 0 ? -leaked : leaked));
}

int main(void) {
	printf("test_ftp_control: FTP control-session state bounded by live flows (issue #563)\n");
	int64_t out0 = tcm_outstanding;
	handler_open();
	CHECK(ctx() != NULL, "FTP context");
	if (ctx() == NULL) return 1;
	/* The registration the core's session expiry goes through: expire()
	 * calls whatever FTP registered, so dropping the registration fails
	 * every expiry check below. */
	(void) init_proto_ftp_struct();
	CHECK(g_registered_cleanup == ftp_session_data_cleanup, "FTP registers its session-data cleanup");
	if (g_registered_cleanup == NULL) return 1;

	rb_seed(RB, "expiry_order.splitmix64", ORDER_SEED);
	uint64_t small = open_and_expire(SMALL, "small");
	uint64_t large = open_and_expire(LARGE, "large");
	CHECK(large == (uint64_t) (LARGE / SMALL) * small,
	      "per-session allocator calls: %llu at %u vs %llu at %u", (unsigned long long) large,
	      LARGE, (unsigned long long) small, SMALL);
	data_lifetime();
	teardown(out0);

	rb_metric(RB, "checks.failed", (uint64_t) failures);
	printf("  %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
