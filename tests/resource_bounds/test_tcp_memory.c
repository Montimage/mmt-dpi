/*
 * test_tcp_memory.c — issue #380 (F-PERF-002): TCP reassembly must reject
 * duplicate segments before allocating, and cap RESERVED storage (blocks
 * incl. headers + image capacities), not only content bytes.
 *
 *   A. AC1 — 1,024 retained one-byte segments, each followed by 169
 *      duplicates (174,080 offers; duplicates aimed at the tail, the head
 *      and an interior node). Every duplicate offer leaves the allocator
 *      call count, the block count, the bump offset and the reserved gauge
 *      unchanged; the whole workload makes exactly as many allocator calls
 *      as the same 1,024 offers without duplicates; reserved storage is the
 *      7-block minimum (114,912 B on LP64) instead of 1,024 blocks.
 *   B. AC2 — with the 4 MiB budget, r->reserved equals a walk of the block
 *      chain (header + cap) plus both image capacities and never exceeds
 *      4,194,304 after ANY operation: the AC1 workload, undrained 8,129-B
 *      segments to exhaustion, two-direction images, image-plus-pending
 *      fill with rare drains (every admitted byte is flattened, in order,
 *      with no gap), and a limit lowered mid-flow.
 *   C. Teardown — clean_session_payload() returns every allocation.
 *   D. OOM — a failed first block drops the segment; a failed image
 *      realloc leaves the segment pending; neither leaks.
 *   E. Fairness (review follow-up) — after one direction's image grows
 *      past 1 MiB (keep-alive) or stops (idle peer), the other direction
 *      is still admitted until content nears the budget; a single stream
 *      filled to the budget reallocates its image a bounded number of times;
 *      randomized two-direction offers/drains at 64 KiB keep
 *      reserved + owed[0] + owed[1] <= limit after every offer; an emptied
 *      head block a larger carve does not fit is freed, never stranded.
 *
 * proto_tcp.c and tcp_segment.c are included directly so the static
 * reassembly helpers run unmodified (tests/parser_boundaries/
 * test_udp_bounds_unit.c convention); the mmt_core symbols proto_tcp.c
 * references are stubbed below. The TU is compiled with
 * -Dmalloc=tcm_malloc ... so allocations are counted in tcp_alloc_count.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/mmt_tcpip/lib/protocols/proto_tcp.c"
#include "../../src/mmt_tcpip/lib/protocols/tcp_segment.c"

#include "tcp_alloc_count.h"

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

#define BUDGET        (4u * 1024u * 1024u)   /* 4,194,304 B */
#define PREFIX_MODEL  16809984ull            /* HEAD: 1,024 x (32 + 16,384) */

/* ---- reassembly gauges (normally mmt_core/packet_pipeline.c) ---- */

static uint64_t g_visits, g_moved, g_dropped;
static int64_t g_live;
void mmt_tcp_reasm_stat_visit(void) { g_visits++; }
void mmt_tcp_reasm_stat_move(uint32_t bytes) { g_moved += bytes; }
void mmt_tcp_reasm_stat_drop(uint32_t bytes) { g_dropped += bytes; }
void mmt_tcp_reasm_stat_live(int64_t delta) { g_live += delta; }

/* ---- link stubs: proto_tcp.c's classification/registration paths are
 * never driven here, only its reassembly helpers ---- */

int get_packet_offset_at_index(const ipacket_t *ipacket, unsigned index) {
	(void) ipacket; (void) index;
	return -1;
}
int set_classified_proto(ipacket_t *ipacket, unsigned index, classified_proto_t p) {
	(void) ipacket; (void) index; (void) p;
	return 0;
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
	(void) ipacket; (void) proto_id; (void) attribute_id; (void) index; (void) data;
}
void set_session_timeout_delay(mmt_session_t *session, uint32_t timeout_delay) {
	(void) session; (void) timeout_delay;
}
int general_short_extraction_with_ordering_change(const ipacket_t *packet,
		mmt_proto_index_t proto_index, attribute_t *extracted_data) {
	(void) packet; (void) proto_index; (void) extracted_data;
	return 0;
}
int general_int_extraction_with_ordering_change(const ipacket_t *packet,
		mmt_proto_index_t proto_index, attribute_t *extracted_data) {
	(void) packet; (void) proto_index; (void) extracted_data;
	return 0;
}
protocol_t *get_protocol_struct_by_id(mmt_proto_id_t proto_id) {
	(void) proto_id;
	return NULL;
}
protocol_t *init_protocol_struct_for_registration(uint32_t proto_id,
		const char *protocol_name) {
	(void) proto_id; (void) protocol_name;
	return NULL;
}
bool register_protocol(protocol_t *protocol_struct, uint32_t proto_id) {
	(void) protocol_struct; (void) proto_id;
	return 0;
}
bool register_attribute_with_protocol(protocol_t *protocol_struct,
		attribute_metadata_t *attribute_metadata) {
	(void) protocol_struct; (void) attribute_metadata;
	return 0;
}
bool register_pre_post_classification_functions(protocol_t *protocol_struct,
		generic_classification_function pre_classification,
		generic_classification_function post_classification) {
	(void) protocol_struct; (void) pre_classification; (void) post_classification;
	return 0;
}
void register_session_data_cleanup_function(protocol_t *protocol_struct,
		generic_session_data_cleanup_function fct) {
	(void) protocol_struct; (void) fct;
}

/* ---- fixture ---- */

static mmt_handler_t g_handler;
static mmt_session_t g_session;
static uint64_t g_peak_reserved;

static void session_open(uint32_t limit) {
	memset(&g_session, 0, sizeof(g_session));
	g_handler.tcp_reassembly_limit = limit;
	g_session.mmt_handler = &g_handler;
}

static uint32_t chain_blocks(const mmt_tcp_reasm_t *r, uint64_t *bytes) {
	uint32_t n = 0;
	uint64_t b = 0;
	for (const mmt_segblk_t *k = r->blocks; k != NULL; k = k->next) {
		n++;
		b += MMT_SEGBLK_HDR + k->cap;
	}
	if (bytes) *bytes = b;
	return n;
}

static uint32_t pending_count(const mmt_tcp_reasm_t *r, int dir) {
	uint32_t n = 0;
	for (const tcp_seg_t *s = r->seg_head[dir]; s != NULL; s = s->next) n++;
	return n;
}

/* Reserved-storage invariant, checked after every operation (AC2). The
 * failure count is capped so a regression does not flood the log. */
static int g_budget_fail_reports;
static void check_budget(const char *what) {
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	if (r == NULL) return;
	uint64_t blocks;
	chain_blocks(r, &blocks);
	uint64_t walked = blocks + r->image_cap[0] + r->image_cap[1];
	if (walked > g_peak_reserved) g_peak_reserved = walked;
	/* Only the head (bump target) may sit empty; any other block with no
	 * live carve is stranded reserved storage. */
	uint32_t stranded = 0;
	if (r->blocks != NULL)
		for (const mmt_segblk_t *k = r->blocks->next; k != NULL; k = k->next)
			stranded += (k->live == 0);
	int ok = (walked == r->reserved) && (walked <= g_handler.tcp_reassembly_limit)
	         && (r->live <= walked) && stranded == 0;
	checks++;
	if (!ok) {
		failures++;
		if (g_budget_fail_reports++ < 5)
			fprintf(stderr, "FAIL budget (%s): walked %llu (blocks %llu + images %u/%u), "
			        "reserved %llu, live %llu, limit %u, stranded %u\n", what,
			        (unsigned long long) walked, (unsigned long long) blocks,
			        r->image_cap[0], r->image_cap[1],
			        (unsigned long long) r->reserved, (unsigned long long) r->live,
			        g_handler.tcp_reassembly_limit, stranded);
	}
}

static uint8_t pattern(int dir, uint64_t off) {
	return (uint8_t) ((off * 131u + (uint64_t) dir * 7u + (off >> 8)) & 0xffu);
}

static uint8_t g_seg_buf[65536];

/* Offer one segment carrying stream bytes [off, off+len) of direction dir;
 * returns 1 when it was admitted (the dropped gauge did not move). */
static int offer(int dir, uint32_t seq, uint64_t off, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) g_seg_buf[i] = pattern(dir, off + i);
	uint64_t d0 = g_dropped;
	tcp_reasm_offer(&g_session, dir, 1, seq, 0, g_seg_buf, len);
	check_budget("offer");
	/* Admission invariant: the drain can always absorb what was admitted. */
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	if (r != NULL) {
		uint64_t tot = r->reserved + tcp_reasm_owed(r, 0) + tcp_reasm_owed(r, 1);
		checks++;
		if (tot > g_handler.tcp_reassembly_limit) {
			failures++;
			if (g_budget_fail_reports++ < 5)
				fprintf(stderr, "FAIL admission: reserved %llu + owed %llu/%llu > limit %u\n",
				        (unsigned long long) r->reserved,
				        (unsigned long long) tcp_reasm_owed(r, 0),
				        (unsigned long long) tcp_reasm_owed(r, 1),
				        g_handler.tcp_reassembly_limit);
		}
	}
	return g_dropped == d0;
}

static void drain(int dir) {
	tcp_reasm_drain(&g_session, dir);
	check_budget("drain");
}

static void teardown(int64_t outstanding0, const char *what) {
	clean_session_payload(&g_session, 0);
	CHECK(g_session.tcp_reasm == NULL, "%s: tcp_reasm not released", what);
	CHECK(tcm_outstanding == outstanding0,
	      "%s: %lld allocation(s) outstanding after teardown", what,
	      (long long) (tcm_outstanding - outstanding0));
	CHECK(g_live == 0, "%s: live gauge %lld after teardown", what, (long long) g_live);
}

/* ------------------------------------------------------------------ */
/* A + B1 — AC1 duplicate workload                                     */
/* ------------------------------------------------------------------ */

#define AC1_SEGS 1024u
#define AC1_DUPS 169u

static uint64_t run_retained(int with_dups, uint64_t *reserved_out, uint32_t *blocks_out) {
	const uint32_t S = 5000;
	int64_t o0 = tcm_outstanding;
	uint64_t c0 = tcm_calls;
	uint64_t d0 = g_dropped;
	uint32_t dup_viol = 0;
	session_open(BUDGET);
	for (uint32_t i = 0; i < AC1_SEGS; i++) {
		CHECK(offer(0, S + i, i, 1), "retained seg %u dropped", i);
		if (!with_dups) continue;
		for (uint32_t k = 0; k < AC1_DUPS; k++) {
			/* tail duplicates dominate; every 5th hits the head and every
			 * 7th an interior node (locate walk). */
			uint32_t t = i;
			if (k % 5 == 1) t = 0;
			else if (k % 7 == 2 && i >= 2) t = i / 2;
			const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
			uint64_t calls = tcm_calls;
			uint32_t nblk = chain_blocks(r, NULL);
			uint32_t used = r->blocks ? r->blocks->used : 0;
			uint64_t res = r->reserved, live = r->live;
			CHECK(!offer(0, S + t, t, 1), "duplicate of seq %u admitted", S + t);
			if (tcm_calls != calls || chain_blocks(r, NULL) != nblk
			    || (r->blocks ? r->blocks->used : 0) != used
			    || r->reserved != res || r->live != live) {
				if (dup_viol++ < 5)
					fprintf(stderr, "  duplicate offer %u/%u (seq %u) touched storage: "
					        "calls +%llu, blocks %u->%u, head used %u->%u, reserved %llu->%llu\n",
					        i, k, S + t, (unsigned long long) (tcm_calls - calls),
					        nblk, chain_blocks(r, NULL), used,
					        r->blocks ? r->blocks->used : 0,
					        (unsigned long long) res, (unsigned long long) r->reserved);
			}
		}
	}
	uint64_t calls = tcm_calls - c0;
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	*reserved_out = r->reserved;
	*blocks_out = chain_blocks(r, NULL);
	if (with_dups) {
		CHECK(dup_viol == 0, "%u duplicate offers allocated or burned block space", dup_viol);
		CHECK(g_dropped - d0 == (uint64_t) AC1_SEGS * AC1_DUPS,
		      "dropped %llu B, expected %u", (unsigned long long) (g_dropped - d0),
		      AC1_SEGS * AC1_DUPS);
		CHECK(r->dropped == (uint64_t) AC1_SEGS * AC1_DUPS, "r->dropped %llu",
		      (unsigned long long) r->dropped);
	}
	CHECK(pending_count(r, 0) == AC1_SEGS, "pending %u != %u", pending_count(r, 0), AC1_SEGS);
	/* Flatten: every retained byte, in order, exactly once. */
	drain(0);
	r = g_session.tcp_reasm;
	CHECK(r->image_len[0] == AC1_SEGS, "image_len %u", r->image_len[0]);
	for (uint32_t i = 0; i < r->image_len[0]; i++) {
		if (r->image[0][i] != pattern(0, i)) {
			CHECK(0, "image[%u] mismatch", i);
			break;
		}
	}
	teardown(o0, with_dups ? "AC1 duplicates" : "AC1 baseline");
	return calls;
}

static void test_ac1(void) {
	uint64_t res_dup, res_base;
	uint32_t blk_dup, blk_base;
	uint32_t carve = MMT_SEGBLK_ALIGN_UP(sizeof(tcp_seg_t)) + MMT_SEGBLK_ALIGN_UP(1);
	uint32_t per_blk = MMT_SEGBLK_PAYLOAD / carve;
	uint32_t want_blk = (AC1_SEGS + per_blk - 1) / per_blk;
	uint64_t want_res = (uint64_t) want_blk * (MMT_SEGBLK_HDR + MMT_SEGBLK_PAYLOAD);

	uint64_t v0 = g_visits;
	uint64_t calls_dup = run_retained(1, &res_dup, &blk_dup);
	uint64_t visits = g_visits - v0;
	uint64_t calls_base = run_retained(0, &res_base, &blk_base);

	/* Counted over the offers only (the drain comes after). */
	CHECK(calls_dup == calls_base,
	      "workload made %llu allocator calls, %llu without duplicates",
	      (unsigned long long) calls_dup, (unsigned long long) calls_base);
	CHECK(calls_base == 1u + want_blk,
	      "baseline made %llu allocator calls, expected %u (state + %u blocks)",
	      (unsigned long long) calls_base, 1u + want_blk, want_blk);
	CHECK(blk_dup == want_blk && blk_base == want_blk,
	      "blocks %u (baseline %u), expected %u", blk_dup, blk_base, want_blk);
	CHECK(res_dup == want_res, "reserved %llu B before drain, expected %llu",
	      (unsigned long long) res_dup, (unsigned long long) want_res);
	if (sizeof(tcp_seg_t) == 80)
		CHECK(res_dup == 114912u, "LP64 reserved %llu != 114,912", (unsigned long long) res_dup);
	CHECK(visits > 0, "interior duplicates never walked the list");

	printf("  AC1: %u offers (%u retained), allocator calls %llu (baseline %llu),\n"
	       "       blocks %u, reserved %llu B (pre-fix model %llu B), locate visits %llu\n",
	       AC1_SEGS * (AC1_DUPS + 1), AC1_SEGS,
	       (unsigned long long) calls_dup, (unsigned long long) calls_base,
	       blk_dup, (unsigned long long) res_dup, PREFIX_MODEL,
	       (unsigned long long) visits);
	printf("       storage: blocks %llu B (headers %u B) + images 0 B = reserved %llu B;"
	       " content %u B\n",
	       (unsigned long long) res_dup, blk_dup * MMT_SEGBLK_HDR,
	       (unsigned long long) res_dup, AC1_SEGS * carve);
	printf("       metadata (outside the budget): mmt_tcp_reasm_t %zu B, node headers"
	       " %u x %u B inside the carves\n",
	       sizeof(mmt_tcp_reasm_t), AC1_SEGS, (unsigned) MMT_SEGBLK_ALIGN_UP(sizeof(tcp_seg_t)));
}

/* ------------------------------------------------------------------ */
/* B2 — undrained 8,129-B segments until the budget is exhausted       */
/* ------------------------------------------------------------------ */

/* Verify that direction `dir`'s image is exactly the admitted segments
 * (offsets recorded in adm[], each `len` bytes) concatenated in order. */
static int image_matches(int dir, const uint64_t *adm, uint32_t nadm, uint32_t len) {
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	if ((uint64_t) r->image_len[dir] != (uint64_t) nadm * len) return 0;
	for (uint32_t k = 0; k < nadm; k++)
		for (uint32_t i = 0; i < len; i++)
			if (r->image[dir][(uint64_t) k * len + i] != pattern(dir, adm[k] + i))
				return 0;
	return 1;
}

static uint64_t g_adm[2][16384];

static void test_large_exhaustion(void) {
	const uint32_t LEN = 8129, N = 2000;
	int64_t o0 = tcm_outstanding;
	uint64_t d0 = g_dropped;
	uint32_t nadm = 0;
	g_peak_reserved = 0;
	session_open(BUDGET);
	for (uint32_t i = 0; i < N; i++) {
		uint64_t off = (uint64_t) i * LEN;
		if (offer(0, 1 + (uint32_t) off, off, LEN)) g_adm[0][nadm++] = off;
	}
	uint64_t peak = g_peak_reserved;
	CHECK(nadm > 0 && nadm < N, "admitted %u of %u", nadm, N);
	CHECK(g_dropped - d0 == (uint64_t) (N - nadm) * LEN, "exhaustion drops not counted");
	uint64_t dd = g_dropped;
	drain(0);
	CHECK(g_dropped == dd, "drain dropped %llu admitted bytes",
	      (unsigned long long) (g_dropped - dd));
	CHECK(g_session.tcp_reasm->seg_head[0] == NULL, "drain left segments pending");
	CHECK(image_matches(0, g_adm[0], nadm, LEN), "image is not the admitted stream");
	printf("  8,129-B exhaustion: admitted %u/%u, peak reserved %llu B (<= %u),"
	       " image %u B\n", nadm, N, (unsigned long long) peak, BUDGET,
	       g_session.tcp_reasm->image_len[0]);
	teardown(o0, "large exhaustion");
}

/* ------------------------------------------------------------------ */
/* B3/B4 — two-direction images and image-plus-pending fill            */
/* ------------------------------------------------------------------ */

static void run_stream(const char *name, int dirs, uint32_t len, uint32_t n,
                       uint32_t drain_every) {
	int64_t o0 = tcm_outstanding;
	uint32_t nadm[2] = {0, 0};
	uint64_t drain_drops = 0;
	g_peak_reserved = 0;
	session_open(BUDGET);
	for (uint32_t i = 0; i < n; i++) {
		for (int d = 0; d < dirs; d++) {
			uint64_t off = (uint64_t) i * len;
			if (offer(d, 7 + (uint32_t) off, off, len) && nadm[d] < 16384)
				g_adm[d][nadm[d]++] = off;
		}
		if ((i + 1) % drain_every == 0) {
			for (int d = 0; d < dirs; d++) {
				uint64_t dd = g_dropped;
				drain(d);
				drain_drops += g_dropped - dd;
			}
		}
	}
	for (int d = 0; d < dirs; d++) {
		uint64_t dd = g_dropped;
		drain(d);
		drain_drops += g_dropped - dd;
	}
	CHECK(drain_drops == 0, "%s: drain dropped %llu admitted bytes", name,
	      (unsigned long long) drain_drops);
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	for (int d = 0; d < dirs; d++) {
		CHECK(r->seg_head[d] == NULL, "%s: dir %d still pending", name, d);
		CHECK(image_matches(d, g_adm[d], nadm[d], len),
		      "%s: dir %d image has gaps or foreign bytes", name, d);
	}
	CHECK(nadm[0] < n, "%s: budget never refused an offer", name);
	printf("  %s: admitted %u+%u of %u x %u B, images %u+%u B (caps %u+%u),"
	       " peak reserved %llu B\n", name, nadm[0], nadm[1], n, len,
	       r->image_len[0], r->image_len[1], r->image_cap[0], r->image_cap[1],
	       (unsigned long long) g_peak_reserved);
	teardown(o0, name);
}

/* ------------------------------------------------------------------ */
/* B5 — limit lowered mid-flow                                         */
/* ------------------------------------------------------------------ */

static void test_lowered_limit(void) {
	const uint32_t LEN = 1460, LOW = 1024u * 1024u;
	int64_t o0 = tcm_outstanding;
	session_open(BUDGET);
	uint32_t i = 0, pend = 0;
	/* ~1.7 MiB of pending segments (~2 MiB of blocks) under 4 MiB. */
	for (; i < 1200; i++)
		pend += offer(0, 1 + i * LEN, (uint64_t) i * LEN, LEN) ? LEN : 0;
	mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	uint64_t res_hi = r->reserved;
	CHECK(pend == 1200u * LEN, "setup: only %u B admitted", pend);

	g_handler.tcp_reassembly_limit = LOW;   /* set_tcp_reassembly_limit() */
	uint64_t calls = tcm_calls;
	for (uint32_t k = 0; k < 64; k++, i++) {
		uint64_t d0 = g_dropped;
		tcp_reasm_offer(&g_session, 0, 1, 1 + i * LEN, 0, g_seg_buf, LEN);
		CHECK(g_dropped - d0 == LEN, "offer admitted over a lowered limit");
		CHECK(r->reserved == res_hi, "reserved moved over a lowered limit");
	}
	CHECK(tcm_calls == calls, "offers over a lowered limit allocated");

	uint64_t d0 = g_dropped;
	tcp_reasm_drain(&g_session, 0);
	uint64_t walked;
	chain_blocks(r, &walked);
	walked += r->image_cap[0] + r->image_cap[1];
	CHECK(walked == r->reserved, "reserved %llu != walked %llu after drain",
	      (unsigned long long) r->reserved, (unsigned long long) walked);
	CHECK(r->seg_head[0] == NULL, "drain wedged: segments left pending");
	CHECK(r->image_len[0] + (g_dropped - d0) == pend,
	      "drain lost bytes: image %u + dropped %llu != pending %u",
	      r->image_len[0], (unsigned long long) (g_dropped - d0), pend);
	CHECK(r->reserved <= LOW, "reserved %llu over the lowered limit after drain",
	      (unsigned long long) r->reserved);
	/* The image only grows once released blocks bring usage under the
	 * lowered budget, so the oldest pending bytes are the ones dropped —
	 * bounded and counted above, never a wedged drain. */
	CHECK(r->image_len[0] > 0 && r->image_len[0] < pend,
	      "lowered-limit drain image %u B of %u", r->image_len[0], pend);
	/* Usage is back under the lowered budget: further offers keep it. */
	for (uint32_t k = 0; k < 64; k++, i++)
		offer(0, 1 + i * LEN, (uint64_t) i * LEN, LEN);
	printf("  lowered limit: %llu B reserved at 4 MiB, drained to image %u B"
	       " (%u B dropped), reserved %llu B (<= %u)\n", (unsigned long long) res_hi,
	       r->image_len[0], pend - r->image_len[0], (unsigned long long) r->reserved, LOW);
	teardown(o0, "lowered limit");
}

/* ------------------------------------------------------------------ */
/* E — cross-direction fairness (#380 review): one direction's image   */
/* capacity must not starve the other while content is far below the  */
/* budget, and growth stays amortized.                                 */
/* ------------------------------------------------------------------ */

/* Slack for block headers, the recycled head block and 16-B rounding. */
#define FAIR_MARGIN (256u * 1024u)

static uint64_t g_fair_off[2];
static uint32_t g_fair_refused, g_fair_growths;

/* Offer the next `len` stream bytes of `dir` and drain it (an extraction
 * per packet). An offer must be admitted while the flow's content plus
 * this carve and FAIR_MARGIN still fits the budget. */
static void fair_step(int dir, uint32_t len) {
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	uint32_t carve = MMT_SEGBLK_ALIGN_UP(sizeof(tcp_seg_t)) + MMT_SEGBLK_ALIGN_UP(len);
	uint64_t live = (r != NULL) ? r->live : 0;
	uint32_t cap = (r != NULL) ? r->image_cap[dir] : 0;
	int must = live + carve + FAIR_MARGIN <= BUDGET;
	uint64_t off = g_fair_off[dir];
	if (offer(dir, 11 + (uint32_t) off, off, len)) g_fair_off[dir] += len;
	else if (must && g_fair_refused++ < 5)
		fprintf(stderr, "  dir %d refused %u B at content %llu B (caps %u/%u, reserved %llu)\n",
		        dir, len, (unsigned long long) live, g_session.tcp_reasm->image_cap[0],
		        g_session.tcp_reasm->image_cap[1],
		        (unsigned long long) g_session.tcp_reasm->reserved);
	else if (must) g_fair_refused++;
	drain(dir);
	if (g_session.tcp_reasm->image_cap[dir] != cap) g_fair_growths++;
}

static void fair_open(void) {
	g_fair_off[0] = g_fair_off[1] = 0;
	g_fair_refused = g_fair_growths = 0;
	session_open(BUDGET);
}

static void fair_close(const char *name, int64_t o0) {
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	for (int d = 0; d < 2; d++) {
		uint32_t n = (uint32_t) g_fair_off[d];
		int ok = r->image_len[d] == g_fair_off[d];
		for (uint32_t i = 0; ok && i < n; i++) ok = r->image[d][i] == pattern(d, i);
		CHECK(ok, "%s: dir %d image is not the admitted stream", name, d);
	}
	CHECK(g_fair_refused == 0, "%s: %u offers refused below the budget", name, g_fair_refused);
	printf("  %s: images %u+%u B (caps %u+%u), reserved %llu B, refused %u,"
	       " image growths %u\n", name, r->image_len[0], r->image_len[1],
	       r->image_cap[0], r->image_cap[1], (unsigned long long) r->reserved,
	       g_fair_refused, g_fair_growths);
	teardown(o0, name);
}

static void test_fairness(void) {
	/* Keep-alive: a 40 KB request, a 1.46 MB response, then more requests. */
	int64_t o0 = tcm_outstanding;
	fair_open();
	for (uint32_t i = 0; i < 100; i++) fair_step(0, 400);
	for (uint32_t i = 0; i < 1000; i++) fair_step(1, 1460);
	for (uint32_t i = 0; i < 200; i++) fair_step(0, 400);
	/* ...and both directions keep going until the budget is near. */
	for (uint32_t i = 0; i < 2000; i++) { fair_step(0, 400); fair_step(1, 1460); }
	CHECK(g_session.tcp_reasm->image_len[0] + g_session.tcp_reasm->image_len[1]
	      + FAIR_MARGIN >= BUDGET, "keep-alive: flow stopped at %u+%u B",
	      g_session.tcp_reasm->image_len[0], g_session.tcp_reasm->image_len[1]);
	fair_close("keep-alive fairness", o0);

	/* One direction sends 1.08 MB and stops; the other must still reach
	 * the budget instead of stopping at its own 1 MiB capacity step. */
	o0 = tcm_outstanding;
	fair_open();
	for (uint32_t i = 0; i < 740; i++) fair_step(0, 1460);
	for (uint32_t i = 0; i < 3000; i++) fair_step(1, 1460);
	CHECK(g_session.tcp_reasm->image_len[1] + g_session.tcp_reasm->image_len[0]
	      + FAIR_MARGIN >= BUDGET, "idle-peer: dir 1 stopped at %u B",
	      g_session.tcp_reasm->image_len[1]);
	fair_close("idle-peer fairness", o0);

	/* Amortized growth: a single in-order stream filled to the budget
	 * reallocates its image a logarithmic number of times. */
	o0 = tcm_outstanding;
	fair_open();
	for (uint32_t i = 0; i < 3000; i++) fair_step(0, 1460);
	CHECK(g_fair_growths <= 24, "single stream: %u image reallocations", g_fair_growths);
	fair_close("single-stream growth", o0);
}

/* Randomized two-direction offer/drain at a small limit: trimming at
 * admission must not let reserved + owed[0] + owed[1] pass the limit, and
 * every admitted byte must still flatten in order without a gap. */
static void test_random_small_limit(void) {
	const uint32_t LIMIT = 64u * 1024u, FLOWS = 300, OFFERS = 120;
	uint32_t rng = 0x380380u, nadm = 0;
	uint64_t drain_drops = 0, bytes = 0;
	int bad = 0;
	for (uint32_t f = 0; f < FLOWS; f++) {
		int64_t o0 = tcm_outstanding;
		uint64_t off[2] = {0, 0};
		session_open(LIMIT);
		for (uint32_t i = 0; i < OFFERS; i++) {
			rng = rng * 1103515245u + 12345u;
			int dir = (int) ((rng >> 16) & 1u);
			uint32_t len = 1 + ((rng >> 17) % 1460u);
			if (offer(dir, 3 + (uint32_t) off[dir], off[dir], len)) { off[dir] += len; nadm++; }
			if (((rng >> 28) & 3u) == 0) {
				uint64_t dd = g_dropped;
				drain(dir);
				drain_drops += g_dropped - dd;
			}
		}
		for (int d = 0; d < 2; d++) {
			uint64_t dd = g_dropped;
			drain(d);
			drain_drops += g_dropped - dd;
		}
		const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
		for (int d = 0; d < 2; d++) {
			int ok = r->image_len[d] == off[d];
			for (uint32_t i = 0; ok && i < r->image_len[d]; i++) ok = r->image[d][i] == pattern(d, i);
			if (!ok) bad++;
			bytes += r->image_len[d];
		}
		teardown(o0, "random small limit");
	}
	CHECK(drain_drops == 0, "random: drain dropped %llu admitted bytes",
	      (unsigned long long) drain_drops);
	CHECK(bad == 0, "random: %d images are not the admitted stream", bad);
	printf("  random 64 KiB: %u flows, %u of %u offers admitted, %llu B flattened\n",
	       FLOWS, nadm, FLOWS * OFFERS, (unsigned long long) bytes);
}

/* An emptied head block that a larger carve does not fit must be freed,
 * not left in the chain behind the new head (stranded reserved storage). */
static void test_recycled_head(void) {
	int64_t o0 = tcm_outstanding;
	const uint32_t lens[] = {1000, 17000, 26000, 35000, 500, 40000};
	uint64_t off = 0;
	session_open(BUDGET);
	for (uint32_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		CHECK(offer(0, 9 + (uint32_t) off, off, lens[i]), "recycled head: %u B dropped", lens[i]);
		off += lens[i];
		drain(0);
	}
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	uint64_t blocks;
	uint32_t n = chain_blocks(r, &blocks);
	CHECK(n == 1, "recycled head: %u blocks (%llu B) after full drains", n,
	      (unsigned long long) blocks);
	CHECK(r->image_len[0] == off, "recycled head: image %u B of %llu", r->image_len[0],
	      (unsigned long long) off);
	printf("  recycled head: %u block(s), %llu B of blocks after %llu B drained\n", n,
	       (unsigned long long) blocks, (unsigned long long) off);
	teardown(o0, "recycled head");
}

/* ------------------------------------------------------------------ */
/* D — allocation failures                                             */
/* ------------------------------------------------------------------ */

static void test_oom(void) {
	int64_t o0 = tcm_outstanding;
	session_open(BUDGET);
	/* call 1 = state, call 2 = first block (fails). */
	tcm_fail_at = tcm_calls + 2;
	uint64_t d0 = g_dropped;
	CHECK(!offer(0, 100, 0, 500), "offer admitted without a block");
	tcm_fail_at = 0;
	CHECK(g_dropped - d0 == 500, "failed block not counted as dropped");
	CHECK(g_session.tcp_reasm != NULL && g_session.tcp_reasm->blocks == NULL,
	      "failed block left a chain");
	CHECK(offer(0, 100, 0, 500) && offer(0, 600, 500, 500), "recovery offers dropped");

	/* Image realloc failure: the segment stays pending, nothing dropped. */
	tcm_fail_at = tcm_calls + 1;
	d0 = g_dropped;
	drain(0);
	tcm_fail_at = 0;
	mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	CHECK(g_dropped == d0, "OOM drain dropped bytes");
	CHECK(pending_count(r, 0) == 2 && r->image_len[0] == 0,
	      "OOM drain did not keep the segments pending");
	drain(0);
	CHECK(r->seg_head[0] == NULL && r->image_len[0] == 1000, "retry drain incomplete");
	teardown(o0, "oom");
}

int main(void) {
	printf("tcp-memory (issue #380): reserved-storage budget %u B\n", BUDGET);
	test_ac1();
	test_large_exhaustion();
	run_stream("two-direction", 2, 1460, 3000, 32);
	run_stream("image+pending", 1, 1460, 6000, 1000);
	test_lowered_limit();
	test_fairness();
	test_random_small_limit();
	test_recycled_head();
	test_oom();
	printf("  checks: %d, failures: %d\n", checks, failures);
	return failures ? 1 : 0;
}
