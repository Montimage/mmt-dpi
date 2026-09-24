/*
 * test_tcp_order.c — issue #382 (F-PERF-003, second part): out-of-order
 * insertion into the TCP pending-segment store is bounded. Interior inserts
 * are located through an AVL index over the pending list instead of a
 * linear list walk, so the whole workload costs O(n log n) node visits.
 *
 *   A. Workload bounds — three out-of-order arrival patterns at 1,024 and
 *      16,384 one-byte segments, every segment accepted (no capacity
 *      refusal): the total visits stay below the issue #381 evidence
 *      (261,632 / 67,100,672 — the sorted-list walk on evens-then-odds) and
 *      grow at most 24-fold for 16x the segments:
 *        interleaved  — evens, then odds;
 *        tail-anchor  — the last segment first, then the rest ascending
 *                       (the list walk visited every earlier node: O(n^2));
 *        shuffled     — a fixed-seed permutation straddling 2^32.
 *      Each run checks the flattened bytes and the index shape (AVL
 *      balance, height bound, in-order = list order).
 *   B. Duplicates located through the index are refused before any carve.
 *   C. An image OOM during the drain resets the index; the next interior
 *      insert rebuilds it and the stream still flattens byte-exact.
 *   D. Pending seqs spanning 2^31 or more (tcp_seq_before no longer
 *      transitive): head prepends repeating indexed seqs are still indexed
 *      once, so later interior inserts stay O(log n) instead of re-walking
 *      an ever-unindexed head prefix (QA review of #382).
 *
 * proto_tcp.c and tcp_segment.c are included directly (the tcp-memory
 * fixture convention); see run_tests.sh.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/mmt_tcpip/lib/protocols/proto_tcp.c"
#include "../../src/mmt_tcpip/lib/protocols/tcp_segment.c"

#include "tcp_alloc_count.h"
#include "rb_result.h"

#define RB "tcp-order"   /* issue #394: results.json fixture id */

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

#define BUDGET (4u * 1024u * 1024u)   /* default tcp_reassembly_limit */
#define N_SMALL 1024u
#define N_LARGE 16384u
/* Issue #381 evidence: evens-then-odds list-walk visits. */
#define EVIDENCE_SMALL 261632ull
#define EVIDENCE_LARGE 67100672ull

#include "tcp_reasm_stubs.h"

static mmt_handler_t g_handler;
static mmt_session_t g_session;
static int64_t g_outstanding0;

static uint8_t pattern(uint64_t off) {
	return (uint8_t) ((off * 131u + (off >> 8) + 3u) & 0xffu);
}

static void session_open(void) {
	memset(&g_session, 0, sizeof(g_session));
	g_handler.tcp_reassembly_limit = BUDGET;
	g_session.mmt_handler = &g_handler;
	g_outstanding0 = tcm_outstanding;
}

static void session_close(const char *what) {
	clean_session_payload(&g_session, 0);
	CHECK(g_session.tcp_reasm == NULL, "%s: tcp_reasm not released", what);
	CHECK(tcm_outstanding == g_outstanding0, "%s: %lld allocation(s) outstanding",
	      what, (long long) (tcm_outstanding - g_outstanding0));
}

/* Offer stream byte `off` (one-byte segment) at seq base + off. */
static int offer1(uint32_t base, uint32_t off) {
	uint8_t b = pattern(off);
	uint64_t d0 = g_dropped;
	tcp_reasm_offer(&g_session, 0, 1, base + off, 0, &b, 1);
	return g_dropped == d0;
}

static void check_image(uint32_t n, const char *what) {
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	CHECK(r != NULL && r->image_len[0] == n, "%s: image %u B, expected %u B", what,
	      r ? r->image_len[0] : 0, n);
	if (r == NULL || r->image_len[0] != n) return;
	uint32_t i = 0;
	while (i < n && r->image[0][i] == pattern(i)) i++;
	CHECK(i == n, "%s: image differs at byte %u", what, i);
	CHECK(r->seg_head[0] == NULL && r->seg_root[0] == NULL,
	      "%s: segments or index left after drain", what);
}

/* ---- index shape ---- */

static int g_shape_ok;
static const tcp_seg_t *g_inorder_prev;
static uint32_t g_inorder_count;

/* Returns the subtree height; clears g_shape_ok on a violation. */
static int shape(const tcp_seg_t *n) {
	if (n == NULL) return 0;
	int hl = shape(n->idx_left);
	/* in-order visit: consecutive index nodes are consecutive list nodes */
	if (g_inorder_prev != NULL && g_inorder_prev->next != n) g_shape_ok = 0;
	g_inorder_prev = n;
	g_inorder_count++;
	int hr = shape(n->idx_right);
	int h = 1 + (hl > hr ? hl : hr);
	if (hl - hr > 1 || hr - hl > 1 || n->idx_height != h) g_shape_ok = 0;
	return h;
}

/* Sync the index (outside any visit measurement) and check that it is a
 * balanced search tree covering exactly the pending list. */
static void check_index(uint32_t n, const char *what) {
	mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	tcp_seg_idx_sync((tcp_seg_t **) &r->seg_root[0], r->seg_head[0], r->seg_tail[0]);
	g_shape_ok = 1;
	g_inorder_prev = NULL;
	g_inorder_count = 0;
	int h = shape(r->seg_root[0]);
	double bound = 1.4405 * log2((double) n + 2.0);
	CHECK(g_shape_ok, "%s: index is not a balanced tree in list order", what);
	CHECK(g_inorder_count == n, "%s: index holds %u of %u pending segments", what,
	      g_inorder_count, n);
	CHECK(h <= (int) bound, "%s: index height %d above the AVL bound %.1f", what, h, bound);
}

/* ---- A: workload bounds ---- */

enum { W_INTERLEAVED, W_TAIL_ANCHOR, W_SHUFFLED, W_COUNT };
static const char *w_name[W_COUNT] = {"interleaved", "tail-anchor", "shuffled"};
static uint32_t g_order[N_LARGE];
#define SHUFFLE_SEED 0x2545F491u

static void build_order(int w, uint32_t n) {
	uint32_t k = 0;
	switch (w) {
	case W_INTERLEAVED:
		for (uint32_t i = 0; i < n; i += 2) g_order[k++] = i;
		for (uint32_t i = 1; i < n; i += 2) g_order[k++] = i;
		break;
	case W_TAIL_ANCHOR:
		g_order[k++] = n - 1;
		for (uint32_t i = 0; i + 1 < n; i++) g_order[k++] = i;
		break;
	default: {
		uint32_t x = SHUFFLE_SEED;
		for (uint32_t i = 0; i < n; i++) g_order[i] = i;
		for (uint32_t i = n - 1; i > 0; i--) {
			x = x * 1664525u + 1013904223u;
			uint32_t j = (uint32_t) (((uint64_t) x * (i + 1)) >> 32);
			uint32_t t = g_order[i]; g_order[i] = g_order[j]; g_order[j] = t;
		}
	}
	}
}

static uint32_t g_admitted;       /* of the last run_workload() */
static uint64_t g_refused_bytes;  /* dropped bytes = refused one-byte offers */

static uint64_t run_workload(int w, uint32_t n) {
	/* shuffled straddles the 32-bit wrap; the others start mid-space */
	uint32_t base = (w == W_SHUFFLED) ? 0xFFFFFFFFu - n / 2 : 5000u;
	char what[64];
	snprintf(what, sizeof(what), "%s %u", w_name[w], n);
	build_order(w, n);
	session_open();
	uint64_t v0 = g_visits, d0 = g_dropped;
	uint32_t admitted = 0;
	for (uint32_t i = 0; i < n; i++) admitted += offer1(base, g_order[i]);
	uint64_t visits = g_visits - v0;
	g_refused_bytes = g_dropped - d0;
	g_admitted = admitted;
	CHECK(admitted == n, "%s: admitted %u (no capacity refusal expected)", what, admitted);
	check_index(n, what);
	tcp_reasm_drain(&g_session, 0);
	check_image(n, what);
	session_close(what);
	return visits;
}

static void test_workloads(void) {
	for (int w = 0; w < W_COUNT; w++) {
		uint64_t vs = run_workload(w, N_SMALL);
		uint32_t as = g_admitted;
		uint64_t rs = g_refused_bytes;
		uint64_t vl = run_workload(w, N_LARGE);
		uint32_t al = g_admitted;
		uint64_t rl = g_refused_bytes;
		CHECK(vs < EVIDENCE_SMALL, "%s: %llu visits at 1,024, bound 261,632", w_name[w],
		      (unsigned long long) vs);
		CHECK(vl < EVIDENCE_LARGE, "%s: %llu visits at 16,384, bound 67,100,672",
		      w_name[w], (unsigned long long) vl);
		CHECK(vl <= 24u * vs, "%s: %llu -> %llu visits exceeds 24-fold growth",
		      w_name[w], (unsigned long long) vs, (unsigned long long) vl);
		printf("  %-11s 1,024 -> %7llu visits, 16,384 -> %8llu visits (x%.1f)\n",
		       w_name[w], (unsigned long long) vs, (unsigned long long) vl,
		       vs ? (double) vl / (double) vs : 0.0);
		const struct { uint32_t n, acc; uint64_t ref, visits; } run[2] = {
			{ N_SMALL, as, rs, vs }, { N_LARGE, al, rl, vl } };
		for (int i = 0; i < 2; i++) {
			char k[64];
			snprintf(k, sizeof k, "%s.n%u.offers", w_name[w], run[i].n);
			rb_metric(RB, k, run[i].n);
			snprintf(k, sizeof k, "%s.n%u.accepted", w_name[w], run[i].n);
			rb_metric(RB, k, run[i].acc);
			snprintf(k, sizeof k, "%s.n%u.refused", w_name[w], run[i].n);
			rb_metric(RB, k, run[i].ref);
			snprintf(k, sizeof k, "%s.n%u.visits", w_name[w], run[i].n);
			rb_metric(RB, k, run[i].visits);
		}
	}
	rb_seed(RB, "shuffled.lcg", SHUFFLE_SEED);
	/* Pin the evens-then-odds counts (also pinned by tests/tcp_pending_order). */
	CHECK(run_workload(W_INTERLEAVED, N_SMALL) == 5375u, "interleaved 1,024 != 5,375 visits");
	CHECK(run_workload(W_INTERLEAVED, N_LARGE) == 118783u, "interleaved 16,384 != 118,783 visits");
}

/* ---- B: duplicates through the index ---- */

static void test_duplicates(void) {
	const uint32_t n = 256, base = 9000;
	session_open();
	for (uint32_t i = 0; i < n; i += 2) CHECK(offer1(base, i), "even %u dropped", i);
	for (uint32_t i = 1; i + 1 < n; i += 4) CHECK(offer1(base, i), "odd %u dropped", i);
	mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	uint64_t res0 = r->reserved, live0 = r->live, calls0 = tcm_calls;
	uint32_t refused = 0, accepted = 0, offers = 0;
	for (uint32_t i = 2; i + 2 < n; i += 2) {
		offers++;
		uint8_t b = 0xEE;
		uint64_t d0 = g_dropped;
		tcp_reasm_offer(&g_session, 0, 1, base + i, 0, &b, 1);
		refused += (g_dropped == d0 + 1);
		accepted += (g_dropped == d0);
	}
	CHECK(refused == n / 2 - 2, "interior duplicates refused %u of %u", refused, n / 2 - 2);
	CHECK(r->reserved == res0 && r->live == live0 && tcm_calls == calls0,
	      "interior duplicates carved storage");
	for (uint32_t i = 3; i < n; i += 4) CHECK(offer1(base, i), "odd %u dropped", i);
	tcp_reasm_drain(&g_session, 0);
	check_image(n, "duplicates");
	session_close("duplicates");
	printf("  duplicates: %u interior duplicates refused through the index, nothing carved\n",
	       refused);
	rb_metric(RB, "duplicates.offers", offers);
	rb_metric(RB, "duplicates.accepted", accepted);
	rb_metric(RB, "duplicates.refused", refused);
}

/* ---- C: OOM during the drain resets the index ---- */

static void test_oom_reset(void) {
	const uint32_t n = 64, base = 70000, gap = 33;
	session_open();
	for (uint32_t i = 0; i < n; i += 2) CHECK(offer1(base, i), "even %u dropped", i);
	for (uint32_t i = 1; i < n; i += 2)
		if (i != gap) CHECK(offer1(base, i), "odd %u dropped", i);
	mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	CHECK(r->seg_root[0] != NULL, "interior inserts built no index");
	tcm_fail_at = tcm_calls + 1;   /* the image allocation */
	tcp_reasm_drain(&g_session, 0);
	tcm_fail_at = 0;
	uint32_t pending = 0, marked = 0;
	for (const tcp_seg_t *s = r->seg_head[0]; s != NULL; s = s->next) {
		pending++;
		marked += (s->idx_height != 0);
	}
	CHECK(pending == n - 1 && r->image_len[0] == 0, "OOM drain did not keep %u pending", n - 1);
	CHECK(r->seg_root[0] == NULL && marked == 0, "OOM drain left a stale index");
	CHECK(offer1(base, gap), "gap filler dropped after the index reset");
	check_index(n, "oom rebuild");
	tcp_reasm_drain(&g_session, 0);
	check_image(n, "oom rebuild");
	session_close("oom");
	printf("  oom: drain OOM reset the index; the next interior insert rebuilt it\n");
}

/* ---- D: seqs spanning 2^31 ---- */

static void offer_seq(uint32_t seq) {
	uint8_t b = 1;
	tcp_reasm_offer(&g_session, 0, 1, seq, 0, &b, 1);
}

/* Returns the visits of the final interior phase. */
static uint64_t run_wide_span(uint32_t m) {
	session_open();
	uint64_t d0 = g_dropped;
	offer_seq(0);
	offer_seq(0x70000000u);
	for (uint32_t k = 1; k <= m; k++) offer_seq(k * 16);      /* indexed interior */
	for (uint32_t x = 0xF0000000u; x >= 0x80000000u; x -= 0x10000000u)
		offer_seq(x);                                         /* head walks back around 2^32 */
	offer_seq(0x6FFFFFF0u);
	offer_seq(0x3FFFFFF0u);
	for (uint32_t k = m; k >= 1; k--) offer_seq(k * 16);      /* prepends repeating indexed seqs */
	uint64_t v0 = g_visits;
	for (uint32_t k = 1; k <= m; k++) offer_seq(k * 16 + 8);  /* interior inserts */
	uint64_t visits = g_visits - v0;
	mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	uint32_t n = 0, unindexed = 0;
	for (const tcp_seg_t *s = r->seg_head[0]; s != NULL; s = s->next) {
		n++;
		unindexed += (s->idx_height == 0);
	}
	CHECK(g_dropped == d0 && n == 3 * m + 12, "wide span %u: %u pending, %llu B dropped",
	      m, n, (unsigned long long) (g_dropped - d0));
	CHECK(unindexed == 0, "wide span %u: %u segments never indexed", m, unindexed);
	session_close("wide span");
	return visits;
}

static void test_wide_span(void) {
	uint64_t vs = run_wide_span(1024);
	uint64_t vl = run_wide_span(8192);
	/* O(m log m): 8x the segments may cost at most 12x the visits (the
	 * pre-fix index re-walked the stuck prefix: 9,588,556 -> 813,294,061). */
	CHECK(vl <= 12u * vs, "wide span: %llu -> %llu visits exceeds 12-fold growth",
	      (unsigned long long) vs, (unsigned long long) vl);
	printf("  wide span: 1,024 -> %llu visits, 8,192 -> %llu visits, every segment indexed\n",
	       (unsigned long long) vs, (unsigned long long) vl);
	rb_metric(RB, "wide_span.n1024.visits", vs);
	rb_metric(RB, "wide_span.n8192.visits", vl);
}

int main(void) {
	printf("tcp-order (issue #382): pending-segment insertion is O(log n) per offer\n");
	test_workloads();
	test_duplicates();
	test_oom_reset();
	test_wide_span();
	rb_metric(RB, "checks.total", (uint64_t) checks);
	rb_metric(RB, "checks.failed", (uint64_t) failures);
	printf("  checks: %d, failures: %d\n", checks, failures);
	return failures ? 1 : 0;
}
