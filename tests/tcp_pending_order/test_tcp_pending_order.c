/*
 * test_tcp_pending_order.c — issue #381 (F-PERF-003, first part):
 * characterize the CURRENT (post-#380) ordering, overlap and sequence-wrap
 * behavior of the TCP pending-segment store before its insertion structure
 * is changed. Every case asserts the exact flattened byte output — what a
 * TCP_SESSION_PAYLOAD_UP/DOWN read returns, since those extractors call
 * tcp_reasm_drain() and hand out r->image[dir] — plus the dropped-byte and
 * visit gauges.
 *
 *   A. in-order         — tail appends, 0 walk visits, incremental drains.
 *   B. reversed         — head prepends, 0 walk visits.
 *   C. interleaved      — evens then odds: interior inserts. Issue #381
 *                         recorded the quadratic sorted-list walk as
 *                         evidence (261,632 visits at 1,024 segments and
 *                         67,100,672 at 16,384 — (n/2-1)*(n/2)); issue #382
 *                         (F-PERF-003) replaced it with the AVL index, and
 *                         the exact counts below (5,375 / 118,783) pin the
 *                         O(n log n) index work: below that evidence, with
 *                         at most 24-fold growth for 16x the segments.
 *   D. duplicate        — same sequence number: the first segment wins
 *                         (pending or already consumed), even when the later
 *                         one is longer or carries different bytes.
 *   E. overlapping      — pending overlaps are concatenated in seq order in
 *                         full (not trimmed); a segment contained in bytes
 *                         already flattened is dropped at drain time.
 *   F. 32-bit wrap      — ordering, duplicates and the consumed frontier
 *                         across 2^32.
 *   G. partially consumed — drains are incremental and never rewrite the
 *                         emitted prefix; gaps are closed silently and a late
 *                         gap filler below the frontier is dropped.
 *   H. teardown         — clean_session_payload() returns every allocation
 *                         with pending segments, images or both, and is a
 *                         no-op when nothing was reassembled.
 *
 * proto_tcp.c and tcp_segment.c are included directly (the tests/
 * resource_bounds tcp-memory convention) and allocations are counted by
 * tests/resource_bounds/tcp_alloc_count.c; see run_tests.sh.
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

#define BUDGET (4u * 1024u * 1024u)   /* default tcp_reassembly_limit */

static mmt_handler_t g_handler;
static mmt_session_t g_session;
static int64_t g_outstanding0;

/* Stream byte at offset `off` of direction `dir`. */
static uint8_t pattern(int dir, uint64_t off) {
	return (uint8_t) ((off * 131u + (uint64_t) dir * 7u + (off >> 8)) & 0xffu);
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
	CHECK(g_live == 0, "%s: live gauge %lld after teardown", what, (long long) g_live);
}

static uint8_t g_seg_buf[65536];

/* Offer stream bytes [off, off+len) of `dir` at sequence number `seq`;
 * returns 1 when admitted (the dropped gauge did not move). */
static int offer(int dir, uint32_t seq, uint64_t off, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) g_seg_buf[i] = pattern(dir, off + i);
	uint64_t d0 = g_dropped;
	tcp_reasm_offer(&g_session, dir, 1, seq, 0, g_seg_buf, len);
	return g_dropped == d0;
}

/* Offer `len` copies of byte `fill` at `seq` (duplicate-content probes). */
static int offer_fill(int dir, uint32_t seq, uint8_t fill, uint32_t len) {
	memset(g_seg_buf, fill, len);
	uint64_t d0 = g_dropped;
	tcp_reasm_offer(&g_session, dir, 1, seq, 0, g_seg_buf, len);
	return g_dropped == d0;
}

/* Drain `dir` and return the bytes dropped by the drain itself. */
static uint64_t drain(int dir) {
	uint64_t d0 = g_dropped;
	tcp_reasm_drain(&g_session, dir);
	return g_dropped - d0;
}

/* ---- expected-output builder ---- */

static uint8_t g_want[1u << 20];
static uint32_t g_want_len;

static void want_reset(void) { g_want_len = 0; }
static void want_range(int dir, uint64_t off, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) g_want[g_want_len++] = pattern(dir, off + i);
}
static void want_fill(uint8_t fill, uint32_t len) {
	memset(g_want + g_want_len, fill, len);
	g_want_len += len;
}

/* The flattened image of `dir` must be exactly g_want. */
static void check_image(int dir, const char *what) {
	const mmt_tcp_reasm_t *r = g_session.tcp_reasm;
	uint32_t len = (r != NULL) ? r->image_len[dir] : 0;
	CHECK(len == g_want_len, "%s: image %u B, expected %u B", what, len, g_want_len);
	if (len == g_want_len && len > 0) {
		uint32_t i = 0;
		while (i < len && r->image[dir][i] == g_want[i]) i++;
		CHECK(i == len, "%s: image differs at byte %u (0x%02x, expected 0x%02x)",
		      what, i, r->image[dir][i], g_want[i]);
	}
	if (r != NULL)
		CHECK(r->seg_head[dir] == NULL && r->pending_len[dir] == 0,
		      "%s: segments still pending after drain", what);
}

/* ------------------------------------------------------------------ */
/* A — in-order                                                        */
/* ------------------------------------------------------------------ */

static void test_in_order(void) {
	const uint32_t N = 64, L = 8, S = 1000;
	session_open();
	uint64_t v0 = g_visits;
	for (uint32_t i = 0; i < N; i++)
		CHECK(offer(0, S + i * L, (uint64_t) i * L, L), "in-order seg %u dropped", i);
	CHECK(g_visits == v0, "in-order appends walked %llu nodes",
	      (unsigned long long) (g_visits - v0));
	CHECK(drain(0) == 0, "in-order drain dropped bytes");
	want_reset();
	want_range(0, 0, N * L);
	check_image(0, "in-order");
	session_close("in-order");

	/* Same stream, drained every 8 offers: identical output. */
	session_open();
	for (uint32_t i = 0; i < N; i++) {
		offer(0, S + i * L, (uint64_t) i * L, L);
		if ((i + 1) % 8 == 0) drain(0);
	}
	check_image(0, "in-order incremental");
	/* The other direction is independent and untouched. */
	CHECK(g_session.tcp_reasm->image_len[1] == 0, "dir 1 image grew");
	session_close("in-order incremental");
	printf("  in-order: %u x %u B, 0 visits, full and incremental drains identical\n", N, L);
}

/* ------------------------------------------------------------------ */
/* B — reversed                                                        */
/* ------------------------------------------------------------------ */

static void test_reversed(void) {
	const uint32_t N = 64, L = 8, S = 1000;
	session_open();
	uint64_t v0 = g_visits;
	for (uint32_t i = N; i-- > 0;)
		CHECK(offer(0, S + i * L, (uint64_t) i * L, L), "reversed seg %u dropped", i);
	CHECK(g_visits == v0, "reversed prepends walked %llu nodes",
	      (unsigned long long) (g_visits - v0));
	CHECK(drain(0) == 0, "reversed drain dropped bytes");
	want_reset();
	want_range(0, 0, N * L);
	check_image(0, "reversed");
	session_close("reversed");
	printf("  reversed: %u x %u B, 0 visits, image in sequence order\n", N, L);
}

/* ------------------------------------------------------------------ */
/* C — interleaved (evens, then odds)                                  */
/* ------------------------------------------------------------------ */

static uint64_t run_interleaved(uint32_t n, uint32_t len, uint32_t base) {
	session_open();
	uint64_t v0 = g_visits;
	uint32_t admitted = 0;
	for (uint32_t i = 0; i < n; i += 2)
		admitted += offer(0, base + i * len, (uint64_t) i * len, len);
	for (uint32_t i = 1; i < n; i += 2)
		admitted += offer(0, base + i * len, (uint64_t) i * len, len);
	uint64_t visits = g_visits - v0;
	CHECK(admitted == n, "interleaved %u: admitted %u", n, admitted);
	CHECK(drain(0) == 0, "interleaved %u: drain dropped bytes", n);
	want_reset();
	want_range(0, 0, n * len);
	check_image(0, "interleaved");
	session_close("interleaved");
	return visits;
}

static void test_interleaved(void) {
	/* Issue #382 (F-PERF-003): the evens are tail appends (0 visits); the
	 * first odd builds the AVL index over the n/2 evens (one visit each),
	 * then every odd but the last (a tail append) descends it in O(log n).
	 * 16 segments: 8 build visits + 27 descent visits. */
	uint64_t v16 = run_interleaved(16, 8, 7000);
	CHECK(v16 == 35u, "interleaved 16: %llu visits, expected 35",
	      (unsigned long long) v16);

	/* Issue #381 recorded the quadratic sorted-list walk as evidence:
	 * 261,632 / 67,100,672 visits at 1,024 / 16,384 segments. The index
	 * must stay below both with at most 24-fold growth. */
	uint64_t v1k = run_interleaved(1024, 1, 5000);
	uint64_t v16k = run_interleaved(16384, 1, 5000);
	CHECK(v1k == 5375u, "interleaved 1,024: %llu visits, expected 5,375",
	      (unsigned long long) v1k);
	CHECK(v16k == 118783u, "interleaved 16,384: %llu visits, expected 118,783",
	      (unsigned long long) v16k);
	CHECK(v1k < 261632u && v16k < 67100672u,
	      "interleaved visits %llu / %llu not below the #381 evidence",
	      (unsigned long long) v1k, (unsigned long long) v16k);
	CHECK(v16k <= 24u * v1k, "interleaved growth %llu -> %llu exceeds 24-fold",
	      (unsigned long long) v1k, (unsigned long long) v16k);
	printf("  interleaved: 16 -> %llu, 1,024 -> %llu, 16,384 -> %llu visits"
	       " (#381 evidence 261,632 / 67,100,672); images in sequence order\n",
	       (unsigned long long) v16, (unsigned long long) v1k, (unsigned long long) v16k);
}

/* ------------------------------------------------------------------ */
/* D — duplicates: the first segment wins                              */
/* ------------------------------------------------------------------ */

static void test_duplicates(void) {
	const uint32_t S = 2000;
	session_open();
	/* Pending list 'A'x4 @S, 'B'x4 @S+4, 'C'x4 @S+8 (gap-free by seq). */
	CHECK(offer_fill(0, S, 'A', 4), "first A dropped");
	CHECK(offer_fill(0, S + 4, 'B', 4), "first B dropped");
	CHECK(offer_fill(0, S + 8, 'C', 4), "first C dropped");
	uint64_t d0 = g_dropped;
	/* head, interior and tail duplicates with different content ... */
	CHECK(!offer_fill(0, S, 'x', 4), "head duplicate admitted");
	CHECK(!offer_fill(0, S + 4, 'y', 4), "interior duplicate admitted");
	CHECK(!offer_fill(0, S + 8, 'z', 4), "tail duplicate admitted");
	/* ... and a LONGER duplicate is still rejected whole. */
	CHECK(!offer_fill(0, S + 8, 'w', 12), "longer tail duplicate admitted");
	CHECK(g_dropped - d0 == 24, "duplicates dropped %llu B, expected 24",
	      (unsigned long long) (g_dropped - d0));
	CHECK(drain(0) == 0, "duplicate drain dropped bytes");
	want_reset();
	want_fill('A', 4);
	want_fill('B', 4);
	want_fill('C', 4);
	check_image(0, "pending duplicates");

	/* Duplicates of consumed data (retransmissions) never reach the image. */
	CHECK(!offer_fill(0, S, 'q', 4), "consumed duplicate admitted");
	CHECK(!offer_fill(0, S + 4, 'q', 8), "consumed two-segment retransmission admitted");
	CHECK(drain(0) == 0, "drain after consumed duplicates dropped bytes");
	check_image(0, "consumed duplicates");
	session_close("duplicates");
	printf("  duplicate: head/interior/tail/longer duplicates dropped (24 B), first wins\n");
}

/* ------------------------------------------------------------------ */
/* E — overlapping ranges                                              */
/* ------------------------------------------------------------------ */

static void test_overlaps(void) {
	const uint32_t S = 3000;

	/* Pending overlap [0,10) + [5,15): concatenated in full, 20 bytes. */
	session_open();
	offer(0, S, 0, 10);
	offer(0, S + 5, 5, 10);
	CHECK(drain(0) == 0, "overlap: drain dropped bytes");
	want_reset();
	want_range(0, 0, 10);
	want_range(0, 5, 10);
	check_image(0, "pending overlap");
	session_close("pending overlap");

	/* Same overlap, later-seq segment first: seq order wins, same output. */
	session_open();
	offer(0, S + 5, 5, 10);
	offer(0, S, 0, 10);
	drain(0);
	check_image(0, "pending overlap reversed");
	session_close("pending overlap reversed");

	/* Contained pending segment [2,5) inside [0,10): dropped at drain,
	 * because the frontier (10) has passed its end once [0,10) is out. */
	session_open();
	offer(0, S, 0, 10);
	CHECK(offer(0, S + 2, 2, 3), "contained segment refused at offer");
	CHECK(drain(0) == 3, "contained segment not dropped at drain");
	want_reset();
	want_range(0, 0, 10);
	check_image(0, "contained overlap");

	/* Against the consumed frontier (10): [5,15) straddles it and is
	 * appended in full; [2,8) and [5,10) end at or below it and are
	 * dropped at offer. */
	CHECK(offer(0, S + 5, 5, 10), "straddling segment dropped");
	CHECK(!offer(0, S + 2, 2, 6), "segment below the frontier admitted");
	CHECK(!offer(0, S + 5, 5, 5), "segment ending at the frontier admitted");
	CHECK(drain(0) == 0, "straddle drain dropped bytes");
	want_range(0, 5, 10);
	check_image(0, "frontier overlap");
	session_close("overlaps");
	printf("  overlapping: pending overlaps concatenated whole; contained/below-frontier"
	       " dropped\n");
}

/* ------------------------------------------------------------------ */
/* F — 32-bit sequence wrap                                            */
/* ------------------------------------------------------------------ */

static void test_wrap(void) {
	const uint32_t N = 8, L = 8, W = 0xFFFFFFE0u;   /* seg 4 starts at 0 */
	uint32_t order[3][8] = {
		{0, 1, 2, 3, 4, 5, 6, 7},   /* in-order across the wrap */
		{7, 6, 5, 4, 3, 2, 1, 0},   /* reversed across the wrap */
		{0, 2, 4, 6, 1, 3, 5, 7},   /* interleaved across the wrap */
	};
	const char *names[3] = {"wrap in-order", "wrap reversed", "wrap interleaved"};
	for (int k = 0; k < 3; k++) {
		session_open();
		uint64_t v0 = g_visits;
		for (uint32_t j = 0; j < N; j++) {
			uint32_t i = order[k][j];
			CHECK(offer(0, W + i * L, (uint64_t) i * L, L), "%s: seg %u dropped", names[k], i);
		}
		if (k < 2)
			CHECK(g_visits == v0, "%s: %llu visits", names[k],
			      (unsigned long long) (g_visits - v0));
		/* A duplicate of the post-wrap seq 0 is still detected. */
		CHECK(!offer(0, 0, 32, L), "%s: duplicate of wrapped seq 0 admitted", names[k]);
		CHECK(drain(0) == 0, "%s: drain dropped bytes", names[k]);
		want_reset();
		want_range(0, 0, N * L);
		check_image(0, names[k]);
		/* Frontier is now 0x20 (wrapped): a pre-wrap retransmission is
		 * below it and dropped; the continuation is appended. */
		CHECK(g_session.tcp_reasm->consumed_seq[0] == W + N * L,
		      "%s: frontier 0x%x", names[k], g_session.tcp_reasm->consumed_seq[0]);
		CHECK(!offer(0, W + L, L, L), "%s: pre-wrap retransmission admitted", names[k]);
		CHECK(offer(0, W + N * L, (uint64_t) N * L, L), "%s: continuation dropped", names[k]);
		drain(0);
		want_range(0, (uint64_t) N * L, L);
		check_image(0, names[k]);
		session_close(names[k]);
	}
	printf("  32-bit wrap: in-order/reversed/interleaved across 2^32 ordered,"
	       " duplicates and frontier wrap-aware\n");
}

/* ------------------------------------------------------------------ */
/* G — partially consumed                                              */
/* ------------------------------------------------------------------ */

static void test_partially_consumed(void) {
	const uint32_t L = 10, S = 4000;
	session_open();
	for (uint32_t i = 0; i < 4; i++) offer(0, S + i * L, (uint64_t) i * L, L);
	drain(0);
	want_reset();
	want_range(0, 0, 4 * L);
	check_image(0, "first drain");
	uint8_t prefix[40];
	memcpy(prefix, g_session.tcp_reasm->image[0], sizeof(prefix));

	/* The second batch is appended; the emitted prefix is never rewritten. */
	for (uint32_t i = 4; i < 8; i++) offer(0, S + i * L, (uint64_t) i * L, L);
	CHECK(g_session.tcp_reasm->image_len[0] == 4 * L, "offer grew the image before a drain");
	drain(0);
	want_range(0, 4 * L, 4 * L);
	check_image(0, "second drain");
	CHECK(memcmp(prefix, g_session.tcp_reasm->image[0], sizeof(prefix)) == 0,
	      "emitted prefix changed");
	CHECK(drain(0) == 0, "empty drain dropped bytes");
	check_image(0, "empty drain");

	/* Gap: [80,90) missing, [90,100) arrives and is drained — the image
	 * closes the gap silently (no filler bytes). */
	offer(0, S + 9 * L, 9 * L, L);
	drain(0);
	want_range(0, 9 * L, L);
	check_image(0, "gap closed");
	/* The late gap filler [80,90) lies wholly below the frontier (100): it
	 * is dropped, never spliced into the image. */
	CHECK(!offer(0, S + 8 * L, 8 * L, L), "late gap filler admitted");
	CHECK(drain(0) == 0, "gap filler drain dropped bytes");
	check_image(0, "late gap filler");
	session_close("partially consumed");
	printf("  partially consumed: incremental drains append, gaps closed silently,"
	       " late filler dropped\n");
}

/* ------------------------------------------------------------------ */
/* H — teardown                                                        */
/* ------------------------------------------------------------------ */

static void test_teardown(void) {
	/* Nothing reassembled: no state, teardown is a no-op (twice). */
	session_open();
	session_close("teardown empty");
	clean_session_payload(&g_session, 0);
	CHECK(g_session.tcp_reasm == NULL, "second teardown resurrected state");

	/* Pending only, both directions, including out-of-order segments. */
	session_open();
	for (uint32_t i = 0; i < 300; i++) {
		offer(0, 100 + (299 - i) * 1460, (uint64_t) (299 - i) * 1460, 1460);
		offer(1, 900 + i * 700, (uint64_t) i * 700, 700);
	}
	CHECK(g_live > 0, "teardown: nothing pending");
	session_close("teardown pending");

	/* Images plus pending in both directions after partial consumption. */
	session_open();
	for (uint32_t i = 0; i < 200; i++) {
		offer(0, 5 + i * 1000, (uint64_t) i * 1000, 1000);
		offer(1, 7 + i * 500, (uint64_t) i * 500, 500);
		if (i == 99) { drain(0); drain(1); }
	}
	CHECK(g_session.tcp_reasm->image_len[0] == 100000 && g_session.tcp_reasm->seg_head[0] != NULL,
	      "teardown: expected image plus pending");
	session_close("teardown image+pending");
	printf("  teardown: empty, pending-only and image+pending sessions release"
	       " every allocation\n");
}

int main(void) {
	printf("tcp-pending-order (issue #381): characterization of the post-#380 store\n");
	test_in_order();
	test_reversed();
	test_interleaved();
	test_duplicates();
	test_overlaps();
	test_wrap();
	test_partially_consumed();
	test_teardown();
	printf("  checks: %d, failures: %d\n", checks, failures);
	return failures ? 1 : 0;
}
