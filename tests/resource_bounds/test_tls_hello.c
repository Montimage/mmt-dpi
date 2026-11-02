/*
 * test_tls_hello.c — the "tls-hello" resource_bounds fixture (issue #568,
 * F-BUG-302): the per-flow buffer that collects a TLS ClientHello split over
 * several TCP segments is bounded by the record's declared length, at most
 * 2^14 bytes, never grows after it is sized, and is freed whatever the
 * outcome.
 *
 * tls_client_hello.c and memory.c are compiled beside this TU with the
 * counted allocator of tcp-memory (-Dmalloc=tcm_malloc ...), so every
 * mmt_malloc() of the reassembly is counted.
 *
 * Workload (fixed seed): 1,000 flows. Every fourth flow declares an oversize
 * record (2^14 + 1 .. 65,535 bytes — no valid TLS record): the reassembly
 * must refuse it without allocating. The others declare 1 .. 2^14 bytes
 * (flow 1 exactly 2^14) and take, in turn, one of four fates:
 *
 *   complete   segments of 1 .. 1,460 bytes, each window of four sent in
 *              reverse order, every fifth one sent twice (at most four
 *              duplicates): must complete with the exact bytes
 *   truncated  segments up to half the record, then nothing: the flow ends
 *              with the reassembly in flight (released at teardown)
 *   holes      single bytes every 64 bytes from offset 1 (records of at least
 *              320 bytes): the fifth disjoint range drops the reassembly
 *   stalls     a first segment, then retransmissions of it alternating with
 *              segments past the record: TLS_HELLO_MAX_STALLS of them drop it
 *
 * Every reassembly is held until teardown (or its drop), so the live peak is
 * the concurrent footprint of the in-flight ones.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "../../src/mmt_tcpip/lib/protocols/tls_client_hello.h"

#include "tcp_alloc_count.h"
#include "rb_result.h"

#define RB "tls-hello"   /* results.json fixture id */

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

#define FLOWS      1000u
#define MSS        1460u
#define HOLES_MIN  320u
#define SEED       0x5eed0568c11e0ed0ULL

static uint64_t g_rng = SEED;

static uint64_t rnd(void) {   /* splitmix64 */
	uint64_t z = (g_rng += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

enum fate { COMPLETE, TRUNCATED, HOLES, STALLS };

static struct {
	uint64_t refused, refused_allocs, buffered, completed, truncated;
	uint64_t dropped_holes, dropped_stalls, corrupt, feeds, feed_allocs;
	uint64_t max_flow_bytes, max_data_bytes, header_bytes, header_varies, resized;
	uint64_t live_bytes, live_peak_bytes;
} m;

static tls_hello_reasm_t *g_slot[FLOWS];
static uint8_t g_msg[TLS_HELLO_MAX_MESSAGE];

/* One segment: `len` bytes of the message from `off`, at position pos. */
static tls_hello_reasm_status_t feed_at(unsigned f, uint32_t pos, uint32_t off, uint32_t len) {
	uint64_t calls = tcm_calls;
	tls_hello_reasm_status_t st = tls_hello_reasm_feed(&g_slot[f], pos, g_msg + off, len);
	m.feeds++;
	if (tcm_calls != calls) m.feed_allocs++;
	return st;
}

static tls_hello_reasm_status_t feed(unsigned f, uint32_t base, uint32_t off, uint32_t len) {
	return feed_at(f, base + off, off, len);
}

static uint32_t seg_len(uint32_t left) {
	uint32_t n = 1 + (uint32_t) (rnd() % MSS);
	return n < left ? n : left;
}

static void run_complete(unsigned f, uint32_t base, uint32_t need) {
	uint32_t cuts[66], n = 0, off = 0, dups = 0;
	while (off < need && n < 63) {
		cuts[n++] = off;
		off += seg_len(need - off);
	}
	if (off < need) cuts[n++] = off;   /* the last segment takes the rest */
	cuts[n] = need;
	tls_hello_reasm_status_t st = TLS_REASM_PENDING;
	for (uint32_t w = 0; w < n; w += 4) {
		uint32_t hi = w + 4 < n ? w + 4 : n;
		for (uint32_t k = hi; k-- > w; ) {
			st = feed(f, base, cuts[k], cuts[k + 1] - cuts[k]);
			if (k % 5 == 0 && dups < 4 && st == TLS_REASM_PENDING) {
				st = feed(f, base, cuts[k], cuts[k + 1] - cuts[k]);
				dups++;
			}
		}
	}
	uint32_t len = 0;
	const uint8_t *d = tls_hello_reasm_data(g_slot[f], &len);
	if (st == TLS_REASM_COMPLETE && d != NULL && len == need && memcmp(d, g_msg, need) == 0) {
		m.completed++;
	} else {
		m.corrupt++;
	}
}

static void run_truncated(unsigned f, uint32_t base, uint32_t need) {
	for (uint32_t off = 0; off < need / 2; ) {
		uint32_t n = seg_len(need / 2 - off);
		CHECK(feed(f, base, off, n) == TLS_REASM_PENDING, "flow %u: truncated feed pending", f);
		off += n;
	}
	m.truncated++;
}

static void run_holes(unsigned f, uint32_t base, uint32_t need) {
	tls_hello_reasm_status_t st = TLS_REASM_PENDING;
	for (uint32_t off = 1; off < need && st != TLS_REASM_DROPPED; off += 64) {
		st = feed(f, base, off, 1);
	}
	CHECK(st == TLS_REASM_DROPPED && g_slot[f] == NULL, "flow %u: holes drop the reassembly", f);
	m.dropped_holes += (st == TLS_REASM_DROPPED);
}

static void run_stalls(unsigned f, uint32_t base, uint32_t need) {
	uint32_t first = seg_len(need - 1);   /* never the whole record */
	tls_hello_reasm_status_t st = feed(f, base, 0, first);
	for (unsigned i = 0; i < 100 && st != TLS_REASM_DROPPED; i++) {
		st = (i % 2) ? feed_at(f, base + need + 7, 0, 10) : feed(f, base, 0, first);
	}
	CHECK(st == TLS_REASM_DROPPED && g_slot[f] == NULL, "flow %u: stalls drop the reassembly", f);
	m.dropped_stalls += (st == TLS_REASM_DROPPED);
}

static uint32_t declared_length(unsigned f, enum fate fate) {
	if (f == 0) return TLS_HELLO_MAX_MESSAGE + 1;
	if (f == 1) return TLS_HELLO_MAX_MESSAGE;
	if (f % 4 == 0) return TLS_HELLO_MAX_MESSAGE + 1 + (uint32_t) (rnd() % (65535 - TLS_HELLO_MAX_MESSAGE));
	if (fate == HOLES) return HOLES_MIN + (uint32_t) (rnd() % (TLS_HELLO_MAX_MESSAGE - HOLES_MIN + 1));
	if (fate == STALLS) return 2 + (uint32_t) (rnd() % (TLS_HELLO_MAX_MESSAGE - 1));
	return 1 + (uint32_t) (rnd() % TLS_HELLO_MAX_MESSAGE);
}

static void run_flow(unsigned f) {
	enum fate fate = (enum fate) ((f / 4) % 4);
	uint32_t need = declared_length(f, fate);
	uint32_t base = (uint32_t) rnd();
	for (uint32_t i = 0; i < need && i < sizeof g_msg; i++) g_msg[i] = (uint8_t) rnd();

	uint64_t calls = tcm_calls;
	tls_hello_reasm_status_t st = tls_hello_reasm_begin(&g_slot[f], need, base, 0);
	if (need > TLS_HELLO_MAX_MESSAGE) {
		CHECK(st == TLS_REASM_DROPPED && g_slot[f] == NULL, "flow %u: oversize %u refused", f, need);
		m.refused++;
		if (tcm_calls != calls) m.refused_allocs++;
		return;
	}
	CHECK(st == TLS_REASM_PENDING && g_slot[f] != NULL, "flow %u: %u-byte record accepted", f, need);
	if (g_slot[f] == NULL) return;
	m.buffered++;
	uint64_t fp = tls_hello_reasm_footprint(g_slot[f]);
	uint64_t hdr = fp - need;
	if (m.buffered == 1) m.header_bytes = hdr;
	if (hdr != m.header_bytes) m.header_varies++;
	if (fp > m.max_flow_bytes) m.max_flow_bytes = fp;
	if (need > m.max_data_bytes) m.max_data_bytes = need;
	if (m.live_bytes + fp > m.live_peak_bytes) m.live_peak_bytes = m.live_bytes + fp;

	switch (fate) {
	case COMPLETE:  run_complete(f, base, need); break;
	case TRUNCATED: run_truncated(f, base, need); break;
	case HOLES:     run_holes(f, base, need); break;
	case STALLS:    run_stalls(f, base, need); break;
	}
	if (g_slot[f] != NULL && tls_hello_reasm_footprint(g_slot[f]) != fp) m.resized++;
	m.live_bytes += tls_hello_reasm_footprint(g_slot[f]);
}

int main(void) {
	rb_seed(RB, "workload", SEED);
	for (unsigned f = 0; f < FLOWS; f++) {
		run_flow(f);
	}
	CHECK(g_slot[1] != NULL && tls_hello_reasm_footprint(g_slot[1]) == m.header_bytes + TLS_HELLO_MAX_MESSAGE,
	      "the 2^14-byte record is held at header + 2^14 bytes");

	uint64_t in_flight = 0;
	for (unsigned f = 0; f < FLOWS; f++) {
		in_flight += (g_slot[f] != NULL);
		tls_hello_reasm_release(&g_slot[f]);   /* session teardown */
	}
	CHECK(m.refused + m.buffered == FLOWS, "every flow refused or buffered");
	CHECK(m.completed + m.truncated + m.dropped_holes + m.dropped_stalls + m.corrupt == m.buffered,
	      "every buffered flow accounted");

	rb_metric(RB, "flows", FLOWS);
	rb_metric(RB, "refused_oversize", m.refused);
	rb_metric(RB, "refused_allocs", m.refused_allocs);
	rb_metric(RB, "buffered", m.buffered);
	rb_metric(RB, "completed", m.completed);
	rb_metric(RB, "truncated", m.truncated);
	rb_metric(RB, "dropped_holes", m.dropped_holes);
	rb_metric(RB, "dropped_stalls", m.dropped_stalls);
	rb_metric(RB, "corrupt", m.corrupt);
	rb_metric(RB, "feeds", m.feeds);
	rb_metric(RB, "feed_allocs", m.feed_allocs);
	rb_metric(RB, "max_flow_bytes", m.max_flow_bytes);
	rb_metric(RB, "max_data_bytes", m.max_data_bytes);
	rb_metric(RB, "header_bytes", m.header_bytes);
	rb_metric(RB, "header_varies", m.header_varies);
	rb_metric(RB, "resized", m.resized);
	rb_metric(RB, "in_flight_at_teardown", in_flight);
	rb_metric(RB, "live_peak_bytes", m.live_peak_bytes);
	rb_metric(RB, "leaked_allocations", (uint64_t) (tcm_outstanding < 0 ? -tcm_outstanding : tcm_outstanding));
	rb_metric(RB, "checks.failed", (uint64_t) failures);
	printf("tls-hello: %u flows, %llu oversize refused, %llu buffered (%llu completed, %llu truncated, "
	       "%llu dropped on holes, %llu on stalls), at most %llu B per flow, %d checks, %d failure(s)\n",
	       FLOWS, (unsigned long long) m.refused, (unsigned long long) m.buffered,
	       (unsigned long long) m.completed, (unsigned long long) m.truncated,
	       (unsigned long long) m.dropped_holes, (unsigned long long) m.dropped_stalls,
	       (unsigned long long) m.max_flow_bytes, checks, failures);
	return failures == 0 ? 0 : 1;
}
