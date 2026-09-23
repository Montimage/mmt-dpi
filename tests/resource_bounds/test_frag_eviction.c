/*
 * test_frag_eviction.c — issue #383 (F-PERF-004): IPv4/IPv6 fragment-map
 * eviction must pick its victim from a maintained order, not by walking
 * every in-flight datagram on each arrival at the ceiling.
 *
 *   A. AC1 — at the 1,024-datagram ceiling, 10,000 replacement arrivals
 *      examine exactly one victim each (<= 10,000 victim visits, against
 *      the 10,240,000 walker callbacks of the old full-map scan), trigger
 *      zero hashmap walker callbacks on the arrival path, and keep index
 *      maintenance (links + unlinks) at two operations per arrival; victims
 *      leave in arrival order and the map never exceeds the ceiling.
 *   B. AC2 — reference order: after every operation the recency list is
 *      compared node-for-node against a reference model for increasing,
 *      equal and backward timestamps (re-touches, arrivals and evictions).
 *      With non-decreasing timestamps the head is also cross-checked
 *      against the old semantics: the smallest last_activity.
 *   C. Removal paths — completion / malformed removal and the age sweep
 *      (mixed IPv4 + IPv6 datagrams) unlink exactly the removed nodes.
 *   D. Teardown — the mmt_close_handler() drain (value destructor walk +
 *      hashmap_free) returns every allocation and leaves the sentinel
 *      empty; a zeroed (memset handler) sentinel reads as empty.
 *
 * The fragment-map sources are included directly so the real static
 * helpers run; hashmap_walk is routed through a counting trampoline so any
 * full-map walk on the arrival path is visible. The TU is compiled with
 * -DMMT_IP_FRAG_INDEX_STATS (index counters) and -Dmalloc=tcm_malloc ...
 * (allocation balance, tcp_alloc_count.c).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashmap.h"

static uint64_t walk_callbacks;
static mmt_hashmap_walker_t walk_inner;

static void counting_walker(mmt_hashmap_t *map, mmt_hent_t *he, void *arg)
{
	walk_callbacks++;
	walk_inner(map, he, arg);
}

static void counted_hashmap_walk(mmt_hashmap_t *map, mmt_hashmap_walker_t w, void *arg)
{
	mmt_hashmap_walker_t saved = walk_inner;
	walk_inner = w;
	hashmap_walk(map, counting_walker, arg);
	walk_inner = saved;
}

#define hashmap_walk counted_hashmap_walk
#include "../../src/mmt_tcpip/lib/protocols/proto_ip_dgram.c"
#include "../../src/mmt_tcpip/lib/protocols/proto_ipv6_dgram.c"
#undef hashmap_walk
#include "../../src/mmt_tcpip/lib/protocols/proto_ip_frag.c"
#include "../../src/mmt_core/src/hashmap.c"

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

#define CEIL        MMT_IP_FRAG_MAP_MAX_ENTRIES
#define ARRIVALS    10000u

/* ------------------------------------------------------------------ */
/* Arrival path — mirrors ip_process_fragment()/ipv6 on the map side:  */
/* lookup, make room, allocate, insert, then stamp + touch.           */
/* ------------------------------------------------------------------ */

static ip_dgram_t *arrive(mmt_hashmap_t *map, mmt_hlru_t *lru, mmt_key_t key,
                          uint32_t ts, int v6)
{
	ip_dgram_t *dg = NULL;
	if (!hashmap_get(map, key, (void **) &dg)) {
		if (!mmt_ip_frag_map_make_room(map, lru))
			return NULL;
		dg = v6 ? (ip_dgram_t *) ipv6_dgram_alloc() : ip_dgram_alloc();
		if (dg == NULL)
			return NULL;
		hashmap_insert_kv(map, key, dg);
	}
	dg->last_activity = ts;
	mmt_ip_frag_lru_touch(lru, &dg->lru, key);
	return dg;
}

static uint64_t index_ops(void)
{
	return mmt_ip_frag_index_stats.links + mmt_ip_frag_index_stats.unlinks;
}

static unsigned list_len(mmt_hlru_t *lru)
{
	unsigned n = 0;
	for (mmt_hlru_t *p = lru->next; p != lru && n <= 2 * CEIL; p = p->next)
		n++;
	return n;
}

/* Every listed node must be the map value stored under its key, with
 * consistent back links, and the list must hold exactly the map's keys. */
static int list_consistent(mmt_hashmap_t *map, mmt_hlru_t *lru)
{
	unsigned n = 0;
	for (mmt_hlru_t *p = lru->next; p != lru; p = p->next) {
		void *val = NULL;
		if (p->next->prev != p || p->prev->next != p)
			return 0;
		if (!hashmap_get(map, p->key, &val) || &((ip_dgram_t *) val)->lru != p)
			return 0;
		if (++n > map->nkeys)
			return 0;
	}
	return n == map->nkeys;
}

/* Close-handler drain: value destructor walk (mmt_close_handler) */
static void drain_walker(mmt_hashmap_t *map, mmt_hent_t *he, void *arg)
{
	(void) map; (void) arg;
	_frag_dgram_free(he->val);
}

/* ------------------------------------------------------------------ */
/* A. AC1 — replacement arrivals at the ceiling                        */
/* ------------------------------------------------------------------ */

static void test_ceiling_work(void)
{
	int64_t base = tcm_outstanding;
	mmt_hashmap_t *map = hashmap_alloc();
	mmt_hlru_t lru;
	memset(&lru, 0, sizeof lru);  /* zeroed like a memset handler */

	for (unsigned i = 0; i < CEIL; i++)
		arrive(map, &lru, (mmt_key_t) i, 1 + i / 8, 0);
	CHECK(map->nkeys == CEIL, "fill: %u entries", map->nkeys);

	memset(&mmt_ip_frag_index_stats, 0, sizeof mmt_ip_frag_index_stats);
	walk_callbacks = 0;
	int order_ok = 1, bounded = 1;
	for (unsigned i = 0; i < ARRIVALS; i++) {
		mmt_key_t k = (mmt_key_t) (CEIL + i);
		/* the head is the oldest arrival still in the map */
		mmt_key_t expect_victim = (mmt_key_t) i;
		if (lru.next->key != expect_victim)
			order_ok = 0;
		if (arrive(map, &lru, k, 1000 + i / 8, i & 1) == NULL)
			bounded = 0;
		void *v = NULL;
		if (hashmap_get(map, expect_victim, &v))
			order_ok = 0;
		if (map->nkeys > CEIL)
			bounded = 0;
	}
	uint64_t visits = mmt_ip_frag_index_stats.victim_visits;
	uint64_t ops = index_ops();
	printf("    A. %u arrivals at %u: %llu victim visits (full scan: %llu), "
	       "%llu walker callbacks, %llu index ops\n",
	       ARRIVALS, CEIL, (unsigned long long) visits,
	       (unsigned long long) ARRIVALS * CEIL,
	       (unsigned long long) walk_callbacks, (unsigned long long) ops);
	CHECK(bounded, "every arrival admitted, map never above the ceiling");
	CHECK(order_ok, "victims leave in arrival order");
	CHECK(visits <= ARRIVALS, "victim visits %llu > %u",
	      (unsigned long long) visits, ARRIVALS);
	CHECK(walk_callbacks == 0, "arrival path walked the map (%llu callbacks)",
	      (unsigned long long) walk_callbacks);
	CHECK(ops <= 2ull * ARRIVALS, "index ops %llu > %u",
	      (unsigned long long) ops, 2 * ARRIVALS);
	CHECK(mmt_ip_frag_index_stats.unlinks == ARRIVALS,
	      "one unlink per eviction (%llu)",
	      (unsigned long long) mmt_ip_frag_index_stats.unlinks);
	CHECK(list_consistent(map, &lru), "list mirrors the map after the flood");

	/* Re-touching the most recent datagram costs no index work. */
	uint64_t before = index_ops();
	arrive(map, &lru, (mmt_key_t) (CEIL + ARRIVALS - 1), 5000, 1);
	CHECK(index_ops() == before, "tail re-touch is free");

	/* D (part). Teardown as mmt_close_handler does it. */
	uint64_t unl = mmt_ip_frag_index_stats.unlinks;
	hashmap_walk(map, drain_walker, NULL);
	CHECK(mmt_ip_frag_index_stats.unlinks - unl == CEIL,
	      "teardown unlinked every datagram");
	CHECK(lru.next == &lru && lru.prev == &lru, "sentinel empty after teardown");
	hashmap_free(map);
	CHECK(tcm_outstanding == base, "teardown leaked %lld allocations",
	      (long long) (tcm_outstanding - base));
}

/* ------------------------------------------------------------------ */
/* B. AC2 — reference order for increasing / equal / backward stamps   */
/* ------------------------------------------------------------------ */

#define REF_N 64
static mmt_key_t ref[CEIL];   /* reference recency order, oldest first */
static unsigned  ref_n;

static void ref_touch(mmt_key_t k)
{
	unsigned i;
	for (i = 0; i < ref_n && ref[i] != k; i++)
		;
	if (i < ref_n) {
		memmove(&ref[i], &ref[i + 1], (ref_n - i - 1) * sizeof ref[0]);
		ref_n--;
	}
	ref[ref_n++] = k;
}

static void ref_evict_head(void)
{
	memmove(&ref[0], &ref[1], (ref_n - 1) * sizeof ref[0]);
	ref_n--;
}

static int list_matches_ref(mmt_hlru_t *lru)
{
	unsigned i = 0;
	for (mmt_hlru_t *p = lru->next; p != lru; p = p->next, i++)
		if (i >= ref_n || p->key != ref[i])
			return 0;
	return i == ref_n;
}

/* Old semantics: the smallest last_activity over the whole map. */
static void min_walker(mmt_hashmap_t *map, mmt_hent_t *he, void *arg)
{
	(void) map;
	uint32_t *m = (uint32_t *) arg;
	uint32_t a = ((ip_dgram_t *) he->val)->last_activity;
	if (a < *m)
		*m = a;
}

enum ts_mode { TS_INCREASING, TS_EQUAL, TS_BACKWARD };

static void test_reference_order(enum ts_mode mode, const char *name)
{
	int64_t base = tcm_outstanding;
	mmt_hashmap_t *map = hashmap_alloc();
	mmt_hlru_t lru = { &lru, &lru, 0 };
	uint32_t ts = (mode == TS_BACKWARD) ? 4000000000u : 100;
	unsigned seed = 383;
	int match = 1, min_ok = 1, victim_ok = 1;
	mmt_key_t next_key = 1;
	ref_n = 0;

	for (unsigned step = 0; step < 6000; step++) {
		seed = seed * 1103515245u + 12345u;
		unsigned r = (seed >> 16) & 0x7fff;
		mmt_key_t k;
		if (map->nkeys > 0 && (r % 3) == 0) {
			k = ref[r % ref_n];               /* re-touch an existing one */
		} else {
			k = next_key++;                   /* new datagram */
			if (map->nkeys >= CEIL) {
				mmt_key_t victim = ref[0];
				ref_evict_head();
				arrive(map, &lru, k, ts, r & 1);
				void *v = NULL;
				if (hashmap_get(map, victim, &v))
					victim_ok = 0;
				ref_touch(k);
				goto stamped;
			}
		}
		arrive(map, &lru, k, ts, r & 1);
		ref_touch(k);
stamped:
		if (mode == TS_INCREASING && (r & 3) == 0)
			ts++;
		else if (mode == TS_BACKWARD && (r & 3) == 0)
			ts--;
		/* full comparison is O(n): do it often, but not every step */
		if ((step & 15) == 0 || map->nkeys < REF_N) {
			if (!list_matches_ref(&lru))
				match = 0;
			if (mode != TS_BACKWARD) {
				uint32_t m = UINT32_MAX;
				counted_hashmap_walk(map, min_walker, &m);
				if (((ip_dgram_t *) (void *) ((char *) lru.next
				      - offsetof(ip_dgram_t, lru)))->last_activity != m)
					min_ok = 0;
			}
		}
	}
	CHECK(match, "%s: list diverged from the reference order", name);
	CHECK(victim_ok, "%s: victim was not the reference head", name);
	if (mode != TS_BACKWARD)
		CHECK(min_ok, "%s: head is not the smallest last_activity", name);
	CHECK(list_matches_ref(&lru), "%s: final order", name);
	CHECK(list_consistent(map, &lru), "%s: list mirrors the map", name);

	/* Teardown as mmt_close_handler() does it. */
	hashmap_walk(map, drain_walker, NULL);
	CHECK(lru.next == &lru, "%s: sentinel empty after teardown", name);
	hashmap_free(map);
	CHECK(tcm_outstanding == base, "%s: leaked %lld allocations", name,
	      (long long) (tcm_outstanding - base));
	printf("    B. %-10s reference order held over 6000 operations\n", name);
}

/* ------------------------------------------------------------------ */
/* C. Removal paths: completion / malformed and the age sweep          */
/* ------------------------------------------------------------------ */

static void test_removal_paths(void)
{
	int64_t base = tcm_outstanding;
	mmt_hashmap_t *map = hashmap_alloc();
	mmt_hlru_t lru = { &lru, &lru, 0 };

	/* 0..99 stale (t=10), 100..199 fresh (t=100), alternating v4/v6 */
	for (unsigned i = 0; i < 200; i++)
		arrive(map, &lru, (mmt_key_t) i, i < 100 ? 10 : 100, i & 1);

	/* Completion / malformed path: remove + free an interior datagram. */
	void *v = NULL;
	hashmap_get(map, 150, &v);
	hashmap_remove(map, 150);
	_frag_dgram_free(v);
	CHECK(list_consistent(map, &lru) && list_len(&lru) == 199,
	      "interior removal keeps the list exact");

	/* Age sweep at t=100 + TIMEOUT - 1: removes exactly the 100 stale. */
	uint64_t unl = mmt_ip_frag_index_stats.unlinks;
	mmt_ip_frag_map_sweep(map, 100 + MMT_IP_FRAG_TIMEOUT_SEC - 1);
	CHECK(map->nkeys == 99, "sweep kept %u (want 99)", map->nkeys);
	CHECK(mmt_ip_frag_index_stats.unlinks - unl == 100,
	      "sweep unlinked the swept datagrams");
	CHECK(list_consistent(map, &lru), "list mirrors the map after the sweep");
	CHECK(lru.next->key == 100, "oldest survivor heads the list");

	/* Evicting from an empty list is a no-op; make_room below the ceiling
	 * never evicts. */
	uint64_t visits = mmt_ip_frag_index_stats.victim_visits;
	CHECK(mmt_ip_frag_map_make_room(map, &lru) == 1
	      && mmt_ip_frag_index_stats.victim_visits == visits,
	      "make_room below the ceiling evicts nothing");

	mmt_ip_frag_map_drain(map);
	CHECK(map->nkeys == 0 && lru.next == &lru, "drain empties map and list");
	mmt_hlru_t zero;
	memset(&zero, 0, sizeof zero);
	mmt_ip_frag_map_evict_oldest(map, &zero);
	CHECK(zero.next == &zero, "zeroed sentinel reads as empty");
	hashmap_free(map);
	CHECK(tcm_outstanding == base, "removal paths leaked %lld allocations",
	      (long long) (tcm_outstanding - base));
	printf("    C. completion, sweep (v4+v6) and drain keep the list exact\n");
}

int main(void)
{
	printf("  fragment-eviction (issue #383):\n");
	test_ceiling_work();
	test_reference_order(TS_INCREASING, "increasing");
	test_reference_order(TS_EQUAL, "equal");
	test_reference_order(TS_BACKWARD, "backward");
	test_removal_paths();

	printf("  %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
