/*
 * test_ipv6_hash_bounds.cpp — issue #379 (F-PERF-001) acceptance harness for
 * the interned-IPv6-address store (ips_map, keyed by ipv6_addr_comp /
 * ipv6_addr_hash over the open-addressing table in hash_utils.cpp).
 *
 * hash_utils.cpp is included directly so the harness reads table internals
 * (mmt_oa_table.seed, .cap) without adding test-only exports — and so the
 * stats tripwires (mmt_oa_comp_call_count) are armed: this TU never defines
 * NDEBUG. The address functions under test come from ipv6_addr_fns.c, which
 * includes ip_session_id_management.c — the REAL comparator and hash run
 * unmodified (the test_udp_bounds_unit.c convention).
 *
 * What this asserts (issue #379 acceptance criteria):
 *   CONTRIB  all 16 address bytes reach the hash: every one of the 128
 *            single-bit variants of a base address hashes differently.
 *   KEYED    two init_map_space tables carry different per-table seeds —
 *            handlers are keyed independently.
 *   LOOKUP   every inserted distinct address is preserved: reproducible
 *            key sets intern through the real get_ip6_id/findID6 path and
 *            through init_map_space on both independently keyed tables.
 *   REGRESS  the pair that collided under the old fold (addresses differing
 *            only in byte 15's top bit — w[1] << 1 dropped it) now hashes
 *            differently and coexists.
 *   WORK     comparator calls at 1,024 / 16,384 inputs are strictly below
 *            751,360 / 200,273,920 and grow at most 24-fold for the 16-fold
 *            input growth.
 *   BOUND    under forced collisions (constant hash → one cluster) every
 *            single operation completes within the finite per-operation
 *            bound of 2 * cap comparator calls (cap = table capacity), and
 *            an insert into a slot-saturated table fails bounded instead of
 *            scanning the ring forever.
 */
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <inttypes.h>

extern "C" {
/* real functions under test (tests/resource_bounds/ipv6_addr_fns.c) */
uint64_t test_ipv6_addr_hash(void *ip);
bool     test_ipv6_addr_comp(void *a, void *b);
void    *test_ipv6_ctx_new(void);
void    *test_ipv6_get_id(void *ctx, void *ip, uint32_t *is_new);
void    *test_ipv6_find_id(void *ctx, void *ip);
void     test_ipv6_ctx_destroy(void *ctx);
}

/* The production table, same TU — internals (seed, cap, counters) visible. */
#include "../../src/mmt_core/src/hash_utils.cpp"

#include "rb_result.h"
#define RB "ipv6-hash"   /* issue #394: results.json fixture id */

static int checks = 0;
static int failures = 0;
#define CHECK(cond, msg) do { \
        checks++; \
        if (!(cond)) { \
            failures++; \
            fprintf(stderr, "FAIL %d: %s\n", __LINE__, msg); \
        } \
    } while (0)

/* ---- comparator-call accounting ------------------------------------------
 * The map's own probe counter (mmt_oa_comp_call_count) counts key_equal
 * invocations through the comparator fallback; each resolves equality with
 * up to TWO comp() calls. For exact "comparator calls" accounting the
 * harness registers a wrapper that counts every real invocation. */
static uint64_t g_comp_calls = 0;
static bool counting_ipv6_comp(void *a, void *b) {
    g_comp_calls++;
    return test_ipv6_addr_comp(a, b);
}
static uint64_t comp_calls(void) { return g_comp_calls; }

/* Forced-collision hash: every key lands on one home slot → one cluster. */
static uint64_t const_hash(void *k) { (void) k; return 0x2A; }

/* ---- reproducible key generation -----------------------------------------
 * addr[i]: bytes 0-7 = i (guaranteed distinct), bytes 8-15 = splitmix64(i)
 * (variety in the half the old fold shifted out). Deterministic across
 * runs — the "reproducible test keys" the criteria name. */
static uint64_t splitmix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}
static void make_addr(uint8_t a[16], uint64_t i) {
    uint64_t hi = splitmix64(i);
    for (int b = 0; b < 8; b++)  a[b]     = (uint8_t) (i  >> (8 * b));
    for (int b = 0; b < 8; b++)  a[8 + b] = (uint8_t) (hi >> (8 * b));
}

/* ---- CONTRIB: all 128 address bits reach the hash ------------------------ */
static void test_all_bytes_contribute(void) {
    fprintf(stderr, "  test: all 16 address bytes contribute to the hash\n");
    uint8_t base[16], flip[16];
    make_addr(base, 0x0123456789ABCDEFULL);
    uint64_t h0 = test_ipv6_addr_hash(base);
    int differ = 0;
    for (int bit = 0; bit < 128; bit++) {
        memcpy(flip, base, 16);
        flip[bit / 8] ^= (uint8_t) (1u << (bit % 8));
        if (test_ipv6_addr_hash(flip) != h0) differ++;
    }
    CHECK(differ == 128, "every single-bit variant must hash differently");
    fprintf(stderr, "    %d/128 single-bit variants changed the hash\n", differ);
}

/* ---- REGRESS: the pair the old fold could not distinguish ----------------- */
static void test_old_fold_collision_pair(void) {
    fprintf(stderr, "  test: old-fold collision pair now separates\n");
    uint8_t a[16], b[16];
    make_addr(a, 7);
    memcpy(b, a, 16);
    b[15] ^= 0x80; /* w[1]'s top bit — dropped by the old (w[1] << 1) fold */
    CHECK(test_ipv6_addr_hash(a) != test_ipv6_addr_hash(b),
          "addresses differing only in byte 15's top bit must hash apart");

    void *map = init_map_space(counting_ipv6_comp, test_ipv6_addr_hash);
    CHECK(map != NULL, "map created");
    if (map == NULL) return;
    CHECK(insert_key_value(map, a, a) == 1, "first of the pair inserts");
    CHECK(insert_key_value(map, b, b) == 1, "old-fold twin inserts as distinct");
    CHECK(find_key_value(map, a) == a && find_key_value(map, b) == b,
          "both halves of the pair are preserved");
    delete_map_space(map);
}

/* ---- KEYED + LOOKUP: distinctness across independently keyed handlers ----- */
static void fill_and_verify(void *map, uint8_t addrs[][16], int n) {
    for (int i = 0; i < n; i++)
        CHECK(insert_key_value(map, addrs[i], addrs[i]) == 1,
              "distinct address inserts");
    for (int i = 0; i < n; i++)
        CHECK(find_key_value(map, addrs[i]) == addrs[i],
              "every inserted distinct address is found");
}

static void test_independent_keying_and_lookup(void) {
    fprintf(stderr, "  test: distinctness preserved on independently keyed tables\n");
    enum { N = 2048 };
    static uint8_t addrs[N][16];
    for (int i = 0; i < N; i++) make_addr(addrs[i], (uint64_t) i);

    void *m1 = init_map_space(counting_ipv6_comp, test_ipv6_addr_hash);
    void *m2 = init_map_space(counting_ipv6_comp, test_ipv6_addr_hash);
    CHECK(m1 != NULL && m2 != NULL, "two handler maps created");
    if (m1 == NULL || m2 == NULL) { delete_map_space(m1); delete_map_space(m2); return; }

    /* Independently keyed: the per-table seeds must differ so a collision
     * set computed for one handler's map does not transfer to the other. */
    uint64_t s1 = ((mmt_oa_table *) m1)->seed;
    uint64_t s2 = ((mmt_oa_table *) m2)->seed;
    CHECK(s1 != s2, "two handler maps are keyed with different seeds");
    fprintf(stderr, "    table seeds: %016llx vs %016llx\n",
            (unsigned long long) s1, (unsigned long long) s2);
    rb_seed(RB, "keyed.table_a", s1);
    rb_seed(RB, "keyed.table_b", s2);

    fill_and_verify(m1, addrs, N);
    fill_and_verify(m2, addrs, N);
    delete_map_space(m1);
    delete_map_space(m2);
}

/* ---- LOOKUP through the real interned-id path (get_ip6_id/findID6) -------- */
static void test_real_context_path(void) {
    fprintf(stderr, "  test: real get_ip6_id/findID6 path preserves distinct addresses\n");
    enum { N = 1024 };
    static uint8_t addrs[N][16];
    for (int i = 0; i < N; i++) make_addr(addrs[i], 0x1000000ULL + (uint64_t) i);

    void *ctx = test_ipv6_ctx_new();
    CHECK(ctx != NULL, "ipv6 internal context created");
    if (ctx == NULL) return;

    static void *ids[N];
    for (int i = 0; i < N; i++) {
        uint32_t is_new = 0;
        ids[i] = test_ipv6_get_id(ctx, addrs[i], &is_new);
        CHECK(ids[i] != NULL && is_new == 1, "new address interns a new id");
    }
    /* Re-interning the same address returns the same id, not a duplicate.
     * The is_new contract is the caller's: get_session() zeroes the flag
     * before calling and get_ip6_id() only raises it on a fresh insert. */
    for (int i = 0; i < N; i += 97) {
        uint32_t is_new = 0;
        void *again = test_ipv6_get_id(ctx, addrs[i], &is_new);
        CHECK(again == ids[i] && is_new == 0,
              "re-interned address resolves to the same id");
    }
    for (int i = 0; i < N; i++)
        CHECK(test_ipv6_find_id(ctx, addrs[i]) == ids[i],
              "findID6 returns the interned id for every distinct address");

    test_ipv6_ctx_destroy(ctx);
}

/* ---- WORK: comparator-call budgets at 1,024 / 16,384 inputs --------------- */
static uint64_t workload_comp_calls(int n) {
    /* Insert n distinct addresses then look each up once — the per-packet
     * workload get_ip6_id performs (find, then insert on miss). */
    static uint8_t addrs[16384][16];
    for (int i = 0; i < n; i++) make_addr(addrs[i], (uint64_t) i);

    void *map = init_map_space(counting_ipv6_comp, test_ipv6_addr_hash);
    if (map == NULL) { failures++; return UINT64_MAX; }
    uint64_t seed = ((mmt_oa_table *) map)->seed;

    uint64_t c0 = comp_calls();
    uint64_t accepted = 0, refused = 0, hits = 0;
    for (int i = 0; i < n; i++) {
        if (insert_key_value(map, addrs[i], addrs[i]) == 1) accepted++;
        else { refused++; failures++; }
    }
    uint64_t c_ins = comp_calls() - c0;
    for (int i = 0; i < n; i++) {
        if (find_key_value(map, addrs[i]) == addrs[i]) hits++;
        else failures++;
    }
    uint64_t c_find = comp_calls() - c0 - c_ins;

    delete_map_space(map);
    char k[64];
    snprintf(k, sizeof k, "n%d.table", n);            rb_seed(RB, k, seed);
    snprintf(k, sizeof k, "n%d.inputs", n);           rb_metric(RB, k, (uint64_t) n);
    snprintf(k, sizeof k, "n%d.inserts_accepted", n); rb_metric(RB, k, accepted);
    snprintf(k, sizeof k, "n%d.inserts_refused", n);  rb_metric(RB, k, refused);
    snprintf(k, sizeof k, "n%d.lookups_hit", n);      rb_metric(RB, k, hits);
    snprintf(k, sizeof k, "n%d.comparator_calls", n); rb_metric(RB, k, c_ins + c_find);
    fprintf(stderr, "    n=%5d: insert %" PRIu64 " + find %" PRIu64
            " = %" PRIu64 " comparator calls\n",
            n, (uint64_t) c_ins, (uint64_t) c_find, (uint64_t) (c_ins + c_find));
    return c_ins + c_find;
}

static void test_work_budget(void) {
    fprintf(stderr, "  test: comparator-call budgets (1,024 / 16,384 inputs)\n");
    const uint64_t BUDGET_1K  = 751360ULL;
    const uint64_t BUDGET_16K = 200273920ULL;

    uint64_t w1  = workload_comp_calls(1024);
    uint64_t w16 = workload_comp_calls(16384);

    CHECK(w1  < BUDGET_1K,  "comparator calls at 1,024 inputs under budget");
    CHECK(w16 < BUDGET_16K, "comparator calls at 16,384 inputs under budget");
    CHECK(w16 <= 24 * w1,
          "work grows at most 24-fold for 16-fold input growth");
    fprintf(stderr, "    growth factor: %.1fx (limit 24x)\n",
            w1 ? (double) w16 / (double) w1 : -1.0);
}

/* ---- BOUND: forced collisions — finite per-operation bound ---------------- */
static void test_forced_collision_bound(void) {
    fprintf(stderr, "  test: forced collisions stay under the per-op bound\n");
    enum { K = 256 };
    static uint8_t addrs[K][16];
    for (int i = 0; i < K; i++) make_addr(addrs[i], 0x2000000ULL + (uint64_t) i);

    void *map = init_map_space(counting_ipv6_comp, const_hash);
    CHECK(map != NULL, "collision map created");
    if (map == NULL) return;

    for (int i = 0; i < K; i++)
        CHECK(insert_key_value(map, addrs[i], addrs[i]) == 1,
              "colliding key still inserts (linear-probe cluster)");

    /* The finite per-operation bound: no probe sequence may visit more
     * than cap slots, so a single op costs at most 2 * cap comparator
     * calls (two comp() invocations per comparator-fallback probe). */
    size_t cap = ((mmt_oa_table *) map)->cap;
    uint64_t bound = 2 * (uint64_t) cap;
    fprintf(stderr, "    table cap=%zu, per-op comparator bound=%llu\n",
            cap, (unsigned long long) bound);

    uint64_t c0, delta, worst = 0;

    /* find hit — worst case: the last key sits at the cluster tail. */
    c0 = comp_calls();
    CHECK(find_key_value(map, addrs[K - 1]) == addrs[K - 1],
          "collided lookup still resolves");
    delta = comp_calls() - c0;
    if (delta > worst) worst = delta;
    CHECK(delta <= bound, "find hit within the per-op bound");
    fprintf(stderr, "    find hit : %llu comp calls\n",
            (unsigned long long) delta);

    /* find miss — absent key walks the whole cluster to the terminator. */
    uint8_t absent[16]; make_addr(absent, 0xDEADBEEFULL);
    c0 = comp_calls();
    CHECK(find_key_value(map, absent) == NULL, "absent key misses");
    delta = comp_calls() - c0;
    if (delta > worst) worst = delta;
    CHECK(delta <= bound, "find miss within the per-op bound");
    fprintf(stderr, "    find miss: %llu comp calls\n",
            (unsigned long long) delta);

    /* delete — bounded by the same probe ceiling. */
    c0 = comp_calls();
    CHECK(delete_key_value(map, addrs[0]) == 1, "delete succeeds");
    delta = comp_calls() - c0;
    if (delta > worst) worst = delta;
    CHECK(delta <= bound, "delete within the per-op bound");
    fprintf(stderr, "    delete   : %llu comp calls\n",
            (unsigned long long) delta);

    /* insert — one more key into the cluster. */
    c0 = comp_calls();
    CHECK(insert_key_value(map, absent, absent) == 1,
          "insert into cluster succeeds");
    delta = comp_calls() - c0;
    if (delta > worst) worst = delta;
    CHECK(delta <= bound, "insert within the per-op bound");
    fprintf(stderr, "    insert   : %llu comp calls\n",
            (unsigned long long) delta);
    rb_metric(RB, "forced_collision.keys", K);
    rb_metric(RB, "forced_collision.cap", cap);
    rb_metric(RB, "forced_collision.per_op_bound", bound);
    rb_metric(RB, "forced_collision.worst_op_comparator_calls", worst);

    delete_map_space(map);
}

/* ---- BOUND: slot-saturated table fails bounded, not unbounded -------------
 * The insert bound is defense-in-depth: used < cap guarantees an EMPTY
 * terminator in correct operation, so a full-ring scan is only reachable
 * if the invariant breaks. Drive it directly through the table internals
 * (same TU): mark every slot live, reset the counters, then insert — the
 * bounded probe must return 0 after at most cap slot visits. */
static void test_saturated_table_bounded_fail(void) {
    fprintf(stderr, "  test: saturated table fails bounded\n");
    void *map = init_map_space(counting_ipv6_comp, const_hash);
    CHECK(map != NULL, "map created");
    if (map == NULL) return;
    mmt_oa_table *t = (mmt_oa_table *) map;

    static uint8_t keys[64][16];
    size_t cap = t->cap;
    CHECK(cap <= 64, "initial capacity fits the fixture");
    for (size_t i = 0; i < cap; i++) {
        make_addr(keys[i], 0x3000000ULL + (uint64_t) i);
        t->slots[i].key   = keys[i];
        t->slots[i].value = keys[i];
    }
    t->size = cap; /* every slot live */
    t->used = 0;   /* broken invariant: bypasses the resize gate only */

    uint8_t probe[16]; make_addr(probe, 0xFEEDFACEULL);
    uint64_t c0 = comp_calls();
    int rc = insert_key_value(map, probe, probe);
    uint64_t delta = comp_calls() - c0;
    CHECK(rc == 0, "insert into a saturated table fails cleanly");
    CHECK(delta <= 2 * (uint64_t) cap,
          "saturated insert is bounded by cap slot visits");
    fprintf(stderr, "    saturated insert: rc=%d after %llu comp calls (cap=%zu)\n",
            rc, (unsigned long long) delta, cap);
    rb_metric(RB, "saturated.inserts_offered", 1);
    rb_metric(RB, "saturated.inserts_refused", rc == 0 ? 1 : 0);
    rb_metric(RB, "saturated.cap", cap);
    rb_metric(RB, "saturated.comparator_calls", delta);

    /* restore consistency before teardown */
    t->used = cap;
    delete_map_space(map);
}

int main(void) {
    fprintf(stderr, "IPv6 address hash + collision-work bounds (issue #379)\n");

    test_all_bytes_contribute();
    test_old_fold_collision_pair();
    test_independent_keying_and_lookup();
    test_real_context_path();
    test_work_budget();
    test_forced_collision_bound();
    test_saturated_table_bounded_fail();

    rb_metric(RB, "checks.total", (uint64_t) checks);
    rb_metric(RB, "checks.failed", (uint64_t) failures);
    if (failures == 0) {
        fprintf(stderr, "ALL CHECKS PASSED (%d checks)\n", checks);
        return 0;
    }
    fprintf(stderr, "%d/%d CHECKS FAILED\n", failures, checks);
    return 1;
}
