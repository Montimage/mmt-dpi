/*
 * test_session_table.c — regression tests for the per-flow session store and
 * the session-timeout milestone lists in src/mmt_core/src/hash_utils.c.
 *
 * Issue #199 coverage:
 *   - F-BUG-001: the table resize must restore the previous slot array when
 *     the grow allocation fails (calloc fault injected via -Wl,--wrap=calloc),
 *     and lookup/insert/delete must early-out on a dead (cap == 0) or absent
 *     session table instead of indexing NULL slots.
 *   - F-BUG-011: update_session_timeout_milestone()/force_session_timeout()
 *     must not dereference session->previous when it is NULL (a session that is
 *     not the milestone head but was never linked into the list).
 *
 * Issue #539 coverage (hash_utils ported from C++ to C):
 *   - the parked-milestone index (a sorted array since the port, a std::map
 *     before) keeps milestones parked out of order sorted: drain and the
 *     range-expiry sweep dispatch ring and parked milestones in ascending
 *     order, as the std::sort over pair<milestone, head> did;
 *   - growing the parked index, and the drain snapshot, are malloc
 *     allocations (malloc fault injected via -Wl,--wrap=malloc): a failure
 *     returns MMT_TIMEOUT_NOMEM / dispatches nothing, and leaves every live
 *     milestone in place.
 *
 * Issue #551 coverage (F-BUG-011):
 *   - the per-table hash seeds start from a per-process random base: the
 *     first tables' seeds are printed ("table seed: 0x...") and must not be
 *     the legacy fixed sequence; run_tests.sh runs `test_session_table seed`
 *     twice and requires different seeds;
 *   - MMT_DETERMINISTIC_SEED=1 restores the legacy sequence exactly
 *     (fmix64(0x243F6A8885A308D3 + k * 0x9E3779B97F4A7C15), k = 1, 2, ...).
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_utils.h" /* pulls packet_processing.h: protocol_instance_t, mmt_handler_t, mmt_session_t */

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); g_failures++; } } while (0)

/* ---- calloc failure injection (linked with -Wl,--wrap=calloc) ------------- */
void *__real_calloc(size_t nmemb, size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);
static long g_calloc_budget = -1; /* -1 = unlimited; N = next N calls succeed */
void *__wrap_calloc(size_t nmemb, size_t size) {
    if (g_calloc_budget == 0) return NULL;
    if (g_calloc_budget > 0) g_calloc_budget--;
    return __real_calloc(nmemb, size);
}

/* ---- malloc failure injection (linked with -Wl,--wrap=malloc) ------------- */
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
static long g_malloc_budget = -1; /* -1 = unlimited; N = next N calls succeed */
void *__wrap_malloc(size_t size) {
    if (g_malloc_budget == 0) return NULL;
    if (g_malloc_budget > 0) g_malloc_budget--;
    return __real_malloc(size);
}

/* ---- key helpers: keys are plain ints addressed by pointer ---------------- */
static bool int_key_comp(void *a, void *b) { return *(int *)a < *(int *)b; }
static uint64_t int_key_hash(void *k) { return (uint64_t)(uint32_t)*(int *)k; }

static protocol_instance_t make_proto_ctx(void *sessions_map) {
    protocol_instance_t pc;
    memset(&pc, 0, sizeof(pc));
    pc.sessions_map = sessions_map;
    return pc;
}

/* ---- issue #551: random per-process table seeds, deterministic override -- */
static uint64_t legacy_mix64(uint64_t h) { /* hash_utils.c's mmt_mix64 */
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

/* Must run before any other table is created: it checks the first two seeds
 * of the process. */
static void test_table_seeds(void) {
    const char *env = getenv("MMT_DETERMINISTIC_SEED");
    bool deterministic = env != NULL && env[0] != '\0' && strcmp(env, "0") != 0;
    uint64_t legacy1 = legacy_mix64(0x243F6A8885A308D3ULL + 0x9E3779B97F4A7C15ULL);
    uint64_t legacy2 = legacy_mix64(0x243F6A8885A308D3ULL + 2 * 0x9E3779B97F4A7C15ULL);
    fprintf(stderr, "  test: table seeds (%s)\n", deterministic ? "MMT_DETERMINISTIC_SEED" : "random");
    void *a = init_session_map_space(int_key_comp, int_key_hash, NULL);
    void *b = init_map_space(int_key_comp, int_key_hash);
    CHECK(a != NULL && b != NULL, "init_*_map_space should succeed");
    if (a == NULL || b == NULL) { delete_session_map_space(a); delete_map_space(b); return; }
    uint64_t sa = mmt_oa_table_seed(a), sb = mmt_oa_table_seed(b);
    printf("table seed: 0x%016llx 0x%016llx\n", (unsigned long long) sa, (unsigned long long) sb);
    fflush(stdout);
    CHECK(sa != sb, "two tables are keyed with different seeds");
    if (deterministic) {
        CHECK(sa == legacy1 && sb == legacy2,
              "MMT_DETERMINISTIC_SEED restores the legacy fixed seed sequence");
    } else {
        CHECK(sa != legacy1 && sb != legacy2,
              "without MMT_DETERMINISTIC_SEED the seeds are not the legacy fixed sequence");
    }
    CHECK(mmt_oa_table_seed(NULL) == 0, "a NULL table has no seed");
    delete_session_map_space(a);
    delete_map_space(b);
}

/* ---- basic insert / lookup / delete on the session table ------------------ */
static void test_session_table_basics(void) {
    fprintf(stderr, "  test: session table insert/get/delete\n");
    void *store = init_session_map_space(int_key_comp, int_key_hash, NULL);
    CHECK(store != NULL, "init_session_map_space should succeed");
    if (store == NULL) return;

    protocol_instance_t pc = make_proto_ctx(store);
    int keys[8], vals[8];
    for (int i = 0; i < 8; i++) { keys[i] = 100 + i; vals[i] = i; }
    for (int i = 0; i < 8; i++)
        CHECK(insert_session_into_protocol_context(&pc, &keys[i], &vals[i]) == 1,
              "insert should succeed");
    for (int i = 0; i < 8; i++)
        CHECK(get_session_from_protocol_context_by_session_key(&pc, &keys[i]) == &vals[i],
              "lookup should return the stored value");
    CHECK(delete_session_from_protocol_context(&pc, &keys[3]) == 1, "delete should succeed");
    CHECK(get_session_from_protocol_context_by_session_key(&pc, &keys[3]) == NULL,
          "deleted key should no longer be found");

    delete_session_map_space(store);
}

/* ---- F-BUG-001: failed grow must keep the old table alive ------------------ */
static void test_resize_failure_preserves_table(void) {
    fprintf(stderr, "  test: session table survives failed resize\n");
    /* Budget 1: the initial 16-slot calloc succeeds, every later calloc fails. */
    g_calloc_budget = 1;
    void *store = init_session_map_space(int_key_comp, int_key_hash, NULL);
    g_calloc_budget = 0; /* hard OOM for the rest of the test */
    CHECK(store != NULL, "init_session_map_space should succeed under budget 1");
    if (store == NULL) { g_calloc_budget = -1; return; }

    protocol_instance_t pc = make_proto_ctx(store);
    int keys[16], vals[16];
    for (int i = 0; i < 16; i++) { keys[i] = i + 1; vals[i] = i * 7; }

    /* The grow fires on the 12th insert ((used+1)*10 >= 16*7). With the grow
       allocation failing, the table must keep the old slots: inserts keep
       working into the remaining free slots and no earlier entry is lost. */
    int inserted = 0;
    for (int i = 0; i < 16; i++) {
        if (insert_session_into_protocol_context(&pc, &keys[i], &vals[i]) == 1)
            inserted++;
    }
    CHECK(inserted == 16, "all 16 inserts should land in the preserved table");
    for (int i = 0; i < 16; i++)
        CHECK(get_session_from_protocol_context_by_session_key(&pc, &keys[i]) == &vals[i],
              "entry must survive the failed resize");

    /* A full table with a broken allocator must fail cleanly, not spin. */
    int extra_key = 999, extra_val = 0;
    CHECK(insert_session_into_protocol_context(&pc, &extra_key, &extra_val) == 0,
          "insert into a full table under OOM should fail, not loop");

    delete_session_map_space(store);
    g_calloc_budget = -1;
}

/* ---- F-BUG-001: dead / absent tables must early-out ------------------------ */
static void test_dead_table_early_outs(void) {
    fprintf(stderr, "  test: session ops on absent/dead table early-out\n");
    int key = 5, val = 9;

    protocol_instance_t pc = make_proto_ctx(NULL); /* sessions_map == NULL */
    CHECK(insert_session_into_protocol_context(&pc, &key, &val) == 0,
          "insert with NULL sessions_map should return 0");
    CHECK(get_session_from_protocol_context_by_session_key(&pc, &key) == NULL,
          "lookup with NULL sessions_map should return NULL");
    CHECK(delete_session_from_protocol_context(&pc, &key) == 1,
          "delete with NULL sessions_map mirrors the not-found return");

    /* NULL protocol_context itself must not be dereferenced. */
    CHECK(insert_session_into_protocol_context(NULL, &key, &val) == 0,
          "insert on NULL context should return 0");
    CHECK(get_session_from_protocol_context_by_session_key(NULL, &key) == NULL,
          "lookup on NULL context should return NULL");
    CHECK(delete_session_from_protocol_context(NULL, &key) == 1,
          "delete on NULL context mirrors the not-found return");
}

/* ---- F-BUG-011: unlink must not deref session->previous == NULL ------------ */
static void test_milestone_unlink_null_previous(void) {
    fprintf(stderr, "  test: milestone unlink with NULL session->previous\n");
    mmt_handler_t h;
    memset(&h, 0, sizeof(h));
    h.timeout_milestones_map = init_timeout_milestones_index();
    CHECK(h.timeout_milestones_map != NULL, "init_timeout_milestones_index should succeed");
    if (h.timeout_milestones_map == NULL) return;

    mmt_session_t head, orphan;
    memset(&head, 0, sizeof(head));
    memset(&orphan, 0, sizeof(orphan));

    /* head occupies milestone 100; orphan shares the milestone value but was
       never linked into the list (previous == NULL, next == NULL). */
    CHECK(insert_session_timeout_milestone(&h, 100, &head) == 1, "insert head at 100");
    orphan.session_timeout_milestone = 100;

    /* Pre-fix this dereferences orphan.previous (NULL) -> crash. */
    CHECK(force_session_timeout(&h, &orphan) == 1,
          "force_session_timeout on unlinked session should return 1");
    CHECK(get_timed_out_session_list(&h, 100) == &head,
          "milestone head must be untouched by the failed unlink");

    orphan.session_timeout_milestone = 100;
    CHECK(update_session_timeout_milestone(&h, 200, 100, &orphan) == 1,
          "update on unlinked session should relink cleanly");
    CHECK(get_timed_out_session_list(&h, 200) == &orphan,
          "session should now head milestone 200");
    CHECK(get_timed_out_session_list(&h, 100) == &head,
          "old milestone head still intact");

    /* Sanity: a properly linked mid-list session still unlinks correctly. */
    mmt_session_t mid;
    memset(&mid, 0, sizeof(mid));
    CHECK(insert_session_timeout_milestone(&h, 300, &head) == 1, "insert head at 300");
    CHECK(insert_session_timeout_milestone(&h, 300, &mid) == 1, "insert mid at 300");
    CHECK(get_timed_out_session_list(&h, 300) == &mid, "mid is the 300 head");
    CHECK(update_session_timeout_milestone(&h, 400, 300, &head) == 1,
          "update on linked session should succeed");
    CHECK(get_timed_out_session_list(&h, 300) == &mid, "mid still heads 300");
    CHECK(mid.next == NULL, "unlink should drop the tail link");

    clear_timeout_milestones(&h);
}

/* ---- iteration over live entries ------------------------------------------ */
static int g_iter_count = 0;
static void count_entry(void *key, void *value, void *args) {
    (void)key; (void)value; (void)args;
    g_iter_count++;
}

static void test_session_iteration(void) {
    fprintf(stderr, "  test: session iteration visits live entries only\n");
    void *store = init_session_map_space(int_key_comp, int_key_hash, NULL);
    CHECK(store != NULL, "init_session_map_space");
    if (store == NULL) return;
    protocol_instance_t pc = make_proto_ctx(store);
    int keys[6], vals[6];
    for (int i = 0; i < 6; i++) { keys[i] = i * 3; vals[i] = i; }
    for (int i = 0; i < 6; i++) insert_session_into_protocol_context(&pc, &keys[i], &vals[i]);
    delete_session_from_protocol_context(&pc, &keys[2]); /* leave a tombstone */

    g_iter_count = 0;
    protocol_sessions_iteration_callback(&pc, count_entry, NULL);
    CHECK(g_iter_count == 5, "iteration should skip the tombstoned slot");

    /* And on a context with no table at all. */
    protocol_instance_t empty = make_proto_ctx(NULL);
    g_iter_count = 0;
    protocol_sessions_iteration_callback(&empty, count_entry, NULL);
    CHECK(g_iter_count == 0, "iteration on NULL table visits nothing");

    delete_session_map_space(store);
}

/* ---- issue #539: parked-milestone index order and allocation failure ------ */
/* A milestone further than the ring's maximum span (1 << 22 s) from every
 * live one cannot get a ring slot and is parked. */
#define FAR_SPAN ((uint32_t) (1u << 23))
#define BASE     ((uint32_t) 100000000u)

static uint32_t g_dispatched[16];
static int g_dispatch_n = 0;
static void record_milestone(void *key, void *value, void *args) {
    (void) key; (void) args;
    const mmt_session_t *head = (const mmt_session_t *) value;
    if (g_dispatch_n < 16) g_dispatched[g_dispatch_n] = head->session_timeout_milestone;
    g_dispatch_n++;
}

static int arm(mmt_handler_t *h, mmt_session_t *s, uint32_t milestone) {
    memset(s, 0, sizeof(*s));
    s->session_timeout_milestone = milestone;
    return insert_session_timeout_milestone(h, milestone, s);
}

static void test_parked_index_order(void) {
    fprintf(stderr, "  test: ring + parked milestones dispatch in ascending order (#539)\n");
    mmt_handler_t h;
    memset(&h, 0, sizeof(h));
    h.timeout_milestones_map = init_timeout_milestones_index();
    CHECK(h.timeout_milestones_map != NULL, "init_timeout_milestones_index");
    if (h.timeout_milestones_map == NULL) return;

    /* One ring milestone, then outliers parked deliberately out of order —
     * above and below it — so the sorted insert is exercised at the tail,
     * the head and in the middle. */
    const uint32_t order[6] = { BASE + 3 * FAR_SPAN, BASE + FAR_SPAN, BASE - FAR_SPAN,
                                BASE + 2 * FAR_SPAN, BASE - 2 * FAR_SPAN, BASE + 5 * FAR_SPAN };
    mmt_session_t ring, parked[6], joiner;
    CHECK(arm(&h, &ring, BASE) == MMT_TIMEOUT_INSERTED, "the first milestone takes a ring slot");
    for (int i = 0; i < 6; i++) {
        CHECK(arm(&h, &parked[i], order[i]) == MMT_TIMEOUT_PARKED, "an out-of-span milestone is parked");
    }
    CHECK(arm(&h, &joiner, BASE + FAR_SPAN) == MMT_TIMEOUT_PARKED, "a session joins its parked milestone");
    CHECK(get_timed_out_session_list(&h, BASE + FAR_SPAN) == &joiner, "the joiner heads the parked list");
    CHECK(joiner.next == &parked[1] && parked[1].previous == &joiner, "the parked list is linked");
    for (int i = 0; i < 6; i++) {
        CHECK(get_timed_out_session_list(&h, order[i]) != NULL, "every parked milestone is reachable");
    }
    CHECK(get_timed_out_session_list(&h, BASE + 4 * FAR_SPAN) == NULL, "an absent milestone is not found");

    /* Range sweep (gap > ring capacity): only [BASE - FAR_SPAN, BASE + 3 * FAR_SPAN)
     * is due — four milestones, ascending; the two outside stay parked. */
    g_dispatch_n = 0;
    timeout_expire_milestones_range(&h, BASE - FAR_SPAN, BASE + 3 * FAR_SPAN, record_milestone);
    CHECK(g_dispatch_n == 4, "the sweep dispatches the four due milestones");
    const uint32_t swept[4] = { BASE - FAR_SPAN, BASE, BASE + FAR_SPAN, BASE + 2 * FAR_SPAN };
    for (int i = 0; i < 4 && i < g_dispatch_n; i++) {
        CHECK(g_dispatched[i] == swept[i], "the sweep dispatches in ascending milestone order");
    }
    CHECK(get_timed_out_session_list(&h, BASE) == NULL, "a swept ring milestone is gone");
    CHECK(get_timed_out_session_list(&h, BASE + FAR_SPAN) == NULL, "a swept parked milestone is gone");
    CHECK(get_timed_out_session_list(&h, BASE - 2 * FAR_SPAN) == &parked[4], "below the range stays parked");
    CHECK(get_timed_out_session_list(&h, BASE + 3 * FAR_SPAN) == &parked[0], "the range end is exclusive");

    /* Drain: everything left, ascending. */
    g_dispatch_n = 0;
    CHECK(timeout_drain_milestones(&h, record_milestone) == 3, "drain dispatches the three left");
    const uint32_t drained[3] = { BASE - 2 * FAR_SPAN, BASE + 3 * FAR_SPAN, BASE + 5 * FAR_SPAN };
    for (int i = 0; i < 3 && i < g_dispatch_n; i++) {
        CHECK(g_dispatched[i] == drained[i], "drain dispatches in ascending milestone order");
    }
    CHECK(timeout_drain_milestones(&h, record_milestone) == 0, "a drained index is empty");

    clear_timeout_milestones(&h);
}

static void test_parked_index_nomem(void) {
    fprintf(stderr, "  test: parked-index and drain allocation failures (#539)\n");
    mmt_handler_t h;
    memset(&h, 0, sizeof(h));
    h.timeout_milestones_map = init_timeout_milestones_index();
    CHECK(h.timeout_milestones_map != NULL, "init_timeout_milestones_index");
    if (h.timeout_milestones_map == NULL) return;

    mmt_session_t ring, outlier, outlier2, parked[5];
    CHECK(arm(&h, &ring, BASE) == MMT_TIMEOUT_INSERTED, "ring milestone");

    /* The parked index has never been allocated: its first entry fails. */
    g_malloc_budget = 0;
    CHECK(arm(&h, &outlier, BASE + FAR_SPAN) == MMT_TIMEOUT_NOMEM,
          "a parked-index allocation failure is MMT_TIMEOUT_NOMEM");
    g_malloc_budget = -1;
    CHECK(get_timed_out_session_list(&h, BASE + FAR_SPAN) == NULL, "the failed park left no entry");
    CHECK(get_timed_out_session_list(&h, BASE) == &ring, "the ring milestone is untouched");

    /* Fill the first parked block, then fail its growth: the index keeps
     * every entry it had. */
    for (int i = 0; i < 4; i++) {
        CHECK(arm(&h, &parked[i], BASE + (uint32_t) (i + 1) * FAR_SPAN) == MMT_TIMEOUT_PARKED, "parked");
    }
    g_malloc_budget = 0;
    CHECK(arm(&h, &outlier2, BASE - FAR_SPAN) == MMT_TIMEOUT_NOMEM, "a failed parked-index growth is NOMEM");
    g_malloc_budget = -1;
    for (int i = 0; i < 4; i++) {
        CHECK(get_timed_out_session_list(&h, BASE + (uint32_t) (i + 1) * FAR_SPAN) == &parked[i],
              "a failed growth keeps the parked entries");
    }
    CHECK(arm(&h, &parked[4], BASE - FAR_SPAN) == MMT_TIMEOUT_PARKED, "the retry parks");

    /* Drain cannot snapshot: nothing is dispatched and nothing detached. */
    g_dispatch_n = 0;
    g_malloc_budget = 0;
    CHECK(timeout_drain_milestones(&h, record_milestone) == 0, "a drain without memory dispatches nothing");
    g_malloc_budget = -1;
    CHECK(g_dispatch_n == 0, "no callback ran");
    CHECK(get_timed_out_session_list(&h, BASE) == &ring, "the ring milestone survives the failed drain");
    CHECK(get_timed_out_session_list(&h, BASE - FAR_SPAN) == &parked[4], "parked milestones survive it");
    CHECK(timeout_drain_milestones(&h, record_milestone) == 6, "the next drain dispatches all six");
    CHECK(g_dispatch_n == 6 && g_dispatched[0] == BASE - FAR_SPAN && g_dispatched[1] == BASE,
          "in ascending order");

    clear_timeout_milestones(&h);
}

int main(int argc, char **argv) {
    /* `seed` mode: print the process's first table seeds only (run_tests.sh
     * compares two runs). */
    if (argc > 1 && strcmp(argv[1], "seed") == 0) {
        test_table_seeds();
        return g_failures == 0 ? 0 : 1;
    }
    fprintf(stderr, "Session table test suite\n");

    test_table_seeds();
    test_session_table_basics();
    test_resize_failure_preserves_table();
    test_dead_table_early_outs();
    test_milestone_unlink_null_previous();
    test_session_iteration();
    test_parked_index_order();
    test_parked_index_nomem();

    if (g_failures == 0) {
        fprintf(stderr, "ALL CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
