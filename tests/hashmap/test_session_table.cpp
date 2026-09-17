/*
 * test_session_table.cpp — regression tests for the per-flow session store and
 * the session-timeout milestone lists in src/mmt_core/src/hash_utils.cpp.
 *
 * Issue #199 coverage:
 *   - F-BUG-001: the table resize must restore the previous slot array when
 *     the grow allocation fails (calloc fault injected via -Wl,--wrap=calloc),
 *     and lookup/insert/delete must early-out on a dead (cap == 0) or absent
 *     session table instead of indexing NULL slots.
 *   - F-BUG-011: update_session_timeout_milestone()/force_session_timeout()
 *     must not dereference session->previous when it is NULL (a session that is
 *     not the milestone head but was never linked into the list).
 */
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {
#include "hash_utils.h" /* pulls packet_processing.h: protocol_instance_t, mmt_handler_t, mmt_session_t */
}

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); g_failures++; } } while (0)

/* ---- calloc failure injection (linked with -Wl,--wrap=calloc) ------------- */
extern "C" void *__real_calloc(size_t nmemb, size_t size);
static long g_calloc_budget = -1; /* -1 = unlimited; N = next N calls succeed */
extern "C" void *__wrap_calloc(size_t nmemb, size_t size) {
    if (g_calloc_budget == 0) return NULL;
    if (g_calloc_budget > 0) g_calloc_budget--;
    return __real_calloc(nmemb, size);
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

/* ---- basic insert / lookup / delete on the session table ------------------ */
static void test_session_table_basics(void) {
    fprintf(stderr, "  test: session table insert/get/delete\n");
    void *store = init_session_map_space(int_key_comp, int_key_hash);
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
    void *store = init_session_map_space(int_key_comp, int_key_hash);
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
    void *store = init_session_map_space(int_key_comp, int_key_hash);
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

int main(void) {
    fprintf(stderr, "Session table test suite\n");

    test_session_table_basics();
    test_resize_failure_preserves_table();
    test_dead_table_early_outs();
    test_milestone_unlink_null_previous();
    test_session_iteration();

    if (g_failures == 0) {
        fprintf(stderr, "ALL CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
