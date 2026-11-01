/*
 * test_classify_freeze.c — the frozen classification chain (issue #560,
 * F-PERF-005 checker walk part 1), driving the real engine:
 *
 *   src/mmt_core/src/packet_registry_classify.c — mmt_classify_chain_freeze()
 *     copies the weight-sorted registration list, in list order, into one
 *     contiguous chain (every checker, plus the default view without the
 *     legacy ones), mmt_classify_chains_freeze() freezes every registered
 *     protocol's chain, and a registration after the freeze drops the frozen
 *     copy onto the retired list;
 *   src/mmt_core/src/packet_registry_handler.c — mmt_init_handler() freezes;
 *   src/mmt_core/src/packet_pipeline.c — proto_packet_classify_next() walks
 *     the frozen chain, and the list while the chain is not frozen;
 *   src/mmt_core/private_include/packet_processing.h —
 *     mmt_classifier_mark_legacy() and mmt_classifier_set_guard() update the
 *     node and drop the frozen copy;
 *   issue #561 (checker walk part 2) — the walk evaluates a guarded
 *     checker's guard on the parent's guard view (mmt_classify_guard_open())
 *     and skips the checker when it is closed, frozen or not.
 *
 * Every checker of the fake parent appends its tag to a trace and the last
 * one matches, so one packet's trace is the exact walk order. The default
 * walk, the legacy walk, the walk before the freeze, after a late
 * registration and after an out-of-memory freeze must all be the order of
 * the list. Under SANITIZE=tsan, a walk runs while another thread freezes
 * the chain, and four threads create handlers concurrently from a chain left
 * unfrozen and each walks it (docs/THREADING.md).
 *
 * Linked with -Wl,--wrap=malloc: g_malloc_budget fails the freeze's
 * allocation.
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "mmt_core.h"
#include "proto_meta.h"
#include "data_defs.h"
#include "plugin_defs.h"
#include "packet_processing.h" /* private: frozen chain, ipacket internals */

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
        __atomic_add_fetch(&g_failures, 1, __ATOMIC_RELAXED); } } while (0)

extern void *__real_malloc(size_t size);
static long g_malloc_budget = -1; /* -1 unlimited; 0 fail; N = next N succeed */

void *__wrap_malloc(size_t size) {
    long b = __atomic_load_n(&g_malloc_budget, __ATOMIC_RELAXED);
    if (b == 0) return NULL;
    if (b > 0) __atomic_store_n(&g_malloc_budget, b - 1, __ATOMIC_RELAXED);
    return __real_malloc(size);
}

#define TEST_STACK_ID 96
#define TEST_PARENT   640 /* the protocol whose chain is under test */
#define TEST_CHILD    641 /* what the final checker classifies */

/* ---------------------------- the checkers ------------------------------ */
/* A no-match checker returns MMT_CLASSIFY_SKIP (0: try the next checker). */

/* The walk order of the current packet, one tag per checker call. Each
 * handler of the concurrent test runs on its own thread, so the trace is
 * thread-local. */
static __thread char g_trace[32];
static __thread size_t g_trace_len;
static __thread int g_identity_ok;

static protocol_t *g_parent;

/* The walk publishes the checker's registration node (its stable identity:
 * the claim stores it, proto_checkers[] its id) — never the frozen entry. */
static void trace(ipacket_t *ipacket, char tag, generic_classification_function self) {
    mmt_classify_proto_t *n;
    void *cur = ipacket_internal(ipacket)->mmt_current_classifier;
    for (n = g_parent->classify_next.classify_protos; n != NULL; n = n->next) {
        if (n->classify_me == self) break;
    }
    if (n == NULL || cur != (void *) n) g_identity_ok = 0;
    if (g_trace_len + 1 < sizeof(g_trace)) {
        g_trace[g_trace_len++] = tag;
        g_trace[g_trace_len] = '\0';
    }
}

static int chk_a(ipacket_t *p, unsigned i);
static int chk_b(ipacket_t *p, unsigned i);
static int chk_c(ipacket_t *p, unsigned i);
static int chk_l(ipacket_t *p, unsigned i);
static int chk_n(ipacket_t *p, unsigned i);
static int chk_z(ipacket_t *p, unsigned i);

static int chk_a(ipacket_t *p, unsigned i) { (void) i; trace(p, 'a', chk_a); return MMT_CLASSIFY_SKIP; }
static int chk_b(ipacket_t *p, unsigned i) { (void) i; trace(p, 'b', chk_b); return MMT_CLASSIFY_SKIP; }
static int chk_c(ipacket_t *p, unsigned i) { (void) i; trace(p, 'c', chk_c); return MMT_CLASSIFY_SKIP; }
static int chk_l(ipacket_t *p, unsigned i) { (void) i; trace(p, 'l', chk_l); return MMT_CLASSIFY_SKIP; }
static int chk_n(ipacket_t *p, unsigned i) { (void) i; trace(p, 'n', chk_n); return MMT_CLASSIFY_SKIP; }

/* The last checker matches: it appends TEST_CHILD and stops the walk. */
static int chk_z(ipacket_t *p, unsigned i) {
    classified_proto_t r;
    trace(p, 'z', chk_z);
    r.offset = 4;
    r.proto_id = TEST_CHILD;
    r.status = Classified;
    (void) set_classified_proto(p, i + 1, r);
    return MMT_CLASSIFY_MATCHED;
}

/* --------------------------- engine plumbing ---------------------------- */

static classified_proto_t stack_classify(ipacket_t *ipacket) {
    classified_proto_t r;
    (void) ipacket;
    r.offset = 0;
    r.proto_id = TEST_PARENT;
    r.status = Classified;
    return r;
}

static protocol_t *register_plain(uint32_t id, const char *name) {
    protocol_t *p = init_protocol_struct_for_registration(id, name);
    if (p == NULL || register_protocol(p, id) != PROTO_REGISTERED) return NULL;
    return p;
}

/* One packet through `h`; returns its walk order. */
static const char *walk(mmt_handler_t *h) {
    pkthdr_t hdr;
    u_char buf[64];
    memset(buf, 0x5a, sizeof(buf));
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = hdr.len = (unsigned) sizeof(buf);
    g_trace_len = 0;
    g_trace[0] = '\0';
    g_identity_ok = 1;
    CHECK(packet_process(h, &hdr, buf) == 1, "packet processed");
    CHECK(g_identity_ok, "the walk publishes each checker's registration node");
    return g_trace;
}

/* The frozen views equal the list, in order: entries[] is every node,
 * default_entries[] every non-legacy node. */
static int frozen_matches_list(const protocol_t *p) {
    const mmt_classify_chain_t *c = p->classify_next.frozen;
    const mmt_classify_proto_t *n;
    uint32_t i = 0, j = 0;
    if (c == NULL || c->default_entries != c->entries + c->count) return 0;
    for (n = p->classify_next.classify_protos; n != NULL; n = n->next, i++) {
        const mmt_classify_entry_t *e = &c->entries[i];
        if (i >= c->count || e->node != n || e->classify_me != n->classify_me
                || e->legacy != n->legacy || e->selection_mask != n->selection_mask
                || e->excluded_proto != n->excluded_proto || e->detection != n->detection
                || e->excluded_slot != n->excluded_slot) return 0;
        if (!n->legacy) {
            if (j >= c->default_count || c->default_entries[j].node != n) return 0;
            j++;
        }
    }
    return i == c->count && j == c->default_count;
}

static int retired_count(const protocol_t *p) {
    int k = 0;
    const mmt_classify_chain_t *c;
    for (c = p->classify_next.retired; c != NULL; c = c->retired_next) k++;
    return k;
}

/* ------------------------------- tests ---------------------------------- */

static void test_freeze_and_order(mmt_handler_t **out) {
    char errbuf[256];
    fprintf(stderr, "  test: freeze at mmt_init_handler keeps the list order\n");
    /* Weights 30, 10, 30 (equal: registration order), 20 legacy, 90. */
    CHECK(register_classification_function_with_parent_protocol(TEST_PARENT, chk_a, 30) == 1, "a registered");
    CHECK(register_classification_function_with_parent_protocol(TEST_PARENT, chk_b, 10) == 1, "b registered");
    CHECK(register_classification_function_with_parent_protocol(TEST_PARENT, chk_c, 30) == 1, "c registered");
    CHECK(register_classification_function_with_parent_protocol(TEST_PARENT, chk_l, 20) == 1, "l registered");
    CHECK(register_classification_function_with_parent_protocol(TEST_PARENT, chk_z, 90) == 1, "z registered");
    CHECK(mmt_classifier_mark_legacy(g_parent, chk_l) == 1, "l marked legacy");
    CHECK(mmt_classifier_set_guard(g_parent, chk_a, 0x92u, TEST_CHILD, NULL, 0) == 1, "a's guard recorded");
    CHECK(mmt_classifier_set_guard(g_parent, chk_n, 1u, TEST_CHILD, NULL, 0) == 0, "an unregistered checker has no guard");
    CHECK(mmt_classifier_set_guard(g_parent, chk_a, 1u, PROTO_MAX_IDENTIFIER, NULL, 0) == 0,
          "an out-of-range excluded protocol is refused");
    CHECK(g_parent->classify_next.frozen == NULL && g_parent->classify_next.retired == NULL,
          "registrations before the first handler freeze nothing and retire nothing");

    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "mmt_init_handler succeeds");
    if (h == NULL) return;
    *out = h;
    const mmt_classify_chain_t *c = g_parent->classify_next.frozen;
    CHECK(c != NULL && c->count == 5 && c->default_count == 4, "chain frozen: 5 checkers, 4 in the default view");
    CHECK(frozen_matches_list(g_parent), "frozen views are the list, in list order");
    CHECK(c != NULL && c->entries[2].classify_me == chk_a && c->entries[2].selection_mask == 0x92u
          && c->entries[2].excluded_proto == TEST_CHILD, "the frozen entry carries the guard inputs");
    CHECK(c != NULL && c->entries[0].selection_mask == 0 && c->entries[0].excluded_proto == PROTO_UNKNOWN,
          "a checker without a guard: mask 0, PROTO_UNKNOWN");
    CHECK(strcmp(walk(h), "bacz") == 0, "default walk: b a c z (legacy l skipped)");
    CHECK(h->last_received_packet.proto_hierarchy.proto_path[2] == TEST_CHILD, "the matching checker classified");

    CHECK(mmt_apply_dpi_profile_by_name(h, "legacy") == 1, "legacy profile applied");
    CHECK(strcmp(walk(h), "blacz") == 0, "legacy walk: b l a c z");
    CHECK(mmt_apply_dpi_profile_by_name(h, "default") == 1, "default profile applied");

    mmt_classify_chains_freeze();
    CHECK(g_parent->classify_next.frozen == c, "a second freeze keeps the frozen chain");
}

static void test_late_registration(mmt_handler_t *h) {
    char errbuf[256];
    fprintf(stderr, "  test: a registration after the freeze is walked\n");
    const mmt_classify_chain_t *old = g_parent->classify_next.frozen;
    CHECK(register_classification_function_with_parent_protocol(TEST_PARENT, chk_n, 50) == 1, "n registered late");
    CHECK(g_parent->classify_next.frozen == NULL, "the late registration drops the frozen copy");
    CHECK(g_parent->classify_next.retired == old && retired_count(g_parent) == 1,
          "the superseded chain is retired, not freed");
    CHECK(strcmp(walk(h), "bacnz") == 0, "existing handler, list walk: n in weight order");

    mmt_handler_t *h2 = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h2 != NULL, "a later handler");
    CHECK(g_parent->classify_next.frozen != NULL && g_parent->classify_next.frozen->count == 6,
          "the next mmt_init_handler re-freezes with n");
    CHECK(frozen_matches_list(g_parent), "re-frozen views are the list, in list order");
    CHECK(strcmp(walk(h), "bacnz") == 0, "existing handler, frozen walk: same order");
    if (h2 != NULL) {
        CHECK(strcmp(walk(h2), "bacnz") == 0, "new handler: same order");
        mmt_close_handler(h2);
    }

    /* The plugins' list mutators drop the frozen copy too. */
    CHECK(mmt_classifier_set_guard(g_parent, chk_n, 0x10u, TEST_CHILD, NULL, 0) == 1, "n's guard recorded after the freeze");
    CHECK(g_parent->classify_next.frozen == NULL && retired_count(g_parent) == 2, "set_guard drops the frozen copy");
    mmt_classify_chains_freeze();
    CHECK(frozen_matches_list(g_parent), "re-frozen with n's guard");
    CHECK(mmt_classifier_mark_legacy(g_parent, chk_n) == 1, "n marked legacy after the freeze");
    CHECK(g_parent->classify_next.frozen == NULL && retired_count(g_parent) == 3, "mark_legacy drops the frozen copy");
    CHECK(strcmp(walk(h), "bacz") == 0, "list walk skips the newly legacy n");
    mmt_classify_chains_freeze();
    CHECK(frozen_matches_list(g_parent) && g_parent->classify_next.frozen->default_count == 4,
          "re-frozen: n left the default view");
    CHECK(strcmp(walk(h), "bacz") == 0, "frozen walk skips n");
}

static void test_freeze_oom(mmt_handler_t *h) {
    fprintf(stderr, "  test: a failed freeze falls back to the list\n");
    mmt_classify_chain_invalidate(&g_parent->classify_next);
    __atomic_store_n(&g_malloc_budget, 0, __ATOMIC_RELAXED);
    CHECK(mmt_classify_chain_freeze(&g_parent->classify_next) == 0, "freeze reports the failed allocation");
    __atomic_store_n(&g_malloc_budget, -1, __ATOMIC_RELAXED);
    CHECK(g_parent->classify_next.frozen == NULL, "nothing published");
    CHECK(strcmp(walk(h), "bacz") == 0, "the walk still visits every checker, in order");
    CHECK(mmt_classify_chain_freeze(&g_parent->classify_next) == 1 && frozen_matches_list(g_parent),
          "the next freeze succeeds");
    protocol_t *child = get_protocol_struct_by_id(TEST_CHILD);
    CHECK(child != NULL && mmt_classify_chain_freeze(&child->classify_next) == 1
          && child->classify_next.frozen == NULL, "an empty chain: nothing to freeze");
}

/* docs/THREADING.md: handlers may be created concurrently, from cold. The
 * chain is left unfrozen, so the first creator freezes it while the others
 * wait on the freeze mutex, then each thread walks it. TSan checks the
 * publication (release store / acquire load) under SANITIZE=tsan. */
static void *worker(void *arg) {
    char errbuf[256];
    int *ok = (int *) arg;
    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    *ok = 0;
    if (h != NULL) {
        int round;
        *ok = 1;
        for (round = 0; round < 4; round++) {
            if (strcmp(walk(h), "bacz") != 0) *ok = 0;
        }
        mmt_close_handler(h);
    }
    return NULL;
}

/* A walker keeps walking an existing handler while another thread's
 * mmt_init_handler() freezes the chain under it: the walker switches from the
 * list to the published array mid-run, with no lock between them, so only the
 * release store / acquire load orders the array's contents (TSan). */
typedef struct { mmt_handler_t *h; int ok; int started; } walker_arg_t;

/* Walks until the chain has been frozen and then 50 rounds more; the main
 * thread freezes only after the first walk (on the list) has run. */
static void *walker(void *arg) {
    walker_arg_t *w = (walker_arg_t *) arg;
    int after = 0;
    w->ok = 1;
    while (after < 50) {
        if (strcmp(walk(w->h), "bacz") != 0) w->ok = 0;
        __atomic_store_n(&w->started, 1, __ATOMIC_RELEASE);
        if (__atomic_load_n(&g_parent->classify_next.frozen, __ATOMIC_ACQUIRE) != NULL) after++;
    }
    return NULL;
}

static void test_publication(mmt_handler_t *h) {
    char errbuf[256];
    pthread_t t;
    walker_arg_t w = { h, 0, 0 };
    fprintf(stderr, "  test: a walk running while another thread freezes\n");
    mmt_classify_chain_invalidate(&g_parent->classify_next);
    CHECK(pthread_create(&t, NULL, walker, &w) == 0, "walker started");
    while (!__atomic_load_n(&w.started, __ATOMIC_ACQUIRE)) {
        /* the walker's first walk runs on the list */
    }
    mmt_handler_t *h2 = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h2 != NULL, "the freezing handler");
    if (h2 == NULL) mmt_classify_chains_freeze(); /* the walker waits for a freeze */
    pthread_join(t, NULL);
    CHECK(w.ok, "the walker saw the list order before and after the publication");
    CHECK(frozen_matches_list(g_parent), "frozen by the other thread");
    if (h2 != NULL) mmt_close_handler(h2);
}

/* ----------------- issue #561: the central guard ----------------------- */

static mmt_classify_guard_view_t g_view;  /* what the parent's hook publishes */
static uint64_t g_view_excluded[4];        /* the flow's dense exclusion set */
static int g_view_calls;
static uint64_t g_det_b[16];               /* b's detection set */
static uint64_t g_det_c[16];               /* c's detection set */

static void test_guard_view(const ipacket_t *ipacket, mmt_classify_guard_view_t *view) {
    (void) ipacket;
    /* atomic: the hook stays installed for the concurrent tests that follow */
    __atomic_add_fetch(&g_view_calls, 1, __ATOMIC_RELAXED);
    *view = g_view;
}

/* The guard open on every test below unless a case closes one input. */
static void view_open(void) {
    memset(g_view_excluded, 0, sizeof(g_view_excluded));
    g_view.selection = 0x3u;
    g_view.detected_word = 0;
    g_view.detected_bits = 1u; /* PROTO_UNKNOWN */
    g_view.excluded = g_view_excluded;
}

static void test_central_guard(mmt_handler_t *h) {
    int pass, calls;
    fprintf(stderr, "  test: the walk evaluates the guards (issue #561)\n");
    g_det_b[0] = 1u;                              /* b detects on PROTO_UNKNOWN */
    g_det_c[0] = 1u;
    g_det_c[1] = (uint64_t) 1u << (70 - 64);      /* c also on protocol 70 */
    CHECK(mmt_classifier_set_guard(g_parent, chk_b, 0x1u, TEST_CHILD, g_det_b, 5) == 0,
          "a detection set needs the parent's guard view");
    CHECK(mmt_classifier_set_guard_view(g_parent, NULL) == 0, "a NULL hook is refused");
    CHECK(mmt_classifier_set_guard_view(g_parent, test_guard_view) == 1, "the guard view installed");
    CHECK(mmt_classifier_set_guard(g_parent, chk_b, 0x1u, TEST_CHILD, g_det_b, 5) == 1, "b guarded on slot 5");
    CHECK(mmt_classifier_set_guard(g_parent, chk_c, 0x2u, TEST_CHILD, g_det_c, 130) == 1, "c guarded on slot 130");
    for (pass = 0; pass < 2; pass++) {
        /* pass 0: the list walk (not frozen yet); pass 1: the frozen walk */
        const char *what = pass ? "frozen" : "list";
        if (pass) {
            mmt_classify_chains_freeze();
            CHECK(frozen_matches_list(g_parent), "frozen with the guards");
        } else {
            CHECK(g_parent->classify_next.frozen == NULL, "set_guard dropped the frozen copy");
        }
        view_open();
        calls = __atomic_load_n(&g_view_calls, __ATOMIC_RELAXED);
        CHECK(strcmp(walk(h), "bacz") == 0, what);
        CHECK(__atomic_load_n(&g_view_calls, __ATOMIC_RELAXED) == calls + 1, "the view is read once per walk");
        g_view.selection = 0x2u;
        CHECK(strcmp(walk(h), "acz") == 0, "a selection bit missing closes b's guard");
        view_open();
        g_view_excluded[0] = (uint64_t) 1u << 5;
        CHECK(strcmp(walk(h), "acz") == 0, "b excluded on the flow (slot 5)");
        g_view_excluded[2] = (uint64_t) 1u << (130 - 128);
        CHECK(strcmp(walk(h), "az") == 0, "c excluded on the flow (slot 130, third word)");
        view_open();
        g_view.detected_word = 1;
        g_view.detected_bits = (uint64_t) 1u << (70 - 64);
        CHECK(strcmp(walk(h), "acz") == 0, "detected protocol 70: in c's detection set, not in b's");
        g_view.detected_bits = 0;
        CHECK(strcmp(walk(h), "az") == 0, "no detected protocol: every guard closed");
        view_open();
        g_view.excluded = NULL;
        CHECK(strcmp(walk(h), "az") == 0, "no flow: every guard closed");
    }
    /* Unguarded again, for the tests that follow. */
    CHECK(mmt_classifier_set_guard(g_parent, chk_b, 0, PROTO_UNKNOWN, NULL, 0) == 1, "b unguarded");
    CHECK(mmt_classifier_set_guard(g_parent, chk_c, 0, PROTO_UNKNOWN, NULL, 0) == 1, "c unguarded");
    mmt_classify_chains_freeze();
    view_open();
    g_view.selection = 0;
    CHECK(strcmp(walk(h), "bacz") == 0, "unguarded checkers are walked whatever the view");
}

static void test_concurrent_freeze(void) {
    enum { N = 4 };
    pthread_t t[N];
    int ok[N];
    int i;
    fprintf(stderr, "  test: concurrent handler creation freezes once\n");
    mmt_classify_chain_invalidate(&g_parent->classify_next);
    int before = retired_count(g_parent);
    for (i = 0; i < N; i++) CHECK(pthread_create(&t[i], NULL, worker, &ok[i]) == 0, "worker started");
    for (i = 0; i < N; i++) {
        pthread_join(t[i], NULL);
        CHECK(ok[i], "worker walked the chain in list order");
    }
    CHECK(frozen_matches_list(g_parent) && retired_count(g_parent) == before,
          "frozen once, nothing retired by the concurrent freezes");
}

int main(void) {
    mmt_handler_t *h = NULL;
    fprintf(stderr, "classify_freeze: the frozen classification chain (issues #560, #561)\n");
    CHECK(init_extraction() == 1, "init_extraction succeeds");
    CHECK(register_protocol_stack(TEST_STACK_ID, (char *) "cf_stack", stack_classify) == 1, "stack registered");
    g_parent = register_plain(TEST_PARENT, "cf_parent");
    CHECK(g_parent != NULL, "parent registered");
    CHECK(register_plain(TEST_CHILD, "cf_child") != NULL, "child registered");
    if (g_parent == NULL) return 1;

    test_freeze_and_order(&h);
    if (h != NULL) {
        test_late_registration(h);
        test_freeze_oom(h);
        test_publication(h);
        test_central_guard(h);
        mmt_close_handler(h);
    }
    test_concurrent_freeze();
    close_extraction(); /* frees the frozen and retired chains (ASan: no UAF) */

    if (g_failures == 0) {
        fprintf(stderr, "  all checks passed\n");
        return 0;
    }
    fprintf(stderr, "  %d check(s) FAILED\n", g_failures);
    return 1;
}
