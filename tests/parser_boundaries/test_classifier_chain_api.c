/*
 * test_classifier_chain_api.c — the frozen classifier chains of the real
 * plugins (issue #560, F-PERF-005 checker walk part 1).
 *
 * mmt_init_handler() freezes every protocol's classification chain into one
 * contiguous array, and init_tcpip_plugin() stores each
 * inter_proto_classif_list.def row's guard inputs — its excluded_proto column
 * and the selection mask that checker's translation unit recorded — in the
 * row's chain node. With the plugins loaded, this test checks:
 *
 *   - every registered protocol's frozen views are its registration list, in
 *     list order: entries[] every node, default_entries[] the non-legacy ones
 *     (the walk order of both DPI profiles is unchanged);
 *   - on the TCP and UDP chains, the nodes carrying a guard are exactly the
 *     .def rows with an excluded protocol, in the weight-sorted registration
 *     order of the file, each with a nonzero selection mask and its row's
 *     legacy flag;
 *   - issue #561: the TCP and UDP chains have a guard view, and every
 *     guarded node has a detection set holding PROTO_UNKNOWN — the walk
 *     evaluates its guard — except the checkers that keep their own guard
 *     (local_guard[] below; check_inter_proto_excluded.py ties the list to
 *     the sources); one excluded protocol keeps one dense slot, distinct
 *     protocols distinct slots.
 *
 * The rows are expanded from the same .def in this translation unit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mmt_core.h"
#include "packet_processing.h" /* private: the chain and frozen-chain layout */
#include "tcpip/mmt_tcpip.h"

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            printf("  FAIL: ");                                      \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
            g_failures++;                                            \
        }                                                            \
    } while (0)

typedef struct {
    uint32_t    parent;
    const char *fn;
    int         weight;
    uint32_t    excluded;
    int         legacy;
} chain_row_t;

static const chain_row_t rows[] = {
#define MMT_INTER_PROTO(parent, fn, w, ex) { parent, #fn, w, ex, 0 },
#define MMT_INTER_PROTO_LEGACY(parent, fn, w, ex) { parent, #fn, w, ex, 1 },
#include "inter_proto_classif_list.def"
#undef MMT_INTER_PROTO_LEGACY
#undef MMT_INTER_PROTO
};
#define N_ROWS (sizeof(rows) / sizeof(rows[0]))

/* Issue #561: the checkers whose unit calls mmt_checker_keeps_local_guard():
 * three keep their own guard, mmt_check_gtp never had one. */
static const char *const local_guard[] = { "mmt_check_gtp", "mmt_check_ndn_http", "mmt_check_tpkt", "mmt_check_vnc" };

static int keeps_local_guard(const char *fn) {
    size_t i;
    for (i = 0; i < sizeof(local_guard) / sizeof(local_guard[0]); i++) {
        if (strcmp(local_guard[i], fn) == 0) return 1;
    }
    return 0;
}

/* Issue #561: the dense slot each excluded protocol got (0xFFFF: none yet). */
static uint16_t g_slot_of[PROTO_MAX_IDENTIFIER];

/* The frozen views are the list, node for node, in list order. */
static void check_frozen(uint32_t id, const protocol_t *p) {
    const mmt_classify_chain_t *c = p->classify_next.frozen;
    const mmt_classify_proto_t *n;
    uint32_t i = 0, j = 0;
    int same = 1;
    CHECK(c != NULL, "protocol %u: chain not frozen after mmt_init_handler()", (unsigned) id);
    if (c == NULL) return;
    for (n = p->classify_next.classify_protos; n != NULL && same; n = n->next, i++) {
        const mmt_classify_entry_t *e = &c->entries[i];
        same = i < c->count && e->node == n && e->classify_me == n->classify_me
                && e->legacy == n->legacy && e->selection_mask == n->selection_mask
                && e->excluded_proto == n->excluded_proto && e->detection == n->detection
                && e->excluded_slot == n->excluded_slot;
        if (same && !n->legacy) {
            same = j < c->default_count && c->default_entries[j].node == n;
            j++;
        }
    }
    CHECK(same && i == c->count && j == c->default_count && c->default_entries == c->entries + c->count,
          "protocol %u: frozen views differ from the list (entry %u)", (unsigned) id, (unsigned) i);
}

/* The guarded nodes of `parent`'s chain, in list order, against the .def rows
 * with an excluded protocol, stably sorted by weight (registration order
 * among equal weights — the order register_classification_function_internal()
 * inserts in). */
static void check_guards(uint32_t parent, const char *name) {
    const protocol_t *p = get_protocol_struct_by_id(parent);
    const mmt_classify_proto_t *n;
    const chain_row_t *want[N_ROWS];
    size_t nw = 0, k = 0, a, b, central = 0;
    if (p == NULL) {
        CHECK(0, "%s: parent protocol not registered", name);
        return;
    }
    for (a = 0; a < N_ROWS; a++) {
        if (rows[a].parent == parent && rows[a].excluded != PROTO_UNKNOWN) want[nw++] = &rows[a];
    }
    for (a = 1; a < nw; a++) { /* stable insertion sort by weight */
        const chain_row_t *r = want[a];
        for (b = a; b > 0 && want[b - 1]->weight > r->weight; b--) want[b] = want[b - 1];
        want[b] = r;
    }
    CHECK(nw > 0, "%s: no .def row with an excluded protocol", name);
    CHECK(p->classify_next.guard_view != NULL, "%s: no guard view (issue #561)", name);
    for (n = p->classify_next.classify_protos; n != NULL; n = n->next) {
        if (n->excluded_proto == PROTO_UNKNOWN) {
            CHECK(n->selection_mask == 0, "%s: a node without an excluded protocol has a selection mask", name);
            continue;
        }
        if (k >= nw) {
            CHECK(0, "%s: more guarded nodes than .def rows", name);
            return;
        }
        CHECK(n->excluded_proto == want[k]->excluded && n->weight == (uint32_t) want[k]->weight
              && n->legacy == want[k]->legacy,
              "%s: guarded node %zu is not row %s (excluded %u, weight %d)", name, k, want[k]->fn,
              (unsigned) want[k]->excluded, want[k]->weight);
        CHECK(n->selection_mask != 0, "%s: %s has no recorded selection mask", name, want[k]->fn);
        if (keeps_local_guard(want[k]->fn)) {
            CHECK(n->detection == NULL, "%s: %s keeps its own guard but is guarded by the walk",
                  name, want[k]->fn);
        } else {
            CHECK(n->detection != NULL && (n->detection[0] & 1u) != 0,
                  "%s: %s has no detection set holding PROTO_UNKNOWN", name, want[k]->fn);
            central++;
        }
        if (n->excluded_proto < PROTO_MAX_IDENTIFIER) {
            uint32_t q;
            if (g_slot_of[n->excluded_proto] == 0xFFFFu) {
                for (q = 0; q < PROTO_MAX_IDENTIFIER; q++) {
                    CHECK(g_slot_of[q] != n->excluded_slot, "%s: %s shares slot %u with protocol %u",
                          name, want[k]->fn, (unsigned) n->excluded_slot, (unsigned) q);
                }
                g_slot_of[n->excluded_proto] = n->excluded_slot;
            }
            CHECK(g_slot_of[n->excluded_proto] == n->excluded_slot,
                  "%s: %s: one excluded protocol, two slots", name, want[k]->fn);
            CHECK(n->excluded_slot < 256, "%s: %s: slot %u past the 4-word set", name, want[k]->fn,
                  (unsigned) n->excluded_slot);
        }
        k++;
    }
    CHECK(k == nw, "%s: %zu guarded nodes for %zu .def rows", name, k, nw);
    printf("  %s: %zu guarded checkers, in .def order; the walk evaluates %zu guards\n", name, k, central);
}

int main(void) {
    char errbuf[256];
    uint32_t id, frozen = 0;
    printf("=== frozen classifier chain test (issues #560, #561) ===\n");
    memset(g_slot_of, 0xFF, sizeof(g_slot_of));
    printf("  %zu inter_proto_classif_list.def rows\n", N_ROWS);
    if (!init_extraction()) {
        printf("  FAIL: init_extraction() failed\n");
        return 1;
    }
    mmt_handler_t *h = mmt_init_handler(1 /* DLT_EN10MB */, 0, errbuf);
    CHECK(h != NULL, "mmt_init_handler: %s", errbuf);

    for (id = 0; id < PROTO_MAX_IDENTIFIER; id++) {
        const protocol_t *p = get_protocol_struct_by_id(id);
        if (p != NULL && p->classify_next.classify_protos != NULL) {
            check_frozen(id, p);
            frozen++;
        }
    }
    printf("  %u classification chains checked\n", (unsigned) frozen);
    CHECK(frozen >= 2, "expected at least the TCP and UDP chains, got %u", (unsigned) frozen);
    check_guards(PROTO_TCP, "tcp");
    check_guards(PROTO_UDP, "udp");

    if (h != NULL) mmt_close_handler(h);
    close_extraction();
    printf("  %d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}
