/*
 * test_core_engine.c — core-engine suite part 1 (issue #241, F-TEST-006).
 *
 * Drives the two largest central files directly, source-compiled so gcov
 * records them:
 *
 *   src/mmt_core/src/packet_registry*.c — handler lifecycle
 *     (init_extraction/mmt_init_handler/mmt_close_handler/close_extraction),
 *     attribute registration and the handler registries;
 *   src/mmt_core/src/packet_pipeline.c — the packet dispatch path
 *     (packet_process -> proto_packet_process) and attribute extraction;
 *   src/mmt_core/src/packet_session.c — proto_session_management, session
 *     create/lookup/timeout/teardown, the timeout-milestone sweep and the
 *     session timer/expiry callbacks;
 *   src/mmt_core/src/packet_stats.c — protocol statistics;
 *   src/mmt_core/src/packet_processing.c — the attribute accessors and
 *     formatting tail — including the OOM cleanup branches under
 *     deterministic malloc/calloc failure injection.
 *
 *   src/mmt_core/src/hash_utils.c — the session store and the
 *     timeout-milestone maps as exercised through the engine (the hashmap
 *     suite already covers the table internals).
 *
 *   src/mmt_core/src/memory.c — the per-flow arena allocator
 *     (mmt_arena_create/alloc/reset/destroy), including every failure path:
 *     NULL arena, size-overflow guards, and injected malloc failures on both
 *     the arena-create and the block-grow allocations.
 *
 * Part 2 (issue #242) also source-compiles:
 *
 *   src/mmt_tcpip/lib/mmt_tcpip_classif_utils.c — hostname matching (the
 *     reversed doted-name trie plus the linear suffix scan), the per-prefix
 *     AVL CIDR attribution trees including the externally-loaded
 *     extend/override rules (issues #26/#74) and the duplicate-CIDR cases
 *     fixed by Task 3.6 (F-BUG-027/028), plus the empty-hostname guard
 *     (F-BUG-030);
 *   src/mmt_tcpip/lib/avltree.c — the tree implementation backing the CIDR
 *     attribution (already covered standalone by tests/avltree);
 *   src/mmt_core/src/mmt_data.c — the memoized cumulative-offset cache behind
 *     get_packet_offset_at_index() (issue #19): lazy prefix-sum build,
 *     high-water-mark extension, invalidation and index clamping.
 *
 * Failure injection: the binary is linked with -Wl,--wrap=malloc
 * -Wl,--wrap=calloc; every libc allocation in the linked library objects is
 * routed through the budget counters below. Since issue #539 that is every
 * allocation the engine makes — hash_utils.c is C, its iteration snapshots
 * and parked-milestone index are plain malloc — the double-OOM session
 * destroy branch (F-BUG-023) is driven by a calloc budget against the
 * timeout-ring growth, and the timeout_milestones_map == NULL branch in
 * mmt_init_handler() by calloc budget 0.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> /* u_char for the pkthdr/packet prototypes */
#include <sys/time.h>

#include "mmt_core.h"
#include "proto_meta.h"
#include "data_defs.h"
#include "plugin_defs.h"
#include "packet_processing.h" /* private: mmt_handler_t / protocol_instance_t internals */
#include "hash_utils.h"
/* Issue #242: tcpip internals for the fabricated internal_packet — brings in
 * mmt_tcpip_protocols.h (MMT_SUPPORT_IPV6, PROTO_* ids) and the
 * mmt_tcpip_internal_packet_struct layout (iph/iphv6). */
#include "mmt_tcpip_internal_defs_macros.h"
#include "mmt_tcpip_plugin_structs.h"
#include <arpa/inet.h>

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
        g_failures++; } } while (0)

/* Issue #255 (F-PERF-010) acceptance: the session record must be at least
 * 190 bytes slimmer. The child-statistics block (12 sub_* counters, 144 B)
 * plus the per-direction proto_path copies (2 x 68 B) = 280 B moved into the
 * lazily-allocated mmt_session_children_stats_t tunnel-parent extension; the
 * record keeps one pointer (8 B). Pre-change sizeof measured 1032 B on this
 * LP64 target — pin the new record to <= 842 B.
 * Issue #252 (F-PERF-002) adds mmt_session_t.proto_checkers[PROTO_PATH_SIZE]
 * (16 pointers = 128 B): the per-layer winning checker recorded so converged
 * flows dispatch their per-packet protocol engine in O(1) instead of
 * re-walking the ~99-node classify chain. A lazily-allocated extension was
 * rejected — virtually every session classifies, so lazy would add an
 * alloc + pointer indirection for a block that is always needed. */
#define CE_SESSION_SIZE_PRE_255 1032u
_Static_assert(sizeof(mmt_session_t) <= CE_SESSION_SIZE_PRE_255 - 190 + 16u * sizeof(void *),
               "issue #255 + #252: session record within the #255 budget plus the #252 checker-dispatch table");

/* ---------------- libc allocation failure injection ---------------------- */
extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);
extern void *__real_realloc(void *ptr, size_t size);

static long g_malloc_budget = -1; /* -1 unlimited; 0 fail; N = next N succeed */
static long g_calloc_budget = -1;

/* Issue #255 (F-PERF-015): instrumentation proving the allocator no longer
 * adds the 8-byte size prefix — the sizes libc actually sees are recorded. */
static size_t g_malloc_last_size;
static size_t g_realloc_last_size;

void *__wrap_malloc(size_t size) {
    g_malloc_last_size = size;
    if (g_malloc_budget == 0) return NULL;
    if (g_malloc_budget > 0) g_malloc_budget--;
    return __real_malloc(size);
}
void *__wrap_calloc(size_t nmemb, size_t size) {
    if (g_calloc_budget == 0) return NULL;
    if (g_calloc_budget > 0) g_calloc_budget--;
    return __real_calloc(nmemb, size);
}
void *__wrap_realloc(void *ptr, size_t size) {
    g_realloc_last_size = size;
    return __real_realloc(ptr, size);
}

/* Internal entry points with no public prototype — exercised for coverage. */
int mmt_attr_snprintf(char *buff, int len, attribute_t *a);
void mmt_print_proto_info(protocol_t *proto);
int is_protocol_valid_attribute(uint32_t proto_id, uint32_t attribute_id);
int proto_packet_analyze(ipacket_t *ipacket, protocol_instance_t *configured_protocol, unsigned index);

/* mmt_tcpip_classif_utils.c entry points (issue #242) — the two public ones
 * are declared in mmt_common_internal_include.h, which is too heavy to pull
 * in here, so all are declared by hand like the block above. */
int mmt_case_sensitive_reverse_hostname_matching(const char *hostname, const char *url,
                                                 size_t hostname_len, size_t url_len);
uint32_t get_proto_id_by_hostname(ipacket_t *ipacket, char *hostname, u_int hostname_len);
uint32_t _get_proto_id_by_hostname(ipacket_t *ipacket, char *hostname, u_int hostname_len);
uint32_t get_proto_id_from_address(ipacket_t *ipacket);
int _find_proto_id_by_address(uint32_t ip_src, uint32_t ip_dest);
int _find_proto_id_by_address6(const uint8_t ip_src[16], const uint8_t ip_dest[16]);
void _init_proto_avltrees(void);
void _free_proto_avltrees(void);
int mmt_tcpip_load_ip_ranges_file(const char *path);
void mmt_tcpip_load_external_ip_ranges(void);

/* ---------------- test protocol + stack plumbing ------------------------- */

#define TEST_STACK_ID   97
#define TEST_PROTO_A    613 /* session-bearing, fully wired */
#define TEST_PROTO_B    614 /* session-bearing, minimal — sits after A so an
                               OOM on B's session map exercises the rollback
                               loop over A's map in mmt_init_handler() */
#define TEST_ATTR_ID    1
#define TEST_TIMEOUT    30  /* default_session_timed_out override */

/* Callback counters — the behavioural assertions of the suite. */
static int g_classify_calls;
static int g_pre_classify_calls;
static int g_post_classify_calls;
static int g_analyse_calls;
static int g_drop_analyse_calls;
static int g_pre_analyse_calls;
static int g_post_analyse_calls;
static int g_session_data_init_calls;
static int g_session_data_cleanup_calls;
static int g_session_ctx_cleanup_calls;
static int g_expiry_calls;
static int g_timer_calls;
static int g_packet_handler_calls;
static int g_attr_handler_calls;
static int g_sessionize_calls;
static uint64_t g_last_expired_id;
static uint32_t g_last_attr_value;
static uint32_t g_last_pkt_len;

/* The sessionizer keys sessions on the first four bytes of the packet. The
 * key is embedded at the tail of the mmt_malloc'd session block so the single
 * mmt_free(session) on the engine's double-OOM path releases both. */
static void *test_sessionize(void *protocol_context, ipacket_t *ipacket,
                             unsigned previous_index, int *is_new) {
    (void) previous_index;
    protocol_instance_t *ctx = (protocol_instance_t *) protocol_context;
    uint32_t k;
    memcpy(&k, ipacket->data, sizeof(k));
    g_sessionize_calls++;

    mmt_session_t *s = (mmt_session_t *) get_session_from_protocol_context_by_session_key(ctx, &k);
    if (s != NULL) { *is_new = 0; return s; }

    s = (mmt_session_t *) mmt_malloc(sizeof(*s) + sizeof(uint32_t));
    if (s == NULL) { *is_new = 1; return NULL; } /* OOM: engine's is_new/NULL branch */
    memset(s, 0, sizeof(*s));
    s->session_key = (void *) (s + 1);
    *(uint32_t *) s->session_key = k;
    if (insert_session_into_protocol_context(ctx, s->session_key, s) == 0) {
        mmt_free(s);
        *is_new = 1;
        return NULL;
    }
    *is_new = 1;
    return s;
}

static bool test_key_comp(void *a, void *b) { return *(uint32_t *) a < *(uint32_t *) b; }
static uint64_t test_key_hash(void *k) { return (uint64_t) *(uint32_t *) k; }

static classified_proto_t test_stack_classify(ipacket_t *ipacket) {
    classified_proto_t r;
    (void) ipacket;
    r.offset = 0;
    r.proto_id = TEST_PROTO_A;
    r.status = Classified;
    return r;
}

/* Issue #255: when armed, A's classifier declares B as the encapsulated
 * protocol — B's sessionizer then creates a session whose parent is A's,
 * turning A's session into a tunnel parent. */
static int g_classify_to_b = 0;
static int test_classify_me(ipacket_t *ipacket, unsigned index) {
    g_classify_calls++;
    if (g_classify_to_b) {
        g_classify_to_b = 0; /* one-shot: only the first packet chains A->B */
        classified_proto_t r;
        r.offset = 4;
        r.proto_id = TEST_PROTO_B;
        r.status = Classified;
        (void) set_classified_proto(ipacket, index + 1, r);
        return MMT_CLASSIFY_MATCHED;
    }
    (void) ipacket; (void) index;
    return 0; /* no match — let the chain continue */
}
static int test_pre_classify(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    g_pre_classify_calls++;
    return MMT_CLASSIFY_CONTINUE;
}
static int test_post_classify(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    g_post_classify_calls++;
    return 1;
}
static int test_analyse(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    g_analyse_calls++;
    return MMT_CONTINUE; /* anything else skips the timeout sweep */
}
static int test_drop_analyse(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    g_drop_analyse_calls++;
    return MMT_DROP;
}
static int test_pre_analyse(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    g_pre_analyse_calls++;
    return MMT_CONTINUE;
}
static int test_post_analyse(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    g_post_analyse_calls++;
    return MMT_CONTINUE;
}
static void test_session_data_init(ipacket_t *ipacket, unsigned index) {
    g_session_data_init_calls++;
    ipacket->session->session_data[index] = mmt_malloc(32);
}
static void test_session_data_cleanup(mmt_session_t *session, unsigned index) {
    g_session_data_cleanup_calls++;
    /* Ownership convention (matches the engine's session_data sharing in
     * setup_new_session): entries below this session's own protocol index are
     * borrowed copies of the parent session's slots — the parent frees them.
     * Freeing them here would double-free once the parent expires. */
    if (index < session->session_protocol_index) return;
    mmt_free(session->session_data[index]);
    session->session_data[index] = NULL;
}
static int test_session_ctx_cleanup(void *protocol_context, mmt_session_t *session, void *args) {
    (void) args;
    g_session_ctx_cleanup_calls++;
    /* Plugin convention: drop the map entry while the key is still valid,
     * then release the session (the key rides at the tail of the block). */
    delete_session_from_protocol_context(protocol_context, session->session_key);
    mmt_free(session->children_stats); /* issue #255: lazily-allocated extension */
    mmt_free(session);
    return 1;
}
static void test_expiry_handler(const mmt_session_t *expired, void *args) {
    (void) args;
    char path[128];
    g_expiry_calls++;
    g_last_expired_id = expired->session_id;
    /* exercise the path-stringifier on the expiring session */
    (void) proto_hierarchy_to_str_with_size(&expired->proto_path, path, sizeof(path));
}
static void test_timer_handler(const mmt_session_t *head, void *args) {
    (void) head; (void) args;
    g_timer_calls++;
}
/* expected MMT_STATS report of test_stats_extract()'s chain (issue #328) */
#define CE_STATS_REPORT "packets=7,data_volume=120,payload_volume=15,sessions=3,timedout_sessions=1"
static int g_pkt_once;
static FILE *g_null_fp;

static int test_packet_handler(const ipacket_t *ipacket, void *args) {
    (void) args;
    g_packet_handler_calls++;
    /* in-packet getters — META_P_LEN was registered for extraction */
    void *d = get_attribute_extracted_data(ipacket, PROTO_META, META_P_LEN);
    if (d != NULL) g_last_pkt_len = *(uint32_t *) d;
    (void) get_attribute_extracted_data_by_name(ipacket, "meta", "packet_len");
    (void) get_extracted_attribute_by_name(ipacket, "meta", "utime");
    (void) get_attribute_extracted_data_encap_index(ipacket, PROTO_META, META_P_LEN, 0);
    (void) get_attribute_extracted_data_at_index(ipacket, PROTO_META, META_P_LEN, 0);
    (void) get_extracted_attribute(ipacket, PROTO_META, META_P_LEN);

    /* packet/session accessors + attribute formatters — once per handler */
    if (!g_pkt_once) {
        g_pkt_once = 1;
        CHECK(get_protocol_index_by_id(ipacket, TEST_PROTO_A) != (unsigned) -1, "proto index by id");
        CHECK(get_protocol_index_by_name(ipacket, "ce_proto_a") != (unsigned) -1, "proto index by name");
        mmt_session_t *ps = get_session_from_packet(ipacket);
        CHECK(ps != NULL, "session reachable from the packet");
        if (ps != NULL) {
            CHECK(get_session_id_from_packet(ipacket) == ps->session_id, "session id from packet");
            set_user_session_context_for_packet(ipacket, (void *) ipacket);
            CHECK(get_user_session_context_from_packet(ipacket) == (void *) ipacket,
                  "user session context round-trip");
            set_user_session_context_for_packet(ipacket, NULL);
            (void) get_proto_session_data_from_packet(ipacket, 1);
            set_proto_session_data(ps, (void *) ipacket, 1);
            CHECK(get_proto_session_data(ps, 1) == (void *) ipacket,
                  "proto session data round-trip");
            set_proto_session_data(ps, NULL, 1);
        }
        /* format every extracted attribute through each formatter —
         * drives the per-data-type switch arms */
        char buf[256];
        for (uint32_t at = 1; at <= META_ATTRIBUTES_NB; at++) {
            attribute_t *a = get_extracted_attribute(ipacket, PROTO_META, at);
            if (a == NULL) continue;
            (void) mmt_attr_snprintf(buf, sizeof(buf), a);
            if (g_null_fp != NULL) {
                (void) mmt_attr_fprintf(g_null_fp, a);
                (void) mmt_attr_format(g_null_fp, a);
            }
        }
        for (uint32_t at = 1; at <= 22; at++) {
            attribute_t *a = get_extracted_attribute(ipacket, TEST_PROTO_A, at);
            if (a == NULL) continue;
            int n = mmt_attr_snprintf(buf, sizeof(buf), a);
            if (at == 19)
                CHECK(n > 0 && strcmp(buf, CE_STATS_REPORT) == 0,
                      "extracted MMT_STATS attribute renders the statistics report");
            if (g_null_fp != NULL) {
                (void) mmt_attr_fprintf(g_null_fp, a);
                (void) mmt_attr_format(g_null_fp, a);
            }
        }
    }
    return 0; /* 0 = continue; 1 would stop before the timeout sweep */
}
static void test_attr_handler(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) user_args;
    g_attr_handler_calls++;
    if (attribute != NULL && attribute->data != NULL)
        g_last_attr_value = *(uint32_t *) attribute->data;
}
static void test_evasion_handler(const ipacket_t *ipacket, mmt_proto_id_t proto_id,
                                 mmt_proto_index_t proto_index, unsigned evasion_id,
                                 void *data, void *args) {
    (void) ipacket; (void) proto_id; (void) proto_index;
    (void) evasion_id; (void) data; (void) args;
}
static int test_attr_extract(const ipacket_t *ipacket, unsigned proto_index, attribute_t *out) {
    uint32_t v = 0;
    int off = get_packet_offset_at_index(ipacket, proto_index);
    if (off < 0 || (size_t) off + sizeof(v) > ipacket->p_hdr->caplen) return 0;
    memcpy(&v, ipacket->data + off, sizeof(v));
    memcpy(out->data, &v, sizeof(v));
    return 1;
}

/* Extractors that fill well-formed values for the typed-attribute formatters
 * (mmt_attr_snprintf/fprintf/format switch arms). */
static int test_fill_extract(const ipacket_t *ipacket, unsigned proto_index, attribute_t *out) {
    (void) ipacket; (void) proto_index;
    memset(out->data, 0x41, (size_t) out->data_len);
    return 1;
}
static int test_var_extract(const ipacket_t *ipacket, unsigned proto_index, attribute_t *out) {
    (void) ipacket; (void) proto_index;
    mmt_binary_var_data_t *b = (mmt_binary_var_data_t *) out->data;
    b->len = 3;
    b->data[0] = 'c'; b->data[1] = 'e'; b->data[2] = '!';
    return 1;
}
static int test_u16arr_extract(const ipacket_t *ipacket, unsigned proto_index, attribute_t *out) {
    (void) ipacket; (void) proto_index;
    mmt_u16_array_t *b = (mmt_u16_array_t *) out->data;
    b->len = 2; b->data[0] = 17; b->data[1] = 42;
    return 1;
}
static int test_u32arr_extract(const ipacket_t *ipacket, unsigned proto_index, attribute_t *out) {
    (void) ipacket; (void) proto_index;
    mmt_u32_array_t *b = (mmt_u32_array_t *) out->data;
    b->len = 2; b->data[0] = 17; b->data[1] = 42;
    return 1;
}
static int test_u64arr_extract(const ipacket_t *ipacket, unsigned proto_index, attribute_t *out) {
    (void) ipacket; (void) proto_index;
    mmt_u64_array_t *b = (mmt_u64_array_t *) out->data;
    b->len = 2; b->data[0] = 17; b->data[1] = 42;
    return 1;
}
/* MMT_STATS attributes point at a chain of per-path statistics instances,
 * exactly like proto_stats_extraction() in packet_stats.c (issue #328). */
static proto_statistics_internal_t g_ce_stats[2];
static int test_stats_extract(const ipacket_t *ipacket, unsigned proto_index, attribute_t *out) {
    (void) ipacket; (void) proto_index;
    memset(g_ce_stats, 0, sizeof(g_ce_stats));
    g_ce_stats[0].packets_count = 3;  g_ce_stats[1].packets_count = 4;
    g_ce_stats[0].data_volume = 100;  g_ce_stats[1].data_volume = 20;
    g_ce_stats[0].payload_volume = 10; g_ce_stats[1].payload_volume = 5;
    g_ce_stats[0].sessions_count = 1; g_ce_stats[1].sessions_count = 2;
    g_ce_stats[1].timedout_sessions_count = 1;
    g_ce_stats[0].next = &g_ce_stats[1];
    out->data = (void *) g_ce_stats;
    return 1;
}
static int test_strptr_extract(const ipacket_t *ipacket, unsigned proto_index, attribute_t *out) {
    (void) ipacket; (void) proto_index;
    char *s = (char *) out->data;
    s[0] = 'c'; s[1] = 'e'; s[2] = '\0';
    return 1;
}

static int g_stack_cleanup_calls;
static void test_stack_cleanup(void *ctx) { (void) ctx; g_stack_cleanup_calls++; }

/* --- count how many live handlers the registry reports --- */
static int g_handler_seen;
static void count_handler(mmt_handler_t *mmt_handler, void *args) {
    if (mmt_handler == args) g_handler_seen++;
}
static int iterate_handlers_count(mmt_handler_t *want) {
    g_handler_seen = 0;
    iterate_through_mmt_handlers(count_handler, want);
    return g_handler_seen;
}

static protocol_t *register_test_protocol(uint32_t proto_id, const char *name, int full) {
    protocol_t *p = init_protocol_struct_for_registration(proto_id, name);
    if (p == NULL) return NULL;
    register_sessionizer_function(p, test_sessionize, test_session_ctx_cleanup, test_key_comp);
    register_session_hash_function(p, test_key_hash);
    if (full) {
        register_session_data_initialization_function(p, test_session_data_init);
        register_session_data_cleanup_function(p, test_session_data_cleanup);
        register_pre_post_classification_functions(p, test_pre_classify, test_post_classify);
        register_pre_post_analysis_functions(p, test_pre_analyse, test_post_analyse);
        register_classification_function(p, test_classify_me);
        register_session_data_analysis_function(p, test_analyse);
    }
    if (register_protocol(p, proto_id) != PROTO_REGISTERED) return NULL;
    return p;
}

static void make_packet(pkthdr_t *hdr, u_char *buf, size_t len, uint32_t key,
                        uint32_t sec, uint32_t usec) {
    memset(buf, 0, len);
    memcpy(buf, &key, sizeof(key));
    memset(hdr, 0, sizeof(*hdr));
    hdr->ts.tv_sec = sec;
    hdr->ts.tv_usec = usec;
    hdr->caplen = (unsigned) len;
    hdr->len = (unsigned) len;
}

/* ============================ arena allocator ============================ */

static void test_arena(void) {
    fprintf(stderr, "  test: arena create/alloc/reset/destroy\n");

    mmt_arena_t *a = mmt_arena_create(1024);
    CHECK(a != NULL, "mmt_arena_create(1024) should succeed");
    if (a == NULL) return;

    void *p1 = mmt_arena_alloc(a, 24);
    CHECK(p1 != NULL, "first arena alloc");
    CHECK(((uintptr_t) p1 % 16) == 0, "arena allocation is 16-byte aligned");
    void *p2 = mmt_arena_alloc(a, 40);
    CHECK(p2 != NULL && p2 != p1, "second arena alloc is distinct");
    CHECK(mmt_arena_alloc(a, 0) != NULL, "zero-size alloc still returns a slot");

    /* carve many slots: the chain grows past the first block */
    uint8_t *ptrs[300];
    int ok = 1;
    for (int i = 0; i < 300; i++) {
        ptrs[i] = (uint8_t *) mmt_arena_alloc(a, 64);
        if (ptrs[i] == NULL) { ok = 0; break; }
        memset(ptrs[i], i & 0xff, 64);
    }
    CHECK(ok, "300 chained allocations across blocks");
    for (int i = 0; i < 300 && ok; i++)
        if (ptrs[i][0] != (uint8_t) (i & 0xff) || ptrs[i][63] != (uint8_t) (i & 0xff)) { ok = 0; break; }
    CHECK(ok, "carved slots do not overlap");

    /* oversized request: dedicated block, does not disturb the chain */
    void *big = mmt_arena_alloc(a, 64 * 1024);
    CHECK(big != NULL && ((uintptr_t) big % 16) == 0, "oversized alloc gets a dedicated aligned block");
    memset(big, 0xa5, 64 * 1024);

    /* reset keeps the head block and recycles the arena */
    mmt_arena_reset(a);
    void *r = mmt_arena_alloc(a, 128);
    CHECK(r != NULL, "alloc after reset reuses the kept head block");

    mmt_arena_destroy(a);

    /* default block size when created with 0 */
    a = mmt_arena_create(0);
    CHECK(a != NULL, "mmt_arena_create(0) uses the default block size");
    if (a != NULL) {
        CHECK(mmt_arena_alloc(a, 32) != NULL, "default-block arena allocates");
        mmt_arena_destroy(a);
    }
}

static void test_arena_failures(void) {
    fprintf(stderr, "  test: arena failure paths\n");

    /* guard branches — rejected before any allocator call */
    CHECK(mmt_arena_create(SIZE_MAX) == NULL, "create: block-size overflow rejected");
    CHECK(mmt_arena_alloc(NULL, 16) == NULL, "alloc on NULL arena returns NULL");
    mmt_arena_reset(NULL);  /* must not crash */
    mmt_arena_destroy(NULL);

    mmt_arena_t *a = mmt_arena_create(256);
    CHECK(a != NULL, "arena for failure-path tests");
    if (a == NULL) return;
    CHECK(mmt_arena_alloc(a, SIZE_MAX - 8) == NULL, "alloc: size overflow guard");
    CHECK(mmt_arena_alloc(a, SIZE_MAX - 15) == NULL, "alloc: grow-block size overflow guard");

    /* injected failure: arena struct allocation */
    g_malloc_budget = 0;
    CHECK(mmt_arena_create(64) == NULL, "create: malloc failure propagates NULL");
    g_malloc_budget = -1;

    /* injected failure: block-grow allocation; the arena stays usable */
    g_malloc_budget = 0;
    CHECK(mmt_arena_alloc(a, 64) == NULL, "alloc: grow malloc failure propagates NULL");
    g_malloc_budget = -1;
    CHECK(mmt_arena_alloc(a, 64) != NULL, "arena survives a failed grow");
    mmt_arena_destroy(a);
}

/* ==================== handler bootstrap + OOM coverage ==================== */

static void test_handler_bootstrap_oom(void) {
    fprintf(stderr, "  test: engine bootstrap + mmt_init_handler OOM paths\n");
    char errbuf[256];

    /* No stack registered yet -> unsupported stack type. */
    errbuf[0] = '\0';
    CHECK(mmt_init_handler(TEST_STACK_ID, 0, errbuf) == NULL,
          "init_handler without a registered stack fails");
    CHECK(strcmp(errbuf, "Unsupported stack type") == 0,
          "unsupported-stack error string");

    CHECK(init_extraction() == 1, "init_extraction succeeds");

    CHECK(register_protocol_stack(TEST_STACK_ID, (char *) "ce_stack", test_stack_classify) == 1,
          "register_protocol_stack succeeds");
    CHECK(register_protocol_stack(TEST_STACK_ID, (char *) "ce_stack", test_stack_classify) == 0,
          "duplicate stack registration is refused");
    /* register_protocol_stack_full + unregister_protocol_stack + cleanup fct */
    CHECK(register_protocol_stack_full(98, (char *) "ce_stack_aux", test_stack_classify,
                                       test_stack_cleanup, NULL) == 1,
          "register_protocol_stack_full succeeds");
    CHECK(unregister_protocol_stack(98) == 1, "unregister aux stack");
    CHECK(g_stack_cleanup_calls == 1, "stack cleanup ran on unregister");
    const char *sname = get_protocol_stack_name(TEST_STACK_ID);
    CHECK(sname != NULL && strcmp(sname, "ce_stack") == 0, "get_protocol_stack_name");
    CHECK(get_protocol_stack_name(4242) == NULL, "unknown stack name is NULL");

    CHECK(register_test_protocol(TEST_PROTO_A, "ce_proto_a", 1) != NULL,
          "register session-bearing protocol A");
    CHECK(register_test_protocol(TEST_PROTO_B, "ce_proto_b", 0) != NULL,
          "register session-bearing protocol B");
    CHECK(is_registered_protocol(TEST_PROTO_A) == 1, "A is registered");
    CHECK(is_valid_protocol_id(TEST_PROTO_A) > 0, "A id is valid");
    CHECK(is_valid_protocol_id(PROTO_MAX_IDENTIFIER) == 0, "id 1000 is invalid");
    CHECK(get_protocol_id_by_name((char *) "ce_proto_a") == TEST_PROTO_A,
          "name->id lookup");
    CHECK(get_protocol_id_by_name((char *) "no_such_proto") == 0,
          "unknown name resolves to 0");
    CHECK(get_protocol_struct_by_id(TEST_PROTO_A) != NULL, "struct by id");

    /* unregister paths on a throwaway proto never used by handlers */
    {
        protocol_t *tmp = init_protocol_struct_for_registration(615, "ce_proto_tmp");
        CHECK(tmp != NULL && register_protocol(tmp, 615) == PROTO_REGISTERED,
              "register tmp proto");
        CHECK(unregister_protocol_by_name((char *) "ce_proto_tmp") == 1,
              "unregister_protocol_by_name");
        CHECK(is_registered_protocol(615) == 0, "tmp proto unregistered");
        CHECK(unregister_protocol_by_name((char *) "ce_proto_tmp") == 0,
              "double unregister reports 0");
        CHECK(unregister_protocol_by_id(616) == 0,
              "unregister never-registered proto id");
    }

    /* mmt_init_handler allocation sweep. Layout with A+B registered:
     *   #1 handler struct (mmt_malloc)
     *   #2 ip_streams map, #3 ip_streams slots (hashmap_alloc)
     *   #4 ip6_streams map, #5 ip6_streams slots
     *   #6 timeout-ring struct (malloc)    + ring slots (calloc)
     *   #7 A's session table (malloc)  + A's slots (calloc)
     *   #8 B's session table (malloc)  + B's slots (calloc)
     * Budgets 0..7 all fail; 8 lets the whole call through.
     */
    for (long b = 0; b <= 8; b++) {
        g_malloc_budget = b;
        mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
        g_malloc_budget = -1;
        if (b < 8) {
            CHECK(h == NULL, "init_handler under malloc budget should fail");
        } else {
            CHECK(h != NULL, "init_handler with enough budget succeeds");
            if (h != NULL) {
                CHECK(h->configured_protocols[TEST_PROTO_A].sessions_map != NULL,
                      "engine created A's session store");
                CHECK(h->configured_protocols[TEST_PROTO_B].sessions_map != NULL,
                      "engine created B's session store");
                mmt_close_handler(h);
            }
        }
    }

    /* calloc budget: the timeout ring's slot array fails first (the
     * F-BUG-012 cleanup frees both ip_streams maps); then A's session slots;
     * then B's — the last failure must roll back A's already-created map. */
    g_calloc_budget = 0;
    CHECK(mmt_init_handler(TEST_STACK_ID, 0, errbuf) == NULL,
          "init_handler fails when the timeout ring cannot be allocated");
    g_calloc_budget = 1;
    CHECK(mmt_init_handler(TEST_STACK_ID, 0, errbuf) == NULL,
          "init_handler fails when A's session slots cannot be allocated");
    g_calloc_budget = 2;
    CHECK(mmt_init_handler(TEST_STACK_ID, 0, errbuf) == NULL,
          "init_handler fails when B's session slots cannot be allocated");
    g_calloc_budget = -1;
}

/* ==================== session lifecycle via the dispatcher ================ */

static void test_session_lifecycle(void) {
    fprintf(stderr, "  test: session create/lookup/timeout/teardown through the dispatcher\n");
    char errbuf[256];
    /* pkt_a is the first packet through the handler, so it is the one the
     * once-only attribute-formatting pass inspects: it must be large enough
     * for the caplen guard (packet_pipeline.c: internal_extract_attribute)
     * to admit the wide fixed-size attributes — BINARY_64DATA_TYPE_LEN (68)
     * and the u16/u32/u64 array types (132/260/516 bytes). At 64 bytes those
     * extractors are refused and the MMT_*_ARRAY snprintf arms stay dark. */
    u_char pkt_a[1024], pkt_b[64], pkt_c[64];
    pkthdr_t hdr;

    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init for lifecycle test");
    if (h == NULL) return;

    CHECK(get_data_link_type(h) == TEST_STACK_ID, "data link type is the test stack");
    CHECK(get_active_session_count(h) == 0, "no sessions yet");
    CHECK(get_active_session_count(NULL) == (uint64_t) -1, "NULL handler count is -1");

    /* per-handler configuration */
    CHECK(set_default_session_timed_out(h, TEST_TIMEOUT) == 1, "set default timeout");
    CHECK(set_long_session_timed_out(h, 600) == 1, "set long timeout");
    CHECK(set_short_session_timed_out(h, 5) == 1, "set short timeout");
    CHECK(set_live_session_timed_out(h, 2) == 1, "set live timeout");
    CHECK(set_default_session_timed_out(NULL, 1) == 0, "NULL handler rejected");
    CHECK(enable_mmt_reassembly(NULL) == 0, "reassembly on NULL handler fails");
    CHECK(enable_port_classify(h) == 1 && h->port_classify == 1, "port classify on");
    CHECK(disable_port_classify(h) == 1 && h->port_classify == 0, "port classify off");
    CHECK(enable_hostname_classify(h) == 1 && disable_hostname_classify(h) == 1, "hostname classify toggles");
    CHECK(enable_ip_address_classify(h) == 1 && disable_ip_address_classify(h) == 1, "ip classify toggles");
    CHECK(enable_port_classify_payload_confirm(h) == 1 &&
          disable_port_classify_payload_confirm(h) == 1, "payload-confirm toggles");
    disable_protocol_analysis(h, TEST_PROTO_A);
    CHECK(h->configured_protocols[TEST_PROTO_A].analysis_enabled == 0,
          "disable analysis flips the status");
    enable_protocol_analysis(h, TEST_PROTO_A);
    CHECK(h->configured_protocols[TEST_PROTO_A].analysis_enabled == 1,
          "enable analysis restores the status");
    disable_protocol_classification(h, TEST_PROTO_B);
    CHECK(h->configured_protocols[TEST_PROTO_B].classify_enabled == 0,
          "disable classification flips the status");
    enable_protocol_classification(h, TEST_PROTO_B);
    CHECK(h->configured_protocols[TEST_PROTO_B].classify_enabled == 1,
          "enable classification restores the status");
    disable_protocol_statistics(h);
    CHECK(h->stats_reporting_status == 0, "statistics disabled");
    enable_protocol_statistics(h);
    CHECK(h->stats_reporting_status != 0, "statistics enabled");

    /* session expiry + periodic timer callbacks */
    CHECK(register_session_timeout_handler(h, test_expiry_handler, NULL) == 1,
          "register expiry handler");
    CHECK(register_session_timer_handler(h, test_timer_handler, NULL, 0) == 1,
          "register timer handler");

    /* attribute extraction: all META attributes + a custom field on A, plus
     * the auto-registered stats/session attributes on A — they are re-extracted
     * per packet and drive proto_*_extraction()/meta extractors. */
    for (uint32_t at = 1; at <= META_ATTRIBUTES_NB; at++) {
        CHECK(register_extraction_attribute(h, PROTO_META, at) == 1,
              "register a META attribute");
    }
    CHECK(register_extraction_attribute(h, TEST_PROTO_A, PROTO_PACKET_COUNT) == 1, "register A packet_count");
    CHECK(register_extraction_attribute(h, TEST_PROTO_A, PROTO_DATA_VOLUME) == 1, "register A data_volume");
    CHECK(register_extraction_attribute(h, TEST_PROTO_A, PROTO_PAYLOAD_VOLUME) == 1, "register A payload_volume");
    CHECK(register_extraction_attribute(h, TEST_PROTO_A, PROTO_FIRST_PACKET_TIME) == 1, "register A first_time");
    CHECK(register_extraction_attribute(h, TEST_PROTO_A, PROTO_LAST_PACKET_TIME) == 1, "register A last_time");
    CHECK(register_extraction_attribute(h, TEST_PROTO_A, PROTO_DATA_LEN) == 1, "register A data_len");
    CHECK(register_extraction_attribute(h, TEST_PROTO_A, PROTO_SESSION) == 1, "register A session attr");
    CHECK(register_extraction_attribute(h, TEST_PROTO_A, PROTO_SESSION_ID) == 1, "register A session id");
    CHECK(is_registered_attribute(h, TEST_PROTO_A, PROTO_SESSION_ID) == 1, "attr is registered");
    CHECK(is_registered_attribute(h, TEST_PROTO_A, 0x7fff) == 0, "unregistered attr");

    /* a custom attribute + handler on A */
    {
        attribute_metadata_t meta;
        memset(&meta, 0, sizeof(meta));
        meta.id = TEST_ATTR_ID;
        strncpy(meta.alias, "ce_field", Max_Alias_Len);
        meta.data_type = MMT_U32_DATA;
        meta.data_len = (int) sizeof(uint32_t);
        meta.position_in_packet = 0;
        meta.scope = SCOPE_PACKET;
        meta.extraction_function = test_attr_extract;
        CHECK(register_attribute_with_protocol(get_protocol_struct_by_id(TEST_PROTO_A), &meta) == 1,
              "register custom attribute metadata");
    }
    /* wire the shared general_*_extraction helpers (extraction_lib.c) onto
     * extra attributes of A — each fires per packet at its packet offset */
    {
        static const struct {
            uint32_t id; const char *alias; uint32_t type; int len;
            int pos; int (*fn)(const ipacket_t *, unsigned, attribute_t *);
        } gen_attrs[] = {
            { 2, "ce_u8",    MMT_U8_DATA,     1,  4, general_char_extraction },
            { 3, "ce_u16",   MMT_U16_DATA,    2,  6, general_short_extraction },
            { 4, "ce_u32",   MMT_U32_DATA,    4,  8, general_int_extraction },
            { 5, "ce_u16be", MMT_U16_DATA,    2, 12, general_short_extraction_with_ordering_change },
            { 6, "ce_u32be", MMT_U32_DATA,    4, 16, general_int_extraction_with_ordering_change },
            { 7, "ce_bin",   MMT_BINARY_DATA, 4, 20, general_byte_to_byte_extraction },
            { 8, "ce_none",  MMT_U8_DATA,     1, 24, silent_extraction },
        };
        for (size_t gi = 0; gi < sizeof(gen_attrs) / sizeof(gen_attrs[0]); gi++) {
            attribute_metadata_t meta;
            memset(&meta, 0, sizeof(meta));
            meta.id = gen_attrs[gi].id;
            strncpy(meta.alias, gen_attrs[gi].alias, Max_Alias_Len);
            meta.data_type = gen_attrs[gi].type;
            meta.data_len = gen_attrs[gi].len;
            meta.position_in_packet = gen_attrs[gi].pos;
            meta.scope = SCOPE_PACKET;
            meta.extraction_function = gen_attrs[gi].fn;
            CHECK(register_attribute_with_protocol(get_protocol_struct_by_id(TEST_PROTO_A), &meta) == 1,
                  "register a general_* attribute");
            CHECK(register_extraction_attribute(h, TEST_PROTO_A, gen_attrs[gi].id) == 1,
                  "extract a general_* attribute");
        }
    }
    /* typed attributes feeding the mmt_attr_* formatter switches — one per
     * data type the formatters distinguish */
    {
        static const struct {
            uint32_t id; const char *alias; uint32_t type; int len;
            int (*fn)(const ipacket_t *, unsigned, attribute_t *);
        } fmt_attrs[] = {
            { 10, "ce_mac",   MMT_DATA_MAC_ADDR,         6,  test_fill_extract },
            { 11, "ce_ip",    MMT_DATA_IP_ADDR,          4,  test_fill_extract },
            { 12, "ce_ip6",   MMT_DATA_IP6_ADDR,         16, test_fill_extract },
            { 13, "ce_flt",   MMT_DATA_FLOAT,            (int) sizeof(float), test_fill_extract },
            { 14, "ce_ptr",   MMT_DATA_POINTER,          (int) sizeof(void *), test_fill_extract },
            { 15, "ce_tv",    MMT_DATA_TIMEVAL,          (int) sizeof(struct timeval), test_fill_extract },
            { 16, "ce_bin64", MMT_BINARY_DATA,           BINARY_64DATA_TYPE_LEN, test_var_extract },
            { 17, "ce_str",   MMT_STRING_DATA,           BINARY_64DATA_TYPE_LEN, test_var_extract },
            { 18, "ce_strp",  MMT_STRING_DATA_POINTER,   (int) sizeof(void *), test_strptr_extract },
            { 19, "ce_stats", MMT_STATS,                 (int) sizeof(void *), test_stats_extract },
            { 20, "ce_a16",   MMT_U16_ARRAY,             (int) U16_ARRAY_TYPE_LEN, test_u16arr_extract },
            { 21, "ce_a32",   MMT_U32_ARRAY,             (int) U32_ARRAY_TYPE_LEN, test_u32arr_extract },
            { 22, "ce_a64",   MMT_U64_ARRAY,             (int) U64_ARRAY_TYPE_LEN, test_u64arr_extract },
        };
        for (size_t fi = 0; fi < sizeof(fmt_attrs) / sizeof(fmt_attrs[0]); fi++) {
            attribute_metadata_t meta;
            memset(&meta, 0, sizeof(meta));
            meta.id = fmt_attrs[fi].id;
            strncpy(meta.alias, fmt_attrs[fi].alias, Max_Alias_Len);
            meta.data_type = fmt_attrs[fi].type;
            meta.data_len = fmt_attrs[fi].len;
            meta.position_in_packet = 0;
            meta.scope = SCOPE_PACKET;
            meta.extraction_function = fmt_attrs[fi].fn;
            CHECK(register_attribute_with_protocol(get_protocol_struct_by_id(TEST_PROTO_A), &meta) == 1,
                  "register a formatter attribute");
            CHECK(register_extraction_attribute(h, TEST_PROTO_A, fmt_attrs[fi].id) == 1,
                  "extract a formatter attribute");
        }
        CHECK(is_protocol_valid_attribute(TEST_PROTO_A, 10) == 1, "valid attribute check");
        CHECK(is_protocol_valid_attribute(TEST_PROTO_A, 0x777) == 0, "invalid attribute check");
        CHECK(is_protocol_valid_attribute(PROTO_MAX_IDENTIFIER, 1) == 0, "invalid proto check");
    }
    CHECK(register_attribute_handler(h, TEST_PROTO_A, TEST_ATTR_ID, test_attr_handler, NULL, NULL) == 1,
          "register attribute handler on A");
    CHECK(register_attribute_handler(h, TEST_PROTO_A, TEST_ATTR_ID, test_attr_handler, NULL, NULL) == 0,
          "duplicate attribute handler registration fails");
    CHECK(has_registered_attribute_handler(h, TEST_PROTO_A, TEST_ATTR_ID) == 1, "attr handler registered");
    CHECK(is_registered_attribute_handler(h, TEST_PROTO_A, TEST_ATTR_ID, test_attr_handler) == 1,
          "specific attr handler found");

    CHECK(register_packet_handler(h, 7, test_packet_handler, NULL) == 1, "register packet handler");
    CHECK(is_registered_packet_handler(h, 7) == 1, "packet handler is registered");
    CHECK(register_packet_handler(h, 7, test_packet_handler, NULL) == 1, "re-register same id tolerated");

    /* --- packet 1: session A created (t=1000, milestone 1030) --- */
    make_packet(&hdr, pkt_a, sizeof(pkt_a), 0xA0A0A0A0u, 1000, 0);
    CHECK(packet_process(h, &hdr, pkt_a) == 1, "packet A1 processed");
    CHECK(h->sessions_count == 1, "one session created");
    CHECK(get_active_session_count(h) == 1, "one active session");
    CHECK(g_session_data_init_calls == 1, "session_data_init ran");
    CHECK(g_classify_calls >= 1 && g_pre_classify_calls >= 1 && g_post_classify_calls >= 1,
          "classification chain ran");
    CHECK(g_analyse_calls >= 1 && g_pre_analyse_calls >= 1 && g_post_analyse_calls >= 1,
          "analysis chain ran");
    CHECK(g_attr_handler_calls >= 1, "attribute handler fired");
    CHECK(g_last_attr_value == 0xA0A0A0A0u, "custom attribute carried the key");
    CHECK(g_last_pkt_len == (uint32_t) sizeof(pkt_a), "META_P_LEN carried the caplen");
    CHECK(g_packet_handler_calls >= 1, "packet handler fired");

    /* --- packet 2: session B created (t=1000, same milestone 1030) --- */
    make_packet(&hdr, pkt_b, sizeof(pkt_b), 0xB0B0B0B0u, 1000, 0);
    CHECK(packet_process(h, &hdr, pkt_b) == 1, "packet B1 processed");
    CHECK(h->sessions_count == 2 && get_active_session_count(h) == 2, "two sessions");
    CHECK(get_timed_out_session_list(h, 1030) != NULL, "milestone 1030 holds a list");

    /* periodic timer fires on milestone heads */
    int timers_before = g_timer_calls;
    process_session_timer_handler(h);
    CHECK(g_timer_calls > timers_before, "timer handler visited live sessions");

    /* --- packet 3: key A again (t=1010) -> lookup hits, milestone moves --- */
    make_packet(&hdr, pkt_a, sizeof(pkt_a), 0xA0A0A0A0u, 1010, 0);
    CHECK(packet_process(h, &hdr, pkt_a) == 1, "packet A2 processed");
    CHECK(h->sessions_count == 2, "lookup reused the session, no new one");
    CHECK(get_timed_out_session_list(h, 1040) != NULL, "A moved to milestone 1040");

    /* protocol statistics for A exist and can be walked back to a path */
    proto_statistics_t *stats = get_protocol_stats(h, TEST_PROTO_A);
    CHECK(stats != NULL, "A has protocol statistics");
    if (stats != NULL) {
        CHECK(stats->packets_count >= 3, "stats counted the packets");
        CHECK(stats->sessions_count >= 1, "stats counted the session");
        proto_hierarchy_t spath;
        memset(&spath, 0, sizeof(spath));
        get_protocol_stats_path(h, stats, &spath);
        CHECK(spath.len >= 1, "stats path resolves");
        proto_statistics_t child;
        get_children_stats(stats, &child);
        reset_statistics(stats);
        CHECK(stats->packets_count == 0, "reset_statistics clears counters");
    }
    CHECK(get_protocol_stats(NULL, TEST_PROTO_A) == NULL, "NULL handler stats");
    CHECK(get_protocol_stats(h, PROTO_MAX_IDENTIFIER) == NULL, "invalid proto stats");

    /* reset_proto_stats walks the populated per-proto stats list — needs
     * packets already processed, unlike the earlier disable call */
    disable_protocol_statistics(h);
    enable_protocol_statistics(h);
    stats = get_protocol_stats(h, TEST_PROTO_A);
    CHECK(stats != NULL && stats->packets_count == 0, "stats reset by disable");

    /* --- packet 4: key C at t=2500 -> C created; the sweep expires A+B --- */
    make_packet(&hdr, pkt_c, sizeof(pkt_c), 0xC0C0C0C0u, 2500, 0);
    CHECK(packet_process(h, &hdr, pkt_c) == 1, "packet C1 processed");
    CHECK(g_expiry_calls == 2, "the timeout sweep expired A and B");
    CHECK(g_session_ctx_cleanup_calls == 2, "session context cleanup ran for A and B");
    CHECK(g_session_data_cleanup_calls == 2, "session data cleanup ran for A and B");
    CHECK(get_active_session_count(h) == 1, "only C remains active");
    CHECK(get_timed_out_session_list(h, 1030) == NULL, "milestone 1030 deleted by the sweep");
    CHECK(get_timed_out_session_list(h, 1040) == NULL, "milestone 1040 deleted by the sweep");

    /* session timer skips fragmenting sessions when no_fragmented is set */
    mmt_session_t *c_head = get_timed_out_session_list(h, 2500 + TEST_TIMEOUT);
    CHECK(c_head != NULL, "C sits on milestone 2530");
    if (c_head != NULL) c_head->is_fragmenting = 1;
    CHECK(register_session_timer_handler(h, test_timer_handler, NULL, 1) == 1, "re-register timer no_fragmented");
    timers_before = g_timer_calls;
    process_session_timer_handler(h);
    CHECK(g_timer_calls == timers_before, "fragmenting session skipped by timer");
    if (c_head != NULL) c_head->is_fragmenting = 0;
    process_session_timer_handler(h);
    CHECK(g_timer_calls > timers_before, "timer fires again once not fragmenting");

    /* session accessor sweep (mmt_data.c) on the live session C */
    if (c_head != NULL) {
        CHECK(get_session_id(c_head) == c_head->session_id, "session id getter");
        CHECK(get_session_handler(c_head) == h, "session handler getter");
        CHECK(get_session_protocol_hierarchy(c_head) != NULL, "session hierarchy");
        CHECK(get_session_protocol_index(c_head) == 1, "session proto index");
        set_user_session_context(c_head, (void *) c_head);
        CHECK(get_user_session_context(c_head) == (void *) c_head, "user ctx round-trip");
        set_user_session_context(c_head, NULL);
        (void) get_session_parent(c_head);
        (void) get_session_packet_count(c_head);
        (void) get_session_packet_cap_count(c_head);
        (void) get_session_data_cap_volume(c_head);
        (void) get_session_ul_packet_count(c_head);
        (void) get_session_ul_cap_packet_count(c_head);
        (void) get_session_dl_packet_count(c_head);
        (void) get_session_dl_cap_packet_count(c_head);
        (void) get_session_byte_count(c_head);
        (void) get_session_ul_byte_count(c_head);
        (void) get_session_ul_cap_byte_count(c_head);
        (void) get_session_dl_byte_count(c_head);
        (void) get_session_dl_cap_byte_count(c_head);
        (void) get_session_data_packet_count(c_head);
        (void) get_session_ul_data_packet_count(c_head);
        (void) get_session_dl_data_packet_count(c_head);
        (void) get_session_data_byte_count(c_head);
        (void) get_session_ul_data_byte_count(c_head);
        (void) get_session_dl_data_byte_count(c_head);
        (void) get_session_total_packet_count(c_head);
        (void) get_session_total_packet_cap_count(c_head);
        (void) get_session_total_data_cap_volume(c_head);
        (void) get_session_total_ul_packet_count(c_head);
        (void) get_session_total_ul_cap_packet_count(c_head);
        (void) get_session_total_dl_packet_count(c_head);
        (void) get_session_total_dl_cap_packet_count(c_head);
        (void) get_session_total_byte_count(c_head);
        (void) get_session_total_ul_byte_count(c_head);
        (void) get_session_total_ul_cap_byte_count(c_head);
        (void) get_session_total_dl_byte_count(c_head);
        (void) get_session_total_dl_cap_byte_count(c_head);
        (void) get_session_total_data_packet_count(c_head);
        (void) get_session_total_ul_data_packet_count(c_head);
        (void) get_session_total_dl_data_packet_count(c_head);
        (void) get_session_total_data_byte_count(c_head);
        (void) get_session_total_ul_data_byte_count(c_head);
        (void) get_session_total_dl_data_byte_count(c_head);
        (void) get_session_init_time(c_head);
        (void) get_session_last_activity_time(c_head);
        (void) get_session_last_data_packet_time_by_direction(c_head, 0);
        (void) get_session_last_data_packet_time_by_direction(c_head, 1);
        (void) get_session_rtt(c_head);
        (void) get_session_content_class_id(c_head);
        (void) get_session_content_type_id(c_head);
        (void) get_session_content_flags(c_head);
        (void) get_session_retransmission_count(c_head);
        (void) get_session_outoforder_count(c_head);
        (void) get_session_next(c_head);
        (void) get_session_previous(c_head);
        (void) get_session_proto_path_direction(c_head, 0);
        (void) get_session_proto_path_direction(c_head, 1);
    }

    /* debug printout handler + print helpers — one packet is enough. The
     * packet also creates session E, which expires at teardown with C. */
    CHECK(register_packet_handler(h, 5, debug_extracted_attributes_printout_handler, NULL) == 1,
          "register debug printout handler");
    make_packet(&hdr, pkt_a, sizeof(pkt_a), 0xE0E0E0E0u, 2500, 0);
    CHECK(packet_process(h, &hdr, pkt_a) == 1, "packet for debug printout");
    CHECK(unregister_packet_handler(h, 5) == 1, "unregister debug printout handler");
    CHECK(h->sessions_count == 4, "session E created by the debug packet");

    mmt_print_info();
    mmt_print_all_protocols();
    mmt_print_proto_info(get_protocol_struct_by_id(TEST_PROTO_A));

    /* force_session_timeout unlinks a live session from its milestone */
    mmt_session_t *forced = (mmt_session_t *) mmt_malloc(sizeof(*forced) + sizeof(uint32_t));
    CHECK(forced != NULL, "fabricated session alloc");
    if (forced != NULL) {
        memset(forced, 0, sizeof(*forced));
        forced->session_key = (void *) (forced + 1);
        *(uint32_t *) forced->session_key = 0xD0D0D0D0u;
        forced->session_timeout_milestone = 9900;
        CHECK(insert_session_timeout_milestone(h, 9900, forced) == 1, "insert milestone 9900");
        CHECK(get_timed_out_session_list(h, 9900) == forced, "9900 list heads the session");
        CHECK(force_session_timeout(h, forced) == 1, "force_session_timeout unlinks");
        CHECK(get_timed_out_session_list(h, 9900) == NULL, "9900 milestone empty after force");
        mmt_free(forced);
    }

    /* handler iteration sees this handler */
    CHECK(iterate_handlers_count(h) == 1, "iterate_through_mmt_handlers sees the handler");

    /* evasion-handler registration is heap-allocated and released by
     * mmt_close_handler — covers both ends of that path */
    CHECK(register_evasion_handler(h, test_evasion_handler, NULL) == 1, "register evasion handler");

    /* unregister paths: drop the packet handler and one attribute handler,
     * then put one back so the teardown frees a non-empty list */
    CHECK(unregister_packet_handler(h, 7) == 1, "unregister packet handler");
    CHECK(is_registered_packet_handler(h, 7) == 0, "packet handler gone");
    CHECK(register_packet_handler(h, 9, test_packet_handler, NULL) == 1, "second packet handler");
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, TEST_ATTR_ID, test_attr_handler) == 1,
          "unregister attribute handler");
    CHECK(has_registered_attribute_handler(h, TEST_PROTO_A, TEST_ATTR_ID) == 0, "attr handler gone");
    CHECK(unregister_extraction_attribute(h, TEST_PROTO_A, PROTO_DATA_LEN) == 1,
          "unregister an extraction attribute");
    CHECK(unregister_extraction_attribute_by_name(h, "meta", "packet_index") == 1,
          "unregister an extraction attribute by name");
    CHECK(register_attribute_handler(h, TEST_PROTO_A, TEST_ATTR_ID, test_attr_handler, NULL, NULL) == 1,
          "re-register attribute handler");

    /* teardown: the remaining sessions C and E expire through
     * mmt_close_handler's timeout_iteration_callback(force_sessions_timeout) */
    mmt_close_handler(h);
    CHECK(g_expiry_calls == 4, "close_handler expired sessions C and E");
    CHECK(g_session_ctx_cleanup_calls == 4, "context cleanup ran for C and E");
    CHECK(g_session_data_cleanup_calls == 4, "data cleanup ran for C and E");
    CHECK(g_last_expired_id != 0, "expiry saw a real session id");
}

/* ============ session-create double-OOM + reassembly mode ================= */

static void test_session_create_oom(void) {
    fprintf(stderr, "  test: session milestone double-OOM + reassembly path\n");
    char errbuf[256];
    u_char pkt_x[64], pkt_y[64], pkt_z[64];
    pkthdr_t hdr;
    int expiry_before = g_expiry_calls;
    int ctx_before = g_session_ctx_cleanup_calls;
    int data_before = g_session_data_cleanup_calls;

    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init for OOM test");
    if (h == NULL) return;
    CHECK(set_default_session_timed_out(h, TEST_TIMEOUT) == 1, "timeout set");
    CHECK(register_session_timeout_handler(h, test_expiry_handler, NULL) == 1, "expiry handler");

    /* X: healthy session at t=5000 (milestone 5030) */
    make_packet(&hdr, pkt_x, sizeof(pkt_x), 0x50505050u, 5000, 0);
    CHECK(packet_process(h, &hdr, pkt_x) == 1, "packet X processed");
    CHECK(h->sessions_count == 1, "session X created");

    /* Y: sessionize + map insert succeed, but the timeout-ring growth inside
     * insert_session_timeout_milestone fails — twice — so the engine must run
     * process_outofmemory_force_sessions_timeout() (which expires X) and then
     * destroy Y on the F-BUG-023 double-OOM path.
     *
     * Ring inserts allocate only when the target slot is already owned by a
     * different live milestone (which forces a grow); a plain calloc budget
     * cannot fail a free-slot claim. The fabricated session below parks on
     * milestone 935 — below last_expiry_timeout (5001) when Y is processed —
     * so the OOM sweep, which only scans forward from last_expiry_timeout,
     * never removes it; and Y's milestone 5031 collides with it modulo the
     * initial ring capacity (5031 % 1024 == 935). Both the first insert and
     * the post-sweep retry hit that slot and fail on the growth calloc. */
    mmt_session_t *stale = (mmt_session_t *) mmt_malloc(sizeof(*stale));
    CHECK(stale != NULL, "fabricated session alloc");
    if (stale == NULL) { mmt_close_handler(h); return; }
    memset(stale, 0, sizeof(*stale));
    stale->session_timeout_milestone = 935;
    CHECK(insert_session_timeout_milestone(h, 935, stale) == 1,
          "stale milestone inserted");

    g_calloc_budget = 0;
    make_packet(&hdr, pkt_y, sizeof(pkt_y), 0x51515151u, 5001, 0);
    CHECK(packet_process(h, &hdr, pkt_y) == 1, "packet Y processed under OOM");
    g_calloc_budget = -1;
    CHECK(h->sessions_count == 1, "Y was destroyed — sessions_count rolled back");
    CHECK(get_active_session_count(h) == 0, "no active sessions after the OOM sweep");
    CHECK(g_expiry_calls == expiry_before + 1, "the OOM sweep expired X");
    CHECK(g_session_ctx_cleanup_calls == ctx_before + 1, "X went through context cleanup");
    CHECK(g_session_data_cleanup_calls == data_before + 2, "data cleanup ran for X and Y");
    CHECK(get_timed_out_session_list(h, 5030) == NULL, "X milestone drained");
    CHECK(get_timed_out_session_list(h, 935) == stale,
          "stale milestone survived the OOM sweep");
    CHECK(force_session_timeout(h, stale) == 1, "stale session unlinked");
    mmt_free(stale);

    /* sessionizer OOM: the session malloc itself fails with is_new set —
     * drives the NULL-session/is_new branch in proto_session_management. */
    g_malloc_budget = 0;
    make_packet(&hdr, pkt_y, sizeof(pkt_y), 0x52525252u, 5002, 0);
    CHECK(packet_process(h, &hdr, pkt_y) == 1, "packet processed with failing session alloc");
    g_malloc_budget = -1;
    CHECK(h->sessions_count == 1, "no session created when the sessionizer OOMs");

    /* reassembly mode: heap ipacket + per-layer offset copy + full cleanup */
    CHECK(enable_mmt_reassembly(h) == 1 && h->has_reassembly == 1, "reassembly enabled");
    make_packet(&hdr, pkt_z, sizeof(pkt_z), 0x53535353u, 5003, 0);
    CHECK(packet_process(h, &hdr, pkt_z) == 1, "packet Z processed in reassembly mode");
    CHECK(h->sessions_count == 2, "session Z created via the reassembly path");
    CHECK(disable_mmt_reassembly(h) == 1 && h->has_reassembly == 0, "reassembly disabled");

    mmt_close_handler(h); /* expires Z */
    CHECK(g_expiry_calls == expiry_before + 2, "close_handler expired Z");
    CHECK(g_session_ctx_cleanup_calls == ctx_before + 2, "context cleanup ran for Z");
}

/* ============ issue #327: analysis-verdict propagation ===================== */

#define TEST_PROTO_V    620 /* verdict test — never appears in a packet path */

static void test_analyse_verdict(void) {
    fprintf(stderr, "  test: first non-MMT_CONTINUE analysis verdict wins\n");
    char errbuf[256];

    /* A dedicated protocol id keeps the dropping analyser off TEST_PROTO_A's
     * chain — analysis registrations are global (no unregister API) and a
     * DROP on A would suppress process_packet_handler()/the timeout sweep
     * for every later packet of every test. */
    CHECK(register_test_protocol(TEST_PROTO_V, "ce_proto_v", 1) != NULL,
          "verdict protocol registered");
    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init for verdict test");
    if (h == NULL) return;
    enable_protocol_analysis(h, TEST_PROTO_V);
    CHECK(h->configured_protocols[TEST_PROTO_V].analysis_enabled == 1,
          "analysis enabled on V");

    /* The dropping analyser sits at weight 10 — the head of the chain, ahead
     * of test_analyse (default weight 50). proto_packet_analyze() must run
     * every analyser for its side effects yet return the FIRST non-CONTINUE
     * verdict: a later MMT_CONTINUE must not erase the earlier MMT_DROP. */
    CHECK(register_session_data_analysis_function_with_protocol(TEST_PROTO_V, test_drop_analyse, 10) == 1,
          "dropping analyser at chain head");

    ipacket_internal_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.mmt_handler = h;
    int pre_before = g_pre_analyse_calls;
    int analyse_before = g_analyse_calls;
    int post_before = g_post_analyse_calls;
    int ret = proto_packet_analyze(&ip.pub, &h->configured_protocols[TEST_PROTO_V], 1);
    CHECK(ret == MMT_DROP, "first non-CONTINUE verdict propagated (not overwritten by a later CONTINUE)");
    CHECK(g_pre_analyse_calls == pre_before + 1, "pre-analysis ran");
    CHECK(g_drop_analyse_calls == 1, "dropping analyser ran");
    CHECK(g_analyse_calls == analyse_before + 1, "later analyser still ran (side effects kept)");
    CHECK(g_post_analyse_calls == post_before + 1, "post-analysis still ran");

    /* Disabled analysis short-circuits to MMT_CONTINUE. */
    disable_protocol_analysis(h, TEST_PROTO_V);
    ret = proto_packet_analyze(&ip.pub, &h->configured_protocols[TEST_PROTO_V], 1);
    CHECK(ret == MMT_CONTINUE, "disabled analysis returns MMT_CONTINUE");

    mmt_close_handler(h);
}

/* ============ issue #549: protocol switches are per handler ============= */

/* Issue #549 (F-BUG-012): enable_/disable_protocol_analysis() and
 * _classification() take a handler but used to write the shared global
 * protocol_t, so disabling a protocol on one handler disabled it on every
 * handler — and the next mmt_init_handler() silently re-enabled it for all.
 * Two handlers on the same stack: switching A off on h1 must leave h2
 * classifying and analysing A, and a handler created afterwards must not
 * switch h1 back on. */
static void test_per_handler_protocol_switches(void) {
    fprintf(stderr, "  test: protocol analysis/classification switches are per handler\n");
    char errbuf[256];
    u_char pkt[64];
    pkthdr_t hdr;

    mmt_handler_t *h1 = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    mmt_handler_t *h2 = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h1 != NULL && h2 != NULL, "two handlers on the test stack");
    if (h1 == NULL || h2 == NULL) {
        if (h1 != NULL) mmt_close_handler(h1);
        if (h2 != NULL) mmt_close_handler(h2);
        return;
    }

    disable_protocol_classification(h1, TEST_PROTO_A);
    disable_protocol_analysis(h1, TEST_PROTO_A);
    CHECK(h1->configured_protocols[TEST_PROTO_A].classify_enabled == 0 &&
          h1->configured_protocols[TEST_PROTO_A].analysis_enabled == 0,
          "A switched off on h1");
    CHECK(h2->configured_protocols[TEST_PROTO_A].classify_enabled == 1 &&
          h2->configured_protocols[TEST_PROTO_A].analysis_enabled == 1,
          "A still on for h2");

    mmt_handler_t *h3 = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h3 != NULL, "third handler created after the disable");
    CHECK(h1->configured_protocols[TEST_PROTO_A].classify_enabled == 0 &&
          h1->configured_protocols[TEST_PROTO_A].analysis_enabled == 0,
          "a later mmt_init_handler() does not switch A back on for h1");
    if (h3 != NULL) mmt_close_handler(h3);

    /* h2 still classifies and analyses A. */
    int cls = g_classify_calls, ana = g_analyse_calls;
    make_packet(&hdr, pkt, sizeof(pkt), 0x549A0001u, 2000, 0);
    CHECK(packet_process(h2, &hdr, pkt) == 1, "packet processed on h2");
    CHECK(g_classify_calls > cls, "h2 still runs A's classification chain");
    CHECK(g_analyse_calls > ana, "h2 still runs A's analysis chain");

    /* h1 skips both chains for A. */
    cls = g_classify_calls;
    ana = g_analyse_calls;
    make_packet(&hdr, pkt, sizeof(pkt), 0x549A0002u, 2000, 0);
    CHECK(packet_process(h1, &hdr, pkt) == 1, "packet processed on h1");
    CHECK(g_classify_calls == cls, "h1 skips A's classification chain");
    CHECK(g_analyse_calls == ana, "h1 skips A's analysis chain");

    /* Switching A back on for h1 restores both chains there. */
    enable_protocol_classification(h1, TEST_PROTO_A);
    enable_protocol_analysis(h1, TEST_PROTO_A);
    make_packet(&hdr, pkt, sizeof(pkt), 0x549A0003u, 2000, 0);
    CHECK(packet_process(h1, &hdr, pkt) == 1, "packet processed on re-enabled h1");
    CHECK(g_classify_calls > cls && g_analyse_calls > ana, "h1 runs A's chains again");

    mmt_close_handler(h1);
    mmt_close_handler(h2);
}

/* ============ issue #255: tunnel-parent extension + prefix-free alloc ===== */

static void test_children_stats_extension(void) {
    fprintf(stderr, "  test: children-stats extension allocated for tunnel parents only\n");
    char errbuf[256];
    u_char pkt[64];
    pkthdr_t hdr;

    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init for tunnel-parent test");
    if (h == NULL) return;

    /* Leaf session: the extension must stay NULL and the accessors read 0. */
    make_packet(&hdr, pkt, sizeof(pkt), 0x60606060u, 7000, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "leaf packet processed");
    uint32_t k_leaf = 0x60606060u;
    mmt_session_t *leaf = (mmt_session_t *) get_session_from_protocol_context_by_session_key(
        &h->configured_protocols[TEST_PROTO_A], &k_leaf);
    CHECK(leaf != NULL, "leaf session found");
    if (leaf != NULL) {
        CHECK(leaf->children_stats == NULL, "leaf session carries no extension");
        CHECK(get_session_packet_count(leaf) == 1, "leaf packet count");
        CHECK(get_session_packet_count(leaf) == get_session_total_packet_count(leaf),
              "leaf own count equals total (no children)");
        /* the direction-path accessor falls back to proto_path on a leaf */
        CHECK(get_session_proto_path_direction(leaf, MMT_SESSION_DIRECTION_UPLINK) ==
              get_session_protocol_hierarchy(leaf), "leaf uplink path is proto_path");
        CHECK(get_session_proto_path_direction(leaf, MMT_SESSION_DIRECTION_DOWNLINK) ==
              get_session_protocol_hierarchy(leaf), "leaf downlink path is proto_path");
    }

    /* Nested packet: A's classifier chains to B, so B's sessionizer creates
     * a session whose parent_session is A's — making A's a tunnel parent. */
    g_classify_to_b = 1;
    make_packet(&hdr, pkt, sizeof(pkt), 0x61616161u, 7001, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "nested packet processed");
    CHECK(g_classify_to_b == 0, "the A->B classification fired");
    /* Second packet on the same flow: the parent is already a tunnel parent,
     * so the per-direction path copy is written at the parent's own index. */
    make_packet(&hdr, pkt, sizeof(pkt), 0x61616161u, 7002, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "second packet on the parent flow");
    uint32_t k_par = 0x61616161u;
    mmt_session_t *parent = (mmt_session_t *) get_session_from_protocol_context_by_session_key(
        &h->configured_protocols[TEST_PROTO_A], &k_par);
    mmt_session_t *child = (mmt_session_t *) get_session_from_protocol_context_by_session_key(
        &h->configured_protocols[TEST_PROTO_B], &k_par);
    CHECK(parent != NULL && child != NULL, "parent and child sessions exist");
    if (parent != NULL && child != NULL) {
        CHECK(child->parent_session == parent, "child session links to its parent");
        CHECK(parent->children_stats != NULL, "tunnel parent allocated the extension");
        CHECK(child->children_stats == NULL, "child session stays a leaf");
        if (parent->children_stats != NULL) {
            /* Both packets on the flow re-hit the child session (the parent's
             * session proto_path permanently carries B once classified), so
             * the parent's sub_packet_count is 2. */
            CHECK(parent->children_stats->sub_packet_count == 2,
                  "the child packets are counted under the parent");
        }
        /* own traffic = total minus children (2 counted packets, all of them
         * also hit the embedded session) */
        CHECK(get_session_total_packet_count(parent) == 2,
              "parent total counts its packets");
        CHECK(get_session_packet_count(parent) == 0,
              "parent packet count nets out the child's");
        /* the per-direction path copy was populated for the parent */
        const proto_hierarchy_t *pp =
            get_session_proto_path_direction(parent, MMT_SESSION_DIRECTION_UPLINK);
        const proto_hierarchy_t *ph = get_session_protocol_hierarchy(parent);
        CHECK(pp != NULL && ph != NULL && pp->len == ph->len,
              "parent direction path mirrors its proto_path");
        /* leaf child: the fallback reports the child's own (longer) path */
        CHECK(get_session_proto_path_direction(child, MMT_SESSION_DIRECTION_UPLINK) ==
              get_session_protocol_hierarchy(child),
              "child direction path is its own proto_path");
    }
    g_classify_to_b = 0;
    mmt_close_handler(h); /* expires both sessions -> ctx cleanup frees the extension */
}

/* ===== issue #500: timeout-ring span overflow is not an out-of-memory ===== */

static int g_range_dispatched;
static void count_dispatch(void *milestone, void *list, void *args) {
    (void) milestone; (void) args;
    for (mmt_session_t *s = (mmt_session_t *) list; s != NULL; s = s->next)
        g_range_dispatched++;
}

static void test_timeout_span_overflow(void) {
    fprintf(stderr, "  test: out-of-span milestone is parked, not treated as OOM (#500)\n");
    char errbuf[256];
    u_char pkt[64];
    pkthdr_t hdr;
    /* 2^23 s is twice the ring's 2^22 s maximum span, and a multiple of the
     * initial 1024-slot capacity, so the far milestone collides with the
     * near one's slot and the forced growth cannot fit the span. */
    const uint32_t far = 1u << 23;

    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init for span-overflow test");
    if (h == NULL) return;
    CHECK(set_default_session_timed_out(h, TEST_TIMEOUT) == 1, "timeout set");
    CHECK(register_session_timeout_handler(h, test_expiry_handler, NULL) == 1, "expiry handler");
    int expiry_before = g_expiry_calls;

    /* Ring level: insert reports the park distinctly, and a parked milestone
     * is looked up, extended, unlinked and range-expired like a ring one. */
    mmt_session_t fake[3];
    memset(fake, 0, sizeof(fake));
    CHECK(insert_session_timeout_milestone(h, 2000, &fake[0]) == MMT_TIMEOUT_INSERTED,
          "near milestone takes a ring slot");
    CHECK(insert_session_timeout_milestone(h, 2000 + far, &fake[1]) == MMT_TIMEOUT_PARKED,
          "out-of-span milestone is parked, not refused");
    CHECK(insert_session_timeout_milestone(h, 2000 + far, &fake[2]) == MMT_TIMEOUT_PARKED,
          "a second session joins the parked milestone");
    CHECK(get_timed_out_session_list(h, 2000 + far) == &fake[2], "parked list is reachable");
    CHECK(get_timed_out_session_list(h, 2000) == &fake[0], "ring slot still owned by 2000");
    fake[2].session_timeout_milestone = 2000 + far;
    CHECK(force_session_timeout(h, &fake[2]) == 1, "a parked session unlinks");
    CHECK(get_timed_out_session_list(h, 2000 + far) == &fake[1], "the rest stays parked");
    g_range_dispatched = 0;
    timeout_expire_milestones_range(h, 2000 + far, 2001 + far, count_dispatch);
    CHECK(g_range_dispatched == 1, "stepping expiry dispatches the parked milestone");
    CHECK(get_timed_out_session_list(h, 2000 + far) == NULL, "parked milestone gone once due");
    CHECK(delete_timeout_milestone(h, 2000) == 1 && get_timed_out_session_list(h, 2000) == NULL,
          "ring milestone deleted");

    /* Packet path: A at t=1000 (milestone 1030); B, created with a delay
     * 2^23 s longer, lands on 1030 + 2^23 — the same slot. Before the fix the
     * insert failed as OOM and the forced sweep expired A on the spot. */
    make_packet(&hdr, pkt, sizeof(pkt), 0x70707070u, 1000, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "session A processed");
    CHECK(set_default_session_timed_out(h, far + TEST_TIMEOUT) == 1, "huge timeout set");
    make_packet(&hdr, pkt, sizeof(pkt), 0x71717171u, 1000, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "session B processed");
    CHECK(set_default_session_timed_out(h, TEST_TIMEOUT) == 1, "timeout restored");
    CHECK(g_expiry_calls == expiry_before, "no forced out-of-memory sweep ran");
    CHECK(get_active_session_count(h) == 2 && h->sessions_count == 2, "A and B both live");
    CHECK(get_timed_out_session_list(h, 1030) != NULL, "A still on its milestone");
    mmt_session_t *b = get_timed_out_session_list(h, 1030 + far);
    CHECK(b != NULL, "B parked on its out-of-span milestone");

    /* A's packet one second later: A's milestone moves to 1031 normally. */
    make_packet(&hdr, pkt, sizeof(pkt), 0x70707070u, 1001, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "A refreshed");
    CHECK(g_expiry_calls == expiry_before, "still nothing expired");

    /* The session still expires: a packet past B's milestone sweeps both. */
    make_packet(&hdr, pkt, sizeof(pkt), 0x72727272u, 1031 + far, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "advancer processed");
    CHECK(g_expiry_calls == expiry_before + 2, "A and the parked B expired");
    CHECK(get_timed_out_session_list(h, 1030 + far) == NULL, "parked milestone drained");
    CHECK(get_active_session_count(h) == 1, "only the advancer remains");
    mmt_close_handler(h);
}

/* ===== issue #499: a tunnel parent outlives its children ================== */

#define TUN_MAX_EXPIRED 16
static uint64_t g_tun_expired[TUN_MAX_EXPIRED];
static int g_tun_nexpired;
static int g_tun_parent_dead;     /* a child expired after its parent */
static int g_tun_parent_unpinned; /* a child expired while its parent did not count it */

static void tun_expiry_handler(const mmt_session_t *expired, void *args) {
    (void) args;
    mmt_session_t *parent = get_session_parent(expired);
    if (parent != NULL) {
        /* Read through the parent pointer — ASan turns a freed parent into a
         * hard failure under SANITIZE=asan. */
        uint64_t pid = get_session_id(parent);
        for (int i = 0; i < g_tun_nexpired; i++)
            if (g_tun_expired[i] == pid) g_tun_parent_dead++;
        if (parent->live_children == 0) g_tun_parent_unpinned++;
    }
    if (g_tun_nexpired < TUN_MAX_EXPIRED)
        g_tun_expired[g_tun_nexpired++] = expired->session_id;
}

static mmt_session_t *tun_lookup(mmt_handler_t *h, uint32_t proto, uint32_t key) {
    return (mmt_session_t *) get_session_from_protocol_context_by_session_key(
        &h->configured_protocols[proto], &key);
}

static void tun_packet(mmt_handler_t *h, uint32_t key, uint32_t sec) {
    u_char pkt[64];
    pkthdr_t hdr;
    make_packet(&hdr, pkt, sizeof(pkt), key, sec, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "tunnel test packet processed");
}

static void test_tunnel_parent_lifetime(void) {
    fprintf(stderr, "  test: tunnel parent never expires before its child (#499)\n");
    char errbuf[256];
    const uint32_t key = 0x80808080u, adv = 0x81818181u;

    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init for tunnel lifetime test");
    if (h == NULL) return;
    CHECK(set_default_session_timed_out(h, TEST_TIMEOUT) == 1, "timeout set");
    CHECK(register_session_timeout_handler(h, tun_expiry_handler, NULL) == 1, "expiry handler");
    g_tun_nexpired = g_tun_parent_dead = g_tun_parent_unpinned = 0;

    /* t=8000: A's classifier chains to B — child session under A's. */
    g_classify_to_b = 1;
    tun_packet(h, key, 8000);
    mmt_session_t *parent = tun_lookup(h, TEST_PROTO_A, key);
    mmt_session_t *child = tun_lookup(h, TEST_PROTO_B, key);
    CHECK(parent != NULL && child != NULL, "parent and child sessions exist");
    if (parent == NULL || child == NULL) { mmt_close_handler(h); return; }
    CHECK(child->parent_session == parent, "child links to its parent");
    CHECK(parent->live_children == 1, "the child pins its parent");
    uint64_t parent_id = parent->session_id, child_id = child->session_id;

    /* The inner flow gets a longer delay than the outer one (as a TCP/HTTP
     * flow inside a GTP tunnel does): the parent's own refresh would
     * expire it at t+30 while the child lives to t+600. */
    set_session_timeout_delay(child, 600);
    tun_packet(h, key, 8001);
    CHECK(child->session_timeout_milestone == 8601, "child milestone follows its delay");
    CHECK(parent->session_timeout_milestone == 8601, "parent raised to its child's milestone");
    tun_packet(h, key, 8100);
    CHECK(parent->session_timeout_milestone >= child->session_timeout_milestone,
          "the parent's own refresh never shortens it below its child");

    /* Past the parent's own delay: it must still be live. Before the fix it
     * expired here and the next tunnel packet walked the freed parent. */
    tun_packet(h, adv, 8200);
    CHECK(g_tun_nexpired == 0, "nothing expired while the child lives");
    uint64_t sessions_before = h->sessions_count;
    tun_packet(h, key, 8201);
    CHECK(h->sessions_count == sessions_before, "the tunnel packet reused the live parent");
    CHECK(parent->session_timeout_milestone == 8801 && child->session_timeout_milestone == 8801,
          "parent and child share the later milestone");

    /* Both due in the same sweep, the parent at the head of the list: the
     * child expires, the parent is deferred to the next second. */
    tun_packet(h, adv, 8900);
    CHECK(g_tun_nexpired == 1 && g_tun_expired[0] == child_id, "the child expired first");
    CHECK(parent->live_children == 0, "the child released its parent");
    tun_packet(h, adv, 8901);
    CHECK(g_tun_nexpired == 2 && g_tun_expired[1] == parent_id, "then the parent expired");
    CHECK(g_tun_parent_dead == 0 && g_tun_parent_unpinned == 0,
          "a child never expired after (or unpinned from) its parent");

    /* Teardown with a live tunnel: the close drain also takes the child
     * first, whatever the milestone order. */
    g_classify_to_b = 1;
    tun_packet(h, key + 1, 9000);
    parent = tun_lookup(h, TEST_PROTO_A, key + 1);
    child = tun_lookup(h, TEST_PROTO_B, key + 1);
    CHECK(parent != NULL && child != NULL && child->parent_session == parent,
          "second tunnel created");
    uint64_t parent_id2 = parent != NULL ? parent->session_id : 0;
    int before_close = g_tun_nexpired;
    mmt_close_handler(h);
    CHECK(g_tun_nexpired == before_close + 2, "close expired both tunnel sessions");
    CHECK(g_tun_nexpired >= 2 && g_tun_expired[g_tun_nexpired - 1] == parent_id2,
          "the close drain took the parent last");
    CHECK(g_tun_parent_dead == 0 && g_tun_parent_unpinned == 0,
          "close expired every child before its parent");
    g_classify_to_b = 0;
}

/* Issues #499/#500: the forced out-of-memory sweep skips a tunnel parent
 * with live children; once it has freed the child, the parent must still be
 * revisited by the next timer sweep instead of staying linked below
 * last_expiry_timeout forever. */
static void test_oom_sweep_revisits_skipped_parent(void) {
    fprintf(stderr, "  test: forced sweep revisits a tunnel parent it skipped (#499/#500)\n");
    char errbuf[256];
    const uint32_t key = 0x82828282u;

    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init for forced-sweep parent test");
    if (h == NULL) return;
    CHECK(set_default_session_timed_out(h, TEST_TIMEOUT) == 1, "timeout set");
    CHECK(register_session_timeout_handler(h, tun_expiry_handler, NULL) == 1, "expiry handler");
    g_tun_nexpired = g_tun_parent_dead = g_tun_parent_unpinned = 0;

    /* As in test_tunnel_parent_lifetime: the child's longer delay makes the
     * refresh raise the parent onto the child's milestone, ahead of it. */
    g_classify_to_b = 1;
    tun_packet(h, key, 10000);
    mmt_session_t *parent = tun_lookup(h, TEST_PROTO_A, key);
    mmt_session_t *child = tun_lookup(h, TEST_PROTO_B, key);
    CHECK(parent != NULL && child != NULL && child->parent_session == parent &&
          parent->live_children == 1, "tunnel parent pinned by its child");
    if (parent == NULL || child == NULL) { mmt_close_handler(h); g_classify_to_b = 0; return; }
    set_session_timeout_delay(child, 60);
    tun_packet(h, key, 10001);
    g_classify_to_b = 0;
    uint32_t m = parent->session_timeout_milestone;
    CHECK(child->session_timeout_milestone == m && get_timed_out_session_list(h, m) == parent &&
          parent->next == child, "parent ahead of its child on one milestone");
    CHECK(h->last_expiry_timeout <= m, "the milestone is still ahead of the sweep");
    uint64_t parent_id = parent->session_id, child_id = child->session_id;

    /* The forced sweep skips the pinned parent and frees the child. */
    process_outofmemory_force_sessions_timeout(h, NULL);
    CHECK(g_tun_nexpired == 1 && g_tun_expired[0] == child_id, "forced sweep expired the child");
    CHECK(parent->live_children == 0, "the child released its parent");
    CHECK(h->last_expiry_timeout <= m, "the sweep resumes at the skipped milestone");

    /* The next timer sweep, past the milestone, now expires the parent. */
    process_timedout_sessions(h, m + 10);
    CHECK(g_tun_nexpired == 2 && g_tun_expired[1] == parent_id,
          "the released parent expired on the next sweep");
    CHECK(g_tun_parent_dead == 0 && g_tun_parent_unpinned == 0,
          "the child expired before its parent");
    mmt_close_handler(h);
}

static void test_alloc_no_prefix(void) {
    fprintf(stderr, "  test: allocator passes natural sizes to libc (F-PERF-015)\n");

    /* mmt_malloc must hand malloc() exactly the requested size — the removed
     * 8-byte size prefix used to inflate every request (48 -> 56 -> 64-byte
     * size class). */
    g_malloc_last_size = 0;
    void *p = mmt_malloc(48);
    CHECK(p != NULL, "mmt_malloc(48) succeeded");
    CHECK(g_malloc_last_size == 48, "malloc sees the natural size (no +8 prefix)");

    g_realloc_last_size = 0;
    void *q = mmt_realloc(p, 64);
    CHECK(q != NULL, "mmt_realloc to 64 succeeded");
    CHECK(g_realloc_last_size == 64, "realloc sees the natural size (no +8 prefix)");
    mmt_free(q);

    /* The internal-allocation-site case: hashmap_insert_kv allocates its
     * mmt_hent_t node through mmt_malloc — it must reach malloc() at exactly
     * sizeof(mmt_hent_t) (the issue's "natural size class" assertion). */
    mmt_hashmap_t *m = hashmap_alloc();
    CHECK(m != NULL, "hashmap_alloc for the size-class check");
    if (m != NULL) {
        static char v;
        g_malloc_last_size = 0;
        hashmap_insert_kv(m, (mmt_key_t) 7, &v);
        CHECK(g_malloc_last_size == sizeof(mmt_hent_t),
              "hashmap node reaches malloc at its natural size class");
        hashmap_free(m);
    }
}

/* ============================ misc helpers ================================ */

static void test_helpers(void) {
    fprintf(stderr, "  test: helper/coverage calls\n");

    proto_hierarchy_t path;
    memset(&path, 0, sizeof(path));
    path.len = 2;
    path.proto_path[0] = PROTO_META;
    path.proto_path[1] = TEST_PROTO_A;
    char buf[256];
    CHECK(proto_hierarchy_to_str_with_size(&path, buf, sizeof(buf)) > 0, "hierarchy to str");
    CHECK(strstr(buf, "ce_proto_a") != NULL, "hierarchy contains the test proto name");
    CHECK(proto_hierarchy_to_str_with_size(NULL, buf, sizeof(buf)) == 0, "NULL hierarchy");
    CHECK(proto_hierarchy_to_str(&path, buf) > 0, "compat hierarchy to str");
    const char *app = get_application_name(&path);
    CHECK(app != NULL && strcmp(app, "ce_proto_a") == 0, "application name is last proto");
    CHECK(get_application_name(NULL) == NULL, "NULL application name");

    CHECK(mmt_match_strprefix((const u_int8_t *) "GET / HTTP", 10, "GET") == 1, "match_prefix hit");
    CHECK(mmt_match_prefix((const u_int8_t *) "GET", 3, "POST", 4) == 0, "match_prefix miss");
    CHECK(mmt_strnstr("hello world", "world", 11) != NULL, "strnstr hit");
    CHECK(mmt_strnstr("hello", "world", 5) == NULL, "strnstr miss");

    CHECK(update_protocol(TEST_PROTO_A, 0) == 0, "update_protocol without fct returns 0");
}

/* ===================== attribute report output (#328) ===================== */

/* Runs one formatter into a temporary stream and returns what it wrote. */
static int capture_stream(int (*fn)(FILE *, attribute_t *), attribute_t *a,
                          char *out, size_t out_len, int *ret) {
    FILE *f = tmpfile();
    if (f == NULL) return 0;
    *ret = fn(f, a);
    fflush(f);
    rewind(f);
    size_t n = fread(out, 1, out_len - 1, f);
    out[n] = '\0';
    fclose(f);
    return 1;
}

static void test_attr_report_output(void) {
    fprintf(stderr, "  test: attribute report/dump output (#328)\n");
    char buf[256], out[512];
    int ret = 0;
    attribute_internal_t attr;
    memset(&attr, 0, sizeof(attr));
    attr.proto_id = PROTO_META;
    attr.field_id = META_P_LEN;
    attribute_t *a = (attribute_t *) &attr;

    /* MMT_STATS: totals over the per-path statistics chain */
    (void) test_stats_extract(NULL, 0, a);
    attr.data_type = MMT_STATS;
    int n = mmt_attr_snprintf(buf, sizeof(buf), a);
    CHECK(n == (int) strlen(CE_STATS_REPORT) && strcmp(buf, CE_STATS_REPORT) == 0,
          "MMT_STATS snprintf renders the summed statistics");
    CHECK(capture_stream(mmt_attr_fprintf, a, out, sizeof(out), &ret)
              && ret == (int) strlen(CE_STATS_REPORT) && strcmp(out, CE_STATS_REPORT) == 0,
          "MMT_STATS fprintf writes the summed statistics");
    CHECK(capture_stream(mmt_attr_format, a, out, sizeof(out), &ret) && ret > 0
              && strncmp(out, "Attribute ", 10) == 0
              && strstr(out, " = " CE_STATS_REPORT "\n") != NULL,
          "MMT_STATS format dumps the summed statistics");

    /* truncation follows the snprintf contract: full length returned */
    char small[8];
    n = mmt_attr_snprintf(small, sizeof(small), a);
    CHECK(n == (int) strlen(CE_STATS_REPORT) && strlen(small) == sizeof(small) - 1,
          "MMT_STATS snprintf truncates and reports the full length");
    CHECK(mmt_attr_snprintf(NULL, 16, a) < 0, "MMT_STATS snprintf rejects a NULL buffer");

    /* no statistics yet: a NULL chain reports zeros */
    attr.data = NULL;
    n = mmt_attr_snprintf(buf, sizeof(buf), a);
    CHECK(n > 0 && strcmp(buf, "packets=0,data_volume=0,payload_volume=0,sessions=0,timedout_sessions=0") == 0,
          "MMT_STATS with no statistics reports zeros");

    /* a data type with no text form: documented negative return, no output */
    attr.data_type = 0x7fff;
    attr.data = (void *) g_ce_stats;
    strcpy(buf, "sentinel");
    CHECK(mmt_attr_snprintf(buf, sizeof(buf), a) < 0 && buf[0] == '\0',
          "unsupported type: snprintf returns negative with an empty string");
    CHECK(capture_stream(mmt_attr_fprintf, a, out, sizeof(out), &ret) && ret < 0 && out[0] == '\0',
          "unsupported type: fprintf returns negative and writes nothing");
    CHECK(capture_stream(mmt_attr_format, a, out, sizeof(out), &ret) && ret < 0 && out[0] == '\0',
          "unsupported type: format returns negative and writes nothing");

    /* types without a dedicated stream writer reuse their snprintf text */
    float fv = 1.5f;
    attr.data_type = MMT_DATA_FLOAT;
    attr.data = &fv;
    CHECK(capture_stream(mmt_attr_fprintf, a, out, sizeof(out), &ret) && strcmp(out, "1.500") == 0,
          "MMT_DATA_FLOAT fprintf writes the snprintf text form");
    CHECK(capture_stream(mmt_attr_format, a, out, sizeof(out), &ret)
              && strstr(out, " = 1.500\n") != NULL,
          "MMT_DATA_FLOAT format dumps the snprintf text form");
    mmt_u16_array_t arr;
    memset(&arr, 0, sizeof(arr));
    arr.len = 2; arr.data[0] = 17; arr.data[1] = 42;
    attr.data_type = MMT_U16_ARRAY;
    attr.data = &arr;
    CHECK(capture_stream(mmt_attr_fprintf, a, out, sizeof(out), &ret) && strcmp(out, "17,42") == 0,
          "MMT_U16_ARRAY fprintf writes the snprintf text form");
    arr.len = 0;
    CHECK(capture_stream(mmt_attr_fprintf, a, out, sizeof(out), &ret) && ret == 0 && out[0] == '\0',
          "empty MMT_U16_ARRAY fprintf writes nothing");
    CHECK(capture_stream(mmt_attr_format, a, out, sizeof(out), &ret)
              && ret > 0 && strstr(out, " = \n") != NULL,
          "empty MMT_U16_ARRAY format dumps an empty value");
}

static int g_proto_seen, g_attr_seen;
static void count_proto(mmt_proto_id_t proto_id, void *args) {
    (void) args;
    if (proto_id == TEST_PROTO_A) g_proto_seen++;
}
static void count_attr(attribute_metadata_t *attribute, mmt_proto_id_t proto_id, void *args) {
    (void) args;
    if (proto_id == TEST_PROTO_A && attribute->id == TEST_ATTR_ID) g_attr_seen++;
}

static void test_iteration(void) {
    fprintf(stderr, "  test: registry iteration\n");
    g_proto_seen = 0;
    iterate_through_protocols(count_proto, NULL);
    CHECK(g_proto_seen == 1, "protocol iteration visits the test proto");
    g_attr_seen = 0;
    iterate_through_protocol_attributes(TEST_PROTO_A, count_attr, NULL);
    CHECK(g_attr_seen == 1, "attribute iteration visits the custom attr");
}

/* ============ classification utilities (issue #242, part 2) ================
 * mmt_tcpip_classif_utils.c is linked into this binary, so its constructor
 * already built the doted-name trie and the ~10k-node IPv4 CIDR AVL trees at
 * load time; the destructor frees them at exit. The checks below drive the
 * lookup entry points directly against fabricated packets. */

/* Fabricate the minimal packet the classification helpers dereference:
 * hostname paths need ->session->content_flags; address paths need
 * ->internal_packet->{iph,iphv6}. */
static void make_classif_packet(ipacket_t *pkt, mmt_session_t *sess,
                                mmt_tcpip_internal_packet_t *internal) {
    memset(ipacket_internal(pkt), 0, sizeof(ipacket_internal_t)); /* issue #535: the private extension too */
    memset(sess, 0, sizeof(*sess));
    memset(internal, 0, sizeof(*internal));
    pkt->session = sess;
    pkt->internal_packet = internal;
}

static void test_hostname_matching(void) {
    fprintf(stderr, "  test: hostname matching (reverse suffix + trie + linear)\n");
    ipacket_internal_t pkt;
    mmt_session_t sess;
    mmt_tcpip_internal_packet_t internal;
    make_classif_packet(&pkt.pub, &sess, &internal);

    /* --- mmt_case_sensitive_reverse_hostname_matching --- */
    CHECK(mmt_case_sensitive_reverse_hostname_matching("www.google.com", ".google.com", 14, 11) == 1,
          "reverse match: subdomain suffix");
    CHECK(mmt_case_sensitive_reverse_hostname_matching("google.com", ".google.com", 10, 11) == 1,
          "reverse match: bare domain equals doted entry");
    CHECK(mmt_case_sensitive_reverse_hostname_matching("xgoogle.com", ".google.com", 11, 11) == 0,
          "reverse match: dot boundary enforced");
    /* F-BUG-026 regression: zero-length and NULL inputs must not be
     * dereferenced (the counters are tested before the cursors). */
    CHECK(mmt_case_sensitive_reverse_hostname_matching("", ".google.com", 0, 11) == 0,
          "reverse match: empty hostname");
    CHECK(mmt_case_sensitive_reverse_hostname_matching("a", "", 1, 0) == 0,
          "reverse match: empty pattern");
    CHECK(mmt_case_sensitive_reverse_hostname_matching(NULL, ".google.com", 0, 11) == 0,
          "reverse match: NULL hostname");
    CHECK(mmt_case_sensitive_reverse_hostname_matching("a", "abc", 1, 3) == 0,
          "reverse match: hostname shorter than pattern");
    CHECK(mmt_case_sensitive_reverse_hostname_matching("abc", "abd", 3, 3) == 0,
          "reverse match: same length, tail differs");

    /* --- get_proto_id_by_hostname: reversed-name trie walk --- */
    char h_sub[] = "www.google.com";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_sub, 14) == PROTO_GOOGLE,
          "trie: subdomain of .google.com");
    char h_bare[] = "google.com";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_bare, 10) == PROTO_GOOGLE,
          "trie: bare domain via the '.'-child fallback");
    /* F-BUG-030 regression: an empty hostname must not fire the '.'
     * fallback on the trie root — it returns PROTO_UNKNOWN. */
    char h_empty[] = "";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_empty, 0) == PROTO_UNKNOWN,
          "trie: empty hostname returns UNKNOWN");
    char h_bound[] = "xgoogle.com";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_bound, 11) == PROTO_UNKNOWN,
          "trie: partial suffix without dot boundary is UNKNOWN");
    char h_tld[] = "nonexistent.invalidtld";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_tld, 22) == PROTO_UNKNOWN,
          "trie: unknown suffix is UNKNOWN");
    /* akamai entries route through the fbcdn* prefix table; the content
     * flags land on the session. */
    char h_fbcdn[] = "fbcdn-video.akamai.net";
    sess.content_flags = 0;
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_fbcdn, 22) == PROTO_FACEBOOK,
          "trie: akamai suffix resolved to facebook via fbcdn prefix");
    CHECK((sess.content_flags & (MMT_CONTENT_CDN | MMT_CONTENT_VIDEO)) ==
          (MMT_CONTENT_CDN | MMT_CONTENT_VIDEO),
          "trie: CDN|VIDEO content flags set on the session");
    char h_ak[] = "whatever.akamai.net";
    sess.content_flags = 0;
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_ak, 19) == PROTO_AKAMAI,
          "trie: plain akamai hostname stays PROTO_AKAMAI");

    /* --- _get_proto_id_by_hostname: linear table scan --- */
    char l_yt[] = "www.youtube.com";
    CHECK(_get_proto_id_by_hostname(&pkt.pub, l_yt, 15) == PROTO_YOUTUBE,
          "linear: subdomain of .youtube.com");
    char l_bare[] = "google.com";
    CHECK(_get_proto_id_by_hostname(&pkt.pub, l_bare, 10) == PROTO_GOOGLE,
          "linear: bare domain matches the doted entry");
    char l_empty[] = "";
    CHECK(_get_proto_id_by_hostname(&pkt.pub, l_empty, 0) == PROTO_UNKNOWN,
          "linear: empty hostname returns UNKNOWN");
    char l_fb[] = "fbcdn-profile.akamai.net";
    sess.content_flags = 0;
    CHECK(_get_proto_id_by_hostname(&pkt.pub, l_fb, 24) == PROTO_FACEBOOK,
          "linear: akamai suffix resolved via fbcdn prefix");
    CHECK((sess.content_flags & MMT_CONTENT_CDN) != 0,
          "linear: CDN content flag set on the session");

    /* Issue #105: hostname classification is case-insensitive — the trie
     * folds every byte to lowercase at build and lookup, and the linear
     * scan folds both cursors, so any case variant of a listed suffix
     * classifies the same. SNI and HTTP Host on the wire vary in case. */
    char h_upper[] = "WWW.GOOGLE.COM";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_upper, 14) == PROTO_GOOGLE,
          "trie: all-caps subdomain of .google.com");
    char h_mixed[] = "WwW.YouTube.Com";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_mixed, 15) == PROTO_YOUTUBE,
          "trie: mixed-case subdomain of .youtube.com");
    char h_bare_up[] = "GOOGLE.COM";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_bare_up, 10) == PROTO_GOOGLE,
          "trie: all-caps bare domain via the '.'-child fallback");
    /* '.Doubleclick.net' was the one mixed-case table entry — unreachable
     * before; it is normalised away as a duplicate of '.doubleclick.net',
     * which now matches any case variant. */
    char h_dclk[] = "ads.DOUBLECLICK.net";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_dclk, 19) == PROTO_DOUBLECLICK,
          "trie: doubleclick.net matches under any case");
    char h_bound_up[] = "XGOOGLE.COM";
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_bound_up, 11) == PROTO_UNKNOWN,
          "trie: dot boundary still enforced under folding");
    char h_fbcdn_up[] = "FBCDN-video.AKAMAI.net";
    sess.content_flags = 0;
    CHECK(get_proto_id_by_hostname(&pkt.pub, h_fbcdn_up, 22) == PROTO_FACEBOOK,
          "trie: mixed-case fbcdn akamai host resolves to facebook");
    CHECK((sess.content_flags & (MMT_CONTENT_CDN | MMT_CONTENT_VIDEO)) ==
          (MMT_CONTENT_CDN | MMT_CONTENT_VIDEO),
          "trie: CDN|VIDEO content flags set under folding");

    char l_upper[] = "WWW.YOUTUBE.COM";
    CHECK(_get_proto_id_by_hostname(&pkt.pub, l_upper, 15) == PROTO_YOUTUBE,
          "linear: all-caps subdomain of .youtube.com");
    char l_dclk[] = "ads.DOUBLECLICK.net";
    CHECK(_get_proto_id_by_hostname(&pkt.pub, l_dclk, 19) == PROTO_DOUBLECLICK,
          "linear: doubleclick.net matches under any case");
}

static void test_ip_attribution(void) {
    fprintf(stderr, "  test: CIDR attribution trees + external range loader\n");
    ipacket_internal_t pkt;
    mmt_session_t sess;
    mmt_tcpip_internal_packet_t internal;
    make_classif_packet(&pkt.pub, &sess, &internal);

    /* --- compiled-in IPv4 table: 1.201.0.0/24 -> PROTO_KAKAO --- */
    CHECK(_find_proto_id_by_address(0x01C90007u, 0xC0000201u) == PROTO_KAKAO,
          "builtin CIDR: source-address match");
    CHECK(_find_proto_id_by_address(0xC0000201u, 0x01C90007u) == PROTO_KAKAO,
          "builtin CIDR: destination-address match");
    CHECK(_find_proto_id_by_address(0xC0000201u, 0xC0000202u) == -1,
          "builtin CIDR: no match returns -1 (192.0.2.0/24 is not in the table)");

    /* get_proto_id_from_address reads the network-order headers. */
    CHECK(get_proto_id_from_address(&pkt.pub) == PROTO_UNKNOWN,
          "no iph/iphv6 -> UNKNOWN");
    struct iphdr ip4;
    memset(&ip4, 0, sizeof(ip4));
    ip4.saddr = htonl(0x01C90007u);
    ip4.daddr = htonl(0xC0000201u);
    internal.iph = (const mmt_una_iphdr_t *) &ip4;
    CHECK(get_proto_id_from_address(&pkt.pub) == PROTO_KAKAO,
          "iph path returns the builtin attribution");
    internal.iph = NULL;

    /* IPv6 with no external rules loaded: empty list -> -1/UNKNOWN. */
    uint8_t v6_src[16], v6_dst[16];
    struct in6_addr a6;
    CHECK(inet_pton(AF_INET6, "2001:db8::9", &a6) == 1, "v6 src parsed");
    memcpy(v6_src, &a6, 16);
    CHECK(inet_pton(AF_INET6, "2001:db7::9", &a6) == 1, "v6 dst parsed");
    memcpy(v6_dst, &a6, 16);
    CHECK(_find_proto_id_by_address6(v6_src, v6_dst) == -1,
          "empty IPv6 range list returns -1");
    struct mmt_ipv6hdr ip6;
    memset(&ip6, 0, sizeof(ip6));
    memcpy(ip6.saddr.mmt_v6_addr, v6_src, 16);
    memcpy(ip6.daddr.mmt_v6_addr, v6_dst, 16);
    internal.iphv6 = &ip6;
    CHECK(get_proto_id_from_address(&pkt.pub) == PROTO_UNKNOWN,
          "iphv6 with no ranges -> UNKNOWN");
    internal.iphv6 = NULL;

    /* --- external range-file loader --- */
    CHECK(mmt_tcpip_load_ip_ranges_file(NULL) == 0, "NULL path rejected");
    CHECK(mmt_tcpip_load_ip_ranges_file("") == 0, "empty path rejected");
    CHECK(mmt_tcpip_load_ip_ranges_file("/nonexistent/ce_ranges.txt") == -1,
          "missing file reports -1");

    /* One rule per loader branch. ce_proto_a (id 613) is still registered
     * from the bootstrap test, so the name-token path resolves. */
    const char *path = "./ce_ip_ranges.txt";
    FILE *fp = fopen(path, "w");
    CHECK(fp != NULL, "ranges file created");
    if (fp == NULL) return;
    fputs("# comment line is stripped\n"
          "192.0.2.0/24 42\n"               /* extend: new dynamic rule */
          "192.0.2.0/24 43\n"               /* duplicate dynamic CIDR: last wins */
          "1.201.1.0/24 55\n"               /* duplicate of a builtin: dropped */
          "9.9.9.0/24 70 override\n"
          "9.9.9.0/24 71 override\n"        /* override dup: last wins */
          "9.9.9.0/24 72\n"                 /* extend under the same CIDR */
          "10.250.0.0/16 60 bogus\n"        /* unknown flag -> extend */
          "10.251.0.0/16\n"                 /* missing proto token -> skip */
          "10.252.0.0 42\n"                 /* missing /prefix -> skip */
          "999.1.1.0/24 42\n"               /* invalid IPv4 -> skip */
          "10.253.0.0/0 42\n"               /* prefix 0 -> skip */
          "10.253.0.0/33 42\n"              /* prefix > 32 -> skip */
          "10.254.0.0/24 nosuchproto\n"     /* unknown protocol -> skip */
          "2001:db8::/32 77\n"              /* IPv6 extend */
          "2001:db8:1::/48 79\n"            /* IPv6 extend, longer prefix */
          "2001:db8::/48 78 override\n"     /* IPv6 override */
          "2001:zz::/32 42\n"               /* invalid IPv6 -> skip */
          "2001:db9::/0 42\n"               /* IPv6 prefix 0 -> skip */
          "2001:db9::/129 42\n"             /* IPv6 prefix > 128 -> skip */
          "2001:db7::/32 ce_proto_a\n",     /* name token -> id 613 */
          fp);
    fclose(fp);
    CHECK(mmt_tcpip_load_ip_ranges_file(path) == 11, "11 valid rules loaded");

    /* extend + last-rule-wins on a duplicate dynamic CIDR */
    CHECK(_find_proto_id_by_address(0xC0000207u, 0x0u) == 43,
          "dynamic extend rule applies (last wins on duplicate)");
    /* Task 3.6 / F-BUG-027: an extend rule duplicating a compiled-in CIDR is
     * a no-op — the builtin attribution stays authoritative. */
    CHECK(_find_proto_id_by_address(0x01C90107u, 0x0u) == PROTO_KAKAO,
          "builtin CIDR wins over a duplicate extend rule");
    /* override rules are consulted before builtin and extend trees, and a
     * duplicate override also resolves last-wins. */
    CHECK(_find_proto_id_by_address(0x09090907u, 0x0u) == 71,
          "override rules take precedence (last wins on duplicate)");
    CHECK(_find_proto_id_by_address(0x0AFA0007u, 0x0u) == 60,
          "unknown flag degrades to an extend rule");

    /* IPv6: override class wins regardless of prefix length; within the
     * extend class the longest prefix wins. v6_src is parked outside every
     * loaded range so each lookup isolates the destination side. */
    CHECK(inet_pton(AF_INET6, "2001:beef::9", &a6) == 1, "v6 unranged addr parsed");
    memcpy(v6_src, &a6, 16);
    CHECK(_find_proto_id_by_address6(v6_src, v6_dst) == 613,
          "IPv6 destination match via protocol-name token");
    CHECK(inet_pton(AF_INET6, "2001:db8:1::5", &a6) == 1, "v6 addr parsed");
    memcpy(v6_dst, &a6, 16);
    CHECK(_find_proto_id_by_address6(v6_src, v6_dst) == 79,
          "IPv6 longest-prefix wins within the extend class");
    CHECK(inet_pton(AF_INET6, "2001:db8::9", &a6) == 1, "v6 addr parsed");
    memcpy(v6_dst, &a6, 16);
    CHECK(_find_proto_id_by_address6(v6_src, v6_dst) == 78,
          "IPv6 override wins over a longer-prefix extend rule");
    /* through the packet accessor */
    CHECK(inet_pton(AF_INET6, "2001:db7::9", &a6) == 1, "v6 addr parsed");
    memcpy(ip6.saddr.mmt_v6_addr, v6_src, 16);
    memcpy(ip6.daddr.mmt_v6_addr, &a6, 16);
    internal.iphv6 = &ip6;
    CHECK(get_proto_id_from_address(&pkt.pub) == 613,
          "iphv6 path returns the external attribution");
    internal.iphv6 = NULL;

    /* env-var entry point: unset -> no-op; set -> loads the same file. */
    unsetenv("MMT_DPI_IP_RANGES_FILE");
    mmt_tcpip_load_external_ip_ranges();
    CHECK(setenv("MMT_DPI_IP_RANGES_FILE", path, 1) == 0, "env var set");
    mmt_tcpip_load_external_ip_ranges();
    CHECK(_find_proto_id_by_address(0xC0000207u, 0x0u) == 43,
          "env-var load is idempotent");
    unsetenv("MMT_DPI_IP_RANGES_FILE");
    remove(path);

    /* teardown + rebuild restore the compiled-in baseline. */
    _free_proto_avltrees();
    CHECK(_find_proto_id_by_address(0xC0000207u, 0x0u) == -1,
          "external rules released with the trees");
    _init_proto_avltrees();
    CHECK(_find_proto_id_by_address(0x01C90007u, 0x0u) == PROTO_KAKAO,
          "builtin attribution intact after free/re-init");
}

static void test_offset_memoization(void) {
    fprintf(stderr, "  test: memoized cumulative offsets (issue #19)\n");
    ipacket_internal_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.proto_headers_offset = &pkt.internal_proto_headers_offset;
    pkt.proto_headers_offset->proto_path[0] = 14;
    pkt.proto_headers_offset->proto_path[1] = 20;
    pkt.proto_headers_offset->proto_path[2] = 8;
    pkt.proto_headers_offset->proto_path[3] = 4;
    pkt.internal_cumulative_offset_valid = 0;

    /* lazy build: the first query sums proto_path[0..index] once. */
    CHECK(get_packet_offset_at_index(&pkt.pub, 2) == 42, "prefix sum 14+20+8");
    CHECK(pkt.internal_cumulative_offset_valid == 1 &&
          pkt.internal_cumulative_offset_hwm == 2, "cache valid, hwm == 2");
    /* cached reads: querying at/below the hwm does not resum. */
    CHECK(get_packet_offset_at_index(&pkt.pub, 1) == 34, "cached lower index");
    CHECK(pkt.internal_cumulative_offset_hwm == 2, "hwm unchanged by cached read");
    /* extending past the hwm resumes the sum from the hwm, not from 0. */
    CHECK(get_packet_offset_at_index(&pkt.pub, 4) == 46, "extension resumes at the hwm");
    CHECK(pkt.internal_cumulative_offset_hwm == 4, "hwm advanced to 4");
    /* a mutated offset stays invisible until the cache is invalidated —
     * that staleness is exactly why set_classified_proto() and the session
     * offset swaps invalidate it. */
    pkt.proto_headers_offset->proto_path[1] = 40;
    CHECK(get_packet_offset_at_index(&pkt.pub, 2) == 42, "mutation invisible while cached");
    invalidate_packet_offset_cache(&pkt.pub);
    CHECK(pkt.internal_cumulative_offset_valid == 0, "invalidation flag dropped");
    CHECK(get_packet_offset_at_index(&pkt.pub, 2) == 62, "rebuilt sum 14+40+8");
    invalidate_packet_offset_cache(NULL); /* NULL-safe helper */
    /* index clamp: anything >= PROTO_PATH_SIZE reads the last slot. */
    CHECK(get_packet_offset_at_index(&pkt.pub, PROTO_PATH_SIZE + 7) ==
          get_packet_offset_at_index(&pkt.pub, PROTO_PATH_SIZE - 1),
          "index is clamped to PROTO_PATH_SIZE-1");
}

/* Issue #243 / F-TEST-018: the TCP-reassembly instrumentation counters in
 * packet_pipeline.c are only incremented from reassembly code paths that the
 * session-lifecycle packets never take. Drive them directly so the accessor
 * block stops being a contiguous uncovered run — and pin the counter contract
 * (resident bytes clamp at zero) while we are here. */
static void test_reasm_stats(void) {
    fprintf(stderr, "  test: tcp-reassembly instrumentation counters\n");
    uint64_t v0 = mmt_tcp_reasm_insert_visits();
    uint64_t m0 = mmt_tcp_reasm_bytes_moved();
    uint64_t d0 = mmt_tcp_reasm_bytes_dropped();
    uint64_t a0 = mmt_reassembly_packet_alloc_count();
    uint64_t r0 = mmt_tcp_reasm_resident_bytes();

    mmt_tcp_reasm_stat_visit();
    mmt_tcp_reasm_stat_visit();
    mmt_tcp_reasm_stat_move(150);
    mmt_tcp_reasm_stat_drop(40);
    mmt_tcp_reasm_stat_live(200);
    mmt_tcp_reasm_stat_live(-50);
    mmt_reassembly_stat_packet_alloc();

    CHECK(mmt_tcp_reasm_insert_visits() == v0 + 2, "visit counter +2");
    CHECK(mmt_tcp_reasm_bytes_moved() == m0 + 150, "moved bytes +150");
    CHECK(mmt_tcp_reasm_bytes_dropped() == d0 + 40, "dropped bytes +40");
    CHECK(mmt_reassembly_packet_alloc_count() == a0 + 1, "packet allocs +1");
    CHECK(mmt_tcp_reasm_resident_bytes() == r0 + 150, "resident bytes +150");

    /* resident bytes are a signed gauge exposed as unsigned: a negative
     * balance reports 0, never wraps. */
    mmt_tcp_reasm_stat_live(-(int64_t) (r0 + 150) - 10);
    CHECK(mmt_tcp_reasm_resident_bytes() == 0, "negative resident clamps to 0");
    /* the gauge sits at -10 here; restoring the prior balance takes r0+10 */
    mmt_tcp_reasm_stat_live((int64_t) r0 + 10);
}

/* Issue #502 (F-BUG-016): get_session_last_data_packet_time_by_direction()
 * indexes a 2-slot array — TO_INITIATOR / FROM_SERVER (2) and any larger
 * direction must be rejected (zero timeval), not read the next field. The
 * session is poisoned with a non-zero pattern so an out-of-range read is
 * visible as a non-zero result. */
static void test_direction_bound(void) {
    mmt_session_t *s = (mmt_session_t *) malloc(sizeof(mmt_session_t));
    CHECK(s != NULL, "direction-bound session allocation");
    if (s == NULL) return;
    memset(s, 0xA5, sizeof(*s));
    s->s_last_data_packet_time[0].tv_sec = 11; s->s_last_data_packet_time[0].tv_usec = 1;
    s->s_last_data_packet_time[1].tv_sec = 22; s->s_last_data_packet_time[1].tv_usec = 2;

    struct timeval t0 = get_session_last_data_packet_time_by_direction(s, 0);
    struct timeval t1 = get_session_last_data_packet_time_by_direction(s, 1);
    CHECK(t0.tv_sec == 11 && t0.tv_usec == 1, "direction 0 returns the initiator slot");
    CHECK(t1.tv_sec == 22 && t1.tv_usec == 2, "direction 1 returns the remote slot");

    struct timeval t2 = get_session_last_data_packet_time_by_direction(s, TO_INITIATOR);
    struct timeval t255 = get_session_last_data_packet_time_by_direction(s, 255);
    CHECK(t2.tv_sec == 0 && t2.tv_usec == 0, "direction 2 (TO_INITIATOR) rejected");
    CHECK(t255.tv_sec == 0 && t255.tv_usec == 0, "direction 255 rejected");

    struct timeval tn = get_session_last_data_packet_time_by_direction(NULL, 0);
    CHECK(tn.tv_sec == 0 && tn.tv_usec == 0, "NULL session rejected");
    free(s);
}

/* ===== issue #501: handler unregistration + event payloads during dispatch ===== */

#define DS_ATTR_PKT   30 /* packet scope: dispatched by proto_process_attribute_handlers() */
#define DS_ATTR_EVT   31 /* event scope: dispatched by fire_attribute_event() */
#define DS_ATTR_EXT   32 /* registered for extraction before any handler */
#define DS_ATTR_RE    33 /* packet scope: a lone handler re-registers itself */
#define DS_ATTR_SW    34 /* event scope: two handlers swap each other in */
#define DS_ATTR_P     35 /* packet scope: P < Q < R by field_id, Q re-registers */
#define DS_ATTR_Q     36
#define DS_ATTR_R     37
#define DS_ATTR_AXB   38 /* event scope: handlers [A, X, B], X re-registers */
#define DS_ATTR_MP    40 /* packet scope: MP < MQ < MS < MR by field_id; MQ's */
#define DS_ATTR_MQ    42 /* callback moves MP's handler to the new field MS */
#define DS_ATTR_MS    43
#define DS_ATTR_MR    45
#define DS_CHURN_CAP  1000 /* the churn handlers stop here so a regression fails, not hangs */

static mmt_handler_t *g_ds_handler;
static int g_ds_self_calls;
static int g_ds_other_calls;
static int g_ds_evt_calls;
static int g_ds_evt_saw_payload;
static uint32_t g_ds_other_value;
static void *g_ds_evt_expected;

/* Unregisters itself from inside its own callback — the dispatch loop must
 * neither touch a freed attribute nor skip the handler that shifts into its
 * slot. */
static void ds_self_unregister(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) user_args;
    g_ds_self_calls++;
    unregister_attribute_handler(g_ds_handler, attribute->proto_id, attribute->field_id, ds_self_unregister);
}
static void ds_other(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) user_args;
    g_ds_other_calls++;
    if (attribute->data != NULL) g_ds_other_value = *(uint32_t *) attribute->data;
}
static void ds_other_self_unregister(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) user_args;
    g_ds_other_calls++;
    unregister_attribute_handler(g_ds_handler, attribute->proto_id, attribute->field_id, ds_other_self_unregister);
}
static void ds_event(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) user_args;
    g_ds_evt_calls++;
    if (attribute->data == g_ds_evt_expected) g_ds_evt_saw_payload++;
}
static void ds_event_self_unregister(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) user_args;
    g_ds_evt_calls++;
    unregister_attribute_handler(g_ds_handler, attribute->proto_id, attribute->field_id, ds_event_self_unregister);
}

/* Re-derived dispatch must terminate when a callback removes and re-adds
 * entries: a lone handler re-registering itself lands in the slot it just
 * left, and two handlers swapping each other in always find their
 * predecessor gone. */
static int g_ds_rereg_calls;
static int g_ds_swap_calls;
static void ds_reregister(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) user_args;
    if (++g_ds_rereg_calls > DS_CHURN_CAP) return;
    unregister_attribute_handler(g_ds_handler, attribute->proto_id, attribute->field_id, ds_reregister);
    register_attribute_handler(g_ds_handler, attribute->proto_id, attribute->field_id, ds_reregister, NULL, NULL);
}
static void ds_swap_y(const ipacket_t *ipacket, attribute_t *attribute, void *user_args);
static void ds_swap_x(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) user_args;
    if (++g_ds_swap_calls > DS_CHURN_CAP) return;
    unregister_attribute_handler(g_ds_handler, attribute->proto_id, attribute->field_id, ds_swap_x);
    register_attribute_handler(g_ds_handler, attribute->proto_id, attribute->field_id, ds_swap_y, NULL, NULL);
}
static void ds_swap_y(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) user_args;
    if (++g_ds_swap_calls > DS_CHURN_CAP) return;
    unregister_attribute_handler(g_ds_handler, attribute->proto_id, attribute->field_id, ds_swap_y);
    register_attribute_handler(g_ds_handler, attribute->proto_id, attribute->field_id, ds_swap_x, NULL, NULL);
}

/* Bystanders: count their calls through user_args (two functions so both
 * can sit on one attribute). */
static void ds_count(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) attribute;
    (*(int *) user_args)++;
}
static void ds_count2(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) attribute;
    (*(int *) user_args)++;
}

/* Moves the ds_count handler from DS_ATTR_MP (already run) to the new field
 * DS_ATTR_MS: the element count stays the same while the walk must still
 * reach both MS and the bystander MR. */
static int g_ds_mover_calls, g_ds_n_mp, g_ds_n_ms, g_ds_n_mr;
static void ds_mover(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void) ipacket; (void) attribute; (void) user_args;
    g_ds_mover_calls++;
    if (is_registered_attribute_handler(g_ds_handler, TEST_PROTO_A, DS_ATTR_MP, ds_count)) {
        unregister_attribute_handler(g_ds_handler, TEST_PROTO_A, DS_ATTR_MP, ds_count);
        register_attribute_handler(g_ds_handler, TEST_PROTO_A, DS_ATTR_MS, ds_count, NULL, &g_ds_n_ms);
    }
}

/* fire_attribute_event() with a pointer to a stack local, as the HTTP parser
 * callbacks (http_parser_integration.c) and the IPv4/IPv6 RTT events
 * (proto_ip.c, proto_ipv6.c) do: the local dies when this returns. */
static void ds_fire_stack_event(ipacket_t *ip, uint32_t attr_id) {
    uint32_t local = 0x5EED5EEDu;
    g_ds_evt_expected = &local;
    fire_attribute_event(ip, TEST_PROTO_A, attr_id, 1, &local);
    g_ds_evt_expected = NULL;
}

static void test_attr_dispatch_safety(void) {
    fprintf(stderr, "  test: attribute handler unregistration and event payloads during dispatch\n");
    char errbuf[256];
    u_char pkt[64];
    pkthdr_t hdr;

    static const struct { uint32_t id; const char *alias; int scope; } ds_attrs[] = {
        { DS_ATTR_PKT, "ce_ds_pkt", SCOPE_PACKET },
        { DS_ATTR_EVT, "ce_ds_evt", SCOPE_EVENT },
        { DS_ATTR_EXT, "ce_ds_ext", SCOPE_PACKET },
        { DS_ATTR_RE,  "ce_ds_re",  SCOPE_PACKET },
        { DS_ATTR_SW,  "ce_ds_sw",  SCOPE_EVENT },
        { DS_ATTR_P,   "ce_ds_p",   SCOPE_PACKET },
        { DS_ATTR_Q,   "ce_ds_q",   SCOPE_PACKET },
        { DS_ATTR_R,   "ce_ds_r",   SCOPE_PACKET },
        { DS_ATTR_AXB, "ce_ds_axb", SCOPE_EVENT },
        { DS_ATTR_MP,  "ce_ds_mp",  SCOPE_PACKET },
        { DS_ATTR_MQ,  "ce_ds_mq",  SCOPE_PACKET },
        { DS_ATTR_MS,  "ce_ds_ms",  SCOPE_PACKET },
        { DS_ATTR_MR,  "ce_ds_mr",  SCOPE_PACKET },
    };
    for (size_t i = 0; i < sizeof(ds_attrs) / sizeof(ds_attrs[0]); i++) {
        attribute_metadata_t meta;
        memset(&meta, 0, sizeof(meta));
        meta.id = ds_attrs[i].id;
        strncpy(meta.alias, ds_attrs[i].alias, Max_Alias_Len);
        meta.data_type = MMT_U32_DATA;
        meta.data_len = (int) sizeof(uint32_t);
        meta.position_in_packet = 0;
        meta.scope = ds_attrs[i].scope;
        meta.extraction_function = (ds_attrs[i].scope == SCOPE_EVENT) ? silent_extraction : test_attr_extract;
        CHECK(register_attribute_with_protocol(get_protocol_struct_by_id(TEST_PROTO_A), &meta) == 1,
              "register a dispatch-safety attribute");
    }

    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init for dispatch-safety test");
    if (h == NULL) return;
    g_ds_handler = h;

    /* (1) packet-scope dispatch: index 0 is the most recently registered
     * handler, so the array is [ds_self_unregister, ds_other]. */
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_PKT, ds_other, NULL, NULL) == 1,
          "register the surviving packet-scope handler");
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_PKT, ds_self_unregister, NULL, NULL) == 1,
          "register the self-unregistering packet-scope handler");
    make_packet(&hdr, pkt, sizeof(pkt), 0xD5D5D5D5u, 3000, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "packet processed");
    CHECK(g_ds_self_calls == 1, "self-unregistering handler ran once");
    CHECK(g_ds_other_calls == 1, "the handler shifted into the freed slot still ran");
    CHECK(g_ds_other_value == 0xD5D5D5D5u, "surviving handler saw the extracted value");
    CHECK(is_registered_attribute_handler(h, TEST_PROTO_A, DS_ATTR_PKT, ds_self_unregister) == 0,
          "self-unregistering handler is gone");
    make_packet(&hdr, pkt, sizeof(pkt), 0xD6D6D6D6u, 3001, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "second packet processed");
    CHECK(g_ds_self_calls == 1 && g_ds_other_calls == 2, "only the surviving handler runs afterwards");

    /* The last handler unregisters itself: the attribute slot is released
     * mid-dispatch — its free must wait until the dispatch loop is done
     * (ASan reports the use-after-free otherwise). */
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_PKT, ds_other) == 1,
          "drop the surviving handler");
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_PKT, ds_other_self_unregister, NULL, NULL) == 1,
          "register a lone self-unregistering handler");
    g_ds_other_calls = 0;
    make_packet(&hdr, pkt, sizeof(pkt), 0xD7D7D7D7u, 3002, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "third packet processed");
    CHECK(g_ds_other_calls == 1, "lone handler ran");
    CHECK(get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_PKT) == NULL,
          "attribute slot released once its last handler left");
    CHECK(h->attr_free_pending == NULL && h->attr_dispatch_depth == 0,
          "deferred frees flushed when dispatch ended");

    /* (2) event dispatch with stack-local payloads. */
    ipacket_internal_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.mmt_handler = h;
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_EVT, ds_event, NULL, NULL) == 1,
          "register the event handler");
    attribute_internal_t *evt = get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_EVT);
    CHECK(evt != NULL, "event attribute registered");
    ds_fire_stack_event(&ip.pub, DS_ATTR_EVT);
    CHECK(g_ds_evt_calls == 1 && g_ds_evt_saw_payload == 1, "event handler saw the payload");
    CHECK(evt != NULL && evt->data == NULL, "attr->data is NULL after event dispatch");
    CHECK(evt != NULL && evt->status == ATTRIBUTE_CONSUMED, "event attribute consumed");

    /* A self-unregistering event handler that is the attribute's last one. */
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_EVT, ds_event_self_unregister, NULL, NULL) == 1,
          "register the self-unregistering event handler");
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_EVT, ds_event) == 1,
          "leave the self-unregistering event handler alone");
    g_ds_evt_calls = 0;
    ds_fire_stack_event(&ip.pub, DS_ATTR_EVT);
    CHECK(g_ds_evt_calls == 1, "self-unregistering event handler ran");
    CHECK(get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_EVT) == NULL,
          "event attribute released after dispatch");
    CHECK(h->attr_free_pending == NULL, "event dispatch flushed its deferred free");

    /* An event fired on a packet-scope attribute must not leave its
     * extraction writing through the dead stack pointer: the next
     * extraction gets its own scratch area back. */
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_PKT, ds_other, NULL, NULL) == 1,
          "re-register the packet-scope handler");
    attribute_internal_t *pa = get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_PKT);
    ds_fire_stack_event(&ip.pub, DS_ATTR_PKT);
    CHECK(pa != NULL && pa->data == NULL, "attr->data is NULL after an event on a packet attribute");
    g_ds_other_value = 0;
    make_packet(&hdr, pkt, sizeof(pkt), 0xD8D8D8D8u, 3003, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "fourth packet processed");
    CHECK(g_ds_other_value == 0xD8D8D8D8u, "extraction after an event writes its own scratch area");
    CHECK(pa != NULL && pa->data == (void *) (pa + 1), "data points back at the scratch area");

    /* (3) registration ownership: a handler added to an attribute already
     * registered for extraction did not register it, so unregistering the
     * handler must not drop that registration. */
    CHECK(register_extraction_attribute(h, TEST_PROTO_A, DS_ATTR_EXT) == 1,
          "register the extraction attribute");
    attribute_internal_t *ext = get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_EXT);
    CHECK(ext != NULL && ext->registration_count == 1, "one extraction registration");
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_EXT, ds_other, NULL, NULL) == 1,
          "handler on an already-registered attribute");
    CHECK(ext != NULL && ext->registration_count == 1, "handler did not add an extraction registration");
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_EXT, ds_other) == 1,
          "unregister that handler");
    CHECK(get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_EXT) == ext,
          "the extraction registration survives the handler");
    CHECK(ext->registration_count == 1, "registration_count unchanged by the handler unregister");
    CHECK(unregister_extraction_attribute(h, TEST_PROTO_A, DS_ATTR_EXT) == 1,
          "unregister the extraction attribute");
    CHECK(get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_EXT) == NULL,
          "attribute released by its own registration");

    /* The handler that created the slot owns that registration: another
     * handler leaving first does not release it, the owner leaving does. */
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_EXT, ds_other, NULL, NULL) == 1,
          "owner handler creates the slot");
    ext = get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_EXT);
    CHECK(ext != NULL && ext->registration_count == 1, "the owner's registration is counted");
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_EXT, ds_event, NULL, NULL) == 1,
          "second handler joins");
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_EXT, ds_event) == 1,
          "second handler leaves");
    CHECK(get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_EXT) == ext && ext->registration_count == 1,
          "non-owner leaving keeps the owner's registration");
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_EXT, ds_other) == 1,
          "owner leaves");
    CHECK(get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_EXT) == NULL,
          "slot released with its owner");

    /* (4) bounded dispatch: a lone packet-scope handler that unregisters and
     * re-registers itself from its callback runs once per packet. */
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_RE, ds_reregister, NULL, NULL) == 1,
          "register the self-re-registering handler");
    g_ds_rereg_calls = 0;
    make_packet(&hdr, pkt, sizeof(pkt), 0xD9D9D9D9u, 3004, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "fifth packet processed");
    CHECK(g_ds_rereg_calls == 1, "self-re-registering handler ran exactly once for the packet");
    CHECK(h->attr_free_pending == NULL && h->attr_dispatch_depth == 0,
          "re-registration dispatch flushed its deferred free");
    CHECK(is_registered_attribute_handler(h, TEST_PROTO_A, DS_ATTR_RE, ds_reregister) == 1,
          "the re-registered handler stays registered");
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_RE, ds_reregister) == 1,
          "unregister the self-re-registering handler");

    /* Two event handlers that swap each other in: [ds_swap_x, ds_event].
     * The dispatch must terminate within the handler count it started
     * with instead of ping-ponging between the pair. */
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_SW, ds_event, NULL, NULL) == 1,
          "register the bystander event handler");
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_SW, ds_swap_x, NULL, NULL) == 1,
          "register the swapping event handler");
    g_ds_swap_calls = 0;
    g_ds_evt_calls = 0;
    ds_fire_stack_event(&ip.pub, DS_ATTR_SW);
    CHECK(g_ds_swap_calls >= 1 && g_ds_swap_calls <= 2, "swapping handlers ran a bounded number of times");
    CHECK(g_ds_evt_calls == 1, "the bystander after the swapping handler ran");
    CHECK(h->attr_free_pending == NULL && h->attr_dispatch_depth == 0,
          "swap dispatch closed its bracket");
    unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_SW, ds_swap_x);
    unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_SW, ds_swap_y);
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_SW, ds_event) == 1,
          "unregister the bystander event handler");
    CHECK(get_registered_attribute(h, TEST_PROTO_A, DS_ATTR_SW) == NULL,
          "swap attribute released");

    /* (5) a re-registering entry followed by a bystander: the replay of the
     * re-created entry must not take the bystander's turn. Element level:
     * attributes P < Q < R, Q's handler re-registers itself. */
    int n_p = 0, n_r = 0;
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_P, ds_count, NULL, &n_p) == 1,
          "register the P bystander");
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_Q, ds_reregister, NULL, NULL) == 1,
          "register the re-registering Q handler");
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_R, ds_count, NULL, &n_r) == 1,
          "register the R bystander");
    for (uint32_t i = 0; i < 2; i++) {
        n_p = n_r = 0;
        g_ds_rereg_calls = 0;
        make_packet(&hdr, pkt, sizeof(pkt), 0xDADADADAu, 3005 + i, 0);
        CHECK(packet_process(h, &hdr, pkt) == 1, "P/Q/R packet processed");
        CHECK(n_p == 1 && g_ds_rereg_calls == 1 && n_r == 1,
              "P, re-registering Q and R each ran exactly once");
    }
    CHECK(h->attr_free_pending == NULL && h->attr_dispatch_depth == 0,
          "P/Q/R dispatch flushed its deferred free");
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_P, ds_count) == 1 &&
          unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_Q, ds_reregister) == 1 &&
          unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_R, ds_count) == 1,
          "unregister the P/Q/R handlers");

    /* Handler level: one attribute holding [A, X, B] (index 0 is the most
     * recent registration); X re-registers itself and moves to index 0. */
    int n_a = 0, n_b = 0;
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_AXB, ds_count2, NULL, &n_b) == 1 &&
          register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_AXB, ds_reregister, NULL, NULL) == 1 &&
          register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_AXB, ds_count, NULL, &n_a) == 1,
          "register [A, X, B]");
    g_ds_rereg_calls = 0;
    ds_fire_stack_event(&ip.pub, DS_ATTR_AXB);
    CHECK(n_a == 1 && g_ds_rereg_calls == 1 && n_b == 1, "A, re-registering X and B each ran exactly once");
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_AXB, ds_count) == 1 &&
          unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_AXB, ds_reregister) == 1 &&
          unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_AXB, ds_count2) == 1,
          "unregister [A, X, B]");

    /* A callback moves a handler from an element already run to a new
     * field between itself and a bystander: the element count is
     * unchanged, yet the new field and the bystander must each run once. */
    CHECK(register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_MP, ds_count, NULL, &g_ds_n_mp) == 1 &&
          register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_MQ, ds_mover, NULL, NULL) == 1 &&
          register_attribute_handler(h, TEST_PROTO_A, DS_ATTR_MR, ds_count, NULL, &g_ds_n_mr) == 1,
          "register MP, MQ (mover) and MR");
    g_ds_mover_calls = g_ds_n_mp = g_ds_n_ms = g_ds_n_mr = 0;
    make_packet(&hdr, pkt, sizeof(pkt), 0xDBDBDBDBu, 3007, 0);
    CHECK(packet_process(h, &hdr, pkt) == 1, "mover packet processed");
    CHECK(g_ds_n_mp == 1 && g_ds_mover_calls == 1, "MP and the mover ran once");
    CHECK(g_ds_n_ms == 1, "the field added between the mover and the bystander ran once");
    CHECK(g_ds_n_mr == 1, "the bystander after the mover ran once");
    CHECK(h->attr_free_pending == NULL && h->attr_dispatch_depth == 0,
          "mover dispatch flushed its deferred free");
    CHECK(unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_MQ, ds_mover) == 1 &&
          unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_MS, ds_count) == 1 &&
          unregister_attribute_handler(h, TEST_PROTO_A, DS_ATTR_MR, ds_count) == 1,
          "unregister MQ, MS and MR");

    mmt_close_handler(h);
    g_ds_handler = NULL;
}

/* ================================ main ==================================== */

/* Issue #505 (F-BUG-014): configured_protocols[] slots are NULL before
 * init_extraction(), after close_extraction() and past the slot where an
 * out-of-memory init_extraction() stopped. _is_registered_protocol() read
 * ->is_registered through the slot unconditionally, so every lookup below
 * crashed; registering into a NULL slot crashed in init_protocol_struct().
 * Called with every slot NULL (after the final close_extraction()). */
/* Defined in packet_registry.c and only reached through protocol_t's
 * function pointers, so no header declares them. */
protocol_t *get_protocol_struct_by_protocol_id(uint32_t proto_id);
int get_attribute_id_by_name_from_protocol_map(uint32_t proto_id, const char *attribute_name);
const char *get_attribute_name_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id);
int get_attribute_data_type_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id);
int get_attribute_length_from_protocol_map(uint32_t proto_id, uint32_t attribute_id);
int get_attribute_scope_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id);
int get_attribute_position_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id);
int is_protocol_valid_attribute(uint32_t proto_id, uint32_t attribute_id);

static void test_null_slot_lookups(void) {
    fprintf(stderr, "  test: protocol lookups on NULL registry slots (#505)\n");
    const uint32_t ids[] = { 0, 1, TEST_PROTO_A, PROTO_MAX_IDENTIFIER - 1 };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        uint32_t id = ids[i];
        CHECK(is_registered_protocol(id) == 0, "is_registered_protocol on a NULL slot");
        CHECK(get_protocol_struct_by_id(id) == NULL, "get_protocol_struct_by_id on a NULL slot");
        CHECK(get_protocol_struct_by_protocol_id(id) == NULL,
              "get_protocol_struct_by_protocol_id on a NULL slot");
        CHECK(get_attribute_id_by_name_from_protocol_map(id, "x") == 0,
              "attribute id lookup on a NULL slot");
        CHECK(get_attribute_name_by_id_from_protocol_map(id, 1) == NULL,
              "attribute name lookup on a NULL slot");
        CHECK(get_attribute_data_type_by_id_from_protocol_map(id, 1) == MMT_UNDEFINED_TYPE,
              "attribute type lookup on a NULL slot");
        CHECK(get_attribute_length_from_protocol_map(id, 1) == 0,
              "attribute length lookup on a NULL slot");
        CHECK(get_attribute_scope_by_id_from_protocol_map(id, 1) == 0,
              "attribute scope lookup on a NULL slot");
        CHECK(get_attribute_position_by_id_from_protocol_map(id, 1) == POSITION_NOT_KNOWN,
              "attribute position lookup on a NULL slot");
        CHECK(is_protocol_valid_attribute(id, 1) == 0, "attribute validity on a NULL slot");
        CHECK(init_protocol_struct_for_registration(id, "ce_null_slot") == NULL,
              "registration into a NULL slot is refused");
        CHECK(unregister_protocol_by_id(id) == 0, "unregister of a NULL slot -> 0 (#673)");
    }
    CHECK(is_registered_protocol(PROTO_MAX_IDENTIFIER) == 0, "out-of-range id");
    CHECK(unregister_protocol_by_id(PROTO_MAX_IDENTIFIER) == 0, "unregister of an out-of-range id -> 0 (#673)");
    CHECK(unregister_protocol_by_name((char *) "ce_null_slot") == 0, "unregister by name with every slot NULL -> 0");
}

int main(void) {
    fprintf(stderr, "Core-engine test suite (session lifecycle + arena allocator)\n");
    g_null_fp = fopen("/dev/null", "w"); /* sink for the fprintf/format helpers */

    /* Run from a directory without a `plugins/` subdir so load_plugins()
     * takes its no-plugin early return deterministically. The run script
     * cd's into a scratch dir. */
    test_arena();
    test_arena_failures();

    test_handler_bootstrap_oom();
    test_session_lifecycle();
    test_session_create_oom();
    test_analyse_verdict();
    test_per_handler_protocol_switches();
    test_children_stats_extension();
    test_timeout_span_overflow();
    test_tunnel_parent_lifetime();
    test_oom_sweep_revisits_skipped_parent();
    test_alloc_no_prefix();
    test_helpers();
    test_attr_report_output();
    test_iteration();
    test_direction_bound();
    test_attr_dispatch_safety();

    /* Issue #242 part 2: classification utilities + offset memoization.
     * These run while ce_proto_a/b are still registered (the ranges-file
     * name-token test resolves "ce_proto_a") and before close_extraction. */
    test_hostname_matching();
    test_ip_attribution();
    test_offset_memoization();
    test_reasm_stats();

    /* Full teardown, then a second init/close cycle — F-BUG-005 regression:
     * the global maps must be NULLed, not left dangling. */
    close_extraction();
    CHECK(init_extraction() == 1, "second init_extraction after close");
    close_extraction();
    test_null_slot_lookups();

    if (g_failures == 0) {
        fprintf(stderr, "ALL CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
