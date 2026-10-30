/*
 * test_ip_session_ids.c — unit tests of the IP session store
 * (src/mmt_tcpip/lib/protocols/ip_session_id_management.c, issue #554).
 *
 * The file is included directly so its file-static helpers (_get_ip4_id,
 * ipv4_addr_hash, ...) run unmodified and gcov attributes the lines to the
 * real source — the tests/resource_bounds/ipv6_addr_fns.c convention. It is
 * linked against the core_engine suite's hash_utils.o and memory.o, so the
 * maps are the real open-addressing tables the SDK uses.
 *
 * Allocation and insertion failures are injected at link time with
 * -Wl,--wrap (malloc, mmt_malloc, mmt_free, insert_key_value,
 * insert_session_into_protocol_context): a wrapper fails only while a test
 * arms it, otherwise it forwards to the real function. mmt_malloc/mmt_free
 * are also counted, so every test can assert that the interned address ids
 * it created were all released.
 *
 * What this asserts:
 *   IPV4     the IPv4 address store: comparator and hash agree on equality
 *            (also for a misaligned address, issue #57), an address interns
 *            once, cleanup frees every id, NULL contexts are refused.
 *   SESSION  get_session() for IPv4 and IPv6: a new key creates a session
 *            whose key points at the interned ids, the same key returns the
 *            same session with is_new 0, ids are shared and reference
 *            counted, and free_session_data() unlinks the session from the
 *            expiry list and frees an id with its last session.
 *   ROLLBACK every failure path of get_session() returns NULL and leaves no
 *            id behind that it created (issue #201): session allocation, the
 *            lower and higher id allocations, the id-map insert and the
 *            session-map insert — while an id that already existed keeps its
 *            reference count.
 *   STATS    the per-protocol counters extracted from ip_session_id_
 *            management.c sum the whole proto_stats list.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/mmt_tcpip/lib/protocols/ip_session_id_management.c"

static int checks = 0;
static int failures = 0;
#define CHECK(desc, cond) do {                                          \
        checks++;                                                       \
        if (cond) { printf("  ok   %s\n", desc); }                      \
        else      { printf("  FAIL %s (line %d)\n", desc, __LINE__);    \
                    failures++; }                                       \
    } while (0)

/* ---- link-time fault injection ------------------------------------------ */

void *__real_malloc(size_t size);
void *__real_mmt_malloc(size_t size);
void  __real_mmt_free(void *x);
int   __real_insert_key_value(void *maplist, void *key, void *value);
int   __real_insert_session_into_protocol_context(void *protocol_context,
                                                  void *key, void *value);

/* -1: disarmed; n >= 0: the call after n more successful ones fails. */
static int fail_malloc_after = -1;
static int fail_mmt_malloc_after = -1;
static int fail_insert_key = 0;
static int fail_insert_session = 0;
static long live_ids = 0;   /* mmt_malloc'd blocks not yet mmt_free'd */

static int should_fail(int *after) {
    if (*after < 0) return 0;
    if (*after == 0) { *after = -1; return 1; }
    (*after)--;
    return 0;
}

void *__wrap_malloc(size_t size) {
    if (should_fail(&fail_malloc_after)) return NULL;
    return __real_malloc(size);
}

void *__wrap_mmt_malloc(size_t size) {
    if (should_fail(&fail_mmt_malloc_after)) return NULL;
    void *p = __real_mmt_malloc(size);
    if (p != NULL) live_ids++;
    return p;
}

void __wrap_mmt_free(void *x) {
    if (x != NULL) live_ids--;
    __real_mmt_free(x);
}

int __wrap_insert_key_value(void *maplist, void *key, void *value) {
    if (fail_insert_key) return 0;
    return __real_insert_key_value(maplist, key, value);
}

int __wrap_insert_session_into_protocol_context(void *protocol_context,
                                                void *key, void *value) {
    if (fail_insert_session) return 0;
    return __real_insert_session_into_protocol_context(protocol_context, key, value);
}

/* ---- a protocol context like the IP/IPv6 plugins set up ----------------- */

/* Session-key predicates over the fields get_session() fills: the interned
 * ids carry the address at offset 0, as the raw keys do. */
static size_t key_alen(const mmt_session_key_t *k) {
    return k->ip_type == 4 ? IPv4_ALEN : IPv6_ALEN;
}

static bool test_key_equal(void *a, void *b) {
    const mmt_session_key_t *l = a, *r = b;
    return l->ip_type == r->ip_type && l->next_proto == r->next_proto
        && l->lower_ip_port == r->lower_ip_port
        && l->higher_ip_port == r->higher_ip_port
        && memcmp(l->lower_ip, r->lower_ip, key_alen(l)) == 0
        && memcmp(l->higher_ip, r->higher_ip, key_alen(l)) == 0;
}

static bool test_key_comp(void *a, void *b) {
    const mmt_session_key_t *l = a, *r = b;
    if (l->next_proto != r->next_proto) return l->next_proto < r->next_proto;
    if (l->lower_ip_port != r->lower_ip_port) return l->lower_ip_port < r->lower_ip_port;
    if (l->higher_ip_port != r->higher_ip_port) return l->higher_ip_port < r->higher_ip_port;
    int c = memcmp(l->lower_ip, r->lower_ip, key_alen(l));
    if (c == 0) c = memcmp(l->higher_ip, r->higher_ip, key_alen(l));
    return c < 0;
}

static uint64_t test_key_hash(void *a) {
    const mmt_session_key_t *k = a;
    const uint8_t *lo = k->lower_ip, *hi = k->higher_ip;
    uint64_t h = 1469598103934665603ULL;
    h = (h ^ k->next_proto) * 1099511628211ULL;
    h = (h ^ k->lower_ip_port) * 1099511628211ULL;
    h = (h ^ k->higher_ip_port) * 1099511628211ULL;
    for (size_t i = 0; i < key_alen(k); i++) {
        h = (h ^ lo[i]) * 1099511628211ULL;
        h = (h ^ hi[i]) * 1099511628211ULL;
    }
    return h;
}

static protocol_instance_t *pctx_new(int ip_type) {
    protocol_instance_t *p = calloc(1, sizeof(*p));
    if (p == NULL) return NULL;
    p->args = ip_type == 4 ? setup_ipv4_internal_context()
                           : setup_ipv6_internal_context();
    p->sessions_map = init_session_map_space(test_key_comp, test_key_hash,
                                             test_key_equal);
    return p;
}

static internal_ip_proto_context_t *ctx_of(protocol_instance_t *p) {
    return (internal_ip_proto_context_t *) p->args;
}

/* Frees every session, then the store — the plugin close order. */
static void pctx_destroy(protocol_instance_t *p, int ip_type) {
    close_session_lists(p);
    delete_map_space(p->sessions_map);
    if (ip_type == 4) {
        cleanup_ipv4_internal_context(ctx_of(p));
        close_ipv4_internal_context(p);
    } else {
        cleanup_ipv6_internal_context(ctx_of(p));
        close_ipv6_internal_context(p);
    }
    free(p);
}

static mmt_session_key_t key4(uint32_t *lo, uint32_t *hi, uint16_t lport,
                              uint16_t hport) {
    mmt_session_key_t k;
    memset(&k, 0, sizeof(k));
    k.ip_type = 4;
    k.next_proto = 6;
    k.is_lower_initiator = 1;
    k.lower_ip_port = lport;
    k.higher_ip_port = hport;
    k.lower_ip = lo;
    k.higher_ip = hi;
    return k;
}

static mmt_session_key_t key6(struct in6_addr *lo, struct in6_addr *hi,
                              uint16_t lport, uint16_t hport) {
    mmt_session_key_t k = key4(NULL, NULL, lport, hport);
    k.ip_type = 6;
    k.is_lower_initiator = 0;
    k.lower_ip = lo;
    k.higher_ip = hi;
    return k;
}

static uint32_t id4_count(protocol_instance_t *p, uint32_t ip) {
    mmt_ip4_id_t *id = _findID4(ctx_of(p), &ip);
    return id == NULL ? 0 : id->count;
}

static uint32_t id6_count(protocol_instance_t *p, struct in6_addr *ip) {
    mmt_ip6_id_t *id = findID6(ctx_of(p), ip);
    return id == NULL ? 0 : id->count;
}

static struct in6_addr addr6(uint8_t last) {
    struct in6_addr a;
    memset(&a, 0, sizeof(a));
    a.s6_addr[0] = 0x20;
    a.s6_addr[1] = 0x01;
    a.s6_addr[15] = last;
    return a;
}

/* ---- IPV4: the address store -------------------------------------------- */

static void test_ipv4_address_store(void) {
    printf("IPv4 address store\n");
    uint32_t a = 0x0a000001, b = 0x0a000002;
    CHECK("ipv4_addr_comp orders distinct addresses one way only",
          ipv4_addr_comp(&a, &b) != ipv4_addr_comp(&b, &a));
    CHECK("ipv4_addr_comp is irreflexive", !ipv4_addr_comp(&a, &a));

    /* Issue #57: the key can point into the byte-aligned packet buffer. */
    unsigned char buf[8];
    memcpy(buf + 1, &a, sizeof(a));
    CHECK("a misaligned copy compares equal to the aligned address",
          !ipv4_addr_comp(buf + 1, &a) && !ipv4_addr_comp(&a, buf + 1));
    CHECK("a misaligned copy hashes like the aligned address",
          ipv4_addr_hash(buf + 1) == ipv4_addr_hash(&a));
    CHECK("distinct addresses hash differently",
          ipv4_addr_hash(&a) != ipv4_addr_hash(&b));

    internal_ip_proto_context_t *ctx = setup_ipv4_internal_context();
    CHECK("an IPv4 context starts empty",
          ctx != NULL && ctx->ips_count == 0 && ctx->sessions_count == 0);
    if (ctx == NULL) return;

    uint32_t is_new = 0;
    mmt_ip4_id_t *ida = _get_ip4_id(ctx, &a, &is_new);
    CHECK("a new address interns a zero-count id",
          ida != NULL && is_new == 1 && ida->ip == a && ida->count == 0);
    is_new = 0;
    CHECK("the same address (misaligned) resolves to the same id",
          _get_ip4_id(ctx, (uint32_t *) (void *) (buf + 1), &is_new) == ida
          && is_new == 0);
    mmt_ip4_id_t *idb = _get_ip4_id(ctx, &b, &is_new);
    CHECK("a second address interns a second id",
          idb != NULL && idb != ida && ctx->ips_count == 2);
    CHECK("_findID4 finds both ids",
          _findID4(ctx, &a) == ida && _findID4(ctx, &b) == idb);

    fail_insert_key = 1;
    uint32_t c = 0x0a000003;
    is_new = 0;
    long before = live_ids;
    CHECK("a failed id-map insert returns NULL",
          _get_ip4_id(ctx, &c, &is_new) == NULL && is_new == 0);
    fail_insert_key = 0;
    CHECK("... and frees the id it allocated",
          live_ids == before && ctx->ips_count == 2 && _findID4(ctx, &c) == NULL);

    fail_mmt_malloc_after = 0;
    CHECK("a failed id allocation returns NULL",
          _get_ip4_id(ctx, &c, &is_new) == NULL && ctx->ips_count == 2);

    CHECK("cleanup of a live context succeeds",
          cleanup_ipv4_internal_context(ctx) == 1);
    CHECK("cleanup freed every id and emptied the map",
          live_ids == 1 && _findID4(ctx, &a) == NULL && _findID4(ctx, &b) == NULL);
    CHECK("cleanup of a NULL context is refused",
          cleanup_ipv4_internal_context(NULL) == 0
          && cleanup_ipv6_internal_context(NULL) == 0);

    protocol_instance_t holder;
    memset(&holder, 0, sizeof(holder));
    close_ipv4_internal_context(&holder);   /* args NULL: setup had failed */
    close_ipv6_internal_context(&holder);
    holder.args = ctx;
    close_ipv4_internal_context(&holder);
    CHECK("closing the context frees it (and a NULL one is a no-op)",
          live_ids == 0);
}

/* ---- SESSION: get_session / free_session_data --------------------------- */

static void test_ipv4_sessions(void) {
    printf("IPv4 sessions\n");
    protocol_instance_t *p = pctx_new(4);
    CHECK("an IPv4 protocol context is set up", p && p->args && p->sessions_map);
    if (!p || !p->args || !p->sessions_map) return;
    internal_ip_proto_context_t *ctx = ctx_of(p);

    uint32_t A = 0x0a000001, B = 0x0a000002, C = 0x0a000003;
    mmt_session_key_t k1 = key4(&A, &B, 1000, 80);
    mmt_session_key_t k2 = key4(&A, &C, 1001, 443);

    int is_new = 0;
    mmt_session_t *s1 = get_session(p, &k1, NULL, &is_new);
    CHECK("a new key creates a session", s1 != NULL && is_new == 1);
    if (s1 == NULL) { pctx_destroy(p, 4); return; }
    mmt_session_key_t *sk = s1->session_key;
    CHECK("the session key is a copy whose addresses are the interned ids",
          sk->lower_ip == _findID4(ctx, &A)
          && sk->higher_ip == _findID4(ctx, &B)
          && sk->lower_ip_port == 1000 && sk->higher_ip_port == 80);
    CHECK("the session records the setup direction",
          s1->setup_packet_direction == 1 && s1->internal_data != NULL);

    is_new = 1;
    CHECK("the same key returns the same session, not new",
          get_session(p, &k1, NULL, &is_new) == s1 && is_new == 0);

    mmt_session_t *s2 = get_session(p, &k2, NULL, &is_new);
    CHECK("a second key creates a second session", s2 && s2 != s1 && is_new == 1);
    CHECK("the shared lower address is interned once and counted twice",
          id4_count(p, A) == 2 && id4_count(p, B) == 1 && id4_count(p, C) == 1
          && ctx->ips_count == 3);
    CHECK("the context counts both sessions",
          ctx->sessions_count == 2 && ctx->active_sessions_count == 2);

    /* free one session from the middle of an expiry list */
    mmt_session_t head, tail;
    memset(&head, 0, sizeof(head));
    memset(&tail, 0, sizeof(tail));
    head.next = s1; s1->previous = &head;
    s1->next = &tail; tail.previous = s1;
    delete_session_from_protocol_context(p, s1->session_key);
    free_session_data(s1->session_key, s1, ctx);
    CHECK("freeing a session unlinks it from the expiry list",
          head.next == &tail && tail.previous == &head);
    CHECK("an id is freed with its last session and kept while shared",
          id4_count(p, A) == 1 && _findID4(ctx, &B) == NULL
          && id4_count(p, C) == 1);
    CHECK("the context counts the remaining session",
          ctx->sessions_count == 1 && ctx->active_sessions_count == 1);

    /* list edges: the head of a list, then the tail of one */
    mmt_session_key_t k3 = key4(&B, &C, 2000, 53);
    mmt_session_t *s3 = get_session(p, &k3, NULL, &is_new);
    CHECK("a third session is created", s3 != NULL && is_new == 1);
    if (s3 != NULL) {
        s3->previous = NULL; s3->next = &tail; tail.previous = s3;
        delete_session_from_protocol_context(p, s3->session_key);
        free_session_data(s3->session_key, s3, ctx);
        CHECK("freeing the list head clears the next session's back link",
              tail.previous == NULL);
    }
    s2->next = NULL; s2->previous = &head; head.next = s2;
    delete_session_from_protocol_context(p, s2->session_key);
    free_session_data(s2->session_key, s2, ctx);
    CHECK("freeing the list tail clears the previous session's link",
          head.next == NULL);
    CHECK("every id is released with the last session",
          _findID4(ctx, &A) == NULL
          && _findID4(ctx, &C) == NULL && live_ids == 1 /* the context */);

    /* close_session_lists frees what is still in the map */
    mmt_session_t *s4 = get_session(p, &k1, NULL, &is_new);
    CHECK("a freed key is new again", s4 != NULL && is_new == 1);
    pctx_destroy(p, 4);
    CHECK("closing the context frees the live sessions and every id",
          live_ids == 0);
}

static void test_ipv6_sessions(void) {
    printf("IPv6 sessions\n");
    protocol_instance_t *p = pctx_new(6);
    CHECK("an IPv6 protocol context is set up", p && p->args && p->sessions_map);
    if (!p || !p->args || !p->sessions_map) return;
    internal_ip_proto_context_t *ctx = ctx_of(p);

    struct in6_addr A = addr6(1), B = addr6(2), C = addr6(3);
    mmt_session_key_t k1 = key6(&A, &B, 5000, 80);
    mmt_session_key_t k2 = key6(&A, &C, 5001, 80);
    int is_new = 0;
    mmt_session_t *s1 = get_session(p, &k1, NULL, &is_new);
    CHECK("a new IPv6 key creates a session", s1 != NULL && is_new == 1);
    CHECK("the setup direction is copied from the key",
          s1 != NULL && s1->setup_packet_direction == 0);
    CHECK("the same IPv6 key returns the same session",
          get_session(p, &k1, NULL, &is_new) == s1 && is_new == 0);
    mmt_session_t *s2 = get_session(p, &k2, NULL, &is_new);
    CHECK("the shared IPv6 address is counted twice",
          s2 != NULL && id6_count(p, &A) == 2 && id6_count(p, &B) == 1
          && ctx->ips_count == 3 && ctx->sessions_count == 2);
    if (s2 != NULL) {
        delete_session_from_protocol_context(p, s2->session_key);
        free_session_data(s2->session_key, s2, ctx);
    }
    CHECK("freeing an IPv6 session releases its unshared id only",
          id6_count(p, &A) == 1 && findID6(ctx, &C) == NULL
          && ctx->sessions_count == 1);
    pctx_destroy(p, 6);
    CHECK("closing the IPv6 context frees every session and id", live_ids == 0);
}

/* ---- ROLLBACK: get_session failure paths -------------------------------- */

static void test_rollback(int ip_type) {
    printf("get_session rollback (IPv%d)\n", ip_type);
    protocol_instance_t *p = pctx_new(ip_type);
    if (!p || !p->args || !p->sessions_map) {
        CHECK("protocol context set up", 0);
        return;
    }
    internal_ip_proto_context_t *ctx = ctx_of(p);
    uint32_t a4 = 0x0a000001, b4 = 0x0a000002, c4 = 0x0a000003;
    struct in6_addr a6 = addr6(1), b6 = addr6(2), c6 = addr6(3);
    mmt_session_key_t k  = ip_type == 4 ? key4(&a4, &b4, 1, 2) : key6(&a6, &b6, 1, 2);
    mmt_session_key_t kc = ip_type == 4 ? key4(&a4, &c4, 3, 4) : key6(&a6, &c6, 3, 4);
#define COUNT(x4, x6) (ip_type == 4 ? id4_count(p, (x4)) : id6_count(p, &(x6)))
#define FOUND(x4, x6) (ip_type == 4 ? (void *) _findID4(ctx, &(x4)) \
                                    : (void *) findID6(ctx, &(x6)))
    long base = live_ids;
    int is_new = 0;

    fail_insert_key = 1;
    CHECK("a failed id-map insert returns NULL",
          get_session(p, &k, NULL, &is_new) == NULL);
    fail_insert_key = 0;
    CHECK("... and interns nothing",
          ctx->ips_count == 0 && FOUND(a4, a6) == NULL && live_ids == base);

    fail_malloc_after = 0;
    CHECK("a failed session allocation returns NULL",
          get_session(p, &k, NULL, &is_new) == NULL);
    CHECK("... before interning any address",
          ctx->ips_count == 0 && FOUND(a4, a6) == NULL && live_ids == base);

    fail_mmt_malloc_after = 0;
    CHECK("a failed lower-id allocation returns NULL",
          get_session(p, &k, NULL, &is_new) == NULL);
    CHECK("... and interns nothing", ctx->ips_count == 0 && live_ids == base);

    fail_mmt_malloc_after = 1;
    CHECK("a failed higher-id allocation returns NULL",
          get_session(p, &k, NULL, &is_new) == NULL);
    CHECK("... and removes the new lower id from the map (issue #201)",
          ctx->ips_count == 0 && FOUND(a4, a6) == NULL && live_ids == base);

    fail_insert_session = 1;
    CHECK("a failed session-map insert returns NULL",
          get_session(p, &k, NULL, &is_new) == NULL);
    fail_insert_session = 0;
    CHECK("... and removes both new ids (issue #201)",
          ctx->ips_count == 0 && FOUND(a4, a6) == NULL && FOUND(b4, b6) == NULL
          && live_ids == base && ctx->sessions_count == 0);

    /* With the lower address already interned by a live session, a failure
     * must leave that id and its count alone. */
    mmt_session_t *s = get_session(p, &k, NULL, &is_new);
    CHECK("the session is created once nothing fails", s != NULL && is_new == 1);
    void *ida = FOUND(a4, a6);
    fail_mmt_malloc_after = 0;   /* the lower id exists: higher allocates */
    CHECK("a failed higher-id allocation with a shared lower id returns NULL",
          get_session(p, &kc, NULL, &is_new) == NULL);
    CHECK("... and keeps the shared lower id and its count",
          FOUND(a4, a6) == ida && COUNT(a4, a6) == 1 && ctx->ips_count == 2);
    fail_insert_session = 1;
    CHECK("a failed session-map insert with a shared lower id returns NULL",
          get_session(p, &kc, NULL, &is_new) == NULL);
    fail_insert_session = 0;
    /* The shared id's count is not checked here: get_session() raises both
     * counts before the insert and does not lower a pre-existing id's count
     * on this failure (issue #707). */
    CHECK("... and frees only the new higher id",
          FOUND(a4, a6) == ida && FOUND(c4, c6) == NULL
          && ctx->ips_count == 2 && ctx->sessions_count == 1);

    pctx_destroy(p, ip_type);
    CHECK("teardown releases every id", live_ids == 0);

    protocol_instance_t none;
    memset(&none, 0, sizeof(none));
    CHECK("get_session refuses a context whose setup failed (issue #212)",
          get_session(&none, &k, NULL, &is_new) == NULL);
#undef COUNT
#undef FOUND
}

static void test_setup_failure(void) {
    printf("context setup failure\n");
    fail_mmt_malloc_after = 0;
    CHECK("IPv4 setup returns NULL when its allocation fails",
          setup_ipv4_internal_context() == NULL);
    fail_mmt_malloc_after = 0;
    CHECK("IPv6 setup returns NULL when its allocation fails",
          setup_ipv6_internal_context() == NULL);
    /* mmt_malloc() is one malloc(); the next one is the id map's table. */
    fail_malloc_after = 1;
    CHECK("IPv4 setup returns NULL when its map cannot be created",
          setup_ipv4_internal_context() == NULL);
    fail_malloc_after = 1;
    CHECK("IPv6 setup returns NULL when its map cannot be created",
          setup_ipv6_internal_context() == NULL);
    CHECK("a failed setup frees what it allocated", live_ids == 0);
}

/* ---- STATS: the per-protocol counters ----------------------------------- */

static void test_stats_extraction(void) {
    printf("per-protocol counters\n");
    mmt_handler_t *h = calloc(1, sizeof(*h));
    CHECK("a handler is allocated", h != NULL);
    if (h == NULL) return;
    proto_hierarchy_t path;
    memset(&path, 0, sizeof(path));
    path.len = 2;
    path.proto_path[0] = 99;
    path.proto_path[1] = 178;
    ipacket_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.mmt_handler = h;
    pkt.proto_hierarchy = &path;

    uint64_t v = 12345;
    attribute_t attr;
    memset(&attr, 0, sizeof(attr));
    attr.data = &v;

    CHECK("no statistics instance counts zero",
          proto_sessions_count_extraction(&pkt, 1, &attr) == 1 && v == 0);

    proto_statistics_internal_t s1, s2;
    memset(&s1, 0, sizeof(s1));
    memset(&s2, 0, sizeof(s2));
    s1.next = &s2;
    s1.ip_frag_packets_count = 3;  s2.ip_frag_packets_count = 4;
    s1.ip_frag_data_volume = 300;  s2.ip_frag_data_volume = 400;
    s1.ip_df_packets_count = 1;    s2.ip_df_packets_count = 2;
    s1.ip_df_data_volume = 1000;   s2.ip_df_data_volume = 2000;
    s1.sessions_count = 10;        s2.sessions_count = 5;
    s1.timedout_sessions_count = 4; s2.timedout_sessions_count = 1;
    h->configured_protocols[178].proto_stats = &s1;

    proto_ip_frag_packet_count_extraction(&pkt, 1, &attr);
    CHECK("fragment packets sum the stats list", v == 7);
    proto_ip_frag_data_volume_extraction(&pkt, 1, &attr);
    CHECK("fragment volume sums the stats list", v == 700);
    proto_ip_df_packet_count_extraction(&pkt, 1, &attr);
    CHECK("defragmented packets sum the stats list", v == 3);
    proto_ip_df_data_volume_extraction(&pkt, 1, &attr);
    CHECK("defragmented volume sums the stats list", v == 3000);
    proto_sessions_count_extraction(&pkt, 1, &attr);
    CHECK("sessions sum the stats list", v == 15);
    proto_active_sessions_count_extraction(&pkt, 1, &attr);
    CHECK("active sessions are sessions minus timed-out ones", v == 10);
    proto_timedout_sessions_count_extraction(&pkt, 1, &attr);
    CHECK("timed-out sessions sum the stats list", v == 5);
    proto_sessions_count_extraction(&pkt, 0, &attr);
    CHECK("the counters read the protocol at the given path index", v == 0);
    free(h);
}

int main(void) {
    printf("IP session store (issue #554)\n");
    test_ipv4_address_store();
    test_ipv4_sessions();
    test_ipv6_sessions();
    test_rollback(4);
    test_rollback(6);
    test_setup_failure();
    test_stats_extraction();

    if (failures == 0) {
        printf("ALL %d IP session store checks passed\n", checks);
        return 0;
    }
    printf("%d/%d IP session store checks FAILED\n", failures, checks);
    return 1;
}
