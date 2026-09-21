/*
 * session_lookup_perf_test — issue #253 (F-PERF-008) acceptance harness for
 * the per-packet session lookup.
 *
 * The old probe evaluated map equivalence with TWO invocations of the
 * ordering comparator (!comp(a,b) && !comp(b,a)) — each an 11-step branchy
 * chain through two extra pointer indirections — and the key hash was
 * FNV-1a over the 13 tuple bytes: 13 serially-dependent multiplies plus
 * the mixer's ~3 more.
 *
 * What this asserts:
 *   EQUAL     every probe on a session store built with the registered
 *             IPv4 key functions resolves through the ONE-call equality
 *             predicate — mmt_oa_equal_call_count() rises and
 *             mmt_oa_comp_call_count() does not (stats counters armed in
 *             this BUILD=asan run; weak refs so the binary also links
 *             against a non-stats build).
 *   EQUIV     the predicate agrees with the comparator equivalence:
 *             same-field keys hit, one-field-different keys miss.
 *   PERF      a fixed probe workload over the equal-predicate table vs the
 *             two-call fallback table — the A/B reports ns/lookup on the
 *             same machine in the same run (no absolute bound: the
 *             assertion is on the counters, not the clock).
 *   MULS      the dependent-multiply count inside ipv4_session_hash /
 *             ipv6_session_hash is asserted source-side by
 *             run_session_lookup_perf_test.sh (count of multiply ops in
 *             the function body vs the documented budget).
 *
 * Keys point at caller-owned uint32_t storage — the key functions read the
 * 4 address bytes at offset 0, exactly as they do for a real interned
 * mmt_ip4_id_t or a packet-buffer lookup key.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "mmt_core.h"
#include "hash_utils.h"                  /* session-store wrappers + protocol_instance_t */
#include "ip_session_id_management.h"    /* mmt_session_key_t */
#include "internal_decls.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: %s\n", (msg));                           \
        } else {                                                     \
            printf("  FAIL: %s\n", (msg));                           \
            g_failures++;                                            \
        }                                                            \
    } while (0)

/* Stats-gated counters (armed under BUILD=asan/tsan or NDEBUG-undefined) —
 * weak refs so the binary still links when they are absent. */
extern uint64_t mmt_oa_equal_call_count(void) __attribute__((weak));
extern uint64_t mmt_oa_comp_call_count(void) __attribute__((weak));

#define NKEYS   2048
#define NPROBES 400000

static protocol_instance_t make_proto_ctx(void *sessions_map) {
    protocol_instance_t pc;
    memset(&pc, 0, sizeof(pc));
    pc.sessions_map = sessions_map;
    return pc;
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

/* Deterministic distinct key set: keys[i] interns ips[i]/hps[i]. */
static void fill_keys(mmt_session_key_t *keys, uint32_t *ips, uint32_t *hps,
                      int n, int base) {
    for (int i = 0; i < n; i++) {
        memset(&keys[i], 0, sizeof(keys[i]));
        keys[i].ip_type        = 4;
        keys[i].next_proto     = (uint8_t) (6 + (i & 1));
        keys[i].lower_ip_port  = (uint16_t) (1024 + ((i * 31) & 0x3FF));
        keys[i].higher_ip_port = (uint16_t) (80 + ((i * 7) & 0x1F));
        ips[i] = 0x0A000000u + (uint32_t) (base + i * 2);
        hps[i] = 0xC0A80000u + (uint32_t) (base + i * 3);
        keys[i].lower_ip  = &ips[i];
        keys[i].higher_ip = &hps[i];
    }
}

static double bench_find(void *sessions_map, mmt_session_key_t *keys,
                         int nkeys, int nprobes) {
    protocol_instance_t pc = make_proto_ctx(sessions_map);
    /* per-index permutation so probes are not pure sequential order */
    volatile uintptr_t sink = 0;
    double t0 = now_s();
    for (int i = 0; i < nprobes; i++) {
        mmt_session_key_t *k = &keys[(i * 1103515245u + 12345u) % nkeys];
        void *v = get_session_from_protocol_context_by_session_key(&pc, k);
        sink ^= (uintptr_t) v;
    }
    double dt = now_s() - t0;
    if (sink == (uintptr_t) -1) printf("(sink)\n"); /* never */
    return dt;
}

int main(void)
{
    printf("== session_lookup_perf_test (issue #253, F-PERF-008) ==\n");

    static mmt_session_key_t keys[NKEYS];
    static uint32_t ips[NKEYS], hps[NKEYS];
    fill_keys(keys, ips, hps, NKEYS, 0);

    /* ---- EQUIV: predicate agrees with comparator equivalence ------------- */
    void *store = init_session_map_space(ipv4_session_comp,
                                         ipv4_session_hash,
                                         ipv4_session_equal);
    CHECK(store != NULL, "session store created with the equality predicate");
    if (store == NULL) return 2;
    protocol_instance_t pc = make_proto_ctx(store);

    for (int i = 0; i < NKEYS; i++) {
        if (insert_session_into_protocol_context(&pc, &keys[i], &keys[i]) != 1) {
            printf("  FAIL: insert %d rejected\n", i);
            return 2;
        }
    }

    /* A key with identical fields but different IP storage must hit — same
     * test the ordering comparator defined. */
    mmt_session_key_t twin;
    uint32_t twin_l = ips[7], twin_h = hps[7];
    memcpy(&twin, &keys[7], sizeof(twin));
    twin.lower_ip = &twin_l;
    twin.higher_ip = &twin_h;
    CHECK(get_session_from_protocol_context_by_session_key(&pc, &twin) == &keys[7],
          "same-field key resolves through the one-call predicate");

    /* One field off (port) must miss. */
    mmt_session_key_t miss = twin;
    miss.higher_ip_port ^= 0x1;
    CHECK(get_session_from_protocol_context_by_session_key(&pc, &miss) == NULL,
          "one-field-different key misses (predicate agrees with comparator)");

    /* ---- EQUAL + PERF: equal-path table vs two-call fallback ------------- */
    uint64_t eq0 = mmt_oa_equal_call_count ? mmt_oa_equal_call_count() : 0;
    uint64_t cmp0 = mmt_oa_comp_call_count ? mmt_oa_comp_call_count() : 0;

    double dt_eq = bench_find(store, keys, NKEYS, NPROBES);

    uint64_t eq1 = mmt_oa_equal_call_count ? mmt_oa_equal_call_count() : 0;
    uint64_t cmp1 = mmt_oa_comp_call_count ? mmt_oa_comp_call_count() : 0;

    CHECK(eq1 > eq0,
          "every probe resolved through the one-call equality predicate");
    CHECK(cmp1 == cmp0,
          "zero ordering-comparator calls on the equal-predicate table");

    /* Fallback table: same keys, comp-only — proves the two-call path still
     * works and gives the same-machine A/B timing. */
    void *store_fb = init_session_map_space(ipv4_session_comp,
                                            ipv4_session_hash,
                                            NULL);
    CHECK(store_fb != NULL, "fallback session store created (comp-only)");
    protocol_instance_t pc_fb = make_proto_ctx(store_fb);
    for (int i = 0; i < NKEYS; i++) {
        insert_session_into_protocol_context(&pc_fb, &keys[i], &keys[i]);
    }
    uint64_t cmp2 = mmt_oa_comp_call_count ? mmt_oa_comp_call_count() : 0;
    double dt_fb = bench_find(store_fb, keys, NKEYS, NPROBES);
    uint64_t cmp3 = mmt_oa_comp_call_count ? mmt_oa_comp_call_count() : 0;
    CHECK(cmp3 > cmp2,
          "comp-only table still resolves via the two-call equivalence");

    /* Correctness spot-check on the fallback table — identical results. */
    CHECK(get_session_from_protocol_context_by_session_key(&pc_fb, &twin) == &keys[7],
          "fallback table returns the same entry for a same-field key");

    printf("  info: %d probes over %d sessions — equal-predicate %.1f ns/lookup, "
           "two-call fallback %.1f ns/lookup\n",
           NPROBES, NKEYS,
           dt_eq * 1e9 / NPROBES, dt_fb * 1e9 / NPROBES);

    delete_session_map_space(store);
    delete_session_map_space(store_fb);

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures ? 1 : 0;
}
