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
 *   GOLDEN    the shipped ipv4_session_hash / ipv6_session_hash return
 *             pinned values for fixed keys — the word-parallel hash the
 *             #253 fix introduced (3 / 5 independent multiplies plus one
 *             finalizer step) — and differ from the FNV-1a byte loop it
 *             replaced (13 / 37 dependent multiplies) on the same keys.
 *             Issue #526 (F-TEST-016) replaced the source-side
 *             multiply-count grep with this executed check: a revert to
 *             FNV-1a or any change to the mixing fails here, and a renamed
 *             function fails to link instead of passing vacuously.
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

/* ---- GOLDEN: pinned outputs of the shipped session-key hashes ---------- */

/* The FNV-1a byte loop the #253 fix replaced (proto_ip.c / proto_ipv6.c
 * before 1e6d3708): next_proto, both ports low byte first, then the
 * address bytes. */
static uint64_t fnv1a_session_hash(const mmt_session_key_t *s, int alen) {
    const unsigned char *lip = (const unsigned char *) s->lower_ip;
    const unsigned char *hip = (const unsigned char *) s->higher_ip;
    uint64_t h = 1469598103934665603ULL;
#define FNV(b) do { h ^= (uint8_t)(b); h *= 1099511628211ULL; } while (0)
    FNV(s->next_proto);
    FNV(s->lower_ip_port & 0xFF);
    FNV((s->lower_ip_port >> 8) & 0xFF);
    FNV(s->higher_ip_port & 0xFF);
    FNV((s->higher_ip_port >> 8) & 0xFF);
    for (int i = 0; i < alen; i++) FNV(lip[i]);
    for (int i = 0; i < alen; i++) FNV(hip[i]);
#undef FNV
    return h;
}

static void check_hash(const char *name, uint64_t (*fn)(void *), int alen,
                       uint8_t next_proto, uint16_t lport, uint16_t hport,
                       const uint8_t *lip, const uint8_t *hip, uint64_t want) {
    mmt_session_key_t k;
    memset(&k, 0, sizeof(k));
    k.ip_type = alen == 4 ? 4 : 6;
    k.next_proto = next_proto;
    k.lower_ip_port = lport;
    k.higher_ip_port = hport;
    k.lower_ip = (void *) lip;
    k.higher_ip = (void *) hip;
    uint64_t got = fn(&k);
    char msg[160];
    snprintf(msg, sizeof(msg), "%s(proto %u, %u/%u) = 0x%016llx (pinned 0x%016llx)",
             name, next_proto, lport, hport,
             (unsigned long long) got, (unsigned long long) want);
    CHECK(got == want, msg);
    snprintf(msg, sizeof(msg), "%s(proto %u, %u/%u) is not the replaced FNV-1a hash",
             name, next_proto, lport, hport);
    CHECK(got != fnv1a_session_hash(&k, alen), msg);
}

static void check_golden_hashes(void) {
    /* The hashes memcpy the addresses into native words, so these values are
     * little-endian results (x86-64, aarch64 — every CI target). */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    static const uint8_t a4[4] = {10, 0, 0, 1}, b4[4] = {192, 168, 0, 1};
    static const uint8_t c4[4] = {172, 16, 0, 9}, d4[4] = {8, 8, 8, 8};
    static const uint8_t a6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    static const uint8_t b6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2};
    static const uint8_t c6[16] = {0xfe,0x80,0,0,0,0,0,0,0x02,0x11,0x22,0xff,0xfe,0x33,0x44,0x55};
    static const uint8_t d6[16] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfb};
    check_hash("ipv4_session_hash", ipv4_session_hash, 4, 6, 1024, 80, a4, b4,
               0x09093b20a5b7907fULL);
    check_hash("ipv4_session_hash", ipv4_session_hash, 4, 17, 53, 40000, c4, d4,
               0xfc5c2db1114bba8cULL);
    check_hash("ipv6_session_hash", ipv6_session_hash, 16, 6, 443, 50000, a6, b6,
               0x85522b09eb0776f4ULL);
    check_hash("ipv6_session_hash", ipv6_session_hash, 16, 17, 5353, 5353, c6, d6,
               0x9038263526cc9e2fULL);
#else
    CHECK(0, "pinned session-hash values are little-endian results; "
             "regenerate them for this host before trusting this gate");
#endif
}

int main(void)
{
    printf("== session_lookup_perf_test (issue #253, F-PERF-008) ==\n");

    /* ---- GOLDEN: shipped hash outputs pinned (issue #526) --------------- */
    check_golden_hashes();

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
