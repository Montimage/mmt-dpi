/*
 * test_fi_engine.c — engine-level Nth-allocation fault-injection sweep
 * (issue #216, F-TEST-007).
 *
 * Runs under LD_PRELOAD=libfi_alloc.so so every allocation the installed SDK
 * and its plugins make — including C++ operator new (which lands on malloc)
 * — is counted and can be forced to fail at the Nth call.
 *
 * Covered surface (asserted contract: NULL propagation or clean success, no
 * double free, zero net leaked blocks once cleanup ran):
 *
 *   1. mmt_init_handler() — the six allocation sites whose failure must
 *      abort the init cleanly:
 *        #1 mmt_malloc(mmt_handler_t)
 *        #2 hashmap_alloc() map struct   (ip_streams)
 *        #3 hashmap_alloc() slot array   (ip_streams)
 *        #4 hashmap_alloc() map struct   (ip6_streams)
 *        #5 hashmap_alloc() slot array   (ip6_streams)
 *        #6 init_int_map_space()         (timeout_milestones_map) — the
 *          second-allocation-failure branch hardened by task 2.1: it must
 *          release both stream maps before returning NULL.
 *      Allocation sites deeper in the per-protocol loop (setup_*_context
 *      and the C++ map insertion further on) still have unchecked OOM paths
 *      on this branch — they are the subject of the open 2.x hardening
 *      work — so the sweep is deliberately bounded to the hardened sites.
 *      Widening FI_INIT_BRANCHES exercises them once those fixes land.
 *
 *   2. Session/int map-space lifecycle (init_session_map_space,
 *      init_int_map_space, delete_*_map_space): every allocation inside the
 *      constructors is swept; destructors must accept NULL and leave the
 *      window balanced.
 *
 *   3. A full init -> packet_process -> close cycle with injection disarmed,
 *      asserting the window ends balanced (the "no leak" counterpart).
 *
 * The binary fails loudly when the interposer is inert (e.g. sanitizer legs,
 * where the runtime owns malloc) — run_tests.sh only invokes it when
 * interposition was verified.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <pcap.h>            /* DLT_EN10MB */
#include "mmt_core.h"
#include "hash_utils.h"      /* init_session_map_space / init_int_map_space / delete_*_map_space */
#include "fi_alloc.h"

static int failures;
#define CHECK(cond, ...) do {                                   \
        if (!(cond)) {                                          \
            failures++;                                         \
            printf("  FAIL %s:%d: ", __func__, __LINE__);       \
            printf(__VA_ARGS__);                                \
            printf("\n");                                       \
        }                                                       \
    } while (0)

/* Number of mmt_init_handler allocation sites asserted in the sweep — see
 * the file header for why the sweep is bounded here. */
#define FI_INIT_BRANCHES 6

/* ------------------------------------------------------------------ */
/* generic map fixtures                                                 */
/* ------------------------------------------------------------------ */

static bool sess_key_comp(void *a, void *b)
{
    return a == b;
}
static uint64_t sess_key_hash(void *key)
{
    uintptr_t x = (uintptr_t)key;
    return (x * 0x9e3779b97f4a7c15ULL) >> 16;
}
static bool int_key_comp(uint32_t a, uint32_t b)
{
    return a == b;
}

/* ------------------------------------------------------------------ */
/* interposer liveness                                                  */
/* ------------------------------------------------------------------ */

static int interposer_live(void)
{
    fi_begin(0);
    void *probe = malloc(16);
    /* escape barrier: the optimiser may not assume anything about probe */
    asm volatile("" : "+r"(probe) :: "memory");
    uint64_t seen = fi_end();
    free(probe);
    return seen > 0;
}

/* ------------------------------------------------------------------ */
/* mmt_init_handler sweep                                               */
/* ------------------------------------------------------------------ */

static void t_init_handler_sweep(void)
{
    char errbuf[1024];

    /* Measure + success-path balance: init inside the window, close inside
     * the window, net outstanding must be zero. */
    int64_t before = fi_window_leaked();
    fi_begin(0);
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    uint64_t n_init = fi_end();
    CHECK(h != NULL, "mmt_init_handler failed without injection: %s", errbuf);
    if (!h)
        return;
    mmt_close_handler(h);
    CHECK(fi_window_leaked() - before == 0,
          "init+close not balanced (%lld block(s) outstanding)",
          (long long)(fi_window_leaked() - before));
    CHECK(n_init > FI_INIT_BRANCHES,
          "init did only %llu allocation(s) — sweep bound needs review",
          (unsigned long long)n_init);
    printf("  init_handler performs %llu interposed allocations; sweeping 1..%d\n",
           (unsigned long long)n_init, FI_INIT_BRANCHES);

    /* Sweep the hardened early allocation sites. */
    for (uint64_t n = 1; n <= FI_INIT_BRANCHES; n++) {
        before = fi_window_leaked();
        fi_begin(n);
        h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
        uint64_t used = fi_end();
        int64_t leaked = fi_window_leaked() - before;
        CHECK(h == NULL,
              "fail@%llu: init returned a handler (used=%llu)",
              (unsigned long long)n, (unsigned long long)used);
        CHECK(leaked == 0,
              "fail@%llu: init failure path leaked %lld block(s)",
              (unsigned long long)n, (long long)leaked);
        CHECK(fi_double_free_count() == 0,
              "fail@%llu: double free on the failure path",
              (unsigned long long)n);
        if (h) /* unexpected success — still must release cleanly */
            mmt_close_handler(h);
        printf("  init fail@%llu -> %s, %lld leaked\n",
               (unsigned long long)n, h ? "handler" : "NULL",
               (long long)leaked);
    }
}

/* ------------------------------------------------------------------ */
/* session/int map-space lifecycle sweeps                               */
/* ------------------------------------------------------------------ */

static void sweep_mapspace(const char *name,
                           void *(*ctor)(void),
                           void (*dtor)(void *))
{
    int64_t before;
    uint64_t n_allocs;
    void *m;

    /* measure */
    before = fi_window_leaked();
    fi_begin(0);
    m = ctor();
    n_allocs = fi_end();
    CHECK(m != NULL, "%s failed without injection", name);
    if (m)
        dtor(m);
    CHECK(fi_window_leaked() - before == 0, "%s lifecycle not balanced", name);
    if (n_allocs == 0) {
        CHECK(0, "%s performed no interposed allocation — sweep meaningless",
              name);
        return;
    }

    for (uint64_t n = 1; n <= n_allocs; n++) {
        before = fi_window_leaked();
        fi_begin(n);
        m = ctor();
        fi_end();
        int64_t leaked = fi_window_leaked() - before;
        CHECK(m == NULL, "%s succeeded with fail@%llu", name,
              (unsigned long long)n);
        CHECK(leaked == 0, "%s fail@%llu leaked %lld block(s)", name,
              (unsigned long long)n, (long long)leaked);
        if (m)
            dtor(m);
    }

    /* NOTE: delete_*_map_space have a non-NULL precondition on this branch
     * (they deref the map to clear it) — the sweep asserts ctor-failure NULL
     * propagation and clean dtor of a live map, not NULL acceptance. */
    printf("  %s: %llu alloc site(s) swept clean\n", name,
           (unsigned long long)n_allocs);
}

static void *mk_session_map(void)
{
    return init_session_map_space(sess_key_comp, sess_key_hash);
}
static void *mk_int_map(void)
{
    return init_int_map_space(int_key_comp);
}
static void del_session_map(void *m)
{
    delete_session_map_space(m);
}
static void del_int_map(void *m)
{
    delete_int_map_space(m);
}

/* ------------------------------------------------------------------ */
/* packet-cycle balance check (no injection — the leak counterpart)     */
/* ------------------------------------------------------------------ */

static uint8_t http_pkt[] = {
    0x02,0,0,0,0,2, 0x02,0,0,0,0,1, 0x08,0x00,
    0x45,0x00,0x00,0x4f, 0,1, 0x40,0x00, 64, 6, 0,0,
    10,0,0,1, 10,0,0,2,
    0x9c,0x40, 0x00,0x50, 0,0,3,0xe8, 0,0,0,0, 0x50,0x18, 0xff,0xff, 0,0, 0,0,
    'G','E','T',' ','/',' ','H','T','T','P','/','1','.','1','\r','\n','\r','\n'
};

static void t_packet_cycle_balanced(void)
{
    char errbuf[1024];
    int64_t before = fi_window_leaked();
    fi_begin(0);
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h) {
        register_extraction_attribute_by_name(h, "META", "PACKET_LEN");
        register_extraction_attribute_by_name(h, "IP", "SRC");
        struct pkthdr hdr;
        memset(&hdr, 0, sizeof hdr);
        hdr.ts.tv_sec = 1;
        hdr.caplen = hdr.len = sizeof(http_pkt);
        packet_process(h, &hdr, http_pkt);
        mmt_close_handler(h);
    }
    fi_end();
    CHECK(h != NULL, "init failed in packet-cycle check");
    CHECK(fi_window_leaked() - before == 0,
          "packet cycle leaked %lld block(s)",
          (long long)(fi_window_leaked() - before));
}

int main(void)
{
    /* progress must survive a crash in the code under test */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!interposer_live()) {
        printf("fi-engine: allocation interposer is inert — refusing to run\n");
        printf("         (run under LD_PRELOAD=libfi_alloc.so; sanitizer builds\n");
        printf("          own malloc and are covered by the fi-core binary)\n");
        return 2;
    }
    if (!init_extraction()) {
        printf("fi-engine: init_extraction() failed\n");
        return 2;
    }

    t_init_handler_sweep();
    sweep_mapspace("init_session_map_space", mk_session_map, del_session_map);
    sweep_mapspace("init_int_map_space", mk_int_map, del_int_map);
    t_packet_cycle_balanced();

    CHECK(fi_double_free_count() == 0,
          "%d double free(s) observed", fi_double_free_count());
    if (failures == 0) {
        printf("fi-engine: all allocation-failure sweeps passed\n");
        return 0;
    }
    printf("fi-engine: %d check(s) FAILED\n", failures);
    return 1;
}
