/*
 * test_fi_core.c — unit-level Nth-allocation fault-injection sweep over the
 * source-compiled allocator + hashmap (issue #216, F-TEST-007).
 *
 * memory.c is compiled with -Dmalloc=fiu_malloc -Drealloc=fiu_realloc
 * -Dfree=fiu_free so every allocation the mmt allocator makes is routed
 * through the counting front-end in fi_alloc.c — including the internal
 * calls of mmt_malloc()/mmt_realloc()/mmt_free() and the mmt_arena block
 * allocator. hashmap.c then exercises that allocator through the public
 * mmt_malloc/mmt_free symbols.
 *
 * For every covered site the contract asserted is the one documented in
 * memory.c (post-B5): the Nth allocation may fail, the function must return
 * NULL (or drop the entry for the void-returning hashmap_insert_kv) without
 * crashing, no double free may occur, and once the object's cleanup ran the
 * window's net outstanding allocation count must be zero.
 *
 * Suites are self-contained: no SDK build needed, runs under every
 * EXTRA_CFLAGS profile (default, -fsigned-char, asan, tsan, coverage).
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "mmt_core.h"      /* mmt_malloc / mmt_realloc / mmt_free / mmt_arena_* */
#include "hashmap.h"       /* private header: hashmap_alloc/insert_kv/get/... */
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

/* ------------------------------------------------------------------ */
/* mmt_malloc / mmt_realloc / mmt_free contract                        */
/* ------------------------------------------------------------------ */

static void t_malloc_contract(void)
{
    /* fail@1: mmt_malloc must return NULL, nothing outstanding. */
    int64_t before = fi_window_leaked();
    fi_begin(1);
    void *p = mmt_malloc(64);
    fi_end();
    CHECK(p == NULL, "mmt_malloc did not propagate allocation failure");
    CHECK(fi_window_leaked() - before == 0, "mmt_malloc failure leaked");

    /* success path balances. */
    fi_begin(0);
    p = mmt_malloc(64);
    fi_end();
    CHECK(p != NULL, "mmt_malloc failed without injection");
    memset(p, 0xa5, 64);
    mmt_free(p);
    CHECK(fi_window_leaked() - before == 0, "mmt_malloc+free not balanced");

    /* huge-but-not-wrapping request must fail cleanly (no abort). */
    p = mmt_malloc((size_t)INT64_MAX);
    CHECK(p == NULL, "mmt_malloc(huge) did not return NULL");
    mmt_free(p);
}

static void t_realloc_contract(void)
{
    int64_t before = fi_window_leaked();
    fi_begin(0);
    unsigned char *p = mmt_malloc(32);
    fi_end();
    CHECK(p != NULL, "setup alloc failed");
    memset(p, 0x11, 32);

    /* failing realloc returns NULL and leaves the original block intact. */
    fi_begin(1);
    void *q = mmt_realloc(p, 4096);
    fi_end();
    CHECK(q == NULL, "mmt_realloc did not propagate allocation failure");
    CHECK(p[0] == 0x11 && p[31] == 0x11,
          "mmt_realloc failure destroyed the original block");
    mmt_free(p);
    CHECK(fi_window_leaked() - before == 0, "failed realloc leaked");

    /* growing realloc that succeeds moves/keeps the block consistently. */
    fi_begin(0);
    p = mmt_malloc(32);
    memset(p, 0x22, 32);
    p = mmt_realloc(p, 4096);
    fi_end();
    CHECK(p != NULL, "mmt_realloc failed without injection");
    CHECK(p[0] == 0x22 && p[31] == 0x22, "mmt_realloc lost contents");
    mmt_free(p);
    CHECK(fi_window_leaked() - before == 0, "realloc pair not balanced");

    mmt_free(NULL); /* must be a no-op */
}

/* ------------------------------------------------------------------ */
/* hashmap_alloc / hashmap_init OOM branches (the B5-era cleanups)      */
/* ------------------------------------------------------------------ */

static void t_hashmap_alloc_sweep(void)
{
    /* measure: alloc() takes 2 allocations (map struct + slot array). */
    int64_t before = fi_window_leaked();
    fi_begin(0);
    mmt_hashmap_t *m = hashmap_alloc();
    uint64_t n_allocs = fi_end();
    CHECK(m != NULL, "hashmap_alloc failed without injection");
    hashmap_free(m);
    CHECK(fi_window_leaked() - before == 0, "hashmap alloc/free not balanced");
    CHECK(n_allocs >= 2, "hashmap_alloc unexpectedly did %llu allocs",
          (unsigned long long)n_allocs);

    /* every allocation site: fail it, expect NULL + full cleanup. */
    for (uint64_t n = 1; n <= n_allocs; n++) {
        before = fi_window_leaked();
        fi_begin(n);
        m = hashmap_alloc();
        fi_end();
        CHECK(m == NULL, "hashmap_alloc succeeded with fail@%llu",
              (unsigned long long)n);
        CHECK(fi_window_leaked() - before == 0,
              "hashmap_alloc fail@%llu leaked %lld block(s)",
              (unsigned long long)n, (long long)(fi_window_leaked() - before));
    }
}

static int walk_count;
static void count_entry(mmt_hashmap_t *map, mmt_hent_t *he, void *arg)
{
    (void)map; (void)he; (void)arg;
    walk_count++;
}

static void t_hashmap_insert_sweep(void)
{
    enum { NKEYS = 24 };
    static char vals[NKEYS];

    /* measure per-insert allocation count (1 hent each on this code). */
    int64_t before = fi_window_leaked();
    mmt_hashmap_t *m = hashmap_alloc();
    CHECK(m != NULL, "hashmap_alloc failed in insert sweep");
    fi_begin(0);
    for (int k = 0; k < NKEYS; k++)
        hashmap_insert_kv(m, (mmt_key_t)(uintptr_t)(k + 1), &vals[k]);
    uint64_t per_run = fi_end();
    hashmap_free(m);
    CHECK(fi_window_leaked() - before == 0, "insert/free not balanced");
    if (per_run == 0 || per_run % NKEYS != 0) {
        CHECK(0, "unexpected insert alloc count %llu",
              (unsigned long long)per_run);
        return;
    }
    uint64_t per_insert = per_run / NKEYS;

    /* Sweep: with the n-th allocation forced to fail, the corresponding
     * insert is dropped, the map stays consistent, and cleanup balances. */
    for (uint64_t n = 1; n <= per_run + 1; n++) {
        before = fi_window_leaked();
        m = hashmap_alloc();
        CHECK(m != NULL, "map alloc failed in sweep");
        fi_begin(n);
        for (int k = 0; k < NKEYS; k++)
            hashmap_insert_kv(m, (mmt_key_t)(uintptr_t)(k + 1), &vals[k]);
        fi_end();

        /* one insert is dropped: the one whose allocation was fail@n */
        uint64_t dropped_key = (n - 1) / per_insert + 1; /* key == index + 1 */
        int      dropped     = (n <= per_run) ? 1 : 0;
        walk_count = 0;
        hashmap_walk(m, count_entry, NULL);
        CHECK((uint64_t)walk_count == (uint64_t)NKEYS - (uint64_t)dropped,
              "fail@%llu left %d entries, expected %d",
              (unsigned long long)n, walk_count, NKEYS - dropped);
        if (dropped) {
            void *hit = NULL;
            CHECK(hashmap_get(m, (mmt_key_t)(uintptr_t)dropped_key, &hit) == 0,
                  "dropped key %llu found after fail@%llu",
                  (unsigned long long)dropped_key, (unsigned long long)n);
        }
        hashmap_free(m);
        CHECK(fi_window_leaked() - before == 0,
              "insert sweep fail@%llu leaked", (unsigned long long)n);
    }
}

/* ------------------------------------------------------------------ */
/* mmt_arena block allocator                                            */
/* ------------------------------------------------------------------ */

static void t_arena_sweep(void)
{
    int64_t before = fi_window_leaked();

    /* fail@1: arena_create must return NULL. */
    fi_begin(1);
    mmt_arena_t *a = mmt_arena_create(4096);
    fi_end();
    CHECK(a == NULL, "mmt_arena_create did not propagate failure");
    CHECK(fi_window_leaked() - before == 0, "arena_create failure leaked");

    a = mmt_arena_create(1024);
    CHECK(a != NULL, "mmt_arena_create failed without injection");

    /* fail@1 on the first block grow: mmt_arena_alloc returns NULL. */
    fi_begin(1);
    void *p = mmt_arena_alloc(a, 128);
    fi_end();
    CHECK(p == NULL, "mmt_arena_alloc did not propagate failure");
    mmt_arena_destroy(a);
    CHECK(fi_window_leaked() - before == 0, "arena_alloc failure leaked");

    /* grow two blocks, fail the second grow, then reset+destroy balanced. */
    a = mmt_arena_create(1024);
    CHECK(a != NULL, "arena create failed");
    p = mmt_arena_alloc(a, 512);
    CHECK(p != NULL, "first arena alloc failed");
    fi_begin(1);
    void *q = mmt_arena_alloc(a, 2048); /* forces a new block */
    fi_end();
    CHECK(q == NULL, "arena block-grow did not propagate failure");
    /* the arena must still serve from the surviving first block. */
    void *r = mmt_arena_alloc(a, 64);
    CHECK(r != NULL, "arena unusable after a failed grow");
    mmt_arena_reset(a);
    mmt_arena_destroy(a);
    CHECK(fi_window_leaked() - before == 0, "arena lifecycle leaked");
}

int main(void)
{
    t_malloc_contract();
    t_realloc_contract();
    t_hashmap_alloc_sweep();
    t_hashmap_insert_sweep();
    t_arena_sweep();

    CHECK(fi_window_leaked() == 0,
          "%lld injected-window allocation(s) never freed",
          (long long)fi_window_leaked());
    CHECK(fi_double_free_count() == 0,
          "%d double free(s) observed", fi_double_free_count());

    if (failures == 0) {
        printf("fi-core: all allocation-failure sweeps passed\n");
        return 0;
    }
    printf("fi-core: %d check(s) FAILED\n", failures);
    return 1;
}
