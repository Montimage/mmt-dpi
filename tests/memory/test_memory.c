/*
 * test_memory.c — comprehensive test suite for memory allocator (src/mmt_core/src/memory.c).
 *
 * Tests cover:
 *   - mmt_malloc basic allocation and free
 *   - mmt_malloc zero size
 *   - mmt_malloc large allocation
 *   - mmt_realloc NULL pointer (should behave like malloc)
 *   - mmt_realloc zero size on NULL (should return NULL)
 *   - mmt_realloc same/larger size (contents preserved, block may move)
 *   - mmt_realloc smaller size (contents preserved, block may move)
 *   - mmt_realloc on NULL with zero size
 *   - mmt_free NULL (should be no-op)
 *   - mmt_arena_create / mmt_arena_destroy lifecycle
 *   - mmt_arena_alloc basic allocation
 *   - mmt_arena_alloc aligned allocations
 *   - mmt_arena_alloc across block boundaries
 *   - mmt_arena_reset (reuses head block)
 *   - mmt_arena_destroy NULL (no-op)
 *   - mmt_arena_alloc NULL arena (returns NULL)
 *   - mmt_arena_alloc zero size (should allocate 1 byte)
 *   - Memory integrity (written bytes are preserved)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "memory.h"

/* Forward-declare functions not in public header */
extern void *mmt_malloc(size_t size);
extern void *mmt_realloc(void *x, size_t size);
extern void mmt_free(void *x);

/* Forward-declare arena types (not in public header) */
typedef struct mmt_arena_s mmt_arena_t;

extern mmt_arena_t *mmt_arena_create(size_t block_size);
extern void *mmt_arena_alloc(mmt_arena_t *a, size_t size);
extern void mmt_arena_reset(mmt_arena_t *a);
extern void mmt_arena_destroy(mmt_arena_t *a);

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); g_failures++; } } while (0)

/* ---- Test: mmt_malloc basic allocation ---- */
static void test_malloc_basic(void) {
    fprintf(stderr, "  test: mmt_malloc basic allocation\n");
    void *p = mmt_malloc(100);
    CHECK(p != NULL, "mmt_malloc(100) should not return NULL");
    if (p) {
        /* Write and read back to verify integrity */
        uint8_t *bytes = (uint8_t*)p;
        for (int i = 0; i < 100; i++) bytes[i] = (uint8_t)(i & 0xFF);
        for (int i = 0; i < 100; i++) CHECK(bytes[i] == (uint8_t)(i & 0xFF), "memory integrity write/read");
        mmt_free(p);
    }
}

/* ---- Test: mmt_malloc zero size ---- */
static void test_malloc_zero(void) {
    fprintf(stderr, "  test: mmt_malloc zero size\n");
    /* mmt_malloc(0) is normalized to a 1-byte request (malloc(0) may return
       NULL legitimately); no size prefix since issue #255. */
    void *p = mmt_malloc(0);
    CHECK(p != NULL, "mmt_malloc(0) should still return a usable pointer");
    if (p) mmt_free(p);
}

/* ---- Test: mmt_malloc large allocation ---- */
static void test_malloc_large(void) {
    fprintf(stderr, "  test: mmt_malloc large allocation (1MB)\n");
    void *p = mmt_malloc(1024 * 1024);
    CHECK(p != NULL, "mmt_malloc(1MB) should not return NULL");
    if (p) {
        uint8_t *bytes = (uint8_t*)p;
        bytes[0] = 0xAA;
        bytes[1024*1024 - 1] = 0xBB;
        CHECK(bytes[0] == 0xAA, "large alloc: first byte preserved");
        CHECK(bytes[1024*1024 - 1] == 0xBB, "large alloc: last byte preserved");
        mmt_free(p);
    }
}

/* ---- Test: mmt_realloc NULL pointer (like malloc) ---- */
static void test_realloc_null(void) {
    fprintf(stderr, "  test: mmt_realloc(NULL, size) behaves like malloc\n");
    void *p = mmt_realloc(NULL, 200);
    CHECK(p != NULL, "mmt_realloc(NULL, 200) should not return NULL");
    if (p) {
        uint8_t *bytes = (uint8_t*)p;
        bytes[0] = 0x42;
        CHECK(bytes[0] == 0x42, "realloc-allocated memory is writable");
        mmt_free(p);
    }
}

/* ---- Test: mmt_realloc NULL with zero size ---- */
static void test_realloc_null_zero(void) {
    fprintf(stderr, "  test: mmt_realloc(NULL, 0) returns NULL\n");
    void *p = mmt_realloc(NULL, 0);
    CHECK(p == NULL, "mmt_realloc(NULL, 0) should return NULL");
}

/* ---- Test: mmt_realloc same size ---- */
static void test_realloc_same_size(void) {
    fprintf(stderr, "  test: mmt_realloc same size\n");
    void *p1 = mmt_malloc(100);
    CHECK(p1 != NULL, "initial malloc");
    if (p1) {
        ((uint8_t*)p1)[0] = 0x5A;
        ((uint8_t*)p1)[99] = 0xA5;
        /* Issue #255: no stored size means mmt_realloc defers to realloc(),
           which MAY return a moved block — the contract only promises the
           contents survive. */
        void *p2 = mmt_realloc(p1, 100);
        CHECK(p2 != NULL, "realloc same size should not return NULL");
        if (p2) {
            CHECK(((uint8_t*)p2)[0] == 0x5A, "realloc: first byte preserved");
            CHECK(((uint8_t*)p2)[99] == 0xA5, "realloc: last byte preserved");
            mmt_free(p2);
        }
    }
}

/* ---- Test: mmt_realloc larger size (reallocation) ---- */
static void test_realloc_larger(void) {
    fprintf(stderr, "  test: mmt_realloc larger size\n");
    void *p1 = mmt_malloc(100);
    CHECK(p1 != NULL, "initial malloc");
    if (p1) {
        uint8_t *bytes = (uint8_t*)p1;
        bytes[0] = 0xDE;
        bytes[99] = 0xAD;
        void *p2 = mmt_realloc(p1, 200);
        CHECK(p2 != NULL, "realloc larger should not return NULL");
        if (p2) {
            /* Old data should be preserved */
            CHECK(((uint8_t*)p2)[0] == 0xDE, "realloc: old first byte preserved");
            CHECK(((uint8_t*)p2)[99] == 0xAD, "realloc: old last byte preserved");
            /* New space should be usable */
            ((uint8_t*)p2)[150] = 0xCA;
            CHECK(((uint8_t*)p2)[150] == 0xCA, "realloc: new space is writable");
            mmt_free(p2);
        }
    }
}

/* ---- Test: mmt_realloc smaller size ---- */
static void test_realloc_smaller(void) {
    fprintf(stderr, "  test: mmt_realloc smaller size\n");
    void *p1 = mmt_malloc(200);
    CHECK(p1 != NULL, "initial malloc");
    if (p1) {
        ((uint8_t*)p1)[0] = 0xDE;
        ((uint8_t*)p1)[49] = 0xED;
        /* Issue #255: shrinking used to short-circuit to the same pointer via
           the stored size; now realloc() decides and may move the block. */
        void *p2 = mmt_realloc(p1, 50);
        CHECK(p2 != NULL, "realloc smaller should not return NULL");
        if (p2) {
            CHECK(((uint8_t*)p2)[0] == 0xDE, "realloc: first byte preserved on shrink");
            CHECK(((uint8_t*)p2)[49] == 0xED, "realloc: last in-range byte preserved on shrink");
            mmt_free(p2);
        }
    }
}

/* ---- Test: mmt_realloc zero size on existing pointer ---- */
static void test_realloc_zero_existing(void) {
    fprintf(stderr, "  test: mmt_realloc(size, 0) frees and returns NULL\n");
    void *p1 = mmt_malloc(100);
    CHECK(p1 != NULL, "initial malloc");
    if (p1) {
        void *p2 = mmt_realloc(p1, 0);
        CHECK(p2 == NULL, "realloc(existing, 0) should return NULL");
    }
}

/* ---- Test: mmt_free NULL ---- */
static void test_free_null(void) {
    fprintf(stderr, "  test: mmt_free(NULL) is no-op\n");
    mmt_free(NULL); /* Should not crash */
}

/* ---- Test: mmt_arena_create / destroy lifecycle ---- */
static void test_arena_lifecycle(void) {
    fprintf(stderr, "  test: arena create/destroy lifecycle\n");
    mmt_arena_t *arena = mmt_arena_create(0); /* default block size */
    CHECK(arena != NULL, "mmt_arena_create should not return NULL");
    if (arena) {
        mmt_arena_destroy(arena);
    }
}

/* ---- Test: mmt_arena_destroy NULL ---- */
static void test_arena_destroy_null(void) {
    fprintf(stderr, "  test: mmt_arena_destroy(NULL) is no-op\n");
    mmt_arena_destroy(NULL); /* Should not crash */
}

/* ---- Test: mmt_arena_alloc NULL arena ---- */
static void test_arena_alloc_null(void) {
    fprintf(stderr, "  test: mmt_arena_alloc(NULL, size) returns NULL\n");
    void *p = mmt_arena_alloc(NULL, 100);
    CHECK(p == NULL, "mmt_arena_alloc(NULL, 100) should return NULL");
}

/* ---- Test: mmt_arena_alloc basic ---- */
static void test_arena_alloc_basic(void) {
    fprintf(stderr, "  test: mmt_arena_alloc basic\n");
    mmt_arena_t *arena = mmt_arena_create(0);
    CHECK(arena != NULL, "arena create");
    if (arena) {
        void *p = mmt_arena_alloc(arena, 64);
        CHECK(p != NULL, "mmt_arena_alloc should not return NULL");
        if (p) {
            /* Verify alignment (16-byte) */
            CHECK(((uintptr_t)p % 16) == 0, "arena alloc should be 16-byte aligned");
            /* Verify we can write */
            uint8_t *bytes = (uint8_t*)p;
            for (int i = 0; i < 64; i++) bytes[i] = (uint8_t)i;
            for (int i = 0; i < 64; i++) CHECK(bytes[i] == (uint8_t)i, "arena alloc: write/read integrity");
        }
        mmt_arena_destroy(arena);
    }
}

/* ---- Test: mmt_arena_alloc zero size (should allocate 1 byte) ---- */
static void test_arena_alloc_zero(void) {
    fprintf(stderr, "  test: mmt_arena_alloc(arena, 0) allocates 1 byte\n");
    mmt_arena_t *arena = mmt_arena_create(0);
    CHECK(arena != NULL, "arena create");
    if (arena) {
        void *p = mmt_arena_alloc(arena, 0);
        CHECK(p != NULL, "mmt_arena_alloc(arena, 0) should not return NULL");
        mmt_arena_destroy(arena);
    }
}

/* ---- Test: mmt_arena_alloc across block boundary ---- */
static void test_arena_cross_block(void) {
    fprintf(stderr, "  test: mmt_arena_alloc across block boundary\n");
    /* Use a tiny block size to force multiple blocks */
    mmt_arena_t *arena = mmt_arena_create(32); /* 32-byte blocks */
    CHECK(arena != NULL, "arena create with small block size");
    if (arena) {
        /* Allocate 32 bytes (fills first block) */
        void *p1 = mmt_arena_alloc(arena, 32);
        CHECK(p1 != NULL, "first alloc should succeed");
        /* Allocate another 32 bytes (should trigger new block) */
        void *p2 = mmt_arena_alloc(arena, 32);
        CHECK(p2 != NULL, "second alloc across boundary should succeed");
        CHECK(p2 != p1, "allocations from different blocks should be at different addresses");

        /* Both should be writable */
        ((uint8_t*)p1)[0] = 0x11;
        ((uint8_t*)p2)[0] = 0x22;
        CHECK(((uint8_t*)p1)[0] == 0x11, "first block data preserved");
        CHECK(((uint8_t*)p2)[0] == 0x22, "second block data preserved");

        mmt_arena_destroy(arena);
    }
}

/* ---- Test: mmt_arena_reset ---- */
static void test_arena_reset(void) {
    fprintf(stderr, "  test: mmt_arena_reset\n");
    mmt_arena_t *arena = mmt_arena_create(64);
    CHECK(arena != NULL, "arena create");
    if (arena) {
        void *p1 = mmt_arena_alloc(arena, 32);
        CHECK(p1 != NULL, "first alloc");
        /* Allocate more to potentially create a second block */
        void *p2 = mmt_arena_alloc(arena, 64); /* might need new block */
        (void)p2;

        mmt_arena_reset(arena);

        /* After reset, should be able to alloc again from the beginning */
        void *p3 = mmt_arena_alloc(arena, 32);
        CHECK(p3 != NULL, "alloc after reset should succeed");

        mmt_arena_destroy(arena);
    }
}

/* ---- Test: mmt_arena_reset NULL ---- */
static void test_arena_reset_null(void) {
    fprintf(stderr, "  test: mmt_arena_reset(NULL) is no-op\n");
    mmt_arena_reset(NULL); /* Should not crash */
}

/* ---- Test: mmt_arena_alloc oversized request gets dedicated block ---- */
static void test_arena_oversized(void) {
    fprintf(stderr, "  test: mmt_arena_alloc oversized request\n");
    mmt_arena_t *arena = mmt_arena_create(16); /* tiny blocks */
    CHECK(arena != NULL, "arena create");
    if (arena) {
        /* Request larger than block size */
        void *p = mmt_arena_alloc(arena, 1024);
        CHECK(p != NULL, "oversized alloc should succeed");
        if (p) {
            /* Should be aligned */
            CHECK(((uintptr_t)p % 16) == 0, "oversized alloc should be 16-byte aligned");
            /* Should be writable for the full size */
            uint8_t *bytes = (uint8_t*)p;
            bytes[0] = 0xAA;
            bytes[1023] = 0xBB;
            CHECK(bytes[0] == 0xAA, "oversized: first byte preserved");
            CHECK(bytes[1023] == 0xBB, "oversized: last byte preserved");
        }
        mmt_arena_destroy(arena);
    }
}

/* ---- Test: multiple arena allocs are sequentially placed ---- */
static void test_arena_sequential(void) {
    fprintf(stderr, "  test: mmt_arena_alloc sequential placement\n");
    mmt_arena_t *arena = mmt_arena_create(256);
    CHECK(arena != NULL, "arena create");
    if (arena) {
        void *p1 = mmt_arena_alloc(arena, 16);
        void *p2 = mmt_arena_alloc(arena, 16);
        void *p3 = mmt_arena_alloc(arena, 16);
        CHECK(p1 != NULL && p2 != NULL && p3 != NULL, "all allocs should succeed");
        if (p1 && p2 && p3) {
            /* They should be at different addresses (bump pointer) */
            CHECK(p1 != p2, "sequential allocs should have different addresses");
            CHECK(p2 != p3, "sequential allocs should have different addresses");
        }
        mmt_arena_destroy(arena);
    }
}

/* ---- Test: custom block size ---- */
static void test_arena_custom_block_size(void) {
    fprintf(stderr, "  test: mmt_arena_create with custom block size\n");
    mmt_arena_t *arena = mmt_arena_create(1024);
    CHECK(arena != NULL, "arena create with custom size");
    if (arena) {
        void *p = mmt_arena_alloc(arena, 512);
        CHECK(p != NULL, "alloc with custom block size should work");
        mmt_arena_destroy(arena);
    }
}

/* ---- F-BUG-009 (issue #199): size arithmetic must not wrap ---- */

static void test_malloc_size_wrap(void) {
    fprintf(stderr, "  test: mmt_malloc rejects oversized requests\n");
    /* Issue #255: no size prefix anymore, so there is no header addition to
       wrap — but near-SIZE_MAX requests must still fail (libc returns NULL)
       rather than handing back a tiny block (the old F-BUG-009 hazard). */
    CHECK(mmt_malloc(SIZE_MAX) == NULL, "mmt_malloc(SIZE_MAX) must return NULL");
    CHECK(mmt_malloc(SIZE_MAX - 4) == NULL, "mmt_malloc(SIZE_MAX-4) must return NULL");
    /* Note: a just-below-the-limit size legitimately reaches real malloc(); under
       ASan that aborts (allocation-size-too-big), so it is not probed here. */
}

static void test_realloc_size_wrap(void) {
    fprintf(stderr, "  test: mmt_realloc rejects oversized requests\n");
    void *p = mmt_malloc(64);
    CHECK(p != NULL, "initial malloc for realloc-wrap test");
    if (p) {
        ((uint8_t*)p)[0] = 0x5A;
        CHECK(mmt_realloc(p, SIZE_MAX) == NULL, "mmt_realloc(p, SIZE_MAX) must return NULL");
        /* Failed realloc leaves the original block untouched. */
        CHECK(((uint8_t*)p)[0] == 0x5A, "original block intact after rejected realloc");
        mmt_free(p);
    }
    CHECK(mmt_realloc(NULL, SIZE_MAX) == NULL, "mmt_realloc(NULL, SIZE_MAX) must return NULL");
}

static void test_arena_alloc_size_wrap(void) {
    fprintf(stderr, "  test: mmt_arena_alloc rejects wrapped sizes\n");
    mmt_arena_t *arena = mmt_arena_create(0);
    CHECK(arena != NULL, "arena create");
    if (arena) {
        /* size + ALIGN-1 wraps to ~0 -> must be rejected, not silently succeed */
        CHECK(mmt_arena_alloc(arena, SIZE_MAX) == NULL, "arena_alloc(SIZE_MAX) must return NULL");
        CHECK(mmt_arena_alloc(arena, SIZE_MAX - 8) == NULL, "arena_alloc(SIZE_MAX-8) must return NULL");
        /* Survives ALIGN_UP but wraps header+capacity -> must be rejected too */
        CHECK(mmt_arena_alloc(arena, SIZE_MAX - 32) == NULL, "arena_alloc(SIZE_MAX-32) must return NULL");
        /* The arena stays usable after rejected requests */
        void *p = mmt_arena_alloc(arena, 64);
        CHECK(p != NULL, "arena still services normal requests after rejected wraps");
        mmt_arena_destroy(arena);
    }
}

static void test_arena_create_size_wrap(void) {
    fprintf(stderr, "  test: mmt_arena_create rejects wrapped block size\n");
    CHECK(mmt_arena_create(SIZE_MAX) == NULL, "arena_create(SIZE_MAX) must return NULL");
    CHECK(mmt_arena_create(SIZE_MAX - 8) == NULL, "arena_create(SIZE_MAX-8) must return NULL");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    fprintf(stderr, "Memory allocator test suite\n");

    test_malloc_basic();
    test_malloc_zero();
    test_malloc_large();
    test_realloc_null();
    test_realloc_null_zero();
    test_realloc_same_size();
    test_realloc_larger();
    test_realloc_smaller();
    test_realloc_zero_existing();
    test_free_null();
    test_arena_lifecycle();
    test_arena_destroy_null();
    test_arena_alloc_null();
    test_arena_alloc_basic();
    test_arena_alloc_zero();
    test_arena_cross_block();
    test_arena_reset();
    test_arena_reset_null();
    test_arena_oversized();
    test_arena_sequential();
    test_arena_custom_block_size();
    test_malloc_size_wrap();
    test_realloc_size_wrap();
    test_arena_alloc_size_wrap();
    test_arena_create_size_wrap();

    if (g_failures == 0) {
        fprintf(stderr, "ALL CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
