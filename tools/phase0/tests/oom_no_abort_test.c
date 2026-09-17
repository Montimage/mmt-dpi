/*
 * oom_no_abort_test — remote-DoS hardening regression test for B5 (issue #16).
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 4 (B5).
 *
 * Before the hardening, mmt_malloc()/mmt_realloc()
 * (src/mmt_core/src/memory.c) called abort() when the underlying
 * malloc()/realloc() failed. Because these live in a shared library that
 * processes untrusted packets, a packet that provoked a huge allocation could
 * tear down the entire host process (remote DoS).
 *
 * The fix changes the contract: on allocation failure the allocators now RETURN
 * NULL instead of aborting. This test forces an allocation failure by requesting
 * an impossibly large block and asserts:
 *
 *   1. mmt_malloc(huge)  returns NULL and the process is still alive afterwards.
 *   2. mmt_realloc(NULL, huge) (== malloc) returns NULL, process still alive.
 *   3. mmt_realloc(buf, huge) on an existing block returns NULL, and the
 *      original block is left intact (standard realloc semantics) so it can
 *      still be freed.
 *   4. A normal small mmt_malloc()/mmt_free() round-trip still works.
 *
 * If the allocator still called abort(), the process would die with SIGABRT
 * before reaching the final "PASS" print and the runner would see a non-zero
 * exit status. A clean exit 0 with every assertion passing is the success
 * condition.
 *
 * Build (see run_oom_no_abort_test.sh):
 *   gcc -g -O1 -o oom_no_abort_test oom_no_abort_test.c \
 *       -L<prefix>/dpi/lib -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "mmt_core.h"

/* An allocation request that no real system can satisfy: SIZE_MAX/2 bytes.
 * malloc() is guaranteed to fail and return NULL, exercising the OOM path
 * deterministically (issue #255 removed the sizeof(size_t) block prefix). */
#define IMPOSSIBLE_SIZE ((size_t)-1 / 2)

static int failures = 0;

#define CHECK(cond, msg)                                            \
    do {                                                            \
        if (cond) {                                                 \
            printf("  ok   - %s\n", (msg));                         \
        } else {                                                    \
            printf("  FAIL - %s\n", (msg));                         \
            failures++;                                             \
        }                                                           \
    } while (0)

int main(void)
{
    printf("oom_no_abort_test: forcing allocation failures (B5)\n");

    /* 1. mmt_malloc() on an impossible size must return NULL, not abort(). */
    void *p = mmt_malloc(IMPOSSIBLE_SIZE);
    CHECK(p == NULL, "mmt_malloc(huge) returns NULL instead of aborting");
    /* Reaching this line at all proves the process was not killed. */

    /* 2. mmt_realloc(NULL, huge) behaves like malloc(huge): NULL, no abort. */
    void *q = mmt_realloc(NULL, IMPOSSIBLE_SIZE);
    CHECK(q == NULL, "mmt_realloc(NULL, huge) returns NULL instead of aborting");

    /* 3. mmt_realloc() growing an existing block to an impossible size must
     *    return NULL and leave the original block usable/freeable. */
    void *buf = mmt_malloc(64);
    CHECK(buf != NULL, "mmt_malloc(64) succeeds");
    if (buf != NULL) {
        void *grown = mmt_realloc(buf, IMPOSSIBLE_SIZE);
        CHECK(grown == NULL,
              "mmt_realloc(buf, huge) returns NULL instead of aborting");
        /* Original block still valid -> free it without crashing. */
        mmt_free(buf);
        CHECK(1, "original block freed after failed realloc (no crash)");
    }

    /* 4. The normal path is unchanged: a small alloc/free round-trips fine. */
    void *small = mmt_malloc(128);
    CHECK(small != NULL, "mmt_malloc(128) succeeds on the normal path");
    if (small != NULL) {
        /* touch the memory to be sure it is writable */
        for (int i = 0; i < 128; i++) ((volatile unsigned char *)small)[i] = (unsigned char)i;
        mmt_free(small);
        CHECK(1, "small block freed (no crash)");
    }

    if (failures == 0) {
        printf("oom_no_abort_test: PASS (allocator returns NULL, host survives)\n");
        return 0;
    }
    printf("oom_no_abort_test: FAIL (%d assertion(s) failed)\n", failures);
    return 1;
}
