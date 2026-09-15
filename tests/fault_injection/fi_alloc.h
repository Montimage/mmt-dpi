/*
 * fi_alloc.h — control API for the Nth-allocation fault-injection harness
 * (issue #216, F-TEST-007).
 *
 * Two interchangeable front-ends share this API:
 *   - libfi_alloc.so : LD_PRELOAD interposer for libc malloc/calloc/realloc/
 *     free. Built from fi_alloc.c with -DFI_INTERPOSE. Catches allocations in
 *     the installed SDK and its plugins, including C++ new (which lands on
 *     malloc underneath).
 *   - fiu_*          : plain functions with the same counting semantics, for
 *     source-compiled units. Compile a library source with
 *     -Dmalloc=fiu_malloc -Drealloc=fiu_realloc -Dfree=fiu_free and its
 *     allocator traffic is counted without LD_PRELOAD (works under every
 *     build profile, including sanitizers).
 *
 * Usage pattern in a test:
 *   int64_t before = fi_window_leaked();
 *   fi_begin(n);                       // arm: the n-th allocation fails
 *   void *r = function_under_test();
 *   fi_end();
 *   // assert on r, fi_window_leaked() - before, fi_double_free_count()
 */
#ifndef MMT_FI_ALLOC_H
#define MMT_FI_ALLOC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Arm the counter: the fail_at-th allocation attempted after this call
 * returns NULL (fail_at == 0 never fails). Disarms any previous window and
 * restarts the per-window counters. */
void     fi_begin(uint64_t fail_at);

/* Disarm. Returns the number of allocation calls observed while armed. */
uint64_t fi_end(void);

/* Number of allocations made inside any window that are still outstanding.
 * Take a delta around the code under test: a leak is a positive delta after
 * its cleanup path ran. Frees keep decrementing after fi_end(), so the
 * "disarm, run cleanup, then measure" pattern is supported. */
int64_t  fi_window_leaked(void);

/* Frees observed on pointers that were already freed (tracked double free).
 * Cumulative since process start — read once at the end. */
int      fi_double_free_count(void);

/* Allocation calls that were forced to fail while armed. */
uint64_t fi_failed_allocs(void);

/* Unit-mode allocator front-ends (see header comment). */
void *fiu_malloc(size_t size);
void *fiu_calloc(size_t nmemb, size_t size);
void *fiu_realloc(void *ptr, size_t size);
void  fiu_free(void *ptr);

#ifdef __cplusplus
}
#endif
#endif /* MMT_FI_ALLOC_H */
