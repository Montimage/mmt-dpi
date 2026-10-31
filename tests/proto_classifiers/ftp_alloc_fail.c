/*
 * ftp_alloc_fail.c — counting, fault-injecting allocator front-end for
 * test_ftp_dialogue (issue #563).
 *
 * The FTP units, mmt_utils.c and the test TU are compiled with
 *   -Dmalloc=fda_malloc -Dcalloc=fda_calloc -Drealloc=fda_realloc -Dfree=fda_free
 * so every allocation they make lands here: fda_outstanding detects a leak,
 * and fda_fail_at fails the n-th call so the out-of-memory branches run.
 * The counters live in THIS translation unit, which is compiled without the
 * macros (glibc's leaf attributes could fold counters private to the
 * caller's TU — the tests/resource_bounds/tcp_alloc_count.c note).
 */
#include <stdint.h>
#include <stdlib.h>

uint64_t fda_calls;        /* allocation calls: malloc, calloc, realloc */
int64_t  fda_outstanding;  /* live blocks handed out and not yet freed */
uint64_t fda_fail_at;      /* 1-based call index to fail; 0 = never */
uint64_t fda_failed;       /* calls forced to fail */

static int fda_should_fail(void) {
	fda_calls++;
	if (fda_fail_at != 0 && fda_calls == fda_fail_at) {
		fda_failed++;
		return 1;
	}
	return 0;
}

void *fda_malloc(size_t size) {
	if (fda_should_fail()) return NULL;
	void *p = malloc(size);
	if (p != NULL) fda_outstanding++;
	return p;
}

void *fda_calloc(size_t nmemb, size_t size) {
	if (fda_should_fail()) return NULL;
	void *p = calloc(nmemb, size);
	if (p != NULL) fda_outstanding++;
	return p;
}

void *fda_realloc(void *ptr, size_t size) {
	if (fda_should_fail()) return NULL;
	void *p = realloc(ptr, size);
	if (p != NULL && ptr == NULL) fda_outstanding++;
	return p;
}

void fda_free(void *ptr) {
	if (ptr != NULL) fda_outstanding--;
	free(ptr);
}
