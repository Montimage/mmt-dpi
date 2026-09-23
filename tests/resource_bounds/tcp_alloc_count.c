/*
 * tcp_alloc_count.c — counting allocator front-end for the "tcp-memory"
 * fixture (issue #380, F-PERF-002).
 *
 * test_tcp_memory.c and memory.c are compiled with
 *   -Dmalloc=tcm_malloc -Dcalloc=tcm_calloc -Drealloc=tcm_realloc -Dfree=tcm_free
 * so every allocation made by proto_tcp.c / tcp_segment.c (and mmt_malloc)
 * lands here. The counters live in THIS translation unit on purpose: glibc
 * declares malloc & co. as leaf functions, so a counter private to the
 * caller's TU could be folded across the call (tests/fault_injection note).
 */
#include <stdint.h>
#include <stdlib.h>

#include "tcp_alloc_count.h"

uint64_t tcm_calls;        /* allocation calls: malloc, calloc, realloc */
int64_t  tcm_outstanding;  /* live blocks handed out and not yet freed */
uint64_t tcm_fail_at;      /* 1-based call index to fail; 0 = never */
uint64_t tcm_failed;       /* calls forced to fail */

static int tcm_should_fail(void) {
	tcm_calls++;
	if (tcm_fail_at != 0 && tcm_calls == tcm_fail_at) {
		tcm_failed++;
		return 1;
	}
	return 0;
}

void *tcm_malloc(size_t size) {
	if (tcm_should_fail()) return NULL;
	void *p = malloc(size);
	if (p != NULL) tcm_outstanding++;
	return p;
}

void *tcm_calloc(size_t nmemb, size_t size) {
	if (tcm_should_fail()) return NULL;
	void *p = calloc(nmemb, size);
	if (p != NULL) tcm_outstanding++;
	return p;
}

void *tcm_realloc(void *ptr, size_t size) {
	if (tcm_should_fail()) return NULL;
	void *p = realloc(ptr, size);
	if (p != NULL && ptr == NULL) tcm_outstanding++;
	return p;
}

void tcm_free(void *ptr) {
	if (ptr != NULL) tcm_outstanding--;
	free(ptr);
}
