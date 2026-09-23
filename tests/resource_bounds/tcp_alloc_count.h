/*
 * tcp_alloc_count.h — counters of the tcp-memory fixture's allocator
 * front-end (issue #380, F-PERF-002). See tcp_alloc_count.c.
 */
#ifndef MMT_TCP_ALLOC_COUNT_H
#define MMT_TCP_ALLOC_COUNT_H

#include <stddef.h>
#include <stdint.h>

extern uint64_t tcm_calls;
extern int64_t  tcm_outstanding;
extern uint64_t tcm_fail_at;
extern uint64_t tcm_failed;

void *tcm_malloc(size_t size);
void *tcm_calloc(size_t nmemb, size_t size);
void *tcm_realloc(void *ptr, size_t size);
void  tcm_free(void *ptr);

#endif /* MMT_TCP_ALLOC_COUNT_H */
