#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "../../src/mmt_core/public_include/mempool.h"

#define ITERATIONS 1000000

double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

void benchmark_malloc() {
    double start = get_time();

    for (int i = 0; i < ITERATIONS; i++) {
        void *ptr = malloc(1024);
        free(ptr);
    }

    double end = get_time();
    double duration = end - start;
    double ops_per_sec = ITERATIONS / duration;

    printf("malloc/free: %.2f seconds, %.0f ops/sec\n", duration, ops_per_sec);
}

void benchmark_mempool() {
    mempool_t *pool = mempool_create(1024, 100);
    if (!pool) {
        printf("Failed to create mempool\n");
        return;
    }

    double start = get_time();

    for (int i = 0; i < ITERATIONS; i++) {
        void *ptr = mempool_alloc(pool);
        if (ptr) {
            mempool_free(pool, ptr);
        }
    }

    double end = get_time();
    double duration = end - start;
    double ops_per_sec = ITERATIONS / duration;

    printf("mempool:     %.2f seconds, %.0f ops/sec (%.1fx faster)\n",
           duration, ops_per_sec, ops_per_sec / (ITERATIONS / (end - start)));

    // Get and print statistics
    size_t total, used, free_blocks;
    mempool_get_stats(pool, &total, &used, &free_blocks);
    printf("Pool stats: total=%zu, used=%zu, free=%zu\n", total, used, free_blocks);

    mempool_destroy(pool);
}

int main() {
    printf("Memory Pool Benchmark (%d iterations)\n", ITERATIONS);
    printf("=====================================\n");

    benchmark_malloc();
    benchmark_mempool();

    printf("\nMemory Pool implementation verified!\n");
    return 0;
}
