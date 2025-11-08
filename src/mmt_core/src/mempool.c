#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include "../public_include/mempool.h"

struct mempool_struct {
    void *memory;
    size_t block_size;
    size_t num_blocks;
    void **free_list;
    size_t free_count;
    pthread_mutex_t lock;
    size_t alloc_count;
    size_t free_count_stat;
};

mempool_t* mempool_create(size_t block_size, size_t num_blocks) {
    mempool_t *pool = calloc(1, sizeof(mempool_t));
    if (!pool) return NULL;

    pool->block_size = block_size;
    pool->num_blocks = num_blocks;
    pool->memory = calloc(num_blocks, block_size);
    if (!pool->memory) {
        free(pool);
        return NULL;
    }

    pool->free_list = malloc(num_blocks * sizeof(void*));
    if (!pool->free_list) {
        free(pool->memory);
        free(pool);
        return NULL;
    }

    pool->free_count = num_blocks;

    // Initialize free list
    for (size_t i = 0; i < num_blocks; i++) {
        pool->free_list[i] = (uint8_t*)pool->memory + (i * block_size);
    }

    pthread_mutex_init(&pool->lock, NULL);
    pool->alloc_count = 0;
    pool->free_count_stat = 0;

    return pool;
}

void* mempool_alloc(mempool_t *pool) {
    if (!pool) return NULL;

    pthread_mutex_lock(&pool->lock);

    if (pool->free_count == 0) {
        pthread_mutex_unlock(&pool->lock);
        return NULL;  // Pool exhausted
    }

    void *block = pool->free_list[--pool->free_count];
    pool->alloc_count++;

    pthread_mutex_unlock(&pool->lock);

    return block;
}

void mempool_free(mempool_t *pool, void *block) {
    if (!pool || !block) return;

    pthread_mutex_lock(&pool->lock);

    // Optional: verify block belongs to this pool
    // For performance, this check can be disabled in release builds

    pool->free_list[pool->free_count++] = block;
    pool->free_count_stat++;

    pthread_mutex_unlock(&pool->lock);
}

void mempool_destroy(mempool_t *pool) {
    if (!pool) return;

    pthread_mutex_destroy(&pool->lock);
    free(pool->free_list);
    free(pool->memory);
    free(pool);
}

void mempool_get_stats(mempool_t *pool, size_t *total, size_t *used, size_t *free_blocks) {
    if (!pool) return;

    pthread_mutex_lock(&pool->lock);
    if (total) *total = pool->num_blocks;
    if (used) *used = pool->num_blocks - pool->free_count;
    if (free_blocks) *free_blocks = pool->free_count;
    pthread_mutex_unlock(&pool->lock);
}
