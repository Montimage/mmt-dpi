#ifndef MMT_MEMPOOL_H
#define MMT_MEMPOOL_H

#include <stddef.h>

typedef struct mempool_struct mempool_t;

/**
 * Create a memory pool
 * @param block_size Size of each block in bytes
 * @param num_blocks Number of blocks to allocate
 * @return Pointer to pool, or NULL on failure
 */
mempool_t *mempool_create(size_t block_size, size_t num_blocks);

/**
 * Allocate a block from the pool
 * @param pool The memory pool
 * @return Pointer to block, or NULL if pool is exhausted
 */
void *mempool_alloc(mempool_t *pool);

/**
 * Free a block back to the pool
 * @param pool The memory pool
 * @param block Block to free
 */
void mempool_free(mempool_t *pool, void *block);

/**
 * Destroy a memory pool
 * @param pool The memory pool
 */
void mempool_destroy(mempool_t *pool);

/**
 * Get pool statistics
 */
void mempool_get_stats(mempool_t *pool, size_t *total, size_t *used, size_t *free_blocks);

#endif /* MMT_MEMPOOL_H */
