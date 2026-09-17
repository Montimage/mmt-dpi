/**
 * TCP segment
 * to store the TCP segment
 */
#include <stdlib.h>
#include <stdint.h>

// #include <sys/types.h>
// #include <sys/stat.h>
// #include <sys/time.h>
// #include <fcntl.h>
// #include <getopt.h>
// #include <signal.h>
// #include <errno.h>
#ifndef TCP_SEGMENT_H
#define TCP_SEGMENT_H
/**
 * Issue #245: sequence numbers are 32-bit wire values kept in 64-bit slots.
 * Ordering comparisons must wrap — a post-2^32 sequence continues the stream
 * rather than sorting before everything. tcp_seq_before(a, b) is the
 * wrap-aware "a sorts before b" relation (half-open window semantics).
 */
static inline int tcp_seq_before(uint64_t a, uint64_t b) {
  return (int32_t)((uint32_t)a - (uint32_t)b) < 0;
}
static inline int tcp_seq_equal(uint64_t a, uint64_t b) {
  return (uint32_t)a == (uint32_t)b;
}

/**
 * Issue #245 (F-PERF-006 / F-BUG-038): bump-block chain backing the pending
 * TCP segment store — replaces the teardown-only per-flow arena so that the
 * consumed prefix is reclaimed while the flow is still alive. A block holds
 * (segment node + payload copy) carves; `live` counts the carved bytes still
 * referenced. Blocks are chained newest-first; the head is the bump target.
 * When a block's live bytes reach zero it is freed — except the head, which
 * is recycled in place (used = 0) to avoid free/malloc churn.
 */
typedef struct mmt_segblk_s {
  struct mmt_segblk_s *next;   /* next (older) block in the chain */
  struct mmt_segblk_s *prev;   /* previous (newer) block — O(1) unlink */
  uint32_t cap;                /* payload bytes in data[] */
  uint32_t used;               /* bump offset into data[] */
  uint32_t live;               /* carved bytes still referenced */
  /* uint8_t data[] follows — MMT_SEGBLK_PAYLOAD or more */
} mmt_segblk_t;

#define MMT_SEGBLK_PAYLOAD  (16u * 1024u)  /* default block payload bytes */
#define MMT_SEGBLK_ALIGN    16u
#define MMT_SEGBLK_ALIGN_UP(n) (((n) + (MMT_SEGBLK_ALIGN - 1u)) & ~(uint32_t)(MMT_SEGBLK_ALIGN - 1u))

/**
 * Carve `size` bytes from the chain headed by *head (allocating a fresh block
 * when needed). On success returns the carved pointer, stores the owning
 * block in *blk_out, and charges the aligned carve size to blk->live.
 * Returns NULL on OOM (the chain is left unchanged).
 */
uint8_t *mmt_segblk_carve(mmt_segblk_t **head, uint32_t size, mmt_segblk_t **blk_out);

/**
 * Release a carve of `carve` bytes previously taken from blk. When the block
 * empties it is recycled in place (chain head) or unlinked and freed.
 */
void mmt_segblk_release(mmt_segblk_t **head, mmt_segblk_t *blk, uint32_t carve);

/** Free every block in the chain (session teardown). */
void mmt_segblk_free_all(mmt_segblk_t *head);

/**
 * Present a TCP segment
 */
typedef struct tcp_seg_struct
{
  uint64_t packet_id;          // id of the packet which contains the segment
  uint64_t seq;                // Sequence number (32-bit wire value)
  uint64_t next_seq;           // Next segment sequence number (32-bit wire value)
  uint64_t ack;                // Acknowledgement number
  uint16_t len;                // Len of segment
  /* Issue #201 (F-BUG-039): ownership tag — 1 when the node AND its data were
   * carved from a per-flow store (arena or mmt_segblk_t block). Store memory
   * is not free()able, so tcp_seg_free() must not free() it (allocator
   * mismatch). */
  uint8_t in_arena;            // 1 = store-backed, 0 = malloc-backed
  uint8_t *data;               // data of segment
  struct tcp_seg_struct *next; // Next segment in link-list
  struct tcp_seg_struct *prev; // Previous segment in link-list
  /* Issue #245: owning bump block + carve size — lets the store reclaim the
   * consumed prefix by releasing dead blocks early (in_arena == 1). */
  mmt_segblk_t *blk;
  uint32_t blk_size;
} tcp_seg_t;

/**
 * Create a new TCP segment
 * @param   seq Sequence number
 * @param   next_seq Next segment sequence number
 * @param   ack Acknowledgement number
 * @param   len len of segment
 * @param   data data of segment
 * @return NULL if cannot allocate memory for a new TCP segment
 *              a pointer points to new TCP segment. The new node has the key = 0, all other attributes are NULL
 */
tcp_seg_t *tcp_seg_new(uint64_t packet_id, uint64_t seq, uint64_t next_seq, uint64_t ack, uint16_t len, uint8_t *data);

/* Forward declaration of the per-flow arena (defined in mmt_core.h). */
struct mmt_arena_s;

/**
 * Issue #20 (P2): create a TCP segment whose node and payload copy are both
 * carved from a per-flow arena instead of two separate malloc()s. The arena is
 * released wholesale on session teardown, so these segments must NOT be passed
 * to tcp_seg_free()/tcp_seg_free_list(). `payload` is copied (len bytes).
 * @return NULL on arena OOM.
 */
tcp_seg_t *tcp_seg_new_in_arena(struct mmt_arena_s *arena, uint64_t packet_id, uint64_t seq, uint64_t next_seq, uint64_t ack, uint16_t len, const uint8_t *payload);

/**
 * Free an TCP segment
 * @param node TCP segment to be free
 */
void tcp_seg_free(tcp_seg_t *seg);

/**
 * Free a segment link-list
 * @param node head of the link-list
 */
void tcp_seg_free_list(tcp_seg_t *head);

/**
 * Insert a new node into a Link-list of tcp segment
 * @param  root current root of Link-list of tcp segment
 * @param  node new node to be inserted
 * @return      new root of the Link-list of tcp segment
 */
tcp_seg_t *tcp_seg_insert(tcp_seg_t *root, tcp_seg_t *seg);

/**
 * Search in the given Link-list of tcp segment a node which has the seq equals with given seq
 * @param  root root of Link-list of tcp segment
 * @param  key  key value to search the node
 * @return      NULL - if there isn't any node in given Link-list of tcp segment which has the given key value
 *                   a pointer points to the node which has given key value
 */
tcp_seg_t *tcp_seg_find(tcp_seg_t *root, uint64_t seq);

/**
 * Show current Link-list of tcp segment structure
 * @param node root of the Link-list of tcp segment
 */
void tcp_seg_show_list(tcp_seg_t *node);

/**
 * Show current TCP segment
 * @param node given node
 */
void tcp_seg_show(tcp_seg_t *node);

/**
 * Get the number of node in the tree
 * @param  node root of the tree
 * @return      number of seg in the Link-list
 */
int tcp_seg_size(tcp_seg_t *node);

int tcp_seg_reassembly(uint8_t *data, tcp_seg_t *root, uint32_t len);

#endif // End of TCP_SEGMENT_H