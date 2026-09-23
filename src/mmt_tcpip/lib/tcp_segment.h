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
/* Issue #380 (F-PERF-002): aligned block header — a block reserves
 * MMT_SEGBLK_HDR + cap bytes of the flow's storage budget. */
#define MMT_SEGBLK_HDR ((uint32_t)MMT_SEGBLK_ALIGN_UP(sizeof(mmt_segblk_t)))

/**
 * Carve `size` bytes from the chain headed by *head (allocating a fresh block
 * when needed). On success returns the carved pointer, stores the owning
 * block in *blk_out, and charges the aligned carve size to blk->live.
 * Returns NULL on OOM (the chain is left unchanged).
 *
 * Issue #380 (F-PERF-002): *reserved is the caller's reserved-storage gauge
 * (MMT_SEGBLK_HDR + cap of every block in the chain, plus whatever else the
 * caller charges to it). A fresh block is only allocated when its
 * MMT_SEGBLK_HDR + cap fits in `room`; its cap is right-sized down to that
 * room (never below the aligned carve) and added to *reserved. Returns NULL
 * without allocating when even the aligned carve does not fit. An empty head
 * block (no live carve) that the carve does not fit is freed first — its
 * storage leaves *reserved and is added to `room` — so it is never stranded
 * behind the new head; that holds even when the new block cannot be had.
 */
uint8_t *mmt_segblk_carve(mmt_segblk_t **head, uint32_t size, mmt_segblk_t **blk_out,
                          uint64_t *reserved, uint64_t room);

/**
 * Release a carve of `carve` bytes previously taken from blk. When the block
 * empties it is recycled in place (chain head, stays reserved) or unlinked
 * and freed (its MMT_SEGBLK_HDR + cap leaves *reserved — issue #380).
 */
void mmt_segblk_release(mmt_segblk_t **head, mmt_segblk_t *blk, uint32_t carve,
                        uint64_t *reserved);

/** Free every block in the chain (session teardown); each freed block's
 * MMT_SEGBLK_HDR + cap leaves *reserved (issue #380). */
void mmt_segblk_free_all(mmt_segblk_t *head, uint64_t *reserved);

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
  /* Issue #382 (F-PERF-003): AVL subtree height in the pending-list index;
   * 0 = not indexed (fits the padding after in_arena). */
  uint8_t idx_height;
  uint8_t *data;               // data of segment
  struct tcp_seg_struct *next; // Next segment in link-list
  struct tcp_seg_struct *prev; // Previous segment in link-list
  /* Issue #245: owning bump block + carve size — lets the store reclaim the
   * consumed prefix by releasing dead blocks early (in_arena == 1). */
  mmt_segblk_t *blk;
  uint32_t blk_size;
  /* Issue #382 (F-PERF-003): AVL children in the pending-list index. */
  struct tcp_seg_struct *idx_left;
  struct tcp_seg_struct *idx_right;
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
 * Issue #380 (F-PERF-002): locate the insert position for `seq` WITHOUT
 * allocating a node — the first segment of the seq-sorted list at `root`
 * whose seq does not sort before `seq` (wrap-aware). The caller treats an
 * equal seq as a duplicate and otherwise links the new node before the
 * returned one. Returns NULL when every segment sorts before `seq` (append
 * at the tail). Each node examined counts once in mmt_tcp_reasm_stat_visit(),
 * the same walk accounting as tcp_seg_insert().
 */
tcp_seg_t *tcp_seg_locate(tcp_seg_t *root, uint64_t seq);

/**
 * Issue #382 (F-PERF-003): balanced (AVL) index over a seq-sorted pending
 * list, so an out-of-order insert costs O(log n) node visits instead of an
 * O(n) list walk. The list stays the source of truth (drain order); the
 * index only answers "where does seq go". It is insert-only: nodes leave
 * it all at once through tcp_seg_idx_reset() (or with the list itself).
 * Callers index lazily — O(1) head/tail links need not touch it, and
 * tcp_seg_idx_sync() indexes those nodes the next time a lookup needs it,
 * at most once per node. The ordering is the wrap-aware tcp_seq_before(),
 * a consistent order only while the pending seqs span less than 2^31 (as
 * for the sorted list it replaces); beyond that the insert position is
 * unspecified, but every node is still indexed exactly once, so the work
 * bound and memory safety hold.
 *
 * AVL height <= 1.45 * log2(n + 2): 64 path slots cover any 32-bit count.
 */
#define TCP_SEG_IDX_MAX_DEPTH 64

typedef struct tcp_seg_idx_path_s {
  tcp_seg_t **link[TCP_SEG_IDX_MAX_DEPTH]; /* child slots from the root down */
  int depth;                               /* link[depth] is the empty slot */
} tcp_seg_idx_path_t;

/**
 * Descend the index at *root for `seq`, recording the path in *path.
 * Returns the first indexed segment whose seq does not sort before `seq`
 * (an equal seq is a duplicate) or NULL when every one sorts before it.
 * Each node examined counts once in mmt_tcp_reasm_stat_visit(). When the
 * returned segment's seq differs from `seq`, the path ends at the empty
 * slot where tcp_seg_idx_link() can attach a new node.
 */
tcp_seg_t *tcp_seg_idx_locate(tcp_seg_t **root, uint64_t seq, tcp_seg_idx_path_t *path);

/**
 * Attach `seg` at the empty slot a tcp_seg_idx_locate() for seg->seq just
 * recorded (the index must not change in between) and rebalance.
 */
void tcp_seg_idx_link(tcp_seg_idx_path_t *path, tcp_seg_t *seg);

/**
 * Bring the index at *root up to date with the list head..tail: an empty
 * index is built from the whole list in O(n) (one visit per node);
 * otherwise the unindexed head prefix and tail suffix (O(1) prepends and
 * appends since the last sync) are inserted. Every list node is indexed on
 * return.
 */
void tcp_seg_idx_sync(tcp_seg_t **root, tcp_seg_t *head, tcp_seg_t *tail);

/**
 * Drop the index at *root; every segment still listed from `head` is
 * marked unindexed. O(list length), no visits counted.
 */
void tcp_seg_idx_reset(tcp_seg_t **root, tcp_seg_t *head);

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