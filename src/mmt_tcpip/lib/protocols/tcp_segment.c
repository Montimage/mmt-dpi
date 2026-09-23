/**
 * TCP segment
 * to store the TCP segment
 */
#include "tcp_segment.h"
#include "mmt_core.h"   // Issue #20: per-flow arena allocator (mmt_arena_*)
#include "packet_processing.h" // Issue #245: mmt_tcp_reasm_stat_visit()
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  //
//  Issue #245: reclaimable bump-block chain (mmt_segblk_t)                  //
//                                                                         //
//  Same bump-pointer model as mmt_arena (carved chunks are never            //
//  individually free()d), but every block counts its live carved bytes so  //
//  a fully-consumed block is recycled (chain head) or freed — the consumed //
//  prefix no longer pins memory until session teardown.                    //
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static inline uint8_t *mmt_segblk_data(mmt_segblk_t *b) {
	return (uint8_t *)b + MMT_SEGBLK_HDR;
}

uint8_t *mmt_segblk_carve(mmt_segblk_t **head, uint32_t size, mmt_segblk_t **blk_out,
                          uint64_t *reserved, uint64_t room) {
	if (head == NULL || blk_out == NULL || reserved == NULL || size == 0) return NULL;
	uint32_t need = MMT_SEGBLK_ALIGN_UP(size);
	mmt_segblk_t *b = *head;
	/* used <= cap is the invariant, so cap - used cannot wrap. */
	if (b == NULL || b->used > b->cap || need > b->cap - b->used) {
		/* Issue #380 (F-PERF-002): a fresh block must fit the caller's
		 * remaining storage room, header included; right-size it down to
		 * that room, but never below the aligned carve. An emptied head
		 * (recycled in place by mmt_segblk_release) that the carve does not
		 * fit is freed first and its storage credited to the room — left
		 * behind the new head it would stay reserved until teardown. */
		if (b != NULL && b->live == 0) {
			*head = b->next;
			if (b->next != NULL) b->next->prev = NULL;
			*reserved -= MMT_SEGBLK_HDR + b->cap;
			room += MMT_SEGBLK_HDR + b->cap;
			free(b);
		}
		if ((uint64_t) MMT_SEGBLK_HDR + need > room) return NULL;
		uint32_t cap = (need > MMT_SEGBLK_PAYLOAD) ? need : MMT_SEGBLK_PAYLOAD;
		if ((uint64_t) MMT_SEGBLK_HDR + cap > room)
			cap = (uint32_t) (room - MMT_SEGBLK_HDR) & ~(uint32_t)(MMT_SEGBLK_ALIGN - 1u);
		mmt_segblk_t *nb = (mmt_segblk_t *) malloc(MMT_SEGBLK_HDR + cap);
		if (nb == NULL) return NULL;
		*reserved += MMT_SEGBLK_HDR + cap;
		nb->cap = cap;
		nb->used = 0;
		nb->live = 0;
		nb->next = *head;         /* prepend; head is the bump target */
		nb->prev = NULL;
		if (*head != NULL) (*head)->prev = nb;
		*head = nb;
		b = nb;
	}
	uint8_t *p = mmt_segblk_data(b) + b->used;
	b->used += need;
	b->live += need;            /* born referenced by its segment */
	*blk_out = b;
	return p;
}

void mmt_segblk_release(mmt_segblk_t **head, mmt_segblk_t *blk, uint32_t carve,
                        uint64_t *reserved) {
	if (head == NULL || blk == NULL || reserved == NULL || carve == 0) return;
	uint32_t need = MMT_SEGBLK_ALIGN_UP(carve);
	if (blk->live < need) need = blk->live; /* defensive: never wrap live */
	blk->live -= need;
	if (blk->live != 0) return;
	if (*head == blk) {
		blk->used = 0;          /* recycle the bump target in place */
		return;
	}
	if (blk->prev != NULL) blk->prev->next = blk->next;
	if (blk->next != NULL) blk->next->prev = blk->prev;
	*reserved -= MMT_SEGBLK_HDR + blk->cap; /* issue #380 */
	free(blk);
}

void mmt_segblk_free_all(mmt_segblk_t *head, uint64_t *reserved) {
	while (head != NULL) {
		mmt_segblk_t *nx = head->next;
		if (reserved != NULL) *reserved -= MMT_SEGBLK_HDR + head->cap; /* issue #380 */
		free(head);
		head = nx;
	}
}

/**
 * Create a new TCP segment
 * @param   seq Sequence number
 * @param   next_seq Next segment sequence number
 * @param   len len of segment
 * @param   data data of segment
 * @return NULL if cannot allocate memory for a new TCP segment
 *              a pointer points to new TCP segment. The new node has the key = 0, all other attributes are NULL
 */
tcp_seg_t * tcp_seg_new(uint64_t packet_id, uint64_t seq, uint64_t next_seq, uint64_t ack, uint16_t len, uint8_t * data){
	// mmt_stream_printf(stdout, "[tcp_seg_new] New segment of packet: %lu\n", packet_id);
	tcp_seg_t * new_seg = (tcp_seg_t *) malloc(sizeof(tcp_seg_t));
	if (new_seg == NULL) {
		// mmt_debug_log("[tcp_seg_new] Cannot create a new tcp_seg_t");
		return NULL;
	}else{
		new_seg->packet_id = packet_id;
		new_seg->seq = seq;
		new_seg->next_seq = next_seq;
		new_seg->ack = ack;
		new_seg->len = len;
		new_seg->in_arena = 0; /* Issue #201: malloc-backed node */
		new_seg->data = data;
		new_seg->next = NULL;
		new_seg->prev = NULL;
		new_seg->blk = NULL;   /* Issue #245: not store-carved */
		new_seg->blk_size = 0;
		new_seg->idx_height = 0; /* Issue #382: not indexed */
		new_seg->idx_left = NULL;
		new_seg->idx_right = NULL;
		return new_seg;
	}
}

/**
 * Issue #20 (P2): create a TCP segment with its node and payload copy carved
 * from a per-flow arena (one bump-allocation each, no per-segment malloc/free).
 */
tcp_seg_t * tcp_seg_new_in_arena(struct mmt_arena_s * arena, uint64_t packet_id, uint64_t seq, uint64_t next_seq, uint64_t ack, uint16_t len, const uint8_t * payload){
	if (arena == NULL) return NULL;
	uint8_t * data = (uint8_t *) mmt_arena_alloc((mmt_arena_t *) arena, len);
	if (data == NULL) return NULL;
	memcpy(data, payload, len);
	tcp_seg_t * new_seg = (tcp_seg_t *) mmt_arena_alloc((mmt_arena_t *) arena, sizeof(tcp_seg_t));
	if (new_seg == NULL) return NULL;
	new_seg->packet_id = packet_id;
	new_seg->seq = seq;
	new_seg->next_seq = next_seq;
	new_seg->ack = ack;
	new_seg->len = len;
	new_seg->in_arena = 1; /* Issue #201 (F-BUG-039): tag arena ownership so
	                          tcp_seg_free()/tcp_seg_free_list() never call
	                          free() on arena memory. */
	new_seg->data = data;
	new_seg->next = NULL;
	new_seg->prev = NULL;
	new_seg->blk = NULL;   /* Issue #245: arena-carved, not segblk-carved */
	new_seg->blk_size = 0;
	new_seg->idx_height = 0; /* Issue #382: not indexed */
	new_seg->idx_left = NULL;
	new_seg->idx_right = NULL;
	return new_seg;
}

/**
 * Free an TCP segment
 * @param node TCP segment to be free
 */
void tcp_seg_free(tcp_seg_t * seg){
	if (seg != NULL) {
		// mmt_stream_printf(stdout, "[tcp_seg_free] Free segment of packet: %lu\n", seg->packet_id);
		/* Issue #201 (F-BUG-039): arena-backed nodes must not reach free() —
		 * the arena is released wholesale on session teardown. Skip the
		 * frees so mixed lists and stray callers cannot trigger an
		 * allocator mismatch. */
		if (seg->in_arena) {
			seg->next = NULL;
			seg->prev = NULL;
			return;
		}
		seg->packet_id = 0;
		seg->seq = 0;
		seg->next_seq = 0;
		seg->ack = 0;
		seg->len = 0;
		free(seg->data);
		seg->data = NULL;
		seg->next = NULL;
		seg->prev = NULL;
		free(seg);
		seg = NULL;
	}
}

/**
 * Free a segment link-list
 * @param node head of the link-list
 */
void tcp_seg_free_list(tcp_seg_t * head) {
	tcp_seg_t * current_seg = head;

	while(current_seg){
		tcp_seg_t * to_be_deleted = current_seg;
		/* Issue #201 (F-BUG-039): cache the successor BEFORE the free —
		 * tcp_seg_free() unlinks the node, and for arena nodes free() would
		 * be an allocator mismatch (handled inside tcp_seg_free). */
		current_seg = current_seg->next;
		if (current_seg != NULL){
			if (current_seg->seq != to_be_deleted->next_seq){
				mmt_debug_log("[tcp_seg_free_list] Packet lost in sequence: %lu (next_seq of packet: %lu) - %lu (seq of packet: %lu)\n", to_be_deleted->next_seq, to_be_deleted->packet_id, current_seg->seq, current_seg->packet_id);
			}
		}
		tcp_seg_free(to_be_deleted);
	}
}

/**
 * Insert a new node into a Link-list of tcp segment
 * @param  root current root of Link-list of tcp segment
 * @param  node new node to be inserted
 * @return      new root of the Link-list of tcp segment
 */
tcp_seg_t * tcp_seg_insert(tcp_seg_t * root, tcp_seg_t * seg){
	if (seg == NULL){
		mmt_debug_log("[tcp_seg_insert] Cannot insert NULL segment\n");
		return NULL;
	}

	if (root == NULL) {
		root = seg;
		return root;
	}

	tcp_seg_t * current_seg = root;

	while(current_seg) {
		/* Issue #245 (F-PERF-004): count the nodes examined — in-order
		 * arrivals are appended via the caller's tail pointer and never
		 * reach this walk, so a runaway counter means a regression. */
		mmt_tcp_reasm_stat_visit();
		if (current_seg->seq == seg->seq) {
			// Duplicated segment. Issue #380 (F-PERF-002) settles the #245
			// policy: the first segment is kept and later duplicates are
			// rejected (proto_tcp.c does so before allocating any storage).
			mmt_debug_log("[tcp_seg_insert] Duplicated segment: seq %lu - packets: %lu, %lu (ignored)\n", seg->seq, current_seg->packet_id, seg->packet_id);
			return NULL; // duplicated segment
		}
		/* Issue #245: wrap-aware ordering — a post-2^32 sequence continues
		 * the stream instead of sorting before the head. */
		if (tcp_seq_before(seg->seq, current_seg->seq)){
			// Found the place to add new segment
			seg->next = current_seg;
			seg->prev = current_seg->prev;
			if (current_seg->prev){
				current_seg->prev->next = seg;
			}

			current_seg->prev = seg;
			if (seg->prev == NULL){
				// New segment should be the root
				return seg;
			}
			return root;
		}

		if (current_seg->next == NULL){
			// The new segment is the biggest sequence number -> add to the end of the list
			current_seg->next = seg;
			seg->prev = current_seg;
			return root;
		}

		current_seg = current_seg->next;
	}
	mmt_debug_log("[tcp_seg_insert] Should not be here seq: %lu - packets: %lu\n", seg->seq, seg->packet_id);
	return NULL; // Should not be here

}



tcp_seg_t * tcp_seg_locate(tcp_seg_t * root, uint64_t seq){
	/* Issue #380 (F-PERF-002): the tcp_seg_insert() walk without the node —
	 * the caller detects duplicates before carving any storage. */
	tcp_seg_t * current_seg = root;
	while (current_seg) {
		mmt_tcp_reasm_stat_visit();
		if (!tcp_seq_before(current_seg->seq, seq)) return current_seg;
		current_seg = current_seg->next;
	}
	return NULL;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  //
//  Issue #382 (F-PERF-003): AVL index over the pending list                 //
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static inline uint8_t tcp_seg_idx_h(const tcp_seg_t * n){
	return (n != NULL) ? n->idx_height : 0;
}

static inline void tcp_seg_idx_fix(tcp_seg_t * n){
	uint8_t l = tcp_seg_idx_h(n->idx_left), r = tcp_seg_idx_h(n->idx_right);
	n->idx_height = (uint8_t) (1 + ((l > r) ? l : r));
}

static tcp_seg_t * tcp_seg_idx_rotate_right(tcp_seg_t * n){
	tcp_seg_t * l = n->idx_left;
	n->idx_left = l->idx_right;
	l->idx_right = n;
	tcp_seg_idx_fix(n);
	tcp_seg_idx_fix(l);
	return l;
}

static tcp_seg_t * tcp_seg_idx_rotate_left(tcp_seg_t * n){
	tcp_seg_t * r = n->idx_right;
	n->idx_right = r->idx_left;
	r->idx_left = n;
	tcp_seg_idx_fix(n);
	tcp_seg_idx_fix(r);
	return r;
}

/* Restore the AVL balance of the subtree at n; returns its new root. */
static tcp_seg_t * tcp_seg_idx_balance(tcp_seg_t * n){
	tcp_seg_idx_fix(n);
	int bf = (int) tcp_seg_idx_h(n->idx_left) - (int) tcp_seg_idx_h(n->idx_right);
	if (bf > 1) {
		if (tcp_seg_idx_h(n->idx_left->idx_left) < tcp_seg_idx_h(n->idx_left->idx_right))
			n->idx_left = tcp_seg_idx_rotate_left(n->idx_left);
		return tcp_seg_idx_rotate_right(n);
	}
	if (bf < -1) {
		if (tcp_seg_idx_h(n->idx_right->idx_right) < tcp_seg_idx_h(n->idx_right->idx_left))
			n->idx_right = tcp_seg_idx_rotate_right(n->idx_right);
		return tcp_seg_idx_rotate_left(n);
	}
	return n;
}

/* Descend for `seq`; an equal seq stops the descent (duplicate) only when
 * stop_on_equal is set, otherwise it is passed on the right. */
static tcp_seg_t * tcp_seg_idx_descend(tcp_seg_t ** root, uint64_t seq, tcp_seg_idx_path_t * path,
                                       int stop_on_equal){
	tcp_seg_t * succ = NULL;
	tcp_seg_t ** link = root;
	int d = 0;
	/* The AVL height bound keeps d far below the path capacity. */
	while (*link != NULL && d < TCP_SEG_IDX_MAX_DEPTH - 1) {
		tcp_seg_t * n = *link;
		mmt_tcp_reasm_stat_visit();
		path->link[d++] = link;
		if (stop_on_equal && tcp_seq_equal(n->seq, seq)) {
			succ = n; /* duplicate */
			break;
		}
		if (tcp_seq_before(seq, n->seq)) {
			succ = n;
			link = &n->idx_left;
		} else {
			link = &n->idx_right;
		}
	}
	path->link[d] = link;
	path->depth = d;
	return succ;
}

tcp_seg_t * tcp_seg_idx_locate(tcp_seg_t ** root, uint64_t seq, tcp_seg_idx_path_t * path){
	return tcp_seg_idx_descend(root, seq, path, 1);
}

void tcp_seg_idx_link(tcp_seg_idx_path_t * path, tcp_seg_t * seg){
	seg->idx_left = NULL;
	seg->idx_right = NULL;
	seg->idx_height = 1;
	*path->link[path->depth] = seg;
	for (int d = path->depth - 1; d >= 0; d--) {
		tcp_seg_t ** link = path->link[d];
		uint8_t old = (*link)->idx_height;
		*link = tcp_seg_idx_balance(*link);
		/* Unchanged height (or a rotation, which restores the pre-insert
		 * height): nothing above can change. */
		if ((*link)->idx_height == old) break;
	}
}

/* Build a perfectly balanced index from the next n list nodes at *cur. */
static tcp_seg_t * tcp_seg_idx_build(tcp_seg_t ** cur, uint32_t n){
	if (n == 0) return NULL;
	tcp_seg_t * left = tcp_seg_idx_build(cur, n / 2);
	tcp_seg_t * mid = *cur;
	*cur = mid->next;
	mmt_tcp_reasm_stat_visit();
	mid->idx_left = left;
	mid->idx_right = tcp_seg_idx_build(cur, n - n / 2 - 1);
	tcp_seg_idx_fix(mid);
	return mid;
}

static void tcp_seg_idx_insert(tcp_seg_t ** root, tcp_seg_t * seg){
	/* Always link: a listed seq can repeat once pending seqs span 2^31 or
	 * more (tcp_seq_before is then not transitive, and a head prepend is
	 * only checked against head and tail). A skipped node would stay
	 * unindexed in the head prefix and be re-walked by every sync. */
	tcp_seg_idx_path_t path;
	(void) tcp_seg_idx_descend(root, seg->seq, &path, 0);
	tcp_seg_idx_link(&path, seg);
}

void tcp_seg_idx_sync(tcp_seg_t ** root, tcp_seg_t * head, tcp_seg_t * tail){
	if (*root == NULL) {
		uint32_t n = 0;
		for (tcp_seg_t * s = head; s != NULL; s = s->next) n++;
		tcp_seg_t * cur = head;
		*root = tcp_seg_idx_build(&cur, n);
		return;
	}
	for (tcp_seg_t * s = head; s != NULL && s->idx_height == 0; s = s->next)
		tcp_seg_idx_insert(root, s);
	for (tcp_seg_t * s = tail; s != NULL && s->idx_height == 0; s = s->prev)
		tcp_seg_idx_insert(root, s);
}

void tcp_seg_idx_reset(tcp_seg_t ** root, tcp_seg_t * head){
	*root = NULL;
	for (tcp_seg_t * s = head; s != NULL; s = s->next)
		s->idx_height = 0;
}

/**
 * Search in the given Link-list of tcp segment a node which has the seq equals with given seq
 * @param  root root of Link-list of tcp segment
 * @param  key  key value to search the node
 * @return      NULL - if there isn't any node in given Link-list of tcp segment which has the given key value
 *                   a pointer points to the node which has given key value
 */
tcp_seg_t * tcp_seg_find(tcp_seg_t * root, uint64_t seq){
	if (root == NULL) return NULL;
	tcp_seg_t * current_seg = root;


	while(current_seg){
		if (current_seg->seq == seq) return current_seg;
		current_seg = current_seg->next;
	}

	return NULL;
}

/**
 * Show current Link-list of tcp segment structure
 * @param seg root of the Link-list of tcp segment
 */
void tcp_seg_show_list(tcp_seg_t * seg){
	if (seg == NULL) {
		mmt_stream_printf(stdout, "[Empty]\n");
	} else {
		tcp_seg_t * current_seg = seg;
		mmt_stream_printf(stdout, "packet_id | prev_seg | seg | seq | next_seq | ack | data | next_seq \n");
		while(current_seg){
			tcp_seg_show(current_seg);
			current_seg = current_seg->next;
		}

	}

}

/**
 * Show current TCP segment
 * @param seg given seg
 */
void tcp_seg_show(tcp_seg_t * seg) {
	if (seg == NULL){
		mmt_stream_printf(stdout, "[NULL]\n");
	} else {
		mmt_stream_printf(stdout, "[%lu | %p | %p | %lu | %lu | %lu | %d | %p | %p]\n", seg->packet_id, seg->prev, seg, seg->seq, seg->next_seq, seg->ack, seg->len, seg->data, seg->next);
	}
}

/**
 * Get the number of segment in the list
 * @param  seg root of the tree
 * @return      number of seg in the Link-list
 */
int tcp_seg_size(tcp_seg_t * seg) {
	int size = 0;

	tcp_seg_t * current_seg = seg;

	while(current_seg){
		size++;
		current_seg = current_seg->next;
	}
	return size;
}

int tcp_seg_reassembly(uint8_t * data, tcp_seg_t * root, uint32_t len){

	uint32_t current_len = 0;

	tcp_seg_t * current_seg = root;

	/* Issue #201 (F-BUG-019): the loop guard only compared current_len < len
	 * but copied the FULL segment — a segment straddling the budget overflowed
	 * `data`. Clamp every copy to the remaining space. */
	while(current_seg && current_len < len) {
		uint32_t chunk = current_seg->len;
		uint32_t avail = len - current_len;
		if (chunk > avail)
			chunk = avail;
		if (chunk > 0)
			memcpy(data + current_len , current_seg->data, chunk);
		current_len +=  chunk;
		current_seg = current_seg->next;
	}
	return 1;
}