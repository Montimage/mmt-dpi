/**
 * TCP segment
 * to store the TCP segment
 */
#include "tcp_segment.h"
#include "mmt_core.h"   // Issue #20: per-flow arena allocator (mmt_arena_*)
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

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
		if (current_seg->seq == seg->seq) {
			// Duplicated segment
			// TODO(#245): discuss whether to override duplicate segment or keep first
			mmt_debug_log("[tcp_seg_insert] Duplicated segment: seq %lu - packets: %lu, %lu (ignored)\n", seg->seq, current_seg->packet_id, seg->packet_id);
			return NULL; // duplicated segment
		}
		if (current_seg->seq > seg->seq){
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