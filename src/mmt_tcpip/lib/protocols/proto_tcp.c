#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "packet_processing.h" /* mmt_have_bytes() — issue #202 caplen prologues */
#include "../mmt_common_internal_include.h"

#include <inttypes.h> /* PRIu64 in debug() calls — only compiled when asserts live (issue #214) */

#include "tcp.h"
#include "tcp_segment.h"

/* Named constants replacing the bare literals below (issue #238):
 * - MMT_ETH_HEADER_LEN is the Ethernet II header (dst + src MAC + ethertype);
 * - MMT_ETH_MIN_FRAME_LEN is the smallest on-wire Ethernet frame (60 bytes,
 *   FCS excluded) — a frame whose IP tot_len plus payload only reaches it is
 *   padding, see tcp_payload_len_extraction();
 * - TCP_DOFF_* name the TCP data-offset (doff) field: a 4-bit count of 32-bit
 *   words whose minimum legal value is 5 (a 20-byte header with no options)
 *   and whose maximum is 15 (60 bytes), see tcp_option_extraction(). */
#define MMT_ETH_HEADER_LEN    14
#define MMT_ETH_MIN_FRAME_LEN 60
#define TCP_DOFF_WORD_BYTES    4
#define TCP_DOFF_MIN_WORDS     5
#define TCP_DOFF_MAX_WORDS    15

/* ------------------------------------------------------------------ */
/* Issue #245: bounded, linear TCP reassembly (F-PERF-004/005/006,      */
/* F-BUG-038).                                                        */
/*                                                                    */
/* Per direction the flattened stream image is a persistent buffer     */
/* grown geometrically up to the handler's tcp_reassembly_limit and    */
/* shared with attribute readers; pending (not yet flattened) segments */
/* live in a seq-sorted doubly-linked list carved from reclaimable     */
/* bump blocks. In-order arrivals append through a tail pointer — the  */
/* root walk is gone. Each extraction drains only the pending tail, so */
/* a byte is copied exactly once (incremental, memoized), and a        */
/* released block frees the consumed prefix instead of pinning it to   */
/* session teardown. r->live (pending carve bytes + image bytes) never */
/* exceeds the ceiling: segments are dropped when it would overflow.   */
/* ------------------------------------------------------------------ */

/* Lazily allocate the session's reassembly extension. */
static mmt_tcp_reasm_t *tcp_reasm_state(mmt_session_t *session) {
    if (session->tcp_reasm == NULL) {
        mmt_tcp_reasm_t *r = (mmt_tcp_reasm_t *) mmt_malloc(sizeof(mmt_tcp_reasm_t));
        if (r != NULL) memset(r, 0, sizeof(*r));
        session->tcp_reasm = r;
    }
    return session->tcp_reasm;
}

/* Release a segment's store carve and its share of the live counter. */
static void tcp_reasm_seg_release(mmt_tcp_reasm_t *r, tcp_seg_t *seg) {
    r->live -= seg->blk_size;
    mmt_tcp_reasm_stat_live(-(int64_t) seg->blk_size);
    mmt_segblk_release(&r->blocks, seg->blk, seg->blk_size);
}

/* Append bytes to the direction's image buffer, growing it geometrically
 * (x4 from a 16 KiB floor) but never past the per-flow ceiling. Returns the
 * number of bytes appended; the caller's segment is only released for what
 * was appended or intentionally dropped. */
static uint32_t tcp_reasm_image_append(mmt_session_t *session, mmt_tcp_reasm_t *r,
                                       int dir, const uint8_t *data, uint32_t len) {
    uint32_t limit = session->mmt_handler->tcp_reassembly_limit;
    uint32_t room = (r->image_len[dir] < limit) ? limit - r->image_len[dir] : 0;
    if (len > room) len = room;
    if (len == 0) return 0;
    uint32_t need = r->image_len[dir] + len;
    if (need > r->image_cap[dir]) {
        /* ncap must be 64-bit: a x4 step past 1 GiB wraps a uint32_t to 0 and
         * the while loop would never terminate (reviewer lane, run r3). */
        uint64_t ncap = (r->image_cap[dir] != 0) ? r->image_cap[dir] : (16u * 1024u);
        while (ncap < need) ncap *= 4;
        if (ncap > limit) ncap = limit;
        /* need <= limit by construction (len <= room), so ncap >= need and
         * ncap <= limit <= UINT32_MAX — the cast back to uint32_t is safe. */
        uint8_t *nb = (uint8_t *) realloc(r->image[dir], (size_t) ncap);
        if (nb == NULL) return 0;   /* OOM — leave the segment pending */
        r->image[dir] = nb;
        r->image_cap[dir] = (uint32_t) ncap;
    }
    memcpy(r->image[dir] + r->image_len[dir], data, len);
    r->image_len[dir] += len;
    r->live += len;
    mmt_tcp_reasm_stat_move(len);
    mmt_tcp_reasm_stat_live((int64_t) len);
    return len;
}

/* Flatten every pending segment of direction `dir` into the image buffer,
 * in seq order, releasing each store carve as it is consumed. Segments whose
 * sequence range was already emitted (consumed prefix) are dropped instead
 * of being spliced into the middle of the image — that is the "consumed
 * prefix is discarded" half of the bound. O(pending) per call. */
static void tcp_reasm_drain(mmt_session_t *session, int dir) {
    mmt_tcp_reasm_t *r = session->tcp_reasm;
    if (r == NULL) return;
    tcp_seg_t *seg = (tcp_seg_t *) r->seg_head[dir];
    while (seg != NULL) {
        tcp_seg_t *nx = seg->next;
        /* unlink seg from the pending list */
        r->seg_head[dir] = nx;
        if (nx != NULL) nx->prev = NULL;
        else r->seg_tail[dir] = NULL;

        if (r->consumed_valid[dir] && !tcp_seq_before(r->consumed_seq[dir], seg->next_seq)) {
            r->dropped += seg->len;
            mmt_tcp_reasm_stat_drop(seg->len);
        } else {
            uint32_t n = tcp_reasm_image_append(session, r, dir, seg->data, seg->len);
            if (n == 0 && r->image_len[dir] + seg->len <= session->mmt_handler->tcp_reassembly_limit
                      && r->image_cap[dir] < r->image_len[dir] + seg->len) {
                /* OOM growing the image — re-link at head and stop: the
                 * pending list keeps the segment for the next read. The
                 * bytes are NOT counted dropped — the segment survives. */
                seg->next = (tcp_seg_t *) r->seg_head[dir];
                seg->prev = NULL;
                if (r->seg_head[dir] != NULL) ((tcp_seg_t *) r->seg_head[dir])->prev = seg;
                else r->seg_tail[dir] = seg;
                r->seg_head[dir] = seg;
                return;
            }
            if (n < seg->len) {
                r->dropped += seg->len - n;
                mmt_tcp_reasm_stat_drop(seg->len - n);
            }
            r->consumed_seq[dir] = (uint32_t) seg->next_seq;
            r->consumed_valid[dir] = 1;
        }
        tcp_reasm_seg_release(r, seg);
        seg = nx;
    }
}

/* Offer a freshly arrived TCP payload segment to the direction's pending
 * store. In-order and descending arrivals take O(1) fast paths (tail /
 * head); other out-of-order segments fall back to the sorted-list insert
 * whose walk is bounded by the ceiling-limited pending window. */
static void tcp_reasm_offer(mmt_session_t *session, int dir, uint64_t packet_id,
                            uint32_t seq, uint32_t ack, const uint8_t *payload,
                            uint32_t len) {
    mmt_tcp_reasm_t *r = tcp_reasm_state(session);
    if (r == NULL) return;
    uint32_t limit = session->mmt_handler->tcp_reassembly_limit;

    /* The consumed prefix is gone for good: a segment whose WHOLE range is
     * below the emitted frontier (a pure retransmission) cannot be spliced
     * mid-image — drop it rather than growing memory for bytes already
     * reported. A partially overlapping segment (seq < frontier < next_seq)
     * is still appended in full, preserving the pre-#245 sorted-concat
     * semantics for overlapping ranges. */
    if (r->consumed_valid[dir] && !tcp_seq_before(r->consumed_seq[dir], seq + len)) {
        r->dropped += len;
        mmt_tcp_reasm_stat_drop(len);
        return;
    }
    uint32_t carve = MMT_SEGBLK_ALIGN_UP(sizeof(tcp_seg_t)) + MMT_SEGBLK_ALIGN_UP(len);
    /* Bounded: pending carve bytes + image bytes never exceed the ceiling. */
    if (r->live + carve > limit) {
        r->dropped += len;
        mmt_tcp_reasm_stat_drop(len);
        return;
    }
    mmt_segblk_t *blk = NULL;
    uint8_t *p = mmt_segblk_carve(&r->blocks, carve, &blk);
    if (p == NULL || blk == NULL) {
        r->dropped += len;
        mmt_tcp_reasm_stat_drop(len);
        return;
    }
    tcp_seg_t *seg = (tcp_seg_t *) p;
    seg->packet_id = packet_id;
    seg->seq = seq;
    seg->next_seq = (uint32_t)(seq + len); /* 32-bit wrap */
    seg->ack = ack;
    seg->len = (uint16_t) len;
    seg->in_arena = 1; /* store-backed: tcp_seg_free() must not free() it */
    seg->data = p + MMT_SEGBLK_ALIGN_UP(sizeof(tcp_seg_t));
    seg->next = NULL;
    seg->prev = NULL;
    seg->blk = blk;
    seg->blk_size = carve;
    memcpy(seg->data, payload, len);

    tcp_seg_t *head = (tcp_seg_t *) r->seg_head[dir];
    tcp_seg_t *tail = (tcp_seg_t *) r->seg_tail[dir];
    if (tail == NULL) {
        r->seg_head[dir] = seg;
        r->seg_tail[dir] = seg;
        r->live += carve;
        mmt_tcp_reasm_stat_live((int64_t) carve);
        return;
    }
    if (tcp_seq_before(tail->seq, seg->seq)) {
        /* F-PERF-004: in-order append through the tail — O(1). */
        tail->next = seg;
        seg->prev = tail;
        r->seg_tail[dir] = seg;
        r->live += carve;
        mmt_tcp_reasm_stat_live((int64_t) carve);
        return;
    }
    if (tcp_seq_equal(seg->seq, tail->seq) || tcp_seq_equal(seg->seq, head->seq)) {
        goto release_dup;
    }
    if (tcp_seq_before(seg->seq, head->seq)) {
        /* Descending order prepends at head — O(1). */
        seg->next = head;
        head->prev = seg;
        r->seg_head[dir] = seg;
        r->live += carve;
        mmt_tcp_reasm_stat_live((int64_t) carve);
        return;
    }
    {
        tcp_seg_t *root = tcp_seg_insert(head, seg);
        if (root == NULL) goto release_dup;
        r->seg_head[dir] = root;
        r->live += carve;
        mmt_tcp_reasm_stat_live((int64_t) carve);
        return;
    }
release_dup:
    /* Duplicate sequence — abandon the segment; the carve is released. */
    mmt_segblk_release(&r->blocks, blk, carve);
    r->dropped += len;
    mmt_tcp_reasm_stat_drop(len);
}

int tcp_data_offset_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — every packet byte this
     * callback dereferences must lie inside the captured data. The data
     * offset nibble lives in byte 12 of the TCP header. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + 12, sizeof(uint8_t))) return 0;

    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & packet->data[proto_offset];
    *((unsigned char *) extracted_data->data) = tcp_hdr->doff; //Already aligned to the correct bit ordering
    return 1;
}

int tcp_fin_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — the flags byte is at offset
     * 13 of the TCP header. See tcp_data_offset_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + 13, sizeof(uint8_t))) return 0;
    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & packet->data[proto_offset];
    // if (tcp_hdr->fin) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->fin; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_syn_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see tcp_fin_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + 13, sizeof(uint8_t))) return 0;
    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & packet->data[proto_offset];
    // if (tcp_hdr->syn) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->syn; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_rst_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see tcp_fin_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + 13, sizeof(uint8_t))) return 0;
    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & packet->data[proto_offset];
    // if (tcp_hdr->rst) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->rst; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_psh_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see tcp_fin_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + 13, sizeof(uint8_t))) return 0;
    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & packet->data[proto_offset];
    // if (tcp_hdr->psh) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->psh; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_ack_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see tcp_fin_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + 13, sizeof(uint8_t))) return 0;
    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & packet->data[proto_offset];
    // if (tcp_hdr->ack) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->ack; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_urg_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see tcp_fin_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + 13, sizeof(uint8_t))) return 0;
    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & packet->data[proto_offset];
    // if (tcp_hdr->urg) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->urg; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_ece_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see tcp_fin_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + 13, sizeof(uint8_t))) return 0;
    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & packet->data[proto_offset];
    if (( tcp_hdr->res2 & 0x01 ) != 0 ) {
        *((unsigned char *) extracted_data->data) = 1; //Already aligned to the correct bit ordering
        return 1;
    }
    return 0;
}

int tcp_cwr_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see tcp_fin_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + 13, sizeof(uint8_t))) return 0;
    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & packet->data[proto_offset];
    if (( tcp_hdr->res2 & 0x02 ) != 0 ) {
        *((unsigned char *) extracted_data->data) = 1; //Already aligned to the correct bit ordering
        return 1;
    }
    return 0;
}

int tcp_established_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {
    /* Issue #202 (F-BUG-033): uniform caplen prologue — this extractor reads
     * no packet bytes; the floor still validates the capture plumbing. */
    if (!mmt_have_bytes(packet, 0, 0) || extracted_data == NULL) return 0;
    if (packet->internal_packet == NULL || packet->internal_packet->flow == NULL) return 0;
    struct mmt_internal_tcpip_session_struct *flow = packet->internal_packet->flow;
    *((unsigned char *) extracted_data->data) = flow->l4.tcp.seen_ack;
    return 1;
}

int tcp_connection_closed_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {
    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * tcp_established_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(packet, 0, 0) || extracted_data == NULL) return 0;
    if (packet->internal_packet == NULL || packet->internal_packet->flow == NULL) return 0;
    struct mmt_internal_tcpip_session_struct *flow = packet->internal_packet->flow;
    *((unsigned char *) extracted_data->data) = flow->l4.tcp.seen_fin_ack;
    return 1;
}

int tcp_flags_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see tcp_fin_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + (size_t) attribute_offset, sizeof(uint8_t))) return 0;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
    *((unsigned char *) extracted_data->data) = *((unsigned char *) & packet->data[proto_offset + attribute_offset]);
    return 1;
}

int tcp_payload_len_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    /* Issue #202 (F-BUG-033): uniform caplen prologue — this extractor reads
     * no packet bytes; the floor still validates the capture plumbing. */
    if (!mmt_have_bytes(ipacket, 0, 0) || extracted_data == NULL) return 0;
    if (ipacket->internal_packet == NULL) return 0;
    /* Padding probe: a minimum-size Ethernet frame pads its payload out to
     * MMT_ETH_MIN_FRAME_LEN on the wire, so when IP tot_len + payload_len +
     * MMT_ETH_HEADER_LEN lands exactly on it the "payload" is padding and no
     * length is reported. (Issue #238, F-CLEAN-010: this block sat inside
     * commented-out `if(payload_packet_len){ ... }` braces that made the live
     * control flow look narrower than it is — they are gone now.) */
    if(ipacket->internal_packet->iph==NULL){
        *((uint32_t*) extracted_data->data) = ipacket->internal_packet->payload_packet_len;
        return 1;
    }

    if((ntohs(ipacket->internal_packet->iph->tot_len) + ipacket->internal_packet->payload_packet_len + MMT_ETH_HEADER_LEN != MMT_ETH_MIN_FRAME_LEN)){
        *((uint32_t*) extracted_data->data) = ipacket->internal_packet->payload_packet_len;
        return 1;
    }
    return 0;
}

int tcp_retransmission_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * tcp_payload_len_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(ipacket, 0, 0) || extracted_data == NULL) return 0;
    if(ipacket->internal_packet){
        *((uint32_t*) extracted_data->data) = ipacket->internal_packet->tcp_retransmission;
        return 1;
    }
    return 0;
}

int tcp_outoforder_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * tcp_payload_len_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(ipacket, 0, 0) || extracted_data == NULL) return 0;
    if(ipacket->internal_packet){
        *((uint32_t*) extracted_data->data) = ipacket->internal_packet->tcp_outoforder;
        return 1;
    }
    return 0;
}


int tcp_session_retransmission_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * tcp_payload_len_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(ipacket, 0, 0) || extracted_data == NULL) return 0;
    if (ipacket->session == NULL) return 0;
    *((uint32_t*) extracted_data->data) = ipacket->session->tcp_retransmissions;
    return 1;
}

int tcp_session_payload_up_len_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * tcp_payload_len_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(ipacket, 0, 0) || extracted_data == NULL) return 0;
    if (ipacket->session == NULL) return 0;
    /* Issue #245: LEN reports the bytes valid in the flattened image — the
     * drain keeps it consistent with what a DATA read returns. */
    tcp_reasm_drain(ipacket->session, ipacket->session->setup_packet_direction);
    mmt_tcp_reasm_t *r = ipacket->session->tcp_reasm;
    *((uint32_t*) extracted_data->data) = (r != NULL) ? r->image_len[ipacket->session->setup_packet_direction] : 0;
    return 1;
}

int tcp_session_payload_up_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * tcp_payload_len_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(ipacket, 0, 0) || extracted_data == NULL) return 0;
    if (ipacket->session){
        uint8_t up_direction = ipacket->session->setup_packet_direction;
        /* Issue #245 (F-PERF-005): incremental flatten — only newly pending
         * segments are appended; the persistent image is returned as-is. */
        tcp_reasm_drain(ipacket->session, up_direction);
        mmt_tcp_reasm_t *r = ipacket->session->tcp_reasm;
        if (r != NULL && r->image_len[up_direction] > 0){
            extracted_data->data = (void*) r->image[up_direction];
            return 1;
        }
    }

    return 0;
}

int tcp_session_payload_down_len_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * tcp_payload_len_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(ipacket, 0, 0) || extracted_data == NULL) return 0;
    if (ipacket->session == NULL) return 0;
    tcp_reasm_drain(ipacket->session, !ipacket->session->setup_packet_direction);
    mmt_tcp_reasm_t *r = ipacket->session->tcp_reasm;
    *((uint32_t*) extracted_data->data) = (r != NULL) ? r->image_len[!ipacket->session->setup_packet_direction] : 0;
    return 1;
}

int tcp_session_payload_down_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * tcp_payload_len_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(ipacket, 0, 0) || extracted_data == NULL) return 0;
    if (ipacket->session){
        uint8_t down_direction = !ipacket->session->setup_packet_direction;
        tcp_reasm_drain(ipacket->session, down_direction);
        mmt_tcp_reasm_t *r = ipacket->session->tcp_reasm;
        if (r != NULL && r->image_len[down_direction] > 0){
            extracted_data->data = (void*) r->image[down_direction];
            return 1;
        }
    }

    return 0;
}
int tcp_session_rtt_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * tcp_payload_len_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(ipacket, 0, 0) || extracted_data == NULL) return 0;
    if(ipacket->session){
        memcpy(extracted_data->data, & ipacket->session->rtt, sizeof (struct timeval));
        // (struct timeval *)extracted_data->data = ;
        return 1;
    }
    return 0;
}

int tcp_option_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t * extracted_data){
    /* Issue #202 (F-BUG-033): route every bounds check through the shared
     * caplen helper so the coverage stays greppable. */
    if (ipacket == NULL || ipacket->p_hdr == NULL || ipacket->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(ipacket, (size_t) proto_offset, sizeof(struct tcphdr))) return 0;
    mmt_una_tcphdr_t * tcp_hdr = (mmt_una_tcphdr_t *) & ipacket->data[proto_offset];
    /* doff is a 4-bit count of 32-bit words (TCP_DOFF_WORD_BYTES each), so it
     * is bounded by TCP_DOFF_MAX_WORDS = 15 by construction; at
     * TCP_DOFF_MIN_WORDS = 5 the header is the 20-byte fixed part with no
     * options to extract. (Issue #238, F-CLEAN-014: the `tcphdr_len < 20 ||
     * tcphdr_len > 60` check that followed was subsumed by these bounds and
     * has been deleted.) */
    int data_offset = tcp_hdr->doff;
    //no optional fields
    if( data_offset <= TCP_DOFF_MIN_WORDS )
       return 0;
    int tcphdr_len = data_offset * TCP_DOFF_WORD_BYTES;
    if (!mmt_have_bytes(ipacket, (size_t) proto_offset, (size_t) tcphdr_len)) return 0;
    int option_offset = proto_offset + (TCP_DOFF_MIN_WORDS * TCP_DOFF_WORD_BYTES); //option fields start after the fixed header
    int end_of_option = proto_offset + tcphdr_len;
    if (end_of_option > (int)ipacket->p_hdr->caplen) end_of_option = ipacket->p_hdr->caplen;

    //structure of a tcp option field
    /*
     * Issue #59: these overlay "&ipacket->data[option_offset]" / opt_field->data
     * of the byte-aligned capture buffer; reading the 32-bit timestamp fields
     * (tsval/tserc) through a strict cast is a misaligned access (UB, aborts
     * under BUILD=asan -fsanitize=alignment). Mirrors PR #58 (#57).
     * Issue #193: 'packed', not 'aligned(1)', actually lowers a struct's
     * alignment requirement — aligned() can only raise it, so the #59
     * annotation was a no-op and the timestamp member loads still tripped
     * UBSan.
     */
    struct tcp_option{
        uint8_t kind;
        uint8_t length; //indicates the total length of the option
        uint8_t data[];
    } __attribute__((packed)) *opt_field;
    struct timestamp_option_field{
        uint32_t tsval;
        uint32_t tserc;
        /* Issue #193: aligned(1) cannot lower a struct's alignment — only
         * 'packed' does — so the timestamp member loads below were still
         * compiled as 4-byte-aligned accesses and trip UBSan on option data
         * at odd offsets. */
    } __attribute__((packed)) *ts_field;

    while( option_offset < end_of_option ){
        if (!mmt_have_bytes(ipacket, (size_t) option_offset, 1)) break;
        opt_field = (struct tcp_option *) &ipacket->data[ option_offset ];
        switch( opt_field->kind ){
        case 0: //end of option list
            return 0;
        case 1: //no option: not have an Option-Length or Option-Data fields following it.
            option_offset += 1; //jump over this option
            break;
        case 2: //Maximum segment size
        case 3: //Window scale
        case 4: //Selective Acknowledgement permitted
        case 5: //Selective ACKnowledgement (SACK)
            if (option_offset + 1 >= end_of_option) return 0;
            if (!mmt_have_bytes(ipacket, (size_t) option_offset, 2)) return 0;
            if (opt_field->length < 2) return 0;
            if (option_offset + opt_field->length > end_of_option) return 0;
            if (!mmt_have_bytes(ipacket, (size_t) option_offset, (size_t) opt_field->length)) return 0;
            option_offset += opt_field->length; //jump over this option
            break;
        case 8: //Timestamp and echo of previous timestamp
            if (option_offset + 1 >= end_of_option) return 0;
            if (!mmt_have_bytes(ipacket, (size_t) option_offset, 2)) return 0;
            if (opt_field->length < 2) return 0;
            if (opt_field->length < 10) return 0;
            if (option_offset + opt_field->length > end_of_option) return 0;
            if (!mmt_have_bytes(ipacket, (size_t) option_offset, (size_t) opt_field->length)) return 0;
            ts_field = (struct timestamp_option_field *) opt_field->data;
            //depending on which attribute we are extracting
            switch( extracted_data->field_id ){
            case TCP_TSVAL:
                *((uint32_t*) extracted_data->data) = ntohl(ts_field->tsval);
                return 1; //we got the value
            case TCP_TSECR:
                *((uint32_t*) extracted_data->data) = ntohl(ts_field->tserc);
                return 1; //we got the value
            default:
                break;
            }
            option_offset += opt_field->length; //jump over this option
            break;
        default:
            if (option_offset + 1 >= end_of_option) return 0;
            if (!mmt_have_bytes(ipacket, (size_t) option_offset, 2)) return 0;
            if (opt_field->length < 2) return 0;
            if (option_offset + opt_field->length > end_of_option) return 0;
            if (!mmt_have_bytes(ipacket, (size_t) option_offset, (size_t) opt_field->length)) return 0;
            option_offset += opt_field->length; //jump over this option
            break;
        }
    }
    //do we need to set the value to zero when not found ???
    switch( extracted_data->field_id ){
        case TCP_TSVAL:
        *((uint32_t*) extracted_data->data) = 0;
        break;
    case TCP_TSECR:
        *((uint32_t*) extracted_data->data) = 0;
        break;
    default:
        break;
    }
    return 0; //no value for the attribute to be extracted
}

static attribute_metadata_t tcp_attributes_metadata[TCP_ATTRIBUTES_NB] = {
    {TCP_SRC_PORT, TCP_SRC_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 0, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_DEST_PORT, TCP_DEST_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_SEQ_NB, TCP_SEQ_NB_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {TCP_ACK_NB, TCP_ACK_NB_ALIAS, MMT_U32_DATA, sizeof (int), 8, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {TCP_DATA_OFF, TCP_DATA_OFF_ALIAS, MMT_U8_DATA, sizeof (char), 12, SCOPE_PACKET, tcp_data_offset_extraction},
    {TCP_FLAGS, TCP_FLAGS_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_flags_extraction},
    {TCP_FIN, TCP_FIN_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_fin_flag_extraction},
    {TCP_SYN, TCP_SYN_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_syn_flag_extraction},
    {TCP_RST, TCP_RST_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_rst_flag_extraction},
    {TCP_PSH, TCP_PSH_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_psh_flag_extraction},
    {TCP_ACK, TCP_ACK_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_ack_flag_extraction},
    {TCP_URG, TCP_URG_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_urg_flag_extraction},
    {TCP_ECE, TCP_ECE_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_ece_flag_extraction},
    {TCP_CWR, TCP_CWR_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_cwr_flag_extraction},
    {TCP_WINDOW, TCP_WINDOW_ALIAS, MMT_U16_DATA, sizeof (short), 14, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_CHECKSUM, TCP_CHECKSUM_ALIAS, MMT_U16_DATA, sizeof (short), 16, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_URG_PTR, TCP_URG_PTR_ALIAS, MMT_U16_DATA, sizeof (short), 18, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_RTT, TCP_RTT_ALIAS, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_session_rtt_extraction},
    {TCP_SYN_RCV, TCP_SYN_RCV_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_syn_flag_extraction},//TODO(#331): extract function not correct
    {TCP_PAYLOAD_LEN, TCP_PAYLOAD_LEN_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_payload_len_extraction},
    {TCP_RETRANSMISSION, TCP_RETRANSMISSION_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_retransmission_extraction},
    {TCP_OUTOFORDER, TCP_OUTOFORDER_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_outoforder_extraction},
    {TCP_SESSION_RETRANSMISSION, TCP_SESSION_RETRANSMISSION_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_retransmission_extraction},
    {TCP_SESSION_PAYLOAD_UP_LEN, TCP_SESSION_PAYLOAD_UP_LEN_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_payload_up_len_extraction},
    {TCP_SESSION_PAYLOAD_UP, TCP_SESSION_PAYLOAD_UP_ALIAS, MMT_DATA_POINTER, sizeof (void*), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_payload_up_extraction},
    {TCP_SESSION_PAYLOAD_DOWN_LEN, TCP_SESSION_PAYLOAD_DOWN_LEN_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_payload_down_len_extraction},
    {TCP_SESSION_PAYLOAD_DOWN, TCP_SESSION_PAYLOAD_DOWN_ALIAS, MMT_DATA_POINTER, sizeof (void*), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_payload_down_extraction},
    // {TCP_SESSION_OUTOFORDER, TCP_SESSION_OUTOFORDER_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_outoforder_extraction},
    {TCP_CONN_ESTABLISHED, TCP_CONN_ESTABLISHED_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_established_extraction},
    {TCP_CONN_CLOSED, TCP_CONN_CLOSED_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_connection_closed_extraction},
	{TCP_TSVAL, TCP_TSVAL_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_option_extraction},
	{TCP_TSECR, TCP_TSECR_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_option_extraction},
};

void clean_session_payload(mmt_session_t * session, unsigned index){
    /* Issue #245: the bounded reassembly extension holds the pending segment
     * block chain plus both image buffers — released in one shot at session
     * teardown (consumed prefix was already reclaimed during the flow). */
    mmt_tcp_reasm_t *r = session->tcp_reasm;
    if (r != NULL) {
        mmt_tcp_reasm_stat_live(-(int64_t) r->live);
        mmt_segblk_free_all(r->blocks);
        free(r->image[0]);
        free(r->image[1]);
        free(r);
        session->tcp_reasm = NULL;
    }
}

int tcp_pre_classification_function(ipacket_t * ipacket, unsigned index) {
    debug("[tcp_pre_classification_function] packet %"PRIu64" at index: %d\n",ipacket->packet_id,index);
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    int l4_offset = get_packet_offset_at_index(ipacket, index);
    if (packet->iphv6) {
        packet->l4_packet_len = (ipacket->p_hdr->caplen - l4_offset);
    }

    ////////////////////////////////////////////////
    packet->tcp = (struct tcphdr *) & ipacket->data[l4_offset];
    packet->udp = NULL;

    if (likely(packet->flow)) {
        mmt_set_flow_protocol_to_packet(packet->flow, packet);
    } else {
        mmt_reset_internal_packet_protocol(packet);
    }

    // This is a TCP flow, get the offset
    // Issue #25 (M6): the TCP data offset (doff) is a 4-bit field that, per
    // RFC 793, must be at least 5 (a 20-byte header with no options). A
    // malformed value below 5 yields a header length that is too small (and
    // would slip past the "l4_packet_len < tcphdr_len" check below for doff 0),
    // so reject the packet before deriving any offsets from it.
    if (packet->tcp->doff < TCP_DOFF_MIN_WORDS) {
        MMT_LOG( PROTO_TCP, MMT_LOG_DEBUG, "*** Warning: malformed packet (tcp data offset < 5)\n" );
        return MMT_CLASSIFY_SKIP;
    }
    uint16_t tcphdr_len = packet->tcp->doff * TCP_DOFF_WORD_BYTES; //TCP header length

    packet->l4_protocol = 6; /* TCP for sure ;) */

    if( packet->l4_packet_len < tcphdr_len ) {
        MMT_LOG( PROTO_TCP, MMT_LOG_DEBUG, "*** Warning: malformed packet (tcp length mismatch)\n" );
        return MMT_CLASSIFY_SKIP;
    }

    packet->payload_packet_len = packet->l4_packet_len - tcphdr_len;
    packet->payload = ((uint8_t *) packet->tcp) + tcphdr_len;
    /* F-BUG-107/#195: l4_packet_len derives from the IP total length and can
     * exceed the captured bytes on truncated pcaps — clamp payload_packet_len
     * to what data[] actually holds so every payload[] read stays in bounds.
     * Synthetic harness packets may carry no p_hdr — skip the clamp then. */
    if (ipacket->p_hdr != NULL) {
        /* uintptr subtraction wraps huge when payload < data -> fails check */
        uintptr_t poff = (uintptr_t)packet->payload - (uintptr_t)ipacket->data;
        uint32_t avail = ( poff < ipacket->p_hdr->caplen )
            ? (uint32_t)(ipacket->p_hdr->caplen - (uint32_t)poff) : 0;
        if( packet->payload_packet_len > avail )
            packet->payload_packet_len = avail;
    }
    packet->actual_payload_len = packet->payload_packet_len;
    packet->https_server_name.ptr = NULL;
    packet->https_server_name.len = 0;

    /* check for new tcp syn packets, here
     * idea: reset detection state if a connection is unknown
     */
     if (packet->tcp!=NULL
        && packet->tcp->syn != 0
        && packet->tcp->ack == 0
        && packet->flow != NULL
        && ipacket->session->packet_count == 0 /*First packet of the flow*/
        && packet->flow->detected_protocol_stack[0] == PROTO_UNKNOWN) {

        memset(packet->flow, 0, sizeof (*(packet->flow))); //BW - TODO(#330): Is this memset needed? the syn should be
        //seen at the start of the flow, this should have been set to zero
        //at the creation of the flow!!! Check this out
        MMT_LOG(PROTO_UNKNOWN, packet,
                MMT_LOG_DEBUG,
                "%s:%u: tcp syn packet for unknown protocol, reset detection state\n", __FUNCTION__, __LINE__);
        }

    mmt_connection_tracking(ipacket, index);

    if (packet->flow == NULL && packet->tcp != NULL) {
        return MMT_CLASSIFY_SKIP;
    }

    //Set the offset for the next proto anyway! we might not get there
    ipacket->proto_headers_offset->proto_path[index + 1] = tcphdr_len;
    invalidate_packet_offset_cache(ipacket); // Issue #19: direct offset write

    MMT_SAVE_AS_BITMASK(packet->detection_bitmask, packet->detected_protocol_stack[0]);

    /* build selction packet bitmask */
    packet->mmt_selection_packet |= (MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

    if (packet->payload_packet_len != 0) {
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;
    }

    if (packet->tcp_retransmission == 0) {
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;
    }

    // Issue #99 (PERF-5 / ACC-17): once an *unknown* TCP flow exceeds a bounded
    // packet budget, give up classifying it, mirroring the UDP stop-guard
    // (proto_udp.c:71). Returning 0 makes proto_packet_classify_next() skip both
    // the ~99-checker chain walk AND post-classification for the rest of the
    // flow's life, so long-lived unknown TCP flows stop re-scanning every packet.
    // The 2x threshold matches UDP. The give-up is gated on the flow still being
    // unknown: post-classification re-asserts an already-classified flow's
    // per-packet protocol path on every packet, so an unconditional give-up would
    // drop that path and misreport long classified flows (e.g. FTP) as unknown.
    if (packet->flow != NULL
        && packet->flow->detected_protocol_stack[0] == PROTO_UNKNOWN
        && ipacket->session->packet_count > (CFG_CLASSIFICATION_THRESHOLD * 2)) {
        return MMT_CLASSIFY_SKIP;
    }

    return MMT_CLASSIFY_CONTINUE;
}

int tcp_pre_classification_function_with_reassemble(ipacket_t * ipacket, unsigned index) {
    debug("[tcp_pre_classification_function_with_reassemble] packet %"PRIu64" at index: %d\n",ipacket->packet_id,index);
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    int l4_offset = get_packet_offset_at_index(ipacket, index);
    if (packet->iphv6) {
        packet->l4_packet_len = (ipacket->p_hdr->caplen - l4_offset);
    }

    ////////////////////////////////////////////////
    packet->tcp = (struct tcphdr *) & ipacket->data[l4_offset];
    packet->udp = NULL;

    if (likely(packet->flow)) {
        mmt_set_flow_protocol_to_packet(packet->flow, packet);
    } else {
        mmt_reset_internal_packet_protocol(packet);
    }

    // This is a TCP flow, get the offset
    // Issue #25 (M6): the TCP data offset (doff) is a 4-bit field that, per
    // RFC 793, must be at least 5 (a 20-byte header with no options). A
    // malformed value below 5 yields a header length that is too small (and
    // would slip past the "l4_packet_len < tcphdr_len" check below for doff 0),
    // so reject the packet before deriving any offsets from it.
    if (packet->tcp->doff < TCP_DOFF_MIN_WORDS) {
        MMT_LOG( PROTO_TCP, MMT_LOG_DEBUG, "*** Warning: malformed packet (tcp data offset < 5)\n" );
        return MMT_CLASSIFY_SKIP;
    }
    uint16_t tcphdr_len = packet->tcp->doff * TCP_DOFF_WORD_BYTES; //TCP header length

    packet->l4_protocol = 6; /* TCP for sure ;) */

    if( packet->l4_packet_len < tcphdr_len ) {
        MMT_LOG( PROTO_TCP, MMT_LOG_DEBUG, "*** Warning: malformed packet (tcp length mismatch)\n" );
        return MMT_CLASSIFY_SKIP;
    }

    packet->payload_packet_len = packet->l4_packet_len - tcphdr_len;
    packet->payload = ((uint8_t *) packet->tcp) + tcphdr_len;
    /* F-BUG-107/#195: l4_packet_len derives from the IP total length and can
     * exceed the captured bytes on truncated pcaps — clamp payload_packet_len
     * to what data[] actually holds so every payload[] read stays in bounds.
     * Synthetic harness packets may carry no p_hdr — skip the clamp then. */
    if (ipacket->p_hdr != NULL) {
        /* uintptr subtraction wraps huge when payload < data -> fails check */
        uintptr_t poff = (uintptr_t)packet->payload - (uintptr_t)ipacket->data;
        uint32_t avail = ( poff < ipacket->p_hdr->caplen )
            ? (uint32_t)(ipacket->p_hdr->caplen - (uint32_t)poff) : 0;
        if( packet->payload_packet_len > avail )
            packet->payload_packet_len = avail;
    }
    packet->actual_payload_len = packet->payload_packet_len;
    packet->https_server_name.ptr = NULL;
    packet->https_server_name.len = 0;

    /* check for new tcp syn packets, here
     * idea: reset detection state if a connection is unknown
     */
     if (packet->tcp!=NULL
        && packet->tcp->syn != 0
        && packet->tcp->ack == 0
        && packet->flow != NULL
        && ipacket->session->packet_count == 0 /*First packet of the flow*/
        && packet->flow->detected_protocol_stack[0] == PROTO_UNKNOWN) {

        memset(packet->flow, 0, sizeof (*(packet->flow))); //BW - TODO(#330): Is this memset needed? the syn should be
        //seen at the start of the flow, this should have been set to zero
        //at the creation of the flow!!! Check this out
        MMT_LOG(PROTO_UNKNOWN, packet,
                MMT_LOG_DEBUG,
                "%s:%u: tcp syn packet for unknown protocol, reset detection state\n", __FUNCTION__, __LINE__);
        }

    mmt_connection_tracking(ipacket, index);

    if (packet->flow == NULL && packet->tcp != NULL) {
        return MMT_CLASSIFY_SKIP;
    }
    // Update segment list
    if (packet->payload_packet_len > 0) {
        /* Issue #245 (F-PERF-004/006, F-BUG-038): the pending store is a
         * bounded seq-sorted list backed by reclaimable bump blocks; in-order
         * arrivals append through a tail pointer and consumed segments are
         * released at drain time instead of on session teardown. */
        tcp_reasm_offer(ipacket->session,
                        ipacket->session->last_packet_direction,
                        ipacket->packet_id,
                        ntohl(packet->tcp->seq), ntohl(packet->tcp->ack),
                        packet->payload, packet->payload_packet_len);
        debug("[tcp_pre_classification_function_with_reassemble] dir %u\n",
              (unsigned) ipacket->session->last_packet_direction);
    }
    //Set the offset for the next proto anyway! we might not get there
    ipacket->proto_headers_offset->proto_path[index + 1] = tcphdr_len;
    invalidate_packet_offset_cache(ipacket); // Issue #19: direct offset write

    MMT_SAVE_AS_BITMASK(packet->detection_bitmask, packet->detected_protocol_stack[0]);

    /* build selction packet bitmask */
    packet->mmt_selection_packet |= (MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

    if (packet->payload_packet_len != 0) {
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;
    }

    if (packet->tcp_retransmission == 0) {
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;
    }

    // Issue #99 (PERF-5 / ACC-17): once an *unknown* TCP flow exceeds a bounded
    // packet budget, give up classifying it, mirroring the UDP stop-guard
    // (proto_udp.c:71). Returning 0 makes proto_packet_classify_next() skip both
    // the ~99-checker chain walk AND post-classification for the rest of the
    // flow's life, so long-lived unknown TCP flows stop re-scanning every packet.
    // The 2x threshold matches UDP. The give-up is gated on the flow still being
    // unknown: post-classification re-asserts an already-classified flow's
    // per-packet protocol path on every packet, so an unconditional give-up would
    // drop that path and misreport long classified flows (e.g. FTP) as unknown.
    if (packet->flow != NULL
        && packet->flow->detected_protocol_stack[0] == PROTO_UNKNOWN
        && ipacket->session->packet_count > (CFG_CLASSIFICATION_THRESHOLD * 2)) {
        return MMT_CLASSIFY_SKIP;
    }

    return MMT_CLASSIFY_CONTINUE;
}


int tcp_post_classification_function(ipacket_t * ipacket, unsigned index) {
    int a;
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    classified_proto_t retval;
    // retval.offset = 0;
    // retval.proto_id = 0;
    retval.status = NonClassified;
    retval.offset = packet->tcp->doff * TCP_DOFF_WORD_BYTES; //TCP header length

    a = packet->detected_protocol_stack[0];
    ////////////////////////////////////////////////
    retval.proto_id = a;

    int new_retval = 0;
    // if (retval.proto_id == PROTO_UNKNOWN && ipacket->session->packet_count >= CFG_CLASSIFICATION_THRESHOLD) {
    if (retval.proto_id == PROTO_UNKNOWN || retval.proto_id == PROTO_GTP) {
        // LN: Check if the protocol id in the last index of protocol hierarchy is not PROTO_UDP -> do not try to classify more - external classification
        if(ipacket->proto_hierarchy->proto_path[ipacket->proto_hierarchy->len - 1]!=PROTO_TCP){
            return new_retval;
        }
        // Issue #87: the "different strategies" this fallback asked for are
        // the DPI profiles — each of the heuristic levers below (IP-range,
        // then port) is gated by its own profile toggle on the handler.
        /* The protocol is unkown and we reached the classification threshold! Try with IP addresses and port numbers before setting it as unkown */
        if (ipacket->mmt_handler->ip_address_classify == 1){
            retval.proto_id = get_proto_id_from_address(ipacket);
        }
        if(retval.proto_id == PROTO_UNKNOWN && ipacket->mmt_handler->port_classify != 0) {
            retval.proto_id =  mmt_guess_protocol_by_port_number(ipacket);
        }
        if (retval.proto_id != PROTO_UNKNOWN){
            retval.status = Classified;
            new_retval = set_classified_proto(ipacket, index + 1, retval);}
        else{
            //LN: Add protocol unknown after TCP
            retval.status = Classified;
            return set_classified_proto(ipacket, index + 1, retval);
        }
    } else {
        /* now shift and insert */
        int stack_size = packet->flow->protocol_stack_info.current_stack_size_minus_one;

        for (a = stack_size; a >= 0; a--) {
            if (packet->flow->detected_protocol_stack[a] != PROTO_UNKNOWN) {
                if ((a > 0 && packet->flow->detected_protocol_stack[a] != packet->flow->detected_protocol_stack[a - 1]) || (a == 0)) {
                    index++;
                    retval.proto_id = packet->flow->detected_protocol_stack[a];
                    retval.status = Classified;
                    new_retval = set_classified_proto(ipacket, index, retval);
                    retval.offset = 0; //From the second proto the offset is the same! //TODO(#330): check this out
                }
            }
        }
    }
    return new_retval;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int update_tcp_protocol(int action_id){
    protocol_t * protocol_struct = get_protocol_struct_by_id(PROTO_TCP);
    switch (action_id)
    {
        case TCP_ENABLE_REASSEMBLE:
        // Enable tcp_action
            mmt_debug_log("[active_tcp_reassembly] action_id: %d", action_id);
            register_session_data_cleanup_function(protocol_struct, clean_session_payload);
            register_pre_post_classification_functions(protocol_struct, tcp_pre_classification_function_with_reassemble, tcp_post_classification_function);
            return 1;
        case TCP_DISABLE_REASSEMBLE:
            mmt_debug_log("[active_tcp_reassembly] action_id: %d", action_id);
            register_session_data_cleanup_function(protocol_struct, NULL);
            register_pre_post_classification_functions(protocol_struct, tcp_pre_classification_function, tcp_post_classification_function);
            return 1;
        default:
            mmt_debug_log("[active_tcp_reassembly] Not implemented yet! %d", action_id);
            break;
    }
    return 0;
}

int init_proto_tcp_struct() {

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TCP, PROTO_TCP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < TCP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &tcp_attributes_metadata[i]);
        }
        register_pre_post_classification_functions(protocol_struct, tcp_pre_classification_function, tcp_post_classification_function);
        protocol_struct->update_protocol_fct = &update_tcp_protocol;
        return register_protocol(protocol_struct, PROTO_TCP);
    } else {
        return 0;
    }
}
