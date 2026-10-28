#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include "packet_processing.h"
#include "mmt_core.h"
#include "memory.h"
#include "plugins_engine.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <pthread.h>
// #include "libntoh.h"

static inline
void cleanup_timedout_sessions(mmt_session_t * timed_out_session) {
    timed_out_session->mmt_handler->active_sessions_count--;
    int i = 0;

    // Clean session data for the different protocols in the session's protocol path
    // (bounded by PROTO_PATH_SIZE: a corrupt len must not read past proto_path[])
    int path_len = timed_out_session->proto_path.len;
    if (path_len > PROTO_PATH_SIZE) path_len = PROTO_PATH_SIZE;
    for (; i < path_len; i++) {
        protocol_t *cleanup_proto = get_protocol_struct_by_id(timed_out_session->proto_path.proto_path[i]);
        if (cleanup_proto != NULL && cleanup_proto->session_data_cleanup != NULL) {
            cleanup_proto->session_data_cleanup(timed_out_session, i);
        }
    }

    //Update the protocol statistics to indicate the session timeout
    update_proto_stats_on_session_timeout(timed_out_session, NULL);

    // Clean the session context — F-BUG-014 (issue #199): the callback is
    // optional (register_sessionizer_function accepts NULL) and the container
    // context itself may be unset; never invoke through a NULL pointer.
    protocol_instance_t * container = (protocol_instance_t *) timed_out_session->protocol_container_context;
    if (container != NULL && container->protocol != NULL && container->protocol->session_context_cleanup != NULL) {
        container->protocol->session_context_cleanup(container,
                timed_out_session, NULL);
    }
}

/* Expire one session: user expiry handler, then cleanup (which frees it).
 * Issue #499 (F-BUG-001): the session's reference on its tunnel parent is
 * dropped only once the session is gone, so the parent is still alive while
 * the expiry handler and the cleanup run. `release_parent` is 0 only on the
 * last-resort teardown drain, which no longer trusts the parent pointer. */
static void expire_session(mmt_handler_t * mmt_handler, mmt_session_t * session, int release_parent) {
    mmt_session_t * parent = session->parent_session;

    //Call user handler for timed out sessions
    if (mmt_handler->session_expiry_handler.handler_fct) {
        mmt_handler->session_expiry_handler.handler_fct(session, mmt_handler->session_expiry_handler.args);
    }

    cleanup_timedout_sessions(session);

    if (release_parent && parent != NULL && parent->live_children > 0) {
        parent->live_children--;
    }
}

/* Issue #499: a tunnel parent whose children are still live is not expired;
 * it is re-armed at the first second the current sweep has not covered
 * (process_timedout_sessions() publishes it in last_expiry_timeout before
 * sweeping), so the next sweep — or the next teardown drain round — sees it
 * again once its children are gone. */
static void defer_parent_expiry(mmt_handler_t * mmt_handler, mmt_session_t * session) {
    uint32_t old_milestone = session->session_timeout_milestone;
    uint32_t milestone = old_milestone + 1;
    if (milestone < mmt_handler->last_expiry_timeout) milestone = mmt_handler->last_expiry_timeout;
    if (milestone <= old_milestone) milestone = old_milestone; // uint32 wrap: stay put
    if (insert_session_timeout_milestone(mmt_handler, milestone, session) != MMT_TIMEOUT_NOMEM) {
        session->session_timeout_milestone = milestone;
    } else if (insert_session_timeout_milestone(mmt_handler, old_milestone, session) == MMT_TIMEOUT_NOMEM) {
        /* Freeing it would leave its children dangling: keep it alive and
         * unreachable from the ring (a leak, never a use-after-free). */
        mmt_debug_log("[error] defer_parent_expiry - cannot re-arm a tunnel parent\n");
    }
}

static void expire_session_list(mmt_handler_t * mmt_handler, mmt_session_t * timed_out_session, int honour_children) {
    mmt_session_t * safe_to_delete_session;
    while (timed_out_session != NULL) {
        safe_to_delete_session = timed_out_session;
        timed_out_session = timed_out_session->next;

        if (honour_children && safe_to_delete_session->live_children > 0) {
            defer_parent_expiry(mmt_handler, safe_to_delete_session);
            continue;
        }
        expire_session(mmt_handler, safe_to_delete_session, honour_children);
    }
}

void force_sessions_timeout(void * timeout_milestone, void * milestone_sessions_list, void * args) {
    (void) timeout_milestone;
    expire_session_list((mmt_handler_t *) args, (mmt_session_t *) milestone_sessions_list, 1);
}

static void force_sessions_timeout_unconditionally(void * timeout_milestone, void * milestone_sessions_list, void * args) {
    (void) timeout_milestone;
    expire_session_list((mmt_handler_t *) args, (mmt_session_t *) milestone_sessions_list, 0);
}

void expire_all_sessions(mmt_handler_t * mmt_handler) {
    /* Issue #499: each drain round expires every session without live
     * children and re-arms the parents that still have some, so a tunnel
     * child always goes before its parent. A child sits at a deeper protocol
     * index than its parent, so nesting is at most PROTO_PATH_SIZE deep and
     * that many rounds empty the ring; the unconditional drain after them
     * only runs if a parent reference count never drained. */
    unsigned round;
    for (round = 0; round <= PROTO_PATH_SIZE; round++) {
        if (timeout_drain_milestones(mmt_handler, force_sessions_timeout) == 0) return;
    }
    timeout_drain_milestones(mmt_handler, force_sessions_timeout_unconditionally);
}

void session_timer_handler_callback(void * timeout_milestone, void * milestone_sessions_list, void * args) {
    mmt_handler_t * mmt_handler = (mmt_handler_t *) args;
    mmt_session_t * current_session = (mmt_session_t *) milestone_sessions_list;
    if (mmt_handler->session_timer_handler.session_timer_handler_fct != NULL) {
        while (current_session != NULL) {
            // mmt_stream_printf(stdout, "session_timer_handler_callback and session id: %"PRIu64"\n",current_session->session_id);
            if (mmt_handler->session_timer_handler.no_fragmented && current_session->is_fragmenting) {
                // Skip processing the session that contains a fragmented packet.
                current_session = current_session->next;
            } else {
                mmt_handler->session_timer_handler.session_timer_handler_fct(current_session, mmt_handler->session_timer_handler.args);
                current_session = current_session->next;
            }
        }
    } else {
        mmt_debug_log("There is not any session_timer_handler\n");
    }
}

/* 1 when `session` is one the packet being processed still uses: its
 * current session or one of that session's tunnel ancestors. */
static int is_packet_session(const ipacket_t * ipacket, const mmt_session_t * session) {
    const mmt_session_t * p;
    if (ipacket == NULL) return 0;
    for (p = ipacket->session; p != NULL; p = p->parent_session) {
        if (p == session) return 1;
    }
    return 0;
}

void process_outofmemory_force_sessions_timeout(mmt_handler_t * mmt_handler, ipacket_t * ipacket) {
    uint32_t timeout_slot_to_free = mmt_handler->last_expiry_timeout;
    uint32_t count = 0;
    uint32_t scanned = 0;
    uint32_t first_skipped = 0;
    int skipped = 0;
    while (count < MMT_OOM_SWEEP_BUDGET && scanned < MMT_OOM_SWEEP_BUDGET) {
        mmt_session_t * timed_out_session = get_timed_out_session_list(mmt_handler, timeout_slot_to_free);
        mmt_session_t * safe_to_delete_session;
        while (timed_out_session != NULL && count < MMT_OOM_SWEEP_BUDGET) {
            safe_to_delete_session = timed_out_session;
            timed_out_session = timed_out_session->next;

            /* Issue #499: a tunnel parent outlives its children, and the
             * sessions of the packet in flight must survive this sweep. */
            if (safe_to_delete_session->live_children > 0 ||
                    is_packet_session(ipacket, safe_to_delete_session)) {
                if (!skipped) {
                    skipped = 1;
                    first_skipped = timeout_slot_to_free;
                }
                continue;
            }
            /* Issue #500 (F-BUG-003): unlink each session before freeing it —
             * the milestone disappears with its last session, so a budget
             * stop mid-list leaves the rest of the list linked and expirable
             * (it used to delete the whole milestone, orphaning them). */
            force_session_timeout(mmt_handler, safe_to_delete_session);
            count++;
            expire_session(mmt_handler, safe_to_delete_session, 1);
        }
        if (count >= MMT_OOM_SWEEP_BUDGET) break; // resume point keeps its remaining sessions
        timeout_slot_to_free++;
        scanned++;
    }
    /* Issues #499/#500: resume the next sweep at the first milestone this one
     * skipped (milestones are walked in ascending order), not past it — the
     * end-of-packet process_timedout_sessions() then revisits it, where
     * force_sessions_timeout() expires a parent whose children this sweep
     * freed, or re-arms it with defer_parent_expiry(). Advancing past it left
     * an overdue skipped session linked below last_expiry_timeout forever. */
    mmt_handler->last_expiry_timeout =
        (skipped && first_skipped < timeout_slot_to_free) ? first_skipped : timeout_slot_to_free;
}

void process_timedout_sessions(mmt_handler_t * mmt_handler, uint32_t current_seconds) {
    if (current_seconds > mmt_handler->last_expiry_timeout && mmt_handler->last_expiry_timeout != 0) {
        uint32_t range_lo = mmt_handler->last_expiry_timeout;
        /* Issue #499: publish the end of this sweep first — a tunnel parent
         * deferred during it re-arms at or after current_seconds, where the
         * next sweep starts. */
        mmt_handler->last_expiry_timeout = current_seconds;
        /* Issue #306: the pcap record timestamp is attacker-controlled — a
         * mutated packet can jump billions of seconds ahead, and the old
         * per-second loop here iterated once per second across the whole
         * gap (a fuzz-discovered CPU denial of service). The ring helper
         * expires exactly the same milestone range in a pass bounded by
         * O(min(gap, ring capacity)). */
        timeout_expire_milestones_range(mmt_handler,
                range_lo, current_seconds,
                force_sessions_timeout);
        /* Issue #201 (F-BUG-020): piggyback the fragment-map expiry sweep on
         * this existing once-per-second expiry pass — armed by the TCP/IP
         * plugin the first time a fragment is reassembled. Issue #418: the
         * IPv6 map (ip6_streams) is swept too — stale partial IPv6 datagrams
         * used to linger until completion, eviction or handler close. */
        if (mmt_handler->frag_map_sweep_fct != NULL) {
            if (mmt_handler->ip_streams != NULL)
                mmt_handler->frag_map_sweep_fct(mmt_handler->ip_streams, current_seconds);
            if (mmt_handler->ip6_streams != NULL)
                mmt_handler->frag_map_sweep_fct(mmt_handler->ip6_streams, current_seconds);
        }
    }
    mmt_handler->last_expiry_timeout = current_seconds;
}

uint64_t get_active_session_count(mmt_handler_t *mmt_handler) {
    if (mmt_handler == NULL) {
        return MMT_INVALID_SESSION_COUNT;
    } else {
        return mmt_handler->active_sessions_count;
    }
}

bool set_default_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value){
    if(mmt_handler==NULL) return 0;
    mmt_handler->default_session_timed_out = timedout_value;
    return 1;
}

bool set_long_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value){
    if(mmt_handler==NULL) return 0;
    mmt_handler->long_session_timed_out = timedout_value;
    return 1;
}

bool set_short_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value){
    if(mmt_handler==NULL) return 0;
    mmt_handler->short_session_timed_out = timedout_value;
    return 1;
}

bool set_live_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value){
    if(mmt_handler==NULL) return 0;
    mmt_handler->live_session_timed_out = timedout_value;
    return 1;
}

/* Issue #245 (F-PERF-006 / F-BUG-038): configure the per-flow ceiling on TCP
 * reassembly bytes. Issue #380 (F-PERF-002): it bounds reserved storage —
 * pending-segment blocks incl. headers + both image capacities (see
 * mmt_core.h). Passing 0 restores the default. */
bool set_tcp_reassembly_limit(mmt_handler_t *mmt_handler,uint32_t bytes){
    if(mmt_handler == NULL) return 0;
    mmt_handler->tcp_reassembly_limit =
        (bytes != 0) ? bytes : MMT_TCP_REASSEMBLY_LIMIT_DEFAULT;
    return 1;
}

bool set_fragment_in_packet(mmt_handler_t *mmt_handler,uint32_t fragment_in_packet){
    if ( mmt_handler == NULL ) return 0;
    mmt_handler->fragment_in_packet = fragment_in_packet;
    return 1;
}

bool set_fragmented_packet_in_session(mmt_handler_t *mmt_handler,uint32_t fragmented_packet_in_session){
    if ( mmt_handler == NULL ) return 0;
    mmt_handler->fragmented_packet_in_session = fragmented_packet_in_session;
    return 1;
}

bool set_fragment_in_session(mmt_handler_t *mmt_handler,uint32_t fragment_in_session){
    if ( mmt_handler == NULL ) return 0;
    mmt_handler->fragment_in_session = fragment_in_session;
    return 1;
}

void set_session_timeout_delay(mmt_session_t * session, uint32_t timeout_delay) {
    session->session_timeout_delay = timeout_delay;
}

/* Issue #499 (F-BUG-001): a tunnel parent never expires before its
 * children — raise every ancestor whose milestone is earlier than this
 * session's to it. Best effort: an ancestor that cannot be moved keeps its
 * milestone, and its expiry is deferred while its children live. */
static void hold_ancestors_milestone(mmt_handler_t * mmt_handler, mmt_session_t * session) {
    uint32_t milestone = session->session_timeout_milestone;
    mmt_session_t * p;
    for (p = session->parent_session; p != NULL; p = p->parent_session) {
        uint32_t old_milestone = p->session_timeout_milestone;
        if (old_milestone >= milestone) continue;
        if (update_session_timeout_milestone(mmt_handler, milestone, old_milestone, p) != MMT_TIMEOUT_NOMEM) {
            p->session_timeout_milestone = milestone;
        } else {
            (void) insert_session_timeout_milestone(mmt_handler, old_milestone, p);
        }
    }
}

/**
 * Initialises the bookkeeping fields of a freshly detected session (issue
 * #240, F-CLEAN-008): the raw field zero-init half of the session
 * constructor, kept as one named function so the constructor below no longer
 * mixes a plugin callback with forty hand-written field stores.
 * @param mmt_handler         handler that owns the session counters
 * @param session             session returned by the protocol's sessionizer
 * @param configured_protocol instance of the owning protocol
 * @param index               index of the owning protocol in the packet path
 */
static void init_new_session_fields(mmt_handler_t * mmt_handler, mmt_session_t * session, protocol_instance_t * configured_protocol, unsigned index) {
    // init session data
    session->session_id = mmt_handler->sessions_count + 1;
    session->next = NULL;
    session->previous = NULL;

    session->fragmented_packet_count = 0;
    session->fragment_count = 0;
    session->is_fragmenting = 0;

    session->packet_count = 0;
    session->packet_cap_count = 0;
    session->data_packet_count = 0;
    session->data_volume = 0;
    session->data_cap_volume = 0;
    session->data_byte_volume = 0;

    session->packet_count_direction[1] = 0;
    session->data_volume_direction[1] = 0;
    session->packet_cap_count_direction[1] = 0;
    session->data_cap_volume_direction[1] = 0;
    session->data_packet_count_direction[1] = 0;
    session->data_byte_volume_direction[1] = 0;

    session->packet_count_direction[0] = 0;
    session->data_volume_direction[0] = 0;
    session->packet_cap_count_direction[0] = 0;
    session->data_cap_volume_direction[0] = 0;
    session->data_packet_count_direction[0] = 0;
    session->data_byte_volume_direction[0] = 0;

    /* Issue #255 (F-PERF-010): the subsession counters + per-direction path
     * copies live in the lazily-allocated tunnel-parent extension — a fresh
     * session has no children, so it starts NULL. */
    session->children_stats = NULL;
    session->live_children = 0; // issue #499: no tunnel child yet

    session->tcp_retransmissions = 0;
    session->tcp_outoforders = 0;
    session->status = NonClassified;
    session->protocol_container_context = configured_protocol;
    session->session_protocol_index = index;
    session->tcp_retransmissions = 0;
    session->tcp_outoforders = 0;
    /* Issue #245: the bounded TCP reassembly extension is allocated lazily on
     * the first TCP payload segment (see mmt_tcp_reasm_t). */
    session->tcp_reasm = NULL;
    /* Issue #252 (F-PERF-002): no layer has a recorded winning checker yet —
     * the first classifications run the full walk and fill the slots. */
    memset(session->proto_checkers, 0, sizeof(session->proto_checkers));
    mmt_handler->sessions_count += 1;
    mmt_handler->active_sessions_count += 1;
}

/**
 * Session-constructor half of proto_session_management() (issue #240,
 * F-CLEAN-008): wires up a freshly sessionized session — field init,
 * timestamps, protocol-path copies, timeout milestone, parent linkage — then
 * runs the plugin's session_data_init callback.
 * @param  ipacket             packet that triggered the new session
 * @param  configured_protocol instance of the owning protocol
 * @param  session             session returned by the sessionizer
 * @param  index               index of the owning protocol in the packet path
 * @return                     1 when the session is live, 0 when it was
 *                             destroyed on the double-OOM path
 */
static int setup_new_session(ipacket_t * ipacket, protocol_instance_t * configured_protocol, mmt_session_t * session, unsigned index) {
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    init_new_session_fields(mmt_handler, session, configured_protocol, index);

    //This corresponds to the first packet of this session, set the session start time
    session->s_init_time.tv_sec = ipacket->p_hdr->ts.tv_sec;
    session->s_init_time.tv_usec = ipacket->p_hdr->ts.tv_usec;

    //Set the session protocol path and headers offset to what we already know from the ipacket
    memcpy(&session->proto_path, ipacket->proto_hierarchy, sizeof (int) + 4 * ipacket->proto_hierarchy->len);
    memcpy(&session->proto_headers_offset, ipacket->proto_headers_offset, sizeof (int) + 4 * ipacket->proto_headers_offset->len);
    memcpy(&session->proto_classif_status, ipacket->proto_classif_status, sizeof (int) + 4 * ipacket->proto_classif_status->len);

    //Set the mmt_handler that is processing this session
    session->mmt_handler = mmt_handler;

    // session timeout initialization
    // session->session_timeout_delay = configured_protocol->protocol->session_timeout_delay;
    session->session_timeout_delay = mmt_handler->default_session_timed_out;
    session->session_timeout_milestone = session->session_timeout_delay + ipacket->p_hdr->ts.tv_sec;

    /* Issue #499: an embedded session pins its tunnel parent (the packet's
     * current session) before anything can sweep — the OOM sweep below
     * skips sessions with live children. */
    session->parent_session = ipacket->session; // NULL: no session encapsulation
    if (session->parent_session != NULL) {
        session->parent_session->live_children++;
    }

    if (insert_session_timeout_milestone(mmt_handler, session->session_timeout_milestone, session) == MMT_TIMEOUT_NOMEM) {
        //If we get here, then there is an out of memory problem! we should deal with
        process_outofmemory_force_sessions_timeout(ipacket->mmt_handler, ipacket);
        if (insert_session_timeout_milestone(mmt_handler, session->session_timeout_milestone, session) == MMT_TIMEOUT_NOMEM) {
            // Double OOM: remain without milestone => session never time-outable (F-BUG-023).
            // Destroy session so we do not leak a non-time-outable flow.
            if (configured_protocol->sessions_map &&
                    delete_session_from_protocol_context(configured_protocol, session->session_key) == 0) {
                /* Issue #327: the session stays reachable through the
                 * sessions map after its memory is freed below — that is
                 * worse than a leaked map slot, so make it loud. The
                 * destroy continues regardless: the memory is owned here. */
                mmt_debug_log( "[error] setup_new_session - delete_session_from_protocol_context failed during double-OOM rollback\n");
            }
            if (configured_protocol->protocol->session_data_cleanup)
                configured_protocol->protocol->session_data_cleanup(session, session->session_protocol_index);
            mmt_handler->active_sessions_count--;
            mmt_handler->sessions_count--;
            if (session->parent_session != NULL) {
                session->parent_session->live_children--; // issue #499: unpin
            }
            /* Issue #255: NULL today (a fresh session is never a tunnel
             * parent) — kept for parity with the plugin destructor in case
             * extension allocation ever moves earlier. */
            mmt_free(session->children_stats);
            mmt_free(session);
            return 0;
        }
    }

    if (ipacket->session == NULL) {
        //No session encapsulation; parent is NULL
        ipacket->session = session;
    } else {
        /* Issue #327: embedded session — the packet's current session is the
         * tunnel parent of this one (linked above). Issue #499: it must not
         * expire before this child. */
        hold_ancestors_milestone(mmt_handler, session);
        /* Issue #255 (F-PERF-010): this turns ipacket->session into a tunnel
         * parent — materialize its children-stats extension now so the
         * counter-update walk below and the per-direction path copies find it
         * allocated (best-effort: it may stay NULL under OOM). */
        (void) mmt_session_get_children_stats(ipacket->session);
        // Share the session data from the parent session up to the index of the new detected encapsulated session
        unsigned i;
        for (i = 0; i < index; i++) {
            session->session_data[i] = session->parent_session->session_data[i];
        }
    }

    //Initialize its session data if such initialization function exists
    if (configured_protocol->protocol->session_data_init != NULL) {
        // debug("[PACKET_PROCESS-]> session_data_init - 0 : %"PRIu64" %p",ipacket->packet_id,(generic_session_data_initialization_function) configured_protocol->protocol->session_data_init);
        configured_protocol->protocol->session_data_init(ipacket, index);
    }
    //Mark this protocol as done with the classification process
    ipacket->proto_classif_status->proto_path[index] = PROTO_CLASSIFICATION_DONE;
    return 1;
}

/**
 * Manage session of this protocol
 * @param  ipacket             packet to process
 * @param  configured_protocol instance of protocol
 * @param  index               index of protocol
 * @return                     0 if this packet does not belong to a new session
 *                             1 if this packet does belong to a new session. New session will be created
 */
int proto_session_management(ipacket_t * ipacket, protocol_instance_t * configured_protocol, unsigned index) {
    int classify_status = ipacket->proto_classif_status->proto_path[index];
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    int is_new_session = 0;

    /* Issue #327: embedded sessions are handled — the sessionizer runs at
     * every protocol index and setup_new_session() links the new session to
     * the packet's current session as its tunnel parent and shares the
     * parent's per-index session data. */
    mmt_session_t * session = ipacket->session;
    if (configured_protocol->protocol->has_session) { // Sessionize packet only if such a function exists!
        session = (mmt_session_t *) configured_protocol->protocol->sessionize(configured_protocol, ipacket, index, & is_new_session);
        /*
         * When a protocol has a session context it is not always necessary that the packet being processed
         * will be put into a corresponding session. This is the case when IP fragmentation is encountered.
         * Therefore, always test the return value of the sessionizer function!
         * There is a valid reason to be paranoiac
         */
        if (session != NULL) { // Check if a session has been detected. This is
            if (is_new_session) {
                is_new_session = NEW_SESSION; //Enforce the use of "NEW_SESSION" value
                if (!setup_new_session(ipacket, configured_protocol, session, index)) {
                    // Double OOM inside the session constructor: the session
                    // was already destroyed — report "no new session".
                    return 0;
                }
            } else {
                // session timeout update
                if (ipacket->p_hdr->ts.tv_sec > session->s_last_activity_time.tv_sec) {// No need to update the timeout if we are still in the same second
                    //if(!session->force_timeout) { //Sessions with force timeout should not be updated! they need to timeout :)
                    uint32_t old_milestone = session->session_timeout_milestone;
                    uint32_t new_milestone = session->session_timeout_delay + ipacket->p_hdr->ts.tv_sec;
                    /* Issue #499: never shorten a tunnel parent's milestone
                     * below the one its children raised it to. */
                    if (session->live_children > 0 && new_milestone < old_milestone) {
                        new_milestone = old_milestone;
                    }
                    if (update_session_timeout_milestone(mmt_handler, new_milestone, old_milestone, session) == MMT_TIMEOUT_NOMEM) {
                        process_outofmemory_force_sessions_timeout(ipacket->mmt_handler, ipacket);
                        if (insert_session_timeout_milestone(mmt_handler, new_milestone, session) == MMT_TIMEOUT_NOMEM) {
                            // Double OOM: keep old milestone so session stays time-outable (F-BUG-023).
                            insert_session_timeout_milestone(mmt_handler, old_milestone, session);
                            // do not advance milestone
                        } else {
                            session->session_timeout_milestone = new_milestone;
                        }
                    } else {
                        session->session_timeout_milestone = new_milestone;
                    }
                    //}
                    /* Issue #499: carry a later child milestone up the tunnel. */
                    if (session->parent_session != NULL) {
                        hold_ancestors_milestone(mmt_handler, session);
                    }
                }
            }

            //Now update the packet structure to point to the flow and the protocol hierarchy info
            if(likely(!ipacket->mmt_handler->has_reassembly)){
                ipacket->proto_headers_offset = &session->proto_headers_offset;
                ipacket->proto_headers_offset_owned = 0; // embedded in the session — never freed
                // Issue #19: offset buffer swapped to the session's stored
                // offsets — invalidate the memoized cumulative-offset cache.
                ipacket->internal_cumulative_offset_valid = 0;

            }else{
                /* Issue #245 (F-PERF-003): copy the session offsets into the
                 * ipacket's embedded internal_proto_headers_offset — same
                 * per-packet snapshot semantics as the old per-layer heap
                 * copy, with zero allocation. proto_session_management runs
                 * once per protocol layer (index+1 recursion); each embedded
                 * session layer refreshes the snapshot. */
                ipacket->proto_headers_offset = &ipacket->internal_proto_headers_offset;
                ipacket->proto_headers_offset_owned = 0; // embedded in the ipacket — never freed
                memcpy(ipacket->proto_headers_offset,&session->proto_headers_offset,sizeof(proto_hierarchy_t));
                // Issue #19: offset buffer replaced — invalidate the memoized
                // cumulative-offset cache.
                ipacket->internal_cumulative_offset_valid = 0;
            }

            ipacket->proto_hierarchy = &session->proto_path;
            ipacket->proto_classif_status = &session->proto_classif_status;
            ipacket->session = session;

            //update the session basic statistics
            session->packet_count     ++;
            session->data_volume      += ipacket->p_hdr->len;
            session->data_cap_volume  += ipacket->total_caplen;
            session->packet_cap_count += ipacket->nb_reassembled_packets[index];
            mmt_session_t * p_session = session->parent_session;
            while(p_session) {
                /* Issue #255: children counters live in the lazily-allocated
                 * extension; a parent that still has none gets it now (NULL
                 * under OOM -> the counter update is skipped). */
                mmt_session_children_stats_t *cs = mmt_session_get_children_stats(p_session);
                if (cs != NULL) {
                    cs->sub_packet_count     ++;
                    cs->sub_data_volume      += ipacket->p_hdr->len;
                    cs->sub_data_cap_volume  += ipacket->total_caplen;
                    cs->sub_packet_cap_count += ipacket->nb_reassembled_packets[index];
                }
                p_session = p_session->parent_session;
            }

            session->s_last_activity_time.tv_sec  = ipacket->p_hdr->ts.tv_sec;
            session->s_last_activity_time.tv_usec = ipacket->p_hdr->ts.tv_usec;

        } else {
            //We arrive here if the protocol has session context but the sessionize reported NULL session
            //This might be an out of memory problem! Check this out
            if (is_new_session) {
                process_outofmemory_force_sessions_timeout(ipacket->mmt_handler, ipacket);
                is_new_session = 0;
            }
        }

    } else {
        //The protocol does not maintain sessions by it own.
        //Rather, it belongs to a session maintained by a parent protocol
        //At this point we should check if the current protocol is newly detected or reclassified
        //If this is the case, initialize its session data if required and copy its registered attributes to the session context
        if ((ipacket->session != NULL) && ((classify_status == PROTO_CLASSIFICATION_DETECTION) || (classify_status == PROTO_RECLASSIFICATION)||(classify_status == PROTO_CLASSIFICATION_UPDATE))) {
            //Initialize its session data if such initialization function exists
            if (configured_protocol->protocol->session_data_init != NULL) {
                // debug("[PACKET_PROCESS-]> session_data_init - 1 : %"PRIu64" %p",ipacket->packet_id,(generic_session_data_initialization_function) configured_protocol->protocol->session_data_init);
                configured_protocol->protocol->session_data_init(ipacket, index);
            }
            is_new_session = NEW_PROTO_IN_SESSION; //This is not a new session, rather a new protocol in the session
        }
        //Mark this protocol as done with the classification process
        ipacket->proto_classif_status->proto_path[index] = PROTO_CLASSIFICATION_DONE;
    }

    return is_new_session;
}

void process_session_timer_handler(mmt_handler_t *mmt) {
    // mmt_stream_printf(stdout, "process_session_timer_handler \n");
    session_timer_iteration_callback(mmt, session_timer_handler_callback);
}
