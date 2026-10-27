/*
 * File:   hash_utils.h
 * Author: montimage
 *
 * Created on 25 juillet 2011, 15:34
 */

#ifndef HASH_UTILS_H
#define	HASH_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include "types_defs.h"
#include "data_defs.h"
#include "packet_processing.h"
#include "mmt_core.h"

#ifdef	__cplusplus
extern "C" {
#endif

    /** Session management API — per-protocol session store helpers. */
    MMTAPI void * MMTCALL get_session_from_protocol_context_by_session_key(void * protocol_context, void * key);
    MMTAPI int MMTCALL insert_session_into_protocol_context(void * protocol_context, void * key, void * value);
    MMTAPI int MMTCALL delete_session_from_protocol_context(void * protocol_context, void * key);
    void clear_sessions_from_protocol_context(void * protocol_context);
    MMTAPI void MMTCALL protocol_sessions_iteration_callback(void * protocol_context, generic_mapspace_iteration_callback fct, void * args);
    // End of API for session management

    /* Issue #533: the core is built -fvisibility=hidden, so only MMTAPI
     * declarations are exported. The MMTAPI-marked helpers in this header
     * are internals libmmt_tcpip binds to after dlopen() — exported for the
     * plugin libraries until #534; the rest stay hidden. */

    // Per-flow session store: a hash table keyed on a packed 5-tuple. The
    // equality predicate tests two keys in one call (issue #253, F-PERF-008);
    // when equal_fct is NULL the table derives equivalence from the ordering
    // comparator as before (a == b iff !cmp(a,b) && !cmp(b,a)). The hash
    // function buckets the keys; hash_fct may be NULL (a correct but slow
    // constant hash is used as a fallback).
    void * init_session_map_space(generic_comparison_fct comp_fct, generic_hash_fct hash_fct, generic_equal_fct equal_fct);
    void delete_session_map_space(void * sessionmap);

    // Generic void*-keyed map — the same open-addressing table as the session
    // store (issue #254): hash_fct must be consistent with comp_fct equality
    // (keys equal under !cmp(a,b) && !cmp(b,a) must hash equally); NULL is a
    // correct but slow constant-hash fallback.
    MMTAPI void * MMTCALL init_map_space(generic_comparison_fct comp_fct, generic_hash_fct hash_fct);
    void * init_int_map_space(generic_int_comparison_fct comp_fct);
    int getmapsize(void * maplist);

    MMTAPI int MMTCALL insert_key_value(void * maplist, void * key, void * value);
    int insert_int_key_value(void * maplist, uint32_t key, void * value);
    int update_key_value(void * maplist, void * key, void * new_value);
    MMTAPI void * MMTCALL find_key_value(void * maplist, void * key);
    void * find_int_key_value(void * maplist, uint32_t key);
    MMTAPI int MMTCALL delete_key_value(void * maplist, void * key);
    int delete_int_key_value(void * maplist, uint32_t key);
    MMTAPI void MMTCALL clear_map_space(void * maplist);
    void clear_int_map_space(void * maplist);
    MMTAPI void MMTCALL delete_map_space(void * maplist);
    void delete_int_map_space(void * maplist);
    MMTAPI void MMTCALL mapspace_iteration_callback(void * maplist, generic_mapspace_iteration_callback fct, void * args);
    void int_mapspace_iteration_callback(void * maplist, generic_mapspace_iteration_callback fct, void * args);

    // Session-timeout index: a timing-wheel ring bounded by the live
    // milestone span (issue #254, F-PERF-013) — insert/update/delete are O(1)
    // and allocate nothing on the hot path.
    //
    // insert/update return one of the MMT_TIMEOUT_* codes below (issue #500):
    // a milestone outside the ring's maximum span is parked, which is a
    // success — only MMT_TIMEOUT_NOMEM (0) is an allocation failure.
#define MMT_TIMEOUT_NOMEM    0 /* allocation failure: the session is in no list */
#define MMT_TIMEOUT_INSERTED 1 /* linked into a ring slot */
#define MMT_TIMEOUT_PARKED   2 /* out-of-span milestone, linked into the parked index */
    void * init_timeout_milestones_index(void);
    int insert_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout, mmt_session_t * session);
    int update_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t new_timeout, uint32_t old_timeout, mmt_session_t * session);
    mmt_session_t * get_timed_out_session_list(mmt_handler_t *mmt_handler, uint32_t timeout);
    int delete_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout);
    void clear_timeout_milestones(mmt_handler_t *mmt_handler);
    int force_session_timeout(mmt_handler_t *mmt_handler, mmt_session_t * session);
    // Issue #306: bounded range expiry — dispatches fct once per live
    // milestone in [range_lo, range_hi), cost O(min(gap, ring capacity)).
    void timeout_expire_milestones_range(mmt_handler_t *mmt_handler, uint32_t range_lo, uint32_t range_hi, generic_mapspace_iteration_callback fct);
    // Issue #499: detach every live milestone and dispatch fct on each in
    // ascending order; fct may re-arm sessions for a later drain. Returns the
    // number of milestones dispatched.
    size_t timeout_drain_milestones(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct);
    void timeout_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct);
    void session_timer_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct);
    int insert_protocol_stack_into_map(uint32_t key, void * value);
    void * get_protocol_stack_from_map(uint32_t key);
    int delete_protocol_stack_from_map(uint32_t key);
    void clear_protocol_stack_map();

#ifdef	__cplusplus
}
#endif

#endif	/* HASH_UTILS_H */

