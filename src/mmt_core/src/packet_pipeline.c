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

/* Issue #193 (F-BUG-032): debug-build tripwires for the central caplen guard
 * in internal_extract_attribute(). They are compiled only in assert-enabled
 * (NDEBUG undefined) or sanitizer-instrumented builds, so production hot paths
 * pay nothing; the accessors below are always exported so test harnesses link
 * regardless of the profile the library was built with. The increments use
 * relaxed atomics, matching proto_status_load/proto_status_store above, so the
 * counters stay race-free on the multi-threaded packet path. */
#if !defined(NDEBUG) || defined(MMT_BUILD_ASAN) || defined(MMT_BUILD_TSAN)
#define MMT_CAPLEN_GUARD_STATS 1
static uint64_t mmt_caplen_guard_total = 0;        /* attributes that reached the guard */
static uint64_t mmt_caplen_guard_refused = 0;      /* attributes the guard refused */
static uint64_t mmt_caplen_guard_unvalidated = 0;  /* attributes that reached an extractor with no caplen validation (must stay 0) */
#else
#define MMT_CAPLEN_GUARD_STATS 0
#endif

uint64_t mmt_caplen_guard_total_count(void) {
#if MMT_CAPLEN_GUARD_STATS
    return __atomic_load_n(&mmt_caplen_guard_total, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

uint64_t mmt_caplen_guard_refused_count(void) {
#if MMT_CAPLEN_GUARD_STATS
    return __atomic_load_n(&mmt_caplen_guard_refused, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

uint64_t mmt_caplen_guard_unvalidated_count(void) {
#if MMT_CAPLEN_GUARD_STATS
    return __atomic_load_n(&mmt_caplen_guard_unvalidated, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

void mmt_caplen_guard_stats_reset(void) {
#if MMT_CAPLEN_GUARD_STATS
    __atomic_store_n(&mmt_caplen_guard_total, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&mmt_caplen_guard_refused, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&mmt_caplen_guard_unvalidated, 0, __ATOMIC_RELAXED);
#endif
}

/* Issue #245: TCP-reassembly instrumentation — see packet_processing.h for
 * the contract. Always-on relaxed-atomic counters; the increments sit on
 * paths that already memcpy() a whole segment, so the cost is noise. */
static uint64_t mmt_tcp_reasm_visits = 0;
static uint64_t mmt_tcp_reasm_moved = 0;
static uint64_t mmt_tcp_reasm_dropped = 0;
static int64_t mmt_tcp_reasm_live = 0;
static uint64_t mmt_reasm_packet_allocs = 0;

void mmt_tcp_reasm_stat_visit(void) {
    __atomic_add_fetch(&mmt_tcp_reasm_visits, 1, __ATOMIC_RELAXED);
}
void mmt_tcp_reasm_stat_move(uint32_t bytes) {
    __atomic_add_fetch(&mmt_tcp_reasm_moved, bytes, __ATOMIC_RELAXED);
}
void mmt_tcp_reasm_stat_drop(uint32_t bytes) {
    __atomic_add_fetch(&mmt_tcp_reasm_dropped, bytes, __ATOMIC_RELAXED);
}
void mmt_tcp_reasm_stat_live(int64_t delta) {
    __atomic_add_fetch(&mmt_tcp_reasm_live, delta, __ATOMIC_RELAXED);
}
void mmt_reassembly_stat_packet_alloc(void) {
    __atomic_add_fetch(&mmt_reasm_packet_allocs, 1, __ATOMIC_RELAXED);
}
uint64_t mmt_tcp_reasm_insert_visits(void) {
    return __atomic_load_n(&mmt_tcp_reasm_visits, __ATOMIC_RELAXED);
}
uint64_t mmt_tcp_reasm_bytes_moved(void) {
    return __atomic_load_n(&mmt_tcp_reasm_moved, __ATOMIC_RELAXED);
}
uint64_t mmt_tcp_reasm_bytes_dropped(void) {
    return __atomic_load_n(&mmt_tcp_reasm_dropped, __ATOMIC_RELAXED);
}
uint64_t mmt_tcp_reasm_resident_bytes(void) {
    int64_t v = __atomic_load_n(&mmt_tcp_reasm_live, __ATOMIC_RELAXED);
    return (v > 0) ? (uint64_t) v : 0;
}
uint64_t mmt_reassembly_packet_alloc_count(void) {
    return __atomic_load_n(&mmt_reasm_packet_allocs, __ATOMIC_RELAXED);
}

/* Issue #252 (F-PERF-002): debug-build tripwires for the classifier chain.
 * mmt_classify_checker_calls counts checker-chain probes (classify_me()
 * invocations reached by walking classify_protos, also broken down per
 * chain-owner protocol), mmt_classify_walk_skips counts the walks skipped
 * because the flow already converged, and mmt_classify_direct_calls counts
 * the O(1) dispatches to the flow's recorded owning protocol engine — the
 * winning checker keeps its per-packet role but is reached directly, not by
 * probing the chain. Same arming contract as the caplen-guard stats above:
 * assert-enabled or sanitizer builds only, relaxed atomics, always-exported
 * accessors so test harnesses link regardless of profile. */
#if !defined(NDEBUG) || defined(MMT_BUILD_ASAN) || defined(MMT_BUILD_TSAN)
#define MMT_CLASSIFY_STATS 1
static uint64_t mmt_classify_checker_calls = 0;
static uint64_t mmt_classify_checker_calls_by_proto[PROTO_MAX_IDENTIFIER];
static uint64_t mmt_classify_walk_skips = 0;
static uint64_t mmt_classify_direct_calls = 0;
#else
#define MMT_CLASSIFY_STATS 0
#endif

uint64_t mmt_classify_checker_call_count(void) {
#if MMT_CLASSIFY_STATS
    return __atomic_load_n(&mmt_classify_checker_calls, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

uint64_t mmt_classify_checker_calls_for_proto(uint32_t proto_id) {
#if MMT_CLASSIFY_STATS
    if (proto_id < PROTO_MAX_IDENTIFIER) {
        return __atomic_load_n(&mmt_classify_checker_calls_by_proto[proto_id], __ATOMIC_RELAXED);
    }
#else
    (void) proto_id;
#endif
    return 0;
}

uint64_t mmt_classify_walk_skip_count(void) {
#if MMT_CLASSIFY_STATS
    return __atomic_load_n(&mmt_classify_walk_skips, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

uint64_t mmt_classify_direct_call_count(void) {
#if MMT_CLASSIFY_STATS
    return __atomic_load_n(&mmt_classify_direct_calls, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

void mmt_classify_stats_reset(void) {
#if MMT_CLASSIFY_STATS
    __atomic_store_n(&mmt_classify_checker_calls, 0, __ATOMIC_RELAXED);
    /* Atomic stores — a plain memset would race with in-flight relaxed
     * increments on the TSan profile. */
    for (uint32_t i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        __atomic_store_n(&mmt_classify_checker_calls_by_proto[i], 0, __ATOMIC_RELAXED);
    }
    __atomic_store_n(&mmt_classify_walk_skips, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&mmt_classify_direct_calls, 0, __ATOMIC_RELAXED);
#endif
}

/**
 * Internal function for extracting attribute data.
 * @param ipacket pointer to internal packet structure
 * @param tmp_attr_ref pointer to the attribute structure
 * @param index index of the protocol in the path
 * @return a positive value if the extraction was done, zero otherwise
 */
int internal_extract_attribute(const ipacket_t * ipacket, struct attribute_internal_struct * tmp_attr_ref, unsigned index) {
    if (ipacket == NULL || ipacket->p_hdr == NULL || ipacket->data == NULL || tmp_attr_ref == NULL) return 0;
#if MMT_CAPLEN_GUARD_STATS
    __atomic_add_fetch(&mmt_caplen_guard_total, 1, __ATOMIC_RELAXED);
    int caplen_validated = 0;
#endif
    /* Central caplen guard (F-BUG-001; issue #193 / F-BUG-032 extends the same
     * floor to POSITION_NOT_KNOWN attributes): an extractor may only run when
     * the extent it declares lies inside the captured bytes.
     *   - fixed offset (position_in_packet >= 0):
     *         proto_offset + position_in_packet + data_len <= caplen
     *   - POSITION_NOT_KNOWN (position_in_packet < 0): the extractor computes
     *     its own offset, so the floor is proto_offset + data_len <= caplen —
     *     and with no declared data_len, the protocol's first captured byte
     *     must at least exist. */
    int proto_offset = get_packet_offset_at_index(ipacket, index);
    if (proto_offset < 0) return 0;
    size_t extent = (size_t) proto_offset;
    if (tmp_attr_ref->position_in_packet > 0) {
        extent += (size_t) tmp_attr_ref->position_in_packet;
    }
    size_t need = (tmp_attr_ref->data_len > 0) ? (size_t) tmp_attr_ref->data_len : 0;
    if (need == 0 && tmp_attr_ref->position_in_packet < 0) {
        need = 1;
    }
    if (!mmt_have_bytes(ipacket, extent, need)) {
#if MMT_CAPLEN_GUARD_STATS
        __atomic_add_fetch(&mmt_caplen_guard_refused, 1, __ATOMIC_RELAXED);
#endif
        return 0;
    }
#if MMT_CAPLEN_GUARD_STATS
    caplen_validated = 1;
#endif
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
#if MMT_CAPLEN_GUARD_STATS
    if (!caplen_validated) __atomic_add_fetch(&mmt_caplen_guard_unvalidated, 1, __ATOMIC_RELAXED);
#endif
    if (tmp_attr_ref->extraction_function(ipacket, index, (attribute_t *) tmp_attr_ref) > 0) {
        //We set the status of the protocol
        tmp_attr_ref->status = ATTRIBUTE_SET;
        //We update the packet id of the attribute
        tmp_attr_ref->packet_id = mmt_handler->last_received_packet.packet_id;
        //We set the index of the protocol
        tmp_attr_ref->protocol_index = index;
        //return a positive value
        return 1;
    }
#ifdef DEBUG
    (void)mmt_debug_log("[debug] internal_extract_attribute (%p) : packet - %"PRIu64", proto_id - %"PRIu32", attribute_id - %"PRIu32" - index: %u\n",tmp_attr_ref->extraction_function,ipacket->packet_id, tmp_attr_ref->proto_id, tmp_attr_ref->field_id, index);
#endif /*DEBUG*/
    // tmp_attr_ref->status = ATTRIBUTE_UNSET;
    return 0;
}

/**
 * Returns a pointer to the extracted data of the attribute identified by its protocol and field ids. The extracted
 * data is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param proto_id the identifier of the protocol of the attribute.
 * @param attribute_id the identifier of the attribute itself.
 * @param index index of the protocol in the protocol path.
 * @return a pointer to the extracted data if it exists, NULL otherwise.
 */
static inline void * _get_attribute_extracted_data_at_index(const ipacket_t * ipacket, uint32_t proto_id, uint32_t attribute_id, unsigned index) {
#ifdef DEBUG
    (void)mmt_debug_log("[debug] _get_attribute_extracted_data_at_index : packet - %"PRIu64", proto_id - %"PRIu32", attribute_id - %"PRIu32" - index: %u\n",ipacket->packet_id, proto_id, attribute_id, index);
#endif /*DEBUG*/
    if ((int) index < 0 || index >= ipacket->proto_hierarchy->len) {
        //the given index is not valid
#ifdef DEBUG
        (void)mmt_debug_log("[error] get_attribute_extracted_data_at_index : packet - %"PRIu64", proto_id - %"PRIu32", attribute_id - %"PRIu32" - index: %u : invalid index (%u)\n",ipacket->packet_id, proto_id, attribute_id, index, index );
#endif /*DEBUG*/
        return NULL;
    }

    if (proto_id != ipacket->proto_hierarchy->proto_path[index]) {
        //the given protocol id does not match the protocol id at the given index
#ifdef DEBUG
        (void)mmt_debug_log("[error] get_attribute_extracted_data_at_index : packet - %"PRIu64", proto_id - %"PRIu32", attribute_id - %"PRIu32" - index: %u : unexpected protocol_id (%u)\n",ipacket->packet_id, proto_id, attribute_id, index, proto_id );
#endif /*DEBUG*/
        return NULL;
    }

    if (!is_registered_protocol(proto_id)) {
        //the given protocol id is not registered
#ifdef DEBUG
        (void)mmt_debug_log("[error] get_attribute_extracted_data_at_index : packet - %"PRIu64", proto_id - %"PRIu32", attribute_id - %"PRIu32" - index: %u : unregistered protocol_id (%u)\n",ipacket->packet_id, proto_id, attribute_id, index, proto_id );
#endif /*DEBUG*/
        return NULL;
    }

    struct attribute_internal_struct * tmp_attr_ref = get_registered_attribute_internal_struct(ipacket, proto_id, attribute_id, index);
    if (tmp_attr_ref == NULL) {
#ifdef DEBUG
        (void)mmt_debug_log("[error] get_attribute_extracted_data_at_index : packet - %"PRIu64", proto_id - %"PRIu32", attribute_id - %"PRIu32" - index: %u : can't retrieve attribute internal structure\n",ipacket->packet_id, proto_id, attribute_id, index );
#endif /*DEBUG*/
        return NULL;
    }

    if (tmp_attr_ref->scope & SCOPE_ON_DEMAND) {
        if (internal_extract_attribute(ipacket, tmp_attr_ref, index)) {
            //return the attribute's data
// #ifdef DEBUG
//             (void)mmt_debug_log("[error] get_attribute_extracted_data_at_index : packet - %"PRIu64", proto_id - %"PRIu32", attribute_id - %"PRIu32" - index: %u : attribute data is null (1/2)\n",ipacket->packet_id, proto_id, attribute_id, index );
// #endif /*DEBUG*/
            tmp_attr_ref->status = ATTRIBUTE_CONSUMED;
            return tmp_attr_ref->data;
        }
    } else {
        /* THIS IS SCOPE_EVENT  should do nothing
        LN: But we shoud return something not NULL ????
        */
    }
#ifdef DEBUG
    if(!(tmp_attr_ref->scope & SCOPE_EVENT)){
        (void)mmt_debug_log("[error] get_attribute_extracted_data_at_index : packet - %"PRIu64", proto_id - %"PRIu32", attribute_id - %"PRIu32" - index: %u : unexpected failure\n",ipacket->packet_id, proto_id, attribute_id, index );
    }
#endif /*DEBUG*/
    return NULL;
}

void * get_attribute_extracted_data_at_index(const ipacket_t * ipacket, uint32_t proto_id, uint32_t attribute_id, unsigned index) {
#ifdef DEBUG
        (void)mmt_debug_log("[debug] get_attribute_extracted_data_at_index: calling _get_attribute_extracted_data_at_index: packet - %"PRIu64", proto_id - %"PRIu32" , attribute_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,attribute_id, index);
#endif /*DEBUG*/
    return _get_attribute_extracted_data_at_index( ipacket, proto_id, attribute_id, index);
}

attribute_t * get_extracted_attribute_at_index(const ipacket_t * ipacket, uint32_t proto_id, uint32_t attribute_id, unsigned index) {
    if ((int) index < 0 || index >= ipacket->proto_hierarchy->len) {
        //the given index is not valid
#ifdef DEBUG
        (void)mmt_debug_log("[error] get_extracted_attribute_at_index: invalid index : packet - %"PRIu64", proto_id - %"PRIu32" , attribute_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,attribute_id, index);
#endif /*DEBUG*/
        return NULL;
    }

    if (proto_id != ipacket->proto_hierarchy->proto_path[index]) {
        //the given protocol id does not match the protocol id at the given index
#ifdef DEBUG
        (void)mmt_debug_log("[error] get_extracted_attribute_at_index: unexpected protocol_id : packet - %"PRIu64", proto_id - %"PRIu32" , attribute_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,attribute_id, index);
#endif /*DEBUG*/
        return NULL;
    }

    if (!is_registered_protocol(proto_id)) {
        //the given protocol id is not registered
#ifdef DEBUG
        (void)mmt_debug_log("[error] get_extracted_attribute_at_index: unregistered protocol_id : packet - %"PRIu64", proto_id - %"PRIu32" , attribute_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,attribute_id, index);
#endif /*DEBUG*/
        return NULL;
    }

    struct attribute_internal_struct * tmp_attr_ref = get_registered_attribute_internal_struct(ipacket, proto_id, attribute_id, index);
    if (tmp_attr_ref == NULL) {
#ifdef DEBUG
        (void)mmt_debug_log("[error] get_extracted_attribute_at_index: can't retrieve attribute internal structure: packet - %"PRIu64", proto_id - %"PRIu32" , attribute_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,attribute_id, index);
#endif /*DEBUG*/
        return NULL;
    }

    if (tmp_attr_ref->scope & SCOPE_ON_DEMAND) {
        if (internal_extract_attribute(ipacket, tmp_attr_ref, index)) {
            //return the attribute's data
// #ifdef DEBUG
//             (void)mmt_debug_log("get_extracted_attribute_at_index: attribute data is not null (1/2): packet - %"PRIu64", proto_id - %"PRIu32" , attribute_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,attribute_id, index);
// #endif /*DEBUG*/
            tmp_attr_ref->status = ATTRIBUTE_CONSUMED;
            return (attribute_t *) tmp_attr_ref;
        }
    } else {
        if (tmp_attr_ref->packet_id == (ipacket->mmt_handler)->last_received_packet.packet_id) {
#ifdef DEBUG
            (void)mmt_debug_log("[error] get_extracted_attribute_at_index: attribute data is null (2/2): packet - %"PRIu64", proto_id - %"PRIu32" , attribute_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,attribute_id, index);
#endif /*DEBUG*/
            return (attribute_t *) tmp_attr_ref;
        }
    }
#ifdef DEBUG
    (void)mmt_debug_log("[error] get_extracted_attribute_at_index : packet - %"PRIu64", proto_id - %"PRIu32", attribute_id - %"PRIu32" - index: %u : unexpected failure\n",ipacket->packet_id, proto_id, attribute_id, index );
#endif /*DEBUG*/
    return NULL;
}

/**
 * Returns a pointer to the extracted data of the attribute identified by its protocol and field names. The extracted
 * data is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param protocol_name the name of the protocol of the attribute.
 * @param attribute_name the name of the attribute itself.
 * @param index index of the protocol in the protocol path.
 * @return a pointer to the extracted data if it exists, NULL otherwise.
 */
void * _get_attribute_extracted_data_at_index_by_name(const ipacket_t * ipacket, const char *protocol_name, const char *attribute_name, unsigned index) {
    if ((int) index < 0 || index >= ipacket->proto_hierarchy->len) {
        //the given index is not valid
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] get_attribute_extracted_data_at_index_by_name(): invalid index - %"PRIu64", protocol_name - %s , attribute_name - %s, index - %u \n", ipacket->packet_id,protocol_name,attribute_name, index);
#endif /*DEBUG*/
        return NULL;
    }

    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] get_attribute_extracted_data_at_index_by_name(): unknown protocol name - %"PRIu64", protocol_name - %s , attribute_name - %s, index - %u \n", ipacket->packet_id,protocol_name,attribute_name, index);
#endif /*DEBUG*/
        return NULL;
    }

    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] get_attribute_extracted_data_at_index_by_name(): unknown attribute name - %"PRIu64", protocol_name - %s , attribute_name - %s, index - %u \n", ipacket->packet_id,protocol_name,attribute_name, index);
#endif /*DEBUG*/
        return NULL;
    }
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] _get_attribute_extracted_data_at_index_by_name: calling _get_attribute_extracted_data_at_index: packet - %"PRIu64", protocol_name - %s , attribute_name - %s, index - %u \n", ipacket->packet_id,protocol_name,attribute_name, index);
#endif /*DEBUG*/
    return _get_attribute_extracted_data_at_index(ipacket, proto_id, attribute_id, index);
}

attribute_t * get_extracted_attribute_at_index_by_name(const ipacket_t * ipacket, const char *protocol_name, const char *attribute_name, unsigned index) {
    if ((int) index < 0 || index >= ipacket->proto_hierarchy->len) {
        //the given index is not valid
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] get_extracted_attribute_at_index_by_name(): invalid index - %"PRIu64", protocol_name - %s , attribute_name - %s, index - %u \n", ipacket->packet_id,protocol_name,attribute_name, index);
#endif /*DEBUG*/
        return NULL;
    }

    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] get_extracted_attribute_at_index_by_name(): unknown protocol name - %"PRIu64", protocol_name - %s , attribute_name - %s, index - %u \n", ipacket->packet_id,protocol_name,attribute_name, index);
#endif /*DEBUG*/
        return NULL;
    }

    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] get_extracted_attribute_at_index_by_name(): unknown attribute name - %"PRIu64", protocol_name - %s , attribute_name - %s, index - %u \n", ipacket->packet_id,protocol_name,attribute_name, index);
#endif /*DEBUG*/
        return NULL;
    }
    return get_extracted_attribute_at_index(ipacket, proto_id, attribute_id, index);
}

void * get_attribute_extracted_data_by_name(const ipacket_t *ipacket, const char *protocol_name, const char *attribute_name) {
    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] get_attribute_extracted_data_by_name(): unknown protocol name - %"PRIu64", protocol_name - %s , attribute_name - %s\n", ipacket->packet_id,protocol_name,attribute_name);
#endif /*DEBUG*/
        return NULL;
    }
    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] get_attribute_extracted_data_by_name(): unknown attribute name - %"PRIu64", protocol_name - %s , attribute_name - %s\n", ipacket->packet_id,protocol_name,attribute_name);
#endif /*DEBUG*/
        return NULL;
    }
    return get_attribute_extracted_data(ipacket, proto_id, attribute_id);
}

attribute_t * get_extracted_attribute_by_name(const ipacket_t *ipacket, const char *protocol_name, const char *attribute_name) {
    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
#ifdef DEBUG
        (void)mmt_debug_log( "get_extracted_attribute_by_name(): unknown protocol name - %"PRIu64", protocol_name - %s , attribute_name - %s\n", ipacket->packet_id,protocol_name,attribute_name);
#endif /*DEBUG*/
        return NULL;
    }
    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
#ifdef DEBUG
        (void)mmt_debug_log( "get_extracted_attribute_by_name(): unknown attribute name - %"PRIu64", protocol_name - %s , attribute_name - %s\n", ipacket->packet_id,protocol_name,attribute_name);
#endif /*DEBUG*/
        return NULL;
    }
    return get_extracted_attribute(ipacket, proto_id, attribute_id);
}


//TODO(#327): this function does not take into account protocol encapsulation where more than one occurrence of the same protocol exists in the path

void * get_attribute_extracted_data(const ipacket_t * ipacket, uint32_t proto_id, uint32_t field_id) {
    unsigned index = 0;
    for (; index < ipacket->proto_hierarchy->len; index++) {
        if (proto_id == ipacket->proto_hierarchy->proto_path[index]) {
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] get_attribute_extracted_data: calling _get_attribute_extracted_data_at_index: packet - %"PRIu64", proto_id - %"PRIu32" , field_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,field_id, index);
#endif /*DEBUG*/
            return _get_attribute_extracted_data_at_index(ipacket, proto_id, field_id, index);
        }
    }

#ifdef DEBUG
    (void)mmt_debug_log( "[debug] get_attribute_extracted_data(): proto_id not found in pathpacket - %"PRIu64", proto_id - %"PRIu32" , field_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,field_id, index);
#endif /*DEBUG*/

    return NULL;
}

void * get_attribute_extracted_data_encap_index(const ipacket_t * ipacket, uint32_t proto_id, uint32_t field_id, unsigned encap_index) {
    unsigned index = 0;
    unsigned encap = 0;
    for (; index < ipacket->proto_hierarchy->len; index++) {
        if (proto_id == ipacket->proto_hierarchy->proto_path[index]) {
            if(encap_index == encap){
#ifdef DEBUG
                (void)mmt_debug_log( "[debug] get_attribute_extracted_data: calling _get_attribute_extracted_data_at_index: packet - %"PRIu64", proto_id - %"PRIu32" , field_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,field_id, index);
#endif /*DEBUG*/
                return _get_attribute_extracted_data_at_index(ipacket, proto_id, field_id, index);
            }
            encap++;
        }
    }

#ifdef DEBUG
    (void)mmt_debug_log( "[debug] get_attribute_extracted_data(): proto_id not found in pathpacket - %"PRIu64", proto_id - %"PRIu32" , field_id - %"PRIu32", index - %u \n", ipacket->packet_id,proto_id,field_id, index);
#endif /*DEBUG*/

    return NULL;
}

attribute_t * get_extracted_attribute(const ipacket_t * ipacket, uint32_t proto_id, uint32_t field_id) {
    unsigned index = 0;
    for (; index < ipacket->proto_hierarchy->len; index++) {
        if (proto_id == ipacket->proto_hierarchy->proto_path[index]) {
            return get_extracted_attribute_at_index(ipacket, proto_id, field_id, index);
        }
    }

#ifdef DEBUG
    (void)mmt_debug_log( "get_extracted_attribute(): proto_id #%u not found in path\n", proto_id );
#endif /*DEBUG*/

    return NULL;
}

void print_attributes_list(struct attribute_internal_struct * tmp_attribute) {
    (void) mmt_attr_format(stdout, (attribute_t *) tmp_attribute);
    // free(tmp_attribute);
}

int debug_extracted_attributes_printout_handler(const ipacket_t *ipacket, void *args) {
    mmt_stream_printf(stdout, "\nPacket id: %"PRIu64" - protocol hierarchy len: %d\n", ipacket->packet_id,ipacket->proto_hierarchy->len);
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    unsigned proto_index = 0;
    int quiet = args ? *((int*)args) : 0;
    struct attribute_internal_struct * tmp_attribute = NULL;
    for (proto_index = 0 ; proto_index < ipacket->proto_hierarchy->len; proto_index++) {
        struct attribute_internal_struct ** attrs = NULL;
        uint32_t nattrs = 0;
        if (is_registered_protocol(ipacket->proto_hierarchy->proto_path[proto_index])) {
            attrs = mmt_handler->proto_registered_attributes[ipacket->proto_hierarchy->proto_path[proto_index]];
            nattrs = mmt_handler->proto_registered_attributes_len[ipacket->proto_hierarchy->proto_path[proto_index]];
        }
        for (uint32_t a = 0; a < nattrs; a++) {
            void * data = NULL;
            tmp_attribute = attrs[a];
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] debug_extracted_attributes_printout_handler: calling _get_attribute_extracted_data_at_index: packet - %"PRIu64", proto_id - %"PRIu32" , field_id - %"PRIu32", index - %u \n", ipacket->packet_id,mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute),tmp_attribute->field_id, proto_index);
        (void)mmt_debug_log( "[debug] debug_extracted_attributes_printout_handler: calling _get_attribute_extracted_data_at_index: packet - %"PRIu64", proto_id - %s , field_id - %s, index - %u \n", ipacket->packet_id,get_protocol_name_by_id(mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute)),get_attribute_name_by_protocol_and_attribute_ids(mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute),tmp_attribute->field_id), proto_index);
#endif /*DEBUG*/
            data = _get_attribute_extracted_data_at_index(ipacket, mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute), tmp_attribute->field_id, proto_index);
            if (!quiet && data != NULL) {
                print_attributes_list(tmp_attribute);
            }
        }

    }
    return 0;
}

static inline void set_ipacket_session_status(ipacket_t * ipacket, uint16_t status) {
    if (ipacket->session != NULL) {
        ipacket->session->status = (uint8_t) status;
    }
}

int set_classified_proto(ipacket_t * ipacket, unsigned index, classified_proto_t classified_proto) {
    int retval = 0;
    if (classified_proto.proto_id == (uint32_t)-1 || index >= PROTO_PATH_SIZE) return retval;
    if (!is_valid_protocol_id(classified_proto.proto_id)) return retval;

    if (index + 1 > ipacket->proto_hierarchy->len) {
        /* Issue #87: DPI profiles bound how deep payload inspection runs —
         * refuse appends below the handler's classification_max_depth.
         * Layers already in the path (update/reclassification branches
         * below) are untouched, and the default bound
         * (PROTO_PATH_SIZE - 1) makes this check a no-op on the bundled
         * configuration. Out-of-band writers (sessionizers, analyse and
         * extraction paths) respect the same cap as the classify walk.
         * A NULL handler (crafted-input harnesses driving dissectors on a
         * fabricated ipacket) carries no bound — the historical behaviour. */
        if (ipacket->mmt_handler != NULL
                && index > ipacket->mmt_handler->classification_max_depth) {
            return retval;
        }
        //Increment the length of the protocol path and protocol offsets
        ipacket->proto_hierarchy->len = index + 1;
        ipacket->proto_headers_offset->len = ipacket->proto_hierarchy->len;
        ipacket->proto_classif_status->len = ipacket->proto_hierarchy->len;

        //Set the detected protocol in the path and update the offsets accordingly
        ipacket->proto_hierarchy->proto_path[index] = classified_proto.proto_id;
        ipacket->proto_headers_offset->proto_path[index] = classified_proto.offset;
        ipacket->proto_classif_status->proto_path[index] = PROTO_CLASSIFICATION_DETECTION;

        /* Issue #252 (F-PERF-002): slots at or beyond the old tip belong to
         * a previously truncated path (or were never recorded) — they cannot
         * own this freshly appended layer. Clear them; a classify_next()
         * walk observing the change re-records, an out-of-band append falls
         * back to the historical full walk. */
        if (ipacket->session != NULL) {
            for (unsigned s = index; s < PROTO_PATH_SIZE; s++) {
                ipacket->session->proto_checkers[s] = NULL;
            }
        }

        retval = PROTO_CLASSIFICATION_DETECTION;
    } else if (ipacket->proto_hierarchy->proto_path[index] == classified_proto.proto_id) {
        //The protocol is already set! just update its offset
        ipacket->proto_headers_offset->proto_path[index] = classified_proto.offset;
        ipacket->proto_classif_status->proto_path[index] = PROTO_CLASSIFICATION_UPDATE;
        retval = PROTO_CLASSIFICATION_UPDATE;
    } else {
        //Set the protocol in the path and update the offsets! We are in the same layer, a protocol reclassification occurred!
        //e.g. Uknown -> HTTP
        ipacket->proto_hierarchy->proto_path[index] = classified_proto.proto_id;
        ipacket->proto_headers_offset->proto_path[index] = classified_proto.offset;
        ipacket->proto_classif_status->proto_path[index] = PROTO_RECLASSIFICATION;

        /* Issue #252 (F-PERF-002): this entry and every deeper layer's
         * recorded winning checkers were earned under the protocol being
         * replaced — a stale slot would dispatch an engine that no longer
         * owns the layer. Drop them; affected layers re-walk the full chain
         * and re-record. When the write happens inside a classify_next()
         * walk, the slot for `index` is re-recorded at post-classify time
         * in the same round; for out-of-band writes (sessionizers, analyse
         * or extraction paths) the cleared slot conservatively restores the
         * historical full walk instead of permanently dispatching the old
         * layer's engine. */
        if (ipacket->session != NULL) {
            for (unsigned s = index; s < PROTO_PATH_SIZE; s++) {
                ipacket->session->proto_checkers[s] = NULL;
            }
        }

        retval = PROTO_RECLASSIFICATION;
    }

    // Issue #19: the per-layer offsets just changed — drop the memoized
    // cumulative-offset cache so get_packet_offset_at_index() rebuilds it.
    ipacket->internal_cumulative_offset_valid = 0;

    /* Issue #252 (F-PERF-002): a checker that writes the path directly
     * (plugin-side set_classified_proto inside its classify_me — e.g. the
     * mobile protocol classifiers) claims the layer for direct dispatch on
     * converged flows. mmt_current_classifier is non-NULL only while a
     * classify_me runs — calls from post_classify or outside walks cannot
     * claim. */
    if (ipacket->mmt_current_classifier != NULL) {
        ipacket->mmt_classifier_claim = ipacket->mmt_current_classifier;
    }

    set_ipacket_session_status(ipacket, classified_proto.status);
    return retval;
}

/**
 * Try to classify encapsulated data
 * @param ipacket             packet to classify
 * @param configured_protocol protocol configuration
 * @param index               index of protocol
 */
int proto_packet_classify_next(ipacket_t * ipacket, protocol_instance_t * configured_protocol, unsigned index) {
    //TODO(#327): review the exit codes; this depends on the return values of the sub-classification routines
    //TODO(#327): why don't to enforce here a threshold on the classification?
    //Verify that classification is not disabled for this protocol
    // Issue #69: lock-free atomic read (relaxed); compiles to a plain load.
    if (proto_status_load(&configured_protocol->protocol->classify_next.status)) {
        mmt_classify_verdict_t classif_status = MMT_CLASSIFY_CONTINUE;
        //Pre-classification
        if (configured_protocol->protocol->classify_next.pre_classify) {
            classif_status = configured_protocol->protocol->classify_next.pre_classify(ipacket, index);
        }
        //Classify next protocol
        /* Issue #87: the classification_max_depth bound skips the whole
         * deeper-layer detection round — checker walk AND post_classify —
         * once the next index would exceed it. pre_classify above still
         * ran, so the current layer's header parse (packet->tcp/udp),
         * sessionization and attribute extraction are unaffected. */
        if (configured_protocol->protocol->classify_next.classify_protos && classif_status != MMT_CLASSIFY_SKIP
                && (ipacket->mmt_handler == NULL
                    || (index + 1) <= ipacket->mmt_handler->classification_max_depth)) { // Classify next proto only when such a function exists!
            /* Issue #252 (F-PERF-002): when the hierarchy already carries a
             * converged (non-UNKNOWN) protocol at index + 1, the packet rides
             * an already-classified flow — the protocol path is session-backed
             * and persists across packets. The chain's identification job at
             * this layer is done, but the WINNING checker is also the flow's
             * per-packet protocol engine (stage machines, SNI/hostname service
             * detection), so it must still see the packet — dispatch straight
             * to it instead of re-walking ~99 cache-cold nodes whose handlers
             * are no-ops on a committed flow. Layers that converged without a
             * recorded winner (port/IP fallback, plugin-side
             * set_classified_proto) keep the full walk so late
             * reclassification stays possible. */
            mmt_classify_proto_t *direct = NULL;
            mmt_classify_proto_t *winner = NULL;
            int expected_proto = PROTO_UNKNOWN;
            /* proto_checkers is PROTO_PATH_SIZE entries like the path itself —
             * the index+1 bound keeps a corrupt len (e.g. the SCTP/S1AP direct
             * len writes) from reading past the table. */
            if (ipacket->session != NULL &&
                    index + 1 < PROTO_PATH_SIZE &&
                    ipacket->proto_hierarchy->len > (index + 1) &&
                    ipacket->proto_hierarchy->proto_path[index + 1] != PROTO_UNKNOWN) {
                expected_proto = ipacket->proto_hierarchy->proto_path[index + 1];
                direct = ipacket->session->proto_checkers[index + 1];
            }
            ipacket->mmt_classifier_claim = NULL;
            if (direct != NULL) {
#if MMT_CLASSIFY_STATS
                __atomic_add_fetch(&mmt_classify_walk_skips, 1, __ATOMIC_RELAXED);
                __atomic_add_fetch(&mmt_classify_direct_calls, 1, __ATOMIC_RELAXED);
#endif
                ipacket->mmt_current_classifier = direct;
                classif_status = direct->classify_me(ipacket, index);
                ipacket->mmt_current_classifier = NULL;
            } else {
                mmt_classify_proto_t * temp = configured_protocol->protocol->classify_next.classify_protos;
                // Checking for the port number ??????
                for (; temp != NULL; temp = temp->next) {
#if MMT_CLASSIFY_STATS
                    __atomic_add_fetch(&mmt_classify_checker_calls, 1, __ATOMIC_RELAXED);
                    __atomic_add_fetch(&mmt_classify_checker_calls_by_proto[configured_protocol->protocol->proto_id], 1, __ATOMIC_RELAXED);
#endif
                    ipacket->mmt_current_classifier = temp;
                    classif_status = temp->classify_me(ipacket, index); //TODO(#327): check the return value and make the corresponding action accordingly!!!
                    // // LN: check if the classify return 1-> do not need to go to check other protocol
                    if(classif_status & MMT_CLASSIFY_MATCHED_MASK){ // Short for classif_status == 1 || classif_status == 2 || classif_status == 3
                        // mmt_stream_printf(stdout, "\n-]> Classified for protocol %d: %"PRIu64" - %d - %p - %u\n",classif_status,ipacket->packet_id,index,temp,temp->weight);
                        winner = temp;
                        break;
                    }
                    // // End of LN
                }
                ipacket->mmt_current_classifier = NULL;
            }

            //Post-classification! Post classification is only accessible if there is a classification function
            //And if the preclassification returned non zero which means: proceed with the classification routines.
            if (configured_protocol->protocol->classify_next.post_classify) {
                int post_ret = configured_protocol->protocol->classify_next.post_classify(ipacket, index);
                if (ipacket->session != NULL &&
                        index + 1 < PROTO_PATH_SIZE &&
                        ipacket->proto_hierarchy->len > (index + 1) &&
                        ipacket->proto_hierarchy->proto_path[index + 1] != expected_proto) {
                    /* The layer's path entry changed this round (first
                     * detection or reclassification — read the path AFTER
                     * post_classify, which is what materialises index+1).
                     * Record the engine that owns it so converged packets
                     * dispatch directly: prefer the plugin-funnel claim —
                     * it also covers checkers that classify via
                     * add_connection/set_classified_proto without returning
                     * a MATCHED verdict — else the verdict winner. A NULL
                     * store means "converged without identifiable owner":
                     * such layers keep the full walk. Safe to store node
                     * pointers: classify chains live as long as the handler,
                     * sessions cannot outlive it. */
                    ipacket->session->proto_checkers[index + 1] =
                            (ipacket->mmt_classifier_claim != NULL)
                            ? (mmt_classify_proto_t *) ipacket->mmt_classifier_claim
                            : winner;
                }
                return post_ret;
            }
        }
    }
    return 1;
}

/**
 * Fires an attribute detection event. If the attribute is registered, this function will extract its value.
 * If the attribute has any registered handlers, they will be called. This function will do nothing if the
 * attribute is not registered.
 * @param proto_id protocol identifier of the attribute
 * @param attribute_id attribute identifier
 * @param data pointer to the attribute data
 */
void fire_attribute_event(ipacket_t * ipacket, uint32_t proto_id, uint32_t attribute_id, unsigned index, void * data) {
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    struct attribute_internal_struct * attr = get_registered_attribute(mmt_handler, proto_id, attribute_id);
    if (attr != NULL) {
        attr->data = data;
        //Set the attribute
        attr->status = ATTRIBUTE_SET;
        //We update the packet id of the attribute
        attr->packet_id = mmt_handler->last_received_packet.packet_id;
        //We set the index of the protocol
        attr->protocol_index = index;
        /* Issue #252 (F-PERF-017): contiguous handler array. */
        for (int h = 0; h < attr->handlers_count; h++) {
            attr->attribute_handlers[h].handler_fct(ipacket, (attribute_t *) attr, attr->attribute_handlers[h].args);
        }
        attr->status = ATTRIBUTE_CONSUMED;
    }
}

void fire_evasion_event(ipacket_t * ipacket, uint32_t proto_id, unsigned proto_index, unsigned evasion_id, void * data) {
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    if(mmt_handler->evasion_handler){
        mmt_handler->evasion_handler->function(ipacket,proto_id,proto_index,evasion_id,data,mmt_handler->evasion_handler->args);
    }else{
#ifdef DEBUG
        mmt_debug_log("There is no evasion_handler!");
#endif
    }
}


/**
 * Process attribute handler of protocol: such as source_port of TCP protocol
 * @param ipacket packet to process the handler on
 * @param index   index of protocol
 */
void proto_process_attribute_handlers(ipacket_t * ipacket, unsigned index) {
    int offset = 0;
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    offset += ipacket->proto_headers_offset->proto_path[index];
    if (offset >= ipacket->p_hdr->caplen) {
        return;
    }
    /* Issue #252 (F-PERF-017): contiguous frozen array — indexed walk, no
     * ->next chasing through separately allocated nodes. Base and length are
     * re-read every iteration because a handler_fct callback may
     * register/unregister attribute handlers, relocating or shifting the
     * array (same contract as process_packet_handler()). */
    uint32_t proto = ipacket->proto_hierarchy->proto_path[index];
    for (uint32_t e = 0; e < mmt_handler->proto_registered_attribute_handlers_len[proto]; e++) {
        attribute_internal_t * attribute = mmt_handler->proto_registered_attribute_handlers[proto][e].attribute;
        internal_extract_attribute(ipacket, attribute, index);
        if (attribute->status == ATTRIBUTE_SET) {
            for (int h = 0; h < attribute->handlers_count; h++) {
                attribute->attribute_handlers[h].handler_fct(ipacket, (attribute_t *) attribute, attribute->attribute_handlers[h].args);
            }
            attribute->status = ATTRIBUTE_CONSUMED;
        }
    }
}
/**
 * Analysis protocol of packet
 * @param  ipacket             packet to analysis
 * @param  configured_protocol instance of protocol
 * @param  index               index of protocol
 * @return                     MMT_CONTINUE : Continue processing to sub-protocol
 *                             MMT_DROP : Stop processing this packet
 *                             MMT_SKIP : Skip processing this packet but will be come back in future
 */
int proto_packet_analyze(ipacket_t * ipacket, protocol_instance_t * configured_protocol, unsigned index) {
    //TODO(#327): review the exit codes; this depends on the return values of the sub-analysis routines
    int retval = MMT_CONTINUE;
    //Verify that analysis is not disabled for this protocol
    // Issue #69: lock-free atomic read (relaxed); compiles to a plain load.
    if (!proto_status_load(&configured_protocol->protocol->data_analyser.status)) {
        return retval;
    }
    //Pre-analysis
    if (configured_protocol->protocol->data_analyser.pre_analyse != NULL) {
        retval = configured_protocol->protocol->data_analyser.pre_analyse(ipacket, index);
    }
    //Analyse data packet
    if (configured_protocol->protocol->data_analyser.analyse && (retval == MMT_CONTINUE)) {
        mmt_analyse_me_t * temp = configured_protocol->protocol->data_analyser.analyse;
        for (; temp != NULL; temp = temp->next) {
            retval = temp->analyse_me(ipacket, index);
        }

        //Post-analysis! Post analysis is only accessible if there is an analysis function
        //and if the pre-analysis returned CONTINUE which means: proceed with the analysis routines.
        if (configured_protocol->protocol->data_analyser.post_analyse) {
            configured_protocol->protocol->data_analyser.post_analyse(ipacket, index);
        }
    }

    return retval;
}

void clean_packet(ipacket_t *ipacket){
    if ( (ipacket->data != ipacket->original_data) &&
       (ipacket->mmt_handler->link_layer_stack->stack_id == DLT_EN10MB) ) {
        // data was dynamically allocated during the reassembly process:
        //   . free dynamically allocated ipacket->data
        //   . reset ipacket->data to its original value
        mmt_free((void *) ipacket->data);
        ipacket->data = ipacket->original_data;
    }
}

void clean_packet_with_reassembly(ipacket_t *ipacket){

    if(ipacket->session){ // Only packet which has session need to be clean those information
        // F-BUG-002 (issue #199): free only packet-owned heap buffers. Since
        // issue #245 the reassembly path writes session offsets into the
        // ipacket's embedded internal_proto_headers_offset, so this flag is
        // never set on a pooled packet — keep the guard for safety.
        if (ipacket->proto_headers_offset_owned && ipacket->proto_headers_offset)
            mmt_free(ipacket->proto_headers_offset);
    }

    /* Issue #245 (F-PERF-003): internal_packet aliases the shared per-protocol
     * context packet (exactly like the non-reassembly path) — never freed. */

    /* Fragment reassembly (ip_process_fragment) may have replaced data with a
     * freshly allocated buffer — free it. The original copy buffer is owned
     * by the slot and survives for reuse. */
    if ((void *) ipacket->data != (void *) ipacket->original_data)
	mmt_free((void *) ipacket->data);

    /* Return the slot to the handler freelist. The ipacket is the slot's
     * first member, so the cast recovers it. Reset the fields that hold
     * pointers into per-packet state so a recycled slot never exposes a stale
     * reference before process_packet_with_reassembly() rewrites them. */
    ipacket->data = ipacket->original_data;
    ipacket->internal_packet = NULL;
    ipacket->proto_headers_offset = NULL;
    ipacket->proto_headers_offset_owned = 0;
    mmt_ipacket_slot_t *slot = (mmt_ipacket_slot_t *) ipacket;
    slot->next_free = ipacket->mmt_handler->ipacket_pool;
    ipacket->mmt_handler->ipacket_pool = slot;
}

/**
 * @brief Process packet_handler function
 *
 * @param ipacket Packet to process
 */
void process_packet_handler(ipacket_t *ipacket) {
    debug("process_packet_handler of ipacket: %"PRIu64"\n", ipacket->packet_id);
    // debug("Last packet_handler_id: %d", ipacket->last_callback_fct_id);
    mmt_handler_t *mmt_handler = ipacket->mmt_handler;
    uint32_t i = 0;
    // Resume after the last handler that already ran for this packet, if any.
    // process_packet_handler() can be re-invoked for the same ipacket after a
    // handler returns 1; last_callback_fct_id records where to continue so the
    // earlier handlers are not run twice. We locate the resume point by handler
    // id (not a cached pointer) exactly once here, rather than re-scanning the
    // list head on every iteration as the previous implementation did. That
    // made dispatch O(H^2); a single resume scan plus one linear pass is O(H).
    //
    // Resuming by id (instead of a saved next pointer persisted on the ipacket)
    // keeps the previous mutation semantics: the handler list may be rebuilt
    // between invocations and a stale pointer would dangle, whereas an id is
    // re-resolved against the current list. Issue #252 (F-PERF-017): the array
    // base and length are re-read every iteration because a callback may
    // register/unregister handlers, relocating or shifting the array.
    if (ipacket->last_callback_fct_id != 0) {
        while (i < mmt_handler->packet_handlers_len &&
               mmt_handler->packet_handlers[i].packet_handler_id != ipacket->last_callback_fct_id) {
            i++;
        }
        // Skip the already-processed handler; if it is no longer present
        // (i == len) the pass below is a no-op.
        i++;
    }
    while (i < mmt_handler->packet_handlers_len) {
        packet_handler_t *handler = &mmt_handler->packet_handlers[i];
        ipacket->last_callback_fct_id = handler->packet_handler_id;
        int result = (handler->function(ipacket, handler->args));
        if (result == 1) {
            debug("process_packet_handler result == 1  status of ipacket: %"PRIu64"\n", ipacket->packet_id);
            return;
        }
        i++;
    }

    process_timedout_sessions(ipacket->mmt_handler, ipacket->p_hdr->ts.tv_sec);

    ipacket->mmt_handler->clean_packet(ipacket);
}

/**
 * @brief Process packet_handler function
 *
 * @param ipacket Packet to process
 */
void mmt_drop_packet(ipacket_t *ipacket) {
    mmt_debug_log("[mmt_drop_packet] Drop packet: %"PRIu64"\n", ipacket->packet_id);

    process_timedout_sessions(ipacket->mmt_handler, ipacket->p_hdr->ts.tv_sec);

    ipacket->mmt_handler->clean_packet(ipacket);
}

/**
 * Proccess packet for each protocol
 * For examples: ETH->IP->TCP->FTP
 * index:        0  ->1 ->2  ->3
 * @param  ipacket      packet to process
 * @param  parent_stats protocol statistic of parrent protocol (statistic of IP for TCP)
 * @param  index        Index of protocol which the packet belongs to
 * @return              MMT_CONTINUE -> continue proccessing the packet
 *                      MMT_DROP     -> drops the packet
 *                      MMT_SKIP     -> skips processing the packet - it will returned in the future
 */
int proto_packet_process(ipacket_t * ipacket, proto_statistics_internal_t * parent_stats, unsigned index) {

    debug("proto_packet_process of %"PRIu64" index: %d", ipacket->packet_id, index);

    int target = MMT_CONTINUE;
    int is_new_session = 0;
    int proto_offset = get_packet_offset_at_index(ipacket, index);
    //Make sure this protocol has data to analyse
    if (proto_offset >= ipacket->p_hdr->len || proto_offset >= ipacket->p_hdr->caplen) {
        //This is not an ubnormal behaviour, this can simply be an ACK packet in an HTTP session
        process_packet_handler(ipacket);
        return target;
    }

    protocol_instance_t * configured_protocol = &(ipacket->mmt_handler)
            ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];

    //The protocol is registered: First we check if it requires to maintain a session
    is_new_session = proto_session_management(ipacket, configured_protocol, index);
    if (is_new_session == NEW_SESSION) {
        parent_stats = update_proto_stats_on_new_session(ipacket, configured_protocol, (proto_statistics_internal_t*)parent_stats, is_new_session, proto_offset, index);
        fire_attribute_event(ipacket, configured_protocol->protocol->proto_id, PROTO_SESSION, index, (void *) ipacket->session);
        // fire_evasion_event(ipacket, configured_protocol->protocol->proto_id, index, 1, (void *) NULL);
    }
    else {
        //Update the protocol statistics
        parent_stats = update_proto_stats_on_packet(ipacket, configured_protocol, parent_stats, proto_offset, index);
    }

    //Analyze packet data
    target = proto_packet_analyze(ipacket, configured_protocol, index);
    //Proceed with the extraction and the handlers notification for this protocol
    //if the target action is CONTINUE or SKIP (skip means continue with this proto but no further)
    if (target != MMT_DROP)
    {
        //Attributes extraction
        proto_process_attribute_handlers(ipacket, index);
    }

    //Proceed with the classification sub-process only if the target action is set to CONTINUE
    if (target == MMT_CONTINUE)
    {

        target = proto_packet_classify_next(ipacket, configured_protocol, index) ? MMT_CONTINUE : MMT_SKIP;
        /* Issue #255 (F-PERF-010): the per-direction proto_path copies moved
         * into the tunnel-parent extension. They are maintained only for
         * sessions that parent embedded sessions (a leaf session's path is
         * identical in both directions — get_session_proto_path_direction()
         * falls back to proto_path then). */
        if (ipacket->session != NULL && ipacket->session->children_stats != NULL)
        {
            // Update proto_path_direction
            if (ipacket->session->proto_path.len > 0)
            {
                mmt_session_children_stats_t *cs = ipacket->session->children_stats;
                int proto_direction = ipacket->session->last_packet_direction;
                int proto_path_len = ipacket->session->proto_path.len;
                if (cs->proto_path_direction[proto_direction].len != proto_path_len)
                {
                    cs->proto_path_direction[proto_direction].len = proto_path_len;
                    int i = 0;
                    for (i = 0; i < proto_path_len; i++)
                    {
                        cs->proto_path_direction[proto_direction].proto_path[i] = ipacket->session->proto_path.proto_path[i];
                    }
                    // debug("[IP] Update protocol path direction: %d", proto_direction);
                }
                else
                {
                    if (cs->proto_path_direction[proto_direction].proto_path[proto_path_len - 1] != ipacket->session->proto_path.proto_path[proto_path_len - 1])
                    {
                        cs->proto_path_direction[proto_direction].proto_path[proto_path_len - 1] = ipacket->session->proto_path.proto_path[proto_path_len - 1];
                    }
                }
            }
        }
        // Need to check if the ipacket is still exist
        // send the packet to the next encapsulated protocol if an encapsulated protocol exists in the path
        if (index ==0 || target == MMT_CONTINUE) {
          if (ipacket->proto_hierarchy->len > (index + 1))
          {
              if (is_registered_protocol(ipacket->proto_hierarchy->proto_path[index + 1]))
              {
                  /* process the packet by the next encapsulated protocol */
                  return proto_packet_process(ipacket, parent_stats, index + 1);
              }
          }
        }
        process_packet_handler(ipacket);
    }
    else
    {
        // The analyzer returned MMT_DROP or MMT_SKIP, so we leave the function
        // here without going through process_packet_handler() -- the only path
        // that calls clean_packet(). In reassembly mode the ipacket is
        // heap-allocated by process_packet_with_reassembly(), so skipping
        // cleanup leaks it (and its dynamically reassembled data buffer). Run
        // the same cleanup hook on these exit paths so the ipacket is freed on
        // DROP/SKIP too. For the embedded (non-reassembly) current_ipacket,
        // clean_packet() only releases a reallocated data buffer and is a
        // no-op otherwise, so this is safe and never double-frees: this branch
        // is mutually exclusive with the process_packet_handler() call above.
        ipacket->mmt_handler->clean_packet(ipacket);
    }
    return target;
}

/* Issue #255 (F-PERF-014): reset the seven PROTO_PATH_SIZE-element per-packet
 * arrays shared by process_packet() and process_packet_with_reassembly().
 * The interleaved scalar loops used to emit ~112 scattered stores per packet;
 * the contiguous memsets (plus the dense fill for nb_reassembled_packets,
 * which resets to 1 — a value memset cannot express) compile down to vector
 * stores at -O2. */
static inline void reset_ipacket_path_arrays(ipacket_t *ipacket) {
    memset(ipacket->is_completed,             0, sizeof(ipacket->is_completed));
    memset(ipacket->is_fragment,              0, sizeof(ipacket->is_fragment));
    memset(ipacket->ipv6_ext_headers_path,    0, sizeof(ipacket->ipv6_ext_headers_path));
    memset(ipacket->ipv6_ext_headers_offset,  0, sizeof(ipacket->ipv6_ext_headers_offset));
    memset(ipacket->ipv6_overlapping,         0, sizeof(ipacket->ipv6_overlapping));
    memset(ipacket->ipv6_outoforder,          0, sizeof(ipacket->ipv6_outoforder));
    int i = 0;
    for (; i < PROTO_PATH_SIZE; i++) {
        ipacket->nb_reassembled_packets[i] = 1;
    }
}

int process_packet(mmt_handler_t *mmt, struct pkthdr *header, const u_char * packet){
    classified_proto_t classified_proto;
    classified_proto.proto_id = PROTO_META;
    classified_proto.offset = 0;
    classified_proto.status = Classified;
    mmt->current_ipacket.data = packet;
    mmt->current_ipacket.proto_hierarchy = &mmt->last_received_packet.proto_hierarchy;
    mmt->current_ipacket.proto_headers_offset = &mmt->last_received_packet.proto_headers_offset;
    mmt->current_ipacket.proto_headers_offset_owned = 0; // embedded in the handler — never freed
    mmt->current_ipacket.proto_classif_status = &mmt->last_received_packet.proto_classif_status;
    mmt->current_ipacket.p_hdr = &mmt->current_ipacket.internal_p_hdr;
    mmt->current_ipacket.p_hdr->ts.tv_sec = header->ts.tv_sec;
    mmt->current_ipacket.p_hdr->ts.tv_usec = header->ts.tv_usec;
    mmt->current_ipacket.p_hdr->caplen = header->caplen;
    mmt->current_ipacket.p_hdr->original_caplen = header->caplen;
    mmt->current_ipacket.p_hdr->original_len = header->len;
    mmt->current_ipacket.p_hdr->len = header->len;
    mmt->current_ipacket.p_hdr->probe_id = header->probe_id;
    mmt->current_ipacket.p_hdr->source_id = header->source_id;
    mmt->current_ipacket.p_hdr->user_args = header->user_args;
    mmt->current_ipacket.original_data = packet;
    mmt->current_ipacket.proto_hierarchy->len = 0;
    mmt->current_ipacket.proto_headers_offset->len = 0;
    mmt->current_ipacket.proto_classif_status->len = 0;
    mmt->current_ipacket.internal_cumulative_offset_valid = 0; // Issue #19
    mmt->current_ipacket.session = NULL;
    mmt->current_ipacket.mmt_handler = mmt;
    mmt->current_ipacket.internal_packet = NULL;
    mmt->current_ipacket.last_callback_fct_id = 0;
    /* Issue #252 (F-PERF-002): the classifier claim channel is per-packet —
     * reset it alongside the rest of the per-packet state. */
    mmt->current_ipacket.mmt_current_classifier = NULL;
    mmt->current_ipacket.mmt_classifier_claim = NULL;
    // IPV6
    mmt->current_ipacket.ipv6_ext_headers_len = 0;
    reset_ipacket_path_arrays(&mmt->current_ipacket);
    mmt->current_ipacket.total_caplen = header->caplen;
    // update_last_received_packet(&mmt->last_received_packet, &mmt->current_ipacket);
    mmt->last_received_packet.packet_id += 1;
    mmt->last_received_packet.packet_len = mmt->current_ipacket.p_hdr->len;
    mmt->last_received_packet.time.tv_sec = mmt->current_ipacket.p_hdr->ts.tv_sec;
    mmt->last_received_packet.time.tv_usec = mmt->current_ipacket.p_hdr->ts.tv_usec;
    mmt->current_ipacket.packet_id = mmt->last_received_packet.packet_id;
    //First set the meta protocol
    (void) set_classified_proto(&mmt->current_ipacket, 0, classified_proto);
    // debug("Packet address (packet_process) - no copied packet: %p", &mmt->current_ipacket);
    return proto_packet_process(&mmt->current_ipacket, NULL, 0);
}

int process_packet_with_reassembly(mmt_handler_t *mmt, struct pkthdr *header, const u_char * packet){
    classified_proto_t classified_proto;
    classified_proto.proto_id = PROTO_META;
    classified_proto.offset = 0;
    classified_proto.status = Classified;
    if (header->caplen > 65535) return 0;
    /* Issue #245 (F-PERF-003): recycle a pooled slot instead of malloc()ing a
     * fresh ipacket + copy buffer per packet. The slot is allocated once and
     * its data buffer only ever grows to the largest caplen seen, so after
     * warm-up this path performs zero allocations per packet. */
    mmt_ipacket_slot_t *slot = mmt->ipacket_pool;
    if (likely(slot != NULL)) {
        mmt->ipacket_pool = slot->next_free;
    } else {
        slot = (mmt_ipacket_slot_t *) mmt_malloc(sizeof(mmt_ipacket_slot_t));
        if (slot == NULL) return 0;
        slot->data = NULL;
        slot->data_cap = 0;
        mmt_reassembly_stat_packet_alloc();
    }
    if (header->caplen > slot->data_cap) {
        uint8_t *grown = (uint8_t *) mmt_realloc(slot->data, header->caplen);
        if (grown == NULL) {
            slot->next_free = mmt->ipacket_pool;
            mmt->ipacket_pool = slot;
            return 0;
        }
        slot->data = grown;
        slot->data_cap = header->caplen;
        mmt_reassembly_stat_packet_alloc();
    }
    ipacket_t *ipacket = &slot->ipacket;
    memcpy(slot->data, packet, header->caplen);
    ipacket->data = slot->data;
    ipacket->original_data = slot->data;
    /* Per-packet copies live in the ipacket's embedded internal_* members: a
     * packet held by a user callback then keeps its own hierarchy/offset/
     * status state instead of aliasing the handler's last_received_packet
     * (issue #245 — also required for the offsets snapshot copied per
     * session layer in proto_session_management). */
    ipacket->proto_hierarchy = &ipacket->internal_proto_hierarchy;
    ipacket->proto_headers_offset = &ipacket->internal_proto_headers_offset;
    ipacket->proto_headers_offset_owned = 0; // embedded in the slot — never freed
    ipacket->proto_classif_status = &ipacket->internal_proto_classif_status;
    // copy_ipacket_header(ipacket, header);
    // Start copy header
    ipacket->p_hdr = &ipacket->internal_p_hdr;
    ipacket->p_hdr->ts.tv_sec = header->ts.tv_sec;
    ipacket->p_hdr->ts.tv_usec = header->ts.tv_usec;
    ipacket->p_hdr->caplen = header->caplen;
    ipacket->p_hdr->original_caplen = header->caplen;
    ipacket->p_hdr->len = header->len;
    ipacket->p_hdr->original_len = header->len;
    ipacket->p_hdr->probe_id = header->probe_id;
    ipacket->p_hdr->source_id = header->source_id;
    ipacket->p_hdr->user_args = header->user_args;
    //End of Copy header
    ipacket->proto_hierarchy->len = 0;
    ipacket->proto_headers_offset->len = 0;
    ipacket->proto_classif_status->len = 0;
    ipacket->internal_cumulative_offset_valid = 0; // Issue #19
    ipacket->session = NULL;
    ipacket->mmt_handler = mmt;
    ipacket->internal_packet = NULL;
    ipacket->last_callback_fct_id = 0;
    /* Issue #252 (F-PERF-002): reset the classifier claim channel — the slot
     * is mmt_malloc'd (never zeroed) and recycled between packets, so the
     * fields must be rearmed here or the first set_classified_proto() below
     * reads uninitialised memory (Valgrind memcheck on the leak gate). */
    ipacket->mmt_current_classifier = NULL;
    ipacket->mmt_classifier_claim = NULL;
    // ipv6
    ipacket->ipv6_ext_headers_len = 0;
    reset_ipacket_path_arrays(ipacket);
    ipacket->total_caplen = header->caplen;
    // update_last_received_packet(&mmt->last_received_packet, ipacket);
    mmt->last_received_packet.packet_id += 1;
    mmt->last_received_packet.packet_len = ipacket->p_hdr->len;
    mmt->last_received_packet.time.tv_sec = ipacket->p_hdr->ts.tv_sec;
    mmt->last_received_packet.time.tv_usec = ipacket->p_hdr->ts.tv_usec;
    ipacket->packet_id = mmt->last_received_packet.packet_id;
    (void) set_classified_proto(ipacket, 0, classified_proto);
    // debug("Packet address (packet_process - copied packet): %p", ipacket);
    return proto_packet_process(ipacket, NULL, 0);
}

bool enable_mmt_reassembly(mmt_handler_t *mmt) {
    if (likely(mmt != NULL)) {
        mmt->process_packet = process_packet_with_reassembly;
        mmt->clean_packet = clean_packet_with_reassembly;
        mmt->has_reassembly = 1;
        return 1;
    }
    return 0;
}

bool disable_mmt_reassembly(mmt_handler_t *mmt) {
    if (likely(mmt != NULL)) {
        mmt->process_packet = process_packet;
        mmt->clean_packet = clean_packet;
        mmt->has_reassembly = 0;
        return 1;
    }
    return 0;
}

bool enable_port_classify(mmt_handler_t *mmt) {
    if (likely(mmt != NULL)) {
        mmt->port_classify = 1;
        return 1;
    }
    return 0;
}

bool disable_port_classify(mmt_handler_t *mmt) {
    if (likely(mmt != NULL)) {
        mmt->port_classify = 0;
        return 1;
    }
    return 0;
}

bool enable_port_classify_payload_confirm(mmt_handler_t *mmt) {
    if (likely(mmt != NULL)) {
        mmt->port_classify_payload_confirm = 1;
        return 1;
    }
    return 0;
}

bool disable_port_classify_payload_confirm(mmt_handler_t *mmt) {
    if (likely(mmt != NULL)) {
        mmt->port_classify_payload_confirm = 0;
        return 1;
    }
    return 0;
}

bool enable_hostname_classify(mmt_handler_t *mmt)
{
    if (likely(mmt != NULL))
    {
        mmt->hostname_classify = 1;
        return 1;
    }
    return 0;
}

bool disable_hostname_classify(mmt_handler_t *mmt)
{
    if (likely(mmt != NULL))
    {
        mmt->hostname_classify = 0;
        return 1;
    }
    return 0;
}

bool enable_ip_address_classify(mmt_handler_t *mmt)
{
    if (likely(mmt != NULL))
    {
        mmt->ip_address_classify = 1;
        return 1;
    }
    return 0;
}

bool disable_ip_address_classify(mmt_handler_t *mmt)
{
    if (likely(mmt != NULL))
    {
        mmt->ip_address_classify = 0;
        return 1;
    }
    return 0;
}

bool packet_process(mmt_handler_t *mmt, struct pkthdr *header, const u_char * packet) {

#ifdef CFG_OS_MAX_PACKET
    if ( mmt->packet_count >= CFG_OS_MAX_PACKET ) {
        (void)mmt_debug_log( "This demo version of MMT is limited to %lu packets.\n", (unsigned long)CFG_OS_MAX_PACKET );
        return 0;
    }
    ++mmt->packet_count;
#endif /*CFG_OS_MAX_PACKET*/

    //Testing packet header and data integrity
    if (likely(header && packet)){
        if (likely(header->caplen > 0  && header->len > 0 && header->len >= header->caplen && header->caplen <= 65535)){
            mmt->process_packet(mmt,header,packet);
            return 1;
        }
    }
    return 0;
}


int base_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    //int * classify_behaviour = (int *) args;
    classified_proto_t retval = (ipacket->mmt_handler)->link_layer_stack->stack_classify(ipacket);
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

/**
 * generic packet processing
 */
void generic_data_extraction(unsigned protocol_index, ipacket_t * ipacket) {
    uint32_t proto_id = get_protocol_id_at_index(ipacket, protocol_index);
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;

    if (!is_registered_protocol(proto_id)) return;
    /* Issue #252 (F-PERF-017): contiguous frozen array of attribute pointers —
     * the per-packet extraction walk indexes it instead of chasing ->next.
     * Base and length are re-read every iteration because an extraction
     * callback may register/unregister attributes, relocating or shifting
     * the array (same contract as process_packet_handler()). */
    for (uint32_t a = 0; a < mmt_handler->proto_registered_attributes_len[proto_id]; a++) {
        struct attribute_internal_struct * tmp_attr_ref = mmt_handler->proto_registered_attributes[proto_id][a];
        if (tmp_attr_ref->extraction_function(ipacket, protocol_index, (attribute_t *) tmp_attr_ref) > 0) {
            //We set the status of the protocol
            tmp_attr_ref->status = ATTRIBUTE_SET;
            //We update the packet id of the attribute
            tmp_attr_ref->packet_id = mmt_handler->last_received_packet.packet_id;
            //We set the index of the protocol
            tmp_attr_ref->protocol_index = protocol_index;
        }
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
