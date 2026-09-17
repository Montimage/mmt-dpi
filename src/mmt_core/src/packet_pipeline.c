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
        if (is_registered_protocol(ipacket->proto_hierarchy->proto_path[proto_index])) {
            tmp_attribute = mmt_handler->proto_registered_attributes[ipacket->proto_hierarchy->proto_path[proto_index]];
        }
        while (tmp_attribute != NULL) {
            void * data = NULL;
#ifdef DEBUG
        (void)mmt_debug_log( "[debug] debug_extracted_attributes_printout_handler: calling _get_attribute_extracted_data_at_index: packet - %"PRIu64", proto_id - %"PRIu32" , field_id - %"PRIu32", index - %u \n", ipacket->packet_id,mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute),tmp_attribute->field_id, proto_index);
        (void)mmt_debug_log( "[debug] debug_extracted_attributes_printout_handler: calling _get_attribute_extracted_data_at_index: packet - %"PRIu64", proto_id - %s , field_id - %s, index - %u \n", ipacket->packet_id,get_protocol_name_by_id(mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute)),get_attribute_name_by_protocol_and_attribute_ids(mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute),tmp_attribute->field_id), proto_index);
#endif /*DEBUG*/
            data = _get_attribute_extracted_data_at_index(ipacket, mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute), tmp_attribute->field_id, proto_index);
            if (!quiet && data != NULL) {
                print_attributes_list(tmp_attribute);
            }
            tmp_attribute = tmp_attribute->next;
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
        //Increment the length of the protocol path and protocol offsets
        ipacket->proto_hierarchy->len = index + 1;
        ipacket->proto_headers_offset->len = ipacket->proto_hierarchy->len;
        ipacket->proto_classif_status->len = ipacket->proto_hierarchy->len;

        //Set the detected protocol in the path and update the offsets accordingly
        ipacket->proto_hierarchy->proto_path[index] = classified_proto.proto_id;
        ipacket->proto_headers_offset->proto_path[index] = classified_proto.offset;
        ipacket->proto_classif_status->proto_path[index] = PROTO_CLASSIFICATION_DETECTION;

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

        retval = PROTO_RECLASSIFICATION;
    }

    // Issue #19: the per-layer offsets just changed — drop the memoized
    // cumulative-offset cache so get_packet_offset_at_index() rebuilds it.
    ipacket->internal_cumulative_offset_valid = 0;

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
        if (configured_protocol->protocol->classify_next.classify_protos && classif_status != MMT_CLASSIFY_SKIP) { // Classify next proto only when such a function exists!
            mmt_classify_proto_t * temp = configured_protocol->protocol->classify_next.classify_protos;
            // Checking for the port number ??????
            for (; temp != NULL; temp = temp->next) {
                classif_status = temp->classify_me(ipacket, index); //TODO(#327): check the return value and make the corresponding action accordingly!!!
                // // LN: check if the classify return 1-> do not need to go to check other protocol
                if(classif_status & MMT_CLASSIFY_MATCHED_MASK){ // Short for classif_status == 1 || classif_status == 2 || classif_status == 3
                    // mmt_stream_printf(stdout, "\n-]> Classified for protocol %d: %"PRIu64" - %d - %p - %u\n",classif_status,ipacket->packet_id,index,temp,temp->weight);
                    break;
                }
                // // End of LN
            }

            //Post-classification! Post classification is only accessible if there is a classification function
            //And if the preclassification returned non zero which means: proceed with the classification routines.
            if (configured_protocol->protocol->classify_next.post_classify) {
                return configured_protocol->protocol->classify_next.post_classify(ipacket, index);
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
        attribute_handler_t * attr_handler_fct = attr->attribute_handler;
        while (attr_handler_fct != NULL) {
            attr_handler_fct->handler_fct(ipacket, (attribute_t *) attr, attr_handler_fct->args);
            attr_handler_fct = attr_handler_fct->next;
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
    attribute_handler_element_t * attribute_handler = mmt_handler->proto_registered_attribute_handlers[ipacket->proto_hierarchy->proto_path[index]];
    while (attribute_handler != NULL) {
        internal_extract_attribute(ipacket, attribute_handler->attribute, index);
        if (attribute_handler->attribute->status == ATTRIBUTE_SET) {
            attribute_handler_t * attr_handler_fct = attribute_handler->attribute->attribute_handler;
            while (attr_handler_fct != NULL) {
                attr_handler_fct->handler_fct(ipacket, (attribute_t *) attribute_handler->attribute, attr_handler_fct->args);
                attr_handler_fct = attr_handler_fct->next;
            }
            attribute_handler->attribute->status = ATTRIBUTE_CONSUMED;
        }
        attribute_handler = attribute_handler->next;
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
        // F-BUG-002 (issue #199): free only packet-owned heap buffers. On the
        // OOM path proto_headers_offset still aliases storage embedded in the
        // handler (last_received_packet) or in the session — freeing that was
        // mmt_free() on a non-heap address.
        if (ipacket->proto_headers_offset_owned && ipacket->proto_headers_offset)
            mmt_free(ipacket->proto_headers_offset);
    }

    mmt_free(ipacket->internal_packet);
    /* Fragment reassembly (ip_process_fragment) may have replaced data with a
     * freshly allocated buffer — free it too, then free the heap copy that
     * process_packet_with_reassembly() made (pointed by original_data).
     * Without the original_data free every fragment-reassembled packet leaked
     * its initial copy (issue #216). */
    if ((void *) ipacket->data != (void *) ipacket->original_data)
	mmt_free((void *) ipacket->data);
    mmt_free((void *) ipacket->original_data);
    mmt_free( ipacket );

}

/**
 * @brief Process packet_handler function
 *
 * @param ipacket Packet to process
 */
void process_packet_handler(ipacket_t *ipacket) {
    debug("process_packet_handler of ipacket: %"PRIu64"\n", ipacket->packet_id);
    // debug("Last packet_handler_id: %d", ipacket->last_callback_fct_id);
    packet_handler_t * temp_packet_handler = ipacket->mmt_handler->packet_handlers;
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
    // re-resolved against the current list. Within the pass below we advance via
    // ->next read after the callback, identical to the original first branch.
    if (ipacket->last_callback_fct_id != 0) {
        while (temp_packet_handler != NULL &&
               temp_packet_handler->packet_handler_id != ipacket->last_callback_fct_id) {
            temp_packet_handler = temp_packet_handler->next;
        }
        // Skip the already-processed handler; if it is no longer present
        // (temp_packet_handler == NULL) the pass below is a no-op.
        if (temp_packet_handler != NULL) {
            temp_packet_handler = temp_packet_handler->next;
        }
    }
    while (temp_packet_handler != NULL) {
        ipacket->last_callback_fct_id = temp_packet_handler->packet_handler_id;
        int result = (temp_packet_handler->function(ipacket, temp_packet_handler->args));
        if (result == 1) {
            debug("process_packet_handler result == 1  status of ipacket: %"PRIu64"\n", ipacket->packet_id);
            return;
        }
        temp_packet_handler = temp_packet_handler->next;
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
    ipacket_t *ipacket;
    ipacket = mmt_malloc(sizeof(ipacket_t));
    if (ipacket == NULL) return 0;
    ipacket->data = mmt_malloc(header->caplen);
    if (ipacket->data == NULL) { mmt_free(ipacket); return 0; }
    memcpy((void *)ipacket->data, (void *)packet, header->caplen);
    ipacket->original_data = ipacket->data;
    // ipacket->proto_hierarchy = (proto_hierarchy_t*)malloc(sizeof(proto_hierarchy_t));
    // ipacket->proto_headers_offset = (proto_hierarchy_t*)malloc(sizeof(proto_hierarchy_t));
    // ipacket->proto_classif_status = (proto_hierarchy_t*)malloc(sizeof(proto_hierarchy_t));
    ipacket->proto_hierarchy = &mmt->last_received_packet.proto_hierarchy;
    ipacket->proto_headers_offset = &mmt->last_received_packet.proto_headers_offset;
    ipacket->proto_headers_offset_owned = 0; // embedded in the handler — never freed
    ipacket->proto_classif_status = &mmt->last_received_packet.proto_classif_status;
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
    struct attribute_internal_struct * tmp_attr_ref;
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;

    if (!is_registered_protocol(proto_id)) return;
    tmp_attr_ref = mmt_handler->proto_registered_attributes[proto_id];

    if (is_registered_protocol(proto_id)) {
        while (tmp_attr_ref != NULL) {
            if (tmp_attr_ref->extraction_function(ipacket, protocol_index, (attribute_t *) tmp_attr_ref) > 0) {
                //We set the status of the protocol
                tmp_attr_ref->status = ATTRIBUTE_SET;
                //We update the packet id of the attribute
                tmp_attr_ref->packet_id = mmt_handler->last_received_packet.packet_id;
                //We set the index of the protocol
                tmp_attr_ref->protocol_index = protocol_index;
            }

            tmp_attr_ref = tmp_attr_ref->next;
        }
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
