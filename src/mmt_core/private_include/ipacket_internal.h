/*
 * ipacket_internal.h — the private extension of the public packet structure
 * (issue #535, F-CLEAN-001). Engine-private: never installed.
 *
 * Kept apart from packet_processing.h so that a test harness which builds a
 * packet fixture needs only this header and data_defs.h.
 */
#ifndef MMT_IPACKET_INTERNAL_H
#define MMT_IPACKET_INTERNAL_H

#include <stddef.h> /* offsetof */
#include "data_defs.h"

/*
 * MMT_PIN_MIRROR(outer, member, pubtype, field): fails the build unless
 * outer.field — a member of an anonymous struct overlaid on outer.member, a
 * pubtype — has the same type and lies at the same offset as
 * outer.member.field. Used for ipacket_internal_t and attribute_internal_t.
 */
#define MMT_PIN_MIRROR(outer, member, pubtype, field) \
    _Static_assert(offsetof(outer, field) == offsetof(outer, member) + offsetof(pubtype, field) \
                   && __builtin_types_compatible_p(__typeof__(((outer *) 0)->field), \
                                                   __typeof__(((pubtype *) 0)->field)), \
                   #outer "." #field " no longer mirrors " #pubtype "." #field)

/**
 * Issue #535 (F-CLEAN-001): the private extension of a packet. Every packet
 * the engine processes is one of these — the handler's current_ipacket, a
 * reassembly slot's ipacket, a dissector's dummy packet — and the ipacket_t *
 * handed to plugins and to the user is &pub. The fields after the union are
 * engine-internal: they are not part of the ABI and may change freely.
 * The anonymous struct is the exact image of the public ipacket_t (pinned
 * below), so engine code and test fixtures that own the storage keep writing
 * pkt.data & co.; code that holds an ipacket_t * reaches the internal fields
 * through ipacket_internal().
 */
typedef struct ipacket_internal_struct {
    union {
        ipacket_t pub; /**< the public packet: what consumers and plugins receive */
        struct {
            uint64_t packet_id;
            uint64_t total_caplen;
            uint8_t is_completed[PROTO_PATH_SIZE];
            uint8_t is_fragment[PROTO_PATH_SIZE];
            uint16_t ipv6_ext_headers_path[PROTO_PATH_SIZE];
            uint32_t ipv6_ext_headers_offset[PROTO_PATH_SIZE];
            uint16_t ipv6_ext_headers_len;
            uint16_t ipv6_overlapping[PROTO_PATH_SIZE];
            uint16_t ipv6_outoforder[PROTO_PATH_SIZE];
            int last_callback_fct_id;
            unsigned nb_reassembled_packets[PROTO_PATH_SIZE];
            proto_hierarchy_t * proto_hierarchy;
            proto_hierarchy_t * proto_headers_offset;
            proto_hierarchy_t * proto_classif_status;
            mmt_session_t * session;
            mmt_tcpip_internal_packet_t * internal_packet;
            mmt_handler_t * mmt_handler;
            pkthdr_t * p_hdr;
            const u_char * data;
        };
    };
    proto_hierarchy_t internal_proto_hierarchy; /**< storage proto_hierarchy points to when the packet owns its path */
    proto_hierarchy_t internal_proto_headers_offset; /**< storage proto_headers_offset points to when the packet owns its offsets */
    proto_hierarchy_t internal_proto_classif_status; /**< storage proto_classif_status points to when the packet owns its status path */
    pkthdr_t internal_p_hdr;                  /**< storage p_hdr points to: the meta-data of the packet */
    const u_char * original_data;             /**< the original packet data. It differs from data in case of IP reassembled data */
    int internal_cumulative_offset[PROTO_PATH_SIZE]; /**< Issue #19: memoized prefix-sum of proto_headers_offset->proto_path, so get_packet_offset_at_index() is amortized O(1) instead of re-summing (O(N^2) per packet). */
    int internal_cumulative_offset_valid;     /**< Issue #19: 0 when the cumulative-offset cache must be rebuilt (invalidate_packet_offset_cache()). */
    int internal_cumulative_offset_hwm;       /**< Issue #19: highest index whose prefix sum is cached (the cache is extended on demand, never beyond what is queried). */
    int proto_headers_offset_owned;           /**< Issue #199 (F-BUG-002): 1 when proto_headers_offset points to a heap buffer owned by this packet (set at its single mmt_malloc site in proto_session_management), 0 when it aliases storage embedded in the handler, the session or this packet. clean_packet_with_reassembly() frees the buffer only when this flag is set. */
    void * mmt_current_classifier;            /**< Issue #252 (F-PERF-002): the checker node currently being probed by proto_packet_classify_next()'s chain walk (NULL outside walks). Read by plugin classification funnels to claim ownership. */
    void * mmt_classifier_claim;              /**< Issue #252 (F-PERF-002): the checker node that last claimed a classification this classify_next() round — written by plugin funnels (mmt_change_internal_flow_packet_protocol, set_classified_proto) copying mmt_current_classifier. */
} ipacket_internal_t;

_Static_assert(offsetof(ipacket_internal_t, pub) == 0, "ipacket_internal_t: pub must stay first");
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, packet_id);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, total_caplen);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, is_completed);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, is_fragment);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, ipv6_ext_headers_path);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, ipv6_ext_headers_offset);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, ipv6_ext_headers_len);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, ipv6_overlapping);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, ipv6_outoforder);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, last_callback_fct_id);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, nb_reassembled_packets);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, proto_hierarchy);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, proto_headers_offset);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, proto_classif_status);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, session);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, internal_packet);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, mmt_handler);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, p_hdr);
MMT_PIN_MIRROR(ipacket_internal_t, pub, ipacket_t, data);
_Static_assert(offsetof(ipacket_internal_t, internal_proto_hierarchy) == sizeof(ipacket_t),
               "ipacket_internal_t: the mirror outgrew ipacket_t");

/**
 * Issue #535: the private extension of a packet the engine handed out. The
 * conversion is valid only for an ipacket_t that is the pub member of an
 * ipacket_internal_t — which every packet the engine processes is; a
 * consumer-made ipacket_t is not. Constness is dropped on purpose: the
 * offset cache is mutable state even behind a const packet (see
 * get_packet_offset_at_index()).
 */
static inline ipacket_internal_t * ipacket_internal(const ipacket_t * ipacket) {
    return (ipacket_internal_t *) ipacket;
}

/**
 * Issue #558: the inline twin of get_packet_offset_at_index() (mmt_data.c),
 * which is exported (MMTAPI, part of the ABI) and stays a real function that
 * forwards here. The engine queries offsets several times per packet, mostly
 * from the plugins, and each of those went through the PLT to an out-of-line
 * body; the SDK's own objects now inline the same memoized prefix sum
 * (issue #19) through the redirect below. Same cache fields, same result.
 */
static inline int mmt_packet_offset_at_index(const ipacket_t * ipacket, unsigned index) {
    ipacket_internal_t * pkt = ipacket_internal(ipacket); // mutable memoization cache only (issue #535: private extension)
    if (index >= (unsigned) PROTO_PATH_SIZE) {
        index = PROTO_PATH_SIZE - 1;
    }
    if (!pkt->internal_cumulative_offset_valid) {
        pkt->internal_cumulative_offset_hwm = -1; // nothing summed yet
        pkt->internal_cumulative_offset_valid = 1;
    }
    // Extend the prefix sum only as far as the queried index (high-water mark),
    // so across a packet the offsets are summed once in total (amortized O(1)
    // per call) instead of re-summed from 0 on every call.
    int hwm = pkt->internal_cumulative_offset_hwm;
    if ((int) index > hwm) {
        int sum = (hwm >= 0) ? pkt->internal_cumulative_offset[hwm] : 0;
        int i;
        for (i = hwm + 1; i <= (int) index; i++) {
            sum += ipacket->proto_headers_offset->proto_path[i];
            pkt->internal_cumulative_offset[i] = sum;
        }
        pkt->internal_cumulative_offset_hwm = (int) index;
    }
    return pkt->internal_cumulative_offset[index];
}

/* Issue #558: SDK objects (built with -D_MMT_BUILD_SDK, rules/common.mk)
 * call the inline twin. Everything else — consumers, and the unit suites
 * that compile a dissector against their own get_packet_offset_at_index()
 * stub — keeps calling the function. A function-like macro: the name alone
 * (a function pointer, the definition in mmt_data.c) still means the export. */
#ifdef _MMT_BUILD_SDK
#define get_packet_offset_at_index(ipacket, index) mmt_packet_offset_at_index((ipacket), (index))
#endif

#endif /* MMT_IPACKET_INTERNAL_H */
