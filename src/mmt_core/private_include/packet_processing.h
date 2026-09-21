/*
 * File:   packet_processing.h
 * Author: montimage
 *
 * Created on 9 mars 2011, 13:59
 */

#ifndef PACKET_PROCESSING_H
#define PACKET_PROCESSING_H

#ifdef __cplusplus
extern "C" {
#endif

#include "data_defs.h"
#include "mmt_core.h"
#include "extraction_lib.h"
#include "hash_utils.h"
#include "hashmap.h"
#include "memory.h"
#include "plugin_defs.h"
#include "cfg_defaults.h"

#include <string.h> /* memset in mmt_session_get_children_stats() */

#define PROTO_CLASSIFICATION_DONE       0 /**< defines that processing is done with the classification process.
                                        * This is to acknowledge that the core took the necessary actions following the
                                        * classification process. */
#define PROTO_CLASSIFICATION_DETECTION  1 /**< defines the detection of a new protocol in the classification process */
#define PROTO_CLASSIFICATION_UPDATE     2 /**< defines that an already classified protocol was encountered. This is an update */
#define PROTO_RECLASSIFICATION          3 /**< defines that a protocol reclassification occurred */

#define NEW_SESSION             1 /**< defines the detection of a new session in the session management sub-process */
#define NEW_PROTO_IN_SESSION    2 /**< defines the detection of a new protocol in a previously detected session */

typedef struct packet_handler_struct               packet_handler_t;
typedef struct evasion_handler_struct              evasion_handler_t;
typedef struct packet_info_struct                  packet_info_t;

typedef struct attribute_handler_struct            attribute_handler_t;
typedef struct attribute_internal_struct           attribute_internal_t;
typedef struct attribute_handler_element_struct    attribute_handler_element_t;

typedef struct session_expiry_handler_struct       session_expiry_handler_t;

typedef struct session_timer_handler_struct        session_timer_handler_t;

typedef struct mmt_classify_proto_struct           mmt_classify_proto_t;
typedef struct mmt_classify_next_struct            mmt_classify_next_t;
typedef struct mmt_proto_data_analysis_proc_struct mmt_analyse_me_t;
typedef struct mmt_proto_data_analysis_struct      mmt_analyser_t;

typedef struct protocol_instance_struct            protocol_instance_t;
typedef struct proto_statistics_internal_struct    proto_statistics_internal_t;
typedef struct protocol_stack_struct               protocol_stack_t;
typedef struct mmt_session_children_stats_struct   mmt_session_children_stats_t;

/**
 * Issue #255 (F-PERF-010): the session's tunnel-parent extension — the
 * subsession (children) counters plus the per-direction protocol-path copies.
 * All of it is meaningful only once the session parents an embedded session
 * (GTP/tunnel/VPN children): the counters stay zero for leaf sessions and the
 * per-direction paths are verbatim copies of proto_path while no child
 * session can extend the path differently per direction. The block used to
 * sit inline in every mmt_session_t (~280 B of a ~1,032 B record); it is now
 * allocated lazily by mmt_session_get_children_stats() the first time the
 * session becomes a parent.
 */
struct mmt_session_children_stats_struct {
    /* per-direction copies of the session's proto_path, maintained for
     * tunnel parents only (see the writer in proto_packet_process()). */
    proto_hierarchy_t proto_path_direction[2];

    /* Children's statistics: subsession aggregates over all sessions created
     * inside this session (tunnel, GTP, VPN, ...). */
    uint64_t sub_packet_count;                   /**< subsession: tracks the number of packets*/
    uint64_t sub_packet_cap_count;               /**< subsession: number of packets which are captured as in this session - include fragmented packets*/
    uint64_t sub_data_cap_volume;                /**< subsession: data volume captured  - include fragmented packets*/
    uint64_t sub_data_volume;                    /**< subsession: tracks the octet data volume */
    uint64_t sub_data_packet_count;              /**< subsession: tracks the number of packets holding effective payload data */
    uint64_t sub_data_byte_volume;               /**< subsession: tracks the effective payload data volume */

    uint64_t sub_packet_count_direction[2];      /**< subsession: Session's packet count in both directions: initiator <-> remote */
    uint64_t sub_data_volume_direction[2];       /**< subsession: Session's data volume in both directions: initiator <-> remote */
    uint64_t sub_packet_cap_count_direction[2];  /**< subsession: Session's packet count ( - include fragmented packets) in both directions: initiator <-> remote */
    uint64_t sub_data_cap_volume_direction[2];   /**< subsession: Session's data volume ( - include fragmented packets) in both directions: initiator <-> remote */
    uint64_t sub_data_packet_count_direction[2]; /**< subsession: Session's effective payload packet count in both directions: initiator <-> remote */
    uint64_t sub_data_byte_volume_direction[2];  /**< subsession: Session's effective payload data volume in both directions: initiator <-> remote */
};

/**
 * Central bounds predicate for packet offsets (issue #193, F-BUG-032).
 *
 * Returns non-zero when `n` bytes starting at absolute packet offset `offset`
 * lie entirely inside the captured data (offset + n <= caplen, evaluated
 * without overflow). Extraction code — the central guard in
 * internal_extract_attribute() and per-parser extractors that compute their
 * own offsets — must route bounds checks through this helper so the coverage
 * stays greppable.
 */
static inline int mmt_have_bytes(const ipacket_t *ipacket, size_t offset, size_t n) {
    if (ipacket == NULL || ipacket->p_hdr == NULL || ipacket->data == NULL) return 0;
    const size_t caplen = (size_t) ipacket->p_hdr->caplen;
    return (offset <= caplen) && (n <= caplen - offset);
}

/**
 * Defines the attribute information.
 * @deprecated use #attribute_metadata_t instead
 */
typedef struct attribute_information_struct {
    int id; /**< identifier of the attribute. Must be unique for a given protocol. */
    char * alias; /**< the alias(name) of the attribute */
    int data_type; /**< the data type of the attribute */
    int data_len; /**< the data length of the attribute */
    int position_in_packet; /**< the position in the packet of the attribute. */
} attribute_information_t;

/**
 * Defines the attribute information.
 * @deprecated use #attribute_metadata_t instead
 */
typedef struct attribute_information_struct_v2 {
    int id; /**< identifier of the attribute. Must be unique for a given protocol. */
    char * alias; /**< the alias(name) of the attribute */
    int data_type; /**< the data type of the attribute */
    int data_len; /**< the data length of the attribute */
    int position_in_packet; /**< the position in the packet of the attribute. */
    int scope; /**< the scope of the attribute (packet, session, ...). */
    generic_attribute_extraction_function extraction_function; /**< the extraction function for this attribute. */
} attribute_information_v2_t;

/**
 * Defines the attribute information relative to field-value based protocol.
 * @deprecated use #attribute_metadata_t instead
 */
typedef struct field_value_attribute_information_struct {
    int id; /**< identifier of the attribute. Must be unique for a given protocol. */
    char * alias; /**< the alias(name) of the attribute */
    int data_type; /**< the data type of the attribute */
    int data_len; /**< the data length of the attribute */
    int position_in_packet; /**< the position in the packet of the attribute. */
    int scope; /**< the scope of the attribute (packet, session, ...). */
    int relative_header_id; /**< the header id relative to this attribute. */
    generic_attribute_extraction_function extraction_function; /**< the extraction function for this attribute. */
} field_value_attribute_information_t;
struct mmt_segblk_s; /* tcp_segment.h — plugin-owned bump block chain */

/**
 * Issue #245 (F-PERF-005/006, F-BUG-038): bounded per-flow TCP reassembly
 * state — a lazily-allocated extension (NULL for sessions that never carry
 * reassembled TCP payload). For each direction the flattened stream image
 * lives in a geometrically-grown buffer capped by the handler's
 * tcp_reassembly_limit, and the not-yet-flattened segments live in a
 * seq-sorted doubly-linked list backed by bump blocks (see mmt_segblk_t in
 * tcp_segment.h). `live` counts pending carved bytes plus image bytes and is
 * the quantity bounded by the ceiling; consumed segments are released
 * promptly (dead blocks are recycled/freed) so the prefix already emitted
 * does not pin memory until teardown.
 */
typedef struct mmt_tcp_reasm_s {
    void *seg_head[2];            /* pending tcp_seg_t list head, seq-sorted */
    void *seg_tail[2];            /* pending list tail — O(1) in-order append */
    uint8_t *image[2];            /* flattened stream image (was session_payload) */
    uint32_t image_len[2];        /* valid bytes in image (was session_payload_len) */
    uint32_t image_cap[2];        /* allocated capacity of image */
    uint32_t consumed_seq[2];     /* seq of the byte just past the image end */
    uint8_t consumed_valid[2];    /* 1 once the direction emitted ≥1 segment */
    uint64_t live;                /* pending carved bytes + image bytes (≤ limit) */
    uint64_t dropped;             /* payload bytes dropped by ceiling/late-arrival */
    struct mmt_segblk_s *blocks;  /* bump-block chain backing pending segs */
} mmt_tcp_reasm_t;

/**
 * Defines the structure of a session.
 */
struct mmt_session_struct {
    uint8_t family;                          /**< identifier of the application family to which this session belongs. */

    uint32_t session_protocol_index;         /**< index of the protocol to which the session belongs */
    uint32_t session_timeout_delay;          /**< The inactivity delay after which the session can be considered as expired */
    uint32_t session_timeout_milestone;      /**< The time expressed as seconds since Epoch (1st Jan 1970) when the session will be considered as expired */
    /* Content Flags: Plugin specific */
    uint32_t content_flags;
    uint32_t tcp_retransmissions;            /**< number of TCP retransmissions */
    uint32_t tcp_outoforders;                 /**< number of TCP outoforder */
    /* tcp sequence number connection tracking and retransmissions counting */
    uint32_t next_tcp_seq_nr[2];

    uint64_t session_id;                     /**< session identifier */
    uint64_t fragmented_packet_count;        /**< number of fragmented packets which are in this session*/
    uint64_t fragment_count;                 /**< number of fragments which are in this session*/
    uint8_t is_fragmenting;                  /** 1 - session is processing a fragmented packet, 0 - session is not processing any fragmented packet*/
    /* Total statistics */
    uint64_t packet_count;                   /**< tracks the number of packets */
    uint64_t packet_cap_count;               /**< number of packets which are captured as in this session - include fragmented packets*/
    uint64_t data_cap_volume;                /**< data volume captured  - include fragmented packets*/
    uint64_t data_volume;                    /**< tracks the octet data volume */
    uint64_t data_packet_count;              /**< tracks the number of packets holding effective payload data */
    uint64_t data_byte_volume;               /**< tracks the effective payload data volume */

    uint64_t packet_count_direction[2];      /**< Session's packet count in both directions: initiator <-> remote */
    uint64_t data_volume_direction[2];       /**< Session's data volume in both directions: initiator <-> remote */
    uint64_t packet_cap_count_direction[2];      /**< Session's packet count ( - include fragmented packets) in both directions: initiator <-> remote */
    uint64_t data_cap_volume_direction[2];       /**< Session's data volume ( - include fragmented packets) in both directions: initiator <-> remote */
    uint64_t data_packet_count_direction[2]; /**< Session's effective payload packet count in both directions: initiator <-> remote */
    uint64_t data_byte_volume_direction[2];  /**< Session's effective payload data volume in both directions: initiator <-> remote */
    // End of total statistics

    /* Children's statistics + per-direction path copies: lazily-allocated
     * extension, non-NULL only for tunnel parents (issue #255, F-PERF-010).
     * Subsession bookkeeping is zero for every leaf session — keeping it
     * inline cost ~280 B per session. */
    mmt_session_children_stats_t *children_stats;

    struct timeval s_init_time;              /**< indicates the time when the session was first detected. */
    struct timeval s_last_activity_time;     /**< indicates the time when the last activity on this session was detected (time of the last packet). */
    struct timeval rtt;                      /**< TCP RTT calculated at connection setup */
    struct timeval s_last_data_packet_time[2];     /**< indicates the time when the last data packet (packet has payload) on this session was detected in both direction: initiator <-> remote. */

    proto_hierarchy_t proto_path;            /**< The session detected protocol hierarchy */
    proto_hierarchy_t proto_headers_offset;  /**< The protocol offsets of the detected protocols */
    proto_hierarchy_t proto_classif_status;  /**< the classification status of the protocols in the path */
    /* Issue #252 (F-PERF-002): the checker node that won each layer's
     * classification — recorded when the checker walk first matches so a
     * converged flow dispatches straight to its owning protocol engine
     * instead of re-walking the whole chain. The winning checker keeps its
     * per-packet role on the flow (stage machines, SNI/hostname service
     * detection); the ~98 non-owning checkers are no-ops on a committed flow.
     * NULL when the layer converged without a winning checker (port/IP
     * fallback, plugin-side set_classified_proto) — such layers keep the
     * full walk so late reclassification stays possible. */
    mmt_classify_proto_t *proto_checkers[PROTO_PATH_SIZE];

    /* BW: MMT content type */
    struct {
        uint16_t content_class;
        uint16_t content_type;
    } content_info;

    mmt_handler_t *mmt_handler;              /**< opaque pointer to the mmt handler that processed this session */

    struct mmt_session_struct *parent_session; /**< pointer to the parent session */
    struct mmt_session_struct * next;        /**< pointer to the next session in the expiry list --- for internal use must not be changed */
    struct mmt_session_struct * previous;    /**< pointer to the previous session in the expiry list --- for internal use must not be changed */

    void * protocol_container_context;       /**< pointer to the protocol to which the session belongs */
    void * session_data[PROTO_PATH_SIZE];    /**< Table of protocol specific session data. This is a repository where each
                                                  detected protocol of this session will maintain its session specific data. */
    void * session_key;                      /**< pointer ot the session key structure */
    void * internal_data;                    /**< interval data  */
    void * user_data;                        /**< user data associated with the structure */
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t status : 3;                      /**< indicate the status of the session */
    uint8_t force_timeout : 1;               /**< indicate if the session timed out (according to the protocol workflow)
                                                  This will be the case after the FIN - ACK tcp connection closing procedure. */
    /* init parameter, internal used to set up timestamp,... */
    uint8_t type : 2;
    uint8_t setup_packet_direction : 1;      /**< the direction of the first packet of this session (Lower_toHigher or Higher_to_Lower) */
    uint8_t last_packet_direction : 1;       /**< the direction of the current packet Lower_toHigher or Higher_to_Lower.
                                                  This is used as indicator to track direction change in bidirectional sessions */
//     uint8_t packet_direction:1,init_finished:1;
// #elif BYTE_ORDER == BIG_ENDIAN
//     uint8_t last_packet_direction : 1, setup_packet_direction : 1, type : 2, status : 4,packet_direction:1,init_finished:1;
#elif BYTE_ORDER == BIG_ENDIAN
    uint8_t last_packet_direction : 1, setup_packet_direction : 1, type : 2, status : 4;
#else
#error "BYTE_ORDER must be defined"
#endif
    /* Issue #245: the TCP reassembly fields (segment lists, payload image
     * buffers, block chain) moved into the lazily-allocated mmt_tcp_reasm_t
     * extension above — a session that never reassembles TCP payload pays
     * only this one pointer. */
    mmt_tcp_reasm_t * tcp_reasm;
};

/**
 * Returns the session's tunnel-parent extension, allocating it on first use
 * (issue #255). Returns NULL under OOM — callers then skip the subsession
 * update, which degrades the children counters to zero rather than aborting
 * the packet path. The returned block is released with the session (the
 * plugin session destructor frees session->children_stats).
 */
static inline mmt_session_children_stats_t *mmt_session_get_children_stats(mmt_session_t *session) {
    if (session->children_stats == NULL) {
        mmt_session_children_stats_t *cs =
            (mmt_session_children_stats_t *) mmt_malloc(sizeof(mmt_session_children_stats_t));
        if (cs != NULL) {
            memset(cs, 0, sizeof(*cs));
            session->children_stats = cs;
        }
    }
    return session->children_stats;
}

/**
 * Defines the packet handler structure.
 */
struct packet_handler_struct {
    int packet_handler_id; /**< identifier of the packet handler */
    generic_packet_handler_callback function; /**< the packet handler callback function */
    u_char * args; /**< registered user argument that will be passed to the callback handler */
    packet_handler_t * next; /**< next packet handler */
};

struct evasion_handler_struct {
    generic_evasion_handler_callback function; // the evasion handler callback function
    void * args; // User arguments that will be passed to the callback handler
};

/**
 * Defines the packet information.
 * NOTE: Kept here because mmt_handler_t embeds packet_info_t by value;
 * the type is effectively private to the packet_processing module but
 * must remain visible wherever mmt_handler_struct is defined.
 */
struct packet_info_struct {
    uint32_t packet_id; /**< identifier of the packet. */
    unsigned int packet_len; /**< length of the packet. */
    struct timeval time; /**< time of arrival of the packet. */
    proto_hierarchy_t proto_hierarchy; /**< the protocol layers corresponding to this packet */
    proto_hierarchy_t proto_headers_offset; /**< the offsets corresponding to the protocol layers of this packet */
    proto_hierarchy_t proto_classif_status; /**< the classification status of the protocols in the path */
};

/**
 * Defines the internal structure of an attribute.
 */
//This structure is a superset of "attribute_t" defined in public include file "data_defs.h" be careful when modifying this.

/**
 * Defines the attribute handler structure
 */
struct attribute_handler_struct {
    attribute_handler_function handler_fct; /**< the handler callback function */
    void * condition; /**< the condition on the attribute value to call the handler. Can ba NULL */
    void * args; /**< pointer to the user defined argument to pass with the handler*/
    attribute_handler_t * next; /**< next in a chain */
};

struct attribute_internal_struct {
    unsigned protocol_index; /**< index of the protocol */
    int status;              /**< status of the attribute. Indicates if it is unset, set or consumed. */
    int data_type;           /**< the data type of the attribute */
    int data_len;            /**< the data length of the attribute */
    int position_in_packet;  /**< the position in the packet of the attribute. */
    int scope;               /**< the scope of the attribute (packet, session, ...). */
    uint32_t proto_id;    /**< identifier of the protocol */
    uint32_t field_id;       /**< identifier of the attribute */
    void *data;              /**< pointer to the attribute data */

    int memsize; /**< indicates the memory size of the attribute including the memory pointed to by data */
    int registration_count; /**< Number of times this attributes has been registered */
    int handlers_count; /**< Number of times this attributes has been registered with an attribute handler */
    uint32_t packet_id; /**< identifier of the packet from which this attribute was extracted */
    generic_attribute_extraction_function extraction_function; /**< the extraction function for this attribute. */
    /* Issue #252 (F-PERF-017): handlers frozen into a contiguous array —
     * handlers_count stays the element count (it was always maintained in
     * lock-step with the old chain), attribute_handlers_cap its capacity.
     * Element 0 is the most recently registered handler, preserving the old
     * head-insert order. */
    attribute_handler_t * attribute_handlers;
    uint32_t attribute_handlers_cap;
    attribute_internal_t * next; /**< next attribute */
};

/**
 * Defines the attribute handler element structure
 */
struct attribute_handler_element_struct {
    attribute_internal_t * attribute; /**< pointer to the internal attribute structure with which the handler is registered */
    attribute_handler_element_t * next; /**< next in a chain */
};

/**
 * Defines the session expiry handler structure
 */
struct session_expiry_handler_struct {
    generic_session_timeout_handler_function handler_fct; /**< the session expiry handler function */
    void * args; /**< pointer to the user defined argument to pass with the handler*/
};

struct session_timer_handler_struct{
    generic_session_timer_handler_function session_timer_handler_fct;
    void *args;
    uint8_t no_fragmented;
};

struct mmt_classify_proto_struct {
    uint32_t weight;
    int (*classify_me) (ipacket_t * ipacket, unsigned index);
    mmt_classify_proto_t * next;
    mmt_classify_proto_t * previous;
};

struct mmt_classify_next_struct {
    int status; /**< indicates if classification is enabled or disabled */
    int (*pre_classify) (ipacket_t * ipacket, unsigned index);
    mmt_classify_proto_t * classify_protos;
    int (*post_classify) (ipacket_t * ipacket, unsigned index);
};

struct mmt_proto_data_analysis_proc_struct {
    uint32_t weight;
    int (*analyse_me) (ipacket_t * ipacket, unsigned index);
    mmt_analyse_me_t * next;
    mmt_analyse_me_t * previous;
};

struct mmt_proto_data_analysis_struct {
    int status; /**< indicates if analysis is enabled or disabled */
    int (*pre_analyse) (ipacket_t * ipacket, unsigned index);
    mmt_analyse_me_t * analyse;
    int (*post_analyse) (ipacket_t * ipacket, unsigned index);
};

/**
 * Defines the protocol statistics interanl structure.
 */
struct proto_statistics_internal_struct {
    uint32_t touched; /**< Indicates if the statistics have been updated since the last reset */
    uint64_t packets_count; /**< Total number of packets seen by the protocol */
    uint64_t data_volume; /**< Total data volume seen by the protocol */
    uint64_t ip_frag_packets_count;         /**< Total number of IP unknown fragmented packets seen by the IP protocol*/
    uint64_t ip_frag_data_volume;           /**< Total data volume of IP unknown fragmented packets seen by the IP protocol*/
    uint64_t ip_df_packets_count;         /**< Total number of defragmented IP packets seen by the IP protocol*/
    uint64_t ip_df_data_volume;           /**< Total data volume of defragmented IP packets seen by the IP protocol*/
    uint64_t payload_volume; /**< Total payload data volume seen by the protocol */
    uint64_t packets_count_direction[2]; /**< Total number of UL/DL packets seen by the protocol */
    uint64_t data_volume_direction[2]; /**< Total UL/DL data volume seen by the protocol */
    uint64_t payload_volume_direction[2]; /**< Total UL/DL payload data volume seen by the protocol */
    uint64_t sessions_count; /**< Total number of sessions seen by the protocol */
    uint64_t timedout_sessions_count; /**< Total number of timedout sessions (this is the difference between sessions count and ative sessions count) */
    proto_statistics_internal_t* next; /**< next instance of statistics for the same protocol */
    struct timeval first_packet_time; // The time of the first packet of the protocol
    struct timeval last_packet_time; // The time of the last packet of the protocol
    protocol_instance_t * proto; /**< pointer to the protocol */
    void * encap_proto_stats; /**< Map including the statistics of encaprulated children protocols */
    proto_statistics_internal_t * parent_proto_stats; /**< pointer to the parent protocol stats */
};

/**
 * Defines a protocol stack
 */
struct protocol_stack_struct {
    uint32_t stack_id; /**< unique identifier of the protocol stack. */
    char stack_name[Max_Alias_Len + 1]; /**< The friendly name of the protocol stack. */
    generic_stack_classification_function stack_classify; /**< The base classification function for the protocol stack. */
    stack_internal_cleanup stack_cleanup; /**< The protocol stack internal data cleanup function. */
    //void * stack_internal_packet; /**< The internal packet data used by the protocol stack. */
    void * stack_internal_context; /**< The internal context for the protocol stack. */
};

/**
 * Defines a protocol structure.
 */
struct protocol_struct {
    int is_registered; /**< indicates if this protocol is registered or not */
    int protocol_code; /**< Code of the protocol. Usually the same as the identifier. */
    int has_session; /**< indicates if the protocol has a session context or not. */
    int session_timeout_delay; /**< indicates if the protocol has a session context or not. */

    uint32_t proto_id; /**< unique identifier of the protocol. */
    const char * protocol_name; /**< The name of the protocol. Must be unique. */

    generic_get_attribute_id_by_name get_attribute_id_by_name; /**< funtion pointer that returns the protocol's attribute id by name */
    generic_get_attribute_name_by_id get_attribute_name_by_id; /**< function pointer that returns the protocol's attribute name by id */
    generic_get_attribute_data_type_by_id get_attribute_data_type_by_id; /**< function pointer that returns the data type of an attribute */
    generic_get_attribute_data_length_by_id get_attribute_data_length_by_id; /**< function pointer that returns the data length of an attribute */
    generic_get_attribute_position_by_id get_attribute_position; /**< function pointer that returns the attribute position in the message */
    generic_is_valid_attribute is_valid_attribute; /**< function pointer that indicates if an attribute is valid for this protocol or not */
    generic_get_attribute_scope get_attribute_scope; /**< function pointer that indicates the scope of an attribute */
    generic_get_attribute_extraction_function get_attribute_extraction_function; /**< function pointer that indicates the extraction function to use for a given attribute of this protocol */
    generic_comparison_fct session_key_compare; /**< Pointer to the session keys comparison function. Will exist if the proto has a session context. */
    generic_hash_fct session_key_hash; /**< Pointer to the session key hash function (packed 5-tuple). Used to back the session store with a hash table. May be NULL (falls back to a slow constant hash). */
    generic_equal_fct session_key_equal; /**< Pointer to the session key equality predicate (issue #253, F-PERF-008). When set, the session store tests keys with ONE call instead of two session_key_compare invocations. May be NULL (falls back to !cmp(a,b) && !cmp(b,a)). */

    mmt_classify_next_t classify_next; /**< For internal use. MUST not be changed. */
    mmt_analyser_t data_analyser; /**< For internal use. Must not be chagned.*/

    void * attributes_map; /**< For internal use. MUST not be changed. */
    void * attributes_names_map; /**< For internal use. MUST not be changed. */
    //void * sessions_map; /**< For internal use. MUST not be changed. */
    //void * classify_next; /**< For internal use. MUST not be changed. */
    void * sessionize; /**< For internal use. MUST not be changed. */
    void * session_data_init; /**< For internal use. Must not be chagned.*/
    void * session_data_cleanup; /**< For internal use. Must not be changed. */
    //void * session_data_analysis; /**< For internal use. Must not be chagned.*/
    void * session_context_cleanup; /**< For internal use. Must not be changed. */
    void * protocol_context_init; /**< For internal use. Must not be changed. */
    void * protocol_context_cleanup; /**< For internal use. Must not be changed. */
    void * protocol_context_args; /**< For internal use. Must not be changed. Pointer to the protocol's context argument.
                                   * Will be passed when calling protocol_context_init and protocol_context_cleanup. */
    //void * args; /**< For internal use. MUST not be changed. */
    int (* update_protocol_fct) (int); // function to update protocol structure
};

struct protocol_instance_struct {
    protocol_t * protocol; /**< pointer to the protocol model */
    proto_statistics_internal_t * proto_stats; /**< pointer to the protocol stats (linked list) */
    void * sessions_map; /**< For internal use. MUST not be changed. */
    void * args; /**< For internal use. MUST not be changed. */
};

/* Issue #245 (F-PERF-003): pooled reassembly ipacket — a slot owns the
 * packet structure plus a grow-once copy buffer, so the reassembly packet
 * path performs no per-packet allocations in steady state. The ipacket member
 * MUST stay first: clean_packet_with_reassembly() recovers the slot from the
 * ipacket pointer by a plain cast. Slots live on the handler's freelist
 * (mmt_handler_struct.ipacket_pool); a packet held by a user callback keeps
 * its slot until mmt_drop_packet()/clean-up, which bounds the pool by the
 * number of concurrently held packets. */
typedef struct mmt_ipacket_slot_s {
    ipacket_t ipacket;                    /* MUST stay the first member */
    struct mmt_ipacket_slot_s *next_free;
    uint8_t *data;                        /* owned copy of the packet bytes */
    uint32_t data_cap;                    /* allocated size of data */
} mmt_ipacket_slot_t;

struct mmt_handler_struct {
    uint8_t has_reassembly; // 0 - no, 1 - yes
    // Classification process configuration
    uint8_t hostname_classify; // 0 - disable, 1 - enable
    uint8_t ip_address_classify; // 0 - disable, 1 - enable
    uint8_t port_classify; // 0 - no classification based on port number, 1 - classification based on port number
    uint8_t port_classify_payload_confirm; // M9 (issue #75): 0 - accept any port-based guess (default), 1 - only accept a port-based guess when a payload signature confirms it
    uint8_t classification_max_depth; // Issue #87: deepest protocol-path index the classifier may write (0..PROTO_PATH_SIZE-1; PROTO_PATH_SIZE-1 = unlimited). Layers already in the path stay; the classify walk and path appends stop below it.

    uint32_t last_expiry_timeout;
    uint32_t attr_extraction_strategy;
    uint32_t stats_reporting_status;
    // General session timedout value
    uint32_t default_session_timed_out;
    uint32_t long_session_timed_out;
    uint32_t short_session_timed_out;
    uint32_t live_session_timed_out;
    uint64_t packet_count;
    uint64_t sessions_count;
    uint64_t active_sessions_count;

    session_expiry_handler_t session_expiry_handler;
    session_timer_handler_t session_timer_handler;    // This is the function registered by user and will be call from function process_timer_handler()

    packet_info_t last_received_packet;
    ipacket_t current_ipacket;
    generic_process_packet_fct process_packet;
    generic_clean_packet_fct clean_packet;
    // Evasion
    evasion_handler_t * evasion_handler;
    uint32_t fragment_in_packet; // Number of new fragment in one packet which will trigger the fragmentation evasion: 1
    uint32_t fragmented_packet_in_session; // Number of fragmented packet in one session which will trigger the fragmentation evasion: 2
    uint32_t fragment_in_session; // Number of fragment in one session which will trigger the fragmentation evasion: 2

    protocol_stack_t * link_layer_stack;
    protocol_instance_t configured_protocols[PROTO_MAX_IDENTIFIER];
    /* Issue #252 (F-PERF-017): the per-protocol registration-time lists are
     * frozen into contiguous arrays — the per-packet attribute/handler walks
     * index these instead of chasing ->next through separately allocated
     * nodes. Register/unregister (cold paths) mutate the arrays in place;
     * the _len/_cap pairs track element count vs allocated capacity.
     * proto_registered_attributes stays sorted by field_id (the order the
     * old sorted-insert list kept). */
    attribute_internal_t ** proto_registered_attributes[PROTO_MAX_IDENTIFIER];
    uint32_t proto_registered_attributes_len[PROTO_MAX_IDENTIFIER];
    uint32_t proto_registered_attributes_cap[PROTO_MAX_IDENTIFIER];
    attribute_handler_element_t * proto_registered_attribute_handlers[PROTO_MAX_IDENTIFIER];
    uint32_t proto_registered_attribute_handlers_len[PROTO_MAX_IDENTIFIER];
    uint32_t proto_registered_attribute_handlers_cap[PROTO_MAX_IDENTIFIER];
    packet_handler_t * packet_handlers;
    uint32_t packet_handlers_len;
    uint32_t packet_handlers_cap;
    // Specific session timedout value
    // uint32_t mmt_http_session_timed_out;
    mmt_hashmap_t *ip_streams;
    /* Destructor for values stored in ip_streams (ip_dgram_t, registered by
     * the IP plugin the first time it pushes an incomplete datagram). The
     * handler owns the map but not the value type, so the plugin hands its
     * destructor over and mmt_close_handler() drains the map before freeing
     * it — otherwise datagrams that never complete leak (issue #216). */
    void (*ip_streams_value_free)(void * value);
    /* IPv6 fragment reassembly keeps its own map (issue #216): the v4/v6
     * key builders share the same 64-bit key space, so a single map could
     * collide a v4 datagram with a v6 one, and the two value types need
     * different destructors — a shared map cannot drain both correctly. */
    mmt_hashmap_t *ip6_streams;
    void (*ip6_streams_value_free)(void * value);
    void * timeout_milestones_map; // Session timeout milestones map
    /* Issue #201 (F-BUG-020): ip_streams holds in-flight IPv4/IPv6 fragment
     * reassembly datagrams. The TCP/IP plugin arms these hooks the first time
     * a fragment is processed; mmt_core invokes the sweep from the existing
     * once-per-second session-expiry pass (process_timedout_sessions) and the
     * drain from mmt_close_handler, so fragment datagrams cannot grow the map
     * for the whole handler lifetime or leak at teardown. The signatures are
     * plugin-agnostic on purpose. */
    void (*frag_map_sweep_fct)(mmt_hashmap_t *map, uint32_t now);
    void (*frag_map_drain_fct)(mmt_hashmap_t *map);
    /* Issue #245: per-flow ceiling on TCP reassembly content bytes (pending
     * segments + flattened image). Set via set_tcp_reassembly_limit(); the
     * default is MMT_TCP_REASSEMBLY_LIMIT_DEFAULT. */
    uint32_t tcp_reassembly_limit;
    /* Issue #245: freelist of mmt_ipacket_slot_t recycled by
     * process_packet_with_reassembly()/clean_packet_with_reassembly() —
     * drained by mmt_close_handler(). */
    mmt_ipacket_slot_t *ipacket_pool;
};



/////////// PLUGIN INIT FOR PROTO_META //////////////////
/**
 * Initializes META protocol. This protocol MUST BE INITIALIZED in order to run mmt.
 * @return a positive value on success, zero on failure.
 */
int init_proto_meta_struct();
/////////////////////////////////////////////////
/////////// PLUGIN INIT FOR PROTO_UNKNOWN //////////////////
/**
 * Initializes Unknown protocol. This protocol MUST BE INITIALIZED in order to run mmt.
 * @return a positive value on success, zero on failure.
 */
int init_proto_unknown_struct();
/////////////////////////////////////////////////

int base_classify_next_proto(ipacket_t * ipacket, unsigned index);

/**
 * Packaging dependent initialization routine. This should be implemented
 * per packaging needs. For the core mmt with no preinstalled plugins this
 * routine does nothing but returing a positive value.
 * @return a positive value on success, zero on failure.
 */
int package_dependent_init();

/**
 * Cleanup function that frees the registered extraction attributes. Will be called on closing the library.
 * @param mmt_handler pointer to the mmt handler we want to unregister the extraction attributes from
 */
void free_registered_extraction_attributes(mmt_handler_t *mmt_handler);

/**
 * Cleanup function that frees the registered attribute handlers.
 * @param mmt_handler pointer to the mmt handler we want to unregister the attribute handlers from
 */
void free_registered_attribute_handlers(mmt_handler_t *mmt_handler);

/**
 * Cleanup function that frees registered packet handlers.
 * @param mmt_handler pointer to the mmt handler we want to unregister the packet handlers from
 */
void free_registered_packet_handlers(mmt_handler_t *mmt_handler);

/**
 * Cleanup function that frees registered protocol.
 */
void free_registered_protocols();

/**
 * Forces the timeout of sessions associated to the least recent timeout slots. The minimum number
 * of sessions to timeout is given by the mmt_handler. This function is intended to be used in
 * out of memory situations.
 * @param mmt_handler pointer to the mmt handler we want to free some sessions
 * @param ipacket pointer to the mmt internal packet that was under processing
 */
void process_outofmemory_force_sessions_timeout(mmt_handler_t *mmt_handler, ipacket_t * ipacket);

/**
 * Creates a protocol statistics instance for the given protocol and the given parent stats
 * @param proto pointer to the protocol instance
 * @param parent_proto_stats pointer to the parent protocol stats
 * @return pointer to the created protocol statistics on success, NULL on failure
 */
proto_statistics_internal_t * create_protocol_stats_instance(protocol_instance_t * proto, proto_statistics_internal_t * parent_proto_stats);

/**
 * Returns a pointer to the protocol statistics in the parent protocol encapsulated stats
 * @param proto pointer to the protocol instance
 * @param parent_proto_stats pointer to the parent protocol stats instance
 * @return pointer to the protocol statistics. If it does not exist, it will be created.
 */
proto_statistics_internal_t * get_protocol_stats_from_parent(protocol_instance_t * proto, proto_statistics_internal_t * parent_proto_stats);

/**
 * Returns a pointer to the protocol statistics of the child protocol identified by \child_proto_id
 * @param proto_stats pointer to the protocol stats instance
 * @param child_proto_id identifier of the child protocol
 * @return pointer to the child protocol statistics if it exists, NULL otherwise.
 */
proto_statistics_internal_t * get_child_protocol_stats(proto_statistics_internal_t * proto_stats, uint32_t child_proto_id);

/**
 * Prints the protocol stats tree rooted at the given protocol
 * @param f file descriptor
 * @param proto pointer to the root protocol
 */
void print_protocol_stats_tree(FILE * f, protocol_instance_t * proto);

/**
 * Prints the protocol stats for the given protocol
 * @param f file descriptor
 * @param proto pointer to the protocol
 */
void print_protocol_stats(FILE * f, protocol_instance_t * proto);

/**
 * Iterates through the registered protocol stacks and calls the given callback function for every registered protocol stack.
 * @param fct The callback function. It will be called for every registered protocol stack.
 * @param args pointer to the user argument. It will be passed to the callback function.
 */
void iterate_through_protocol_stacks(generic_mapspace_iteration_callback fct, void * args);


  /** Checks when the @p payload starts with the string literal @p str.
   * When the string is larger than the payload, check fails.
   * @return non-zero if check succeeded
   */
int mmt_match_prefix(const u_int8_t *payload, size_t payload_len, const char *str, size_t str_len);
  /* version of mmt_match_prefix with string literal */
#define mmt_match_strprefix(payload, payload_len, str) mmt_match_prefix((payload), (payload_len), (str), (sizeof(str)-1))

  /**
   * Search the first occurrence of substring -find- in -s-
   * The search is limited to the first -slen- characters of the string
   *
   * @par    s     = string to parse
   * @par    find  = string to match with -s-
   * @par    slen  = max length to match between -s- and -find-
   * @return a pointer to the beginning of the located substring;
   *         NULL if the substring is not found
   *
   */
char* mmt_strnstr(const char *s, const char *find, size_t slen);

int process_packet(mmt_handler_t *mmt, struct pkthdr *header, const u_char * packet);
int process_packet_with_reassembly(mmt_handler_t *mmt, struct pkthdr *header, const u_char * packet);
void clean_packet(ipacket_t * ipacket);
void clean_packet_with_reassembly(ipacket_t * ipacket);

/* ===== Internal cross-module prototypes (issues #239, #240) ===============
 * The packet-processing module is split into five translation units:
 * packet_processing.c (the attribute accessors/formatting tail and misc
 * helpers), packet_pipeline.c (per-packet processing path and the
 * attribute-extraction machinery), packet_registry.c (protocol / handler /
 * attribute registration and handler lifecycle), packet_session.c (session
 * lifecycle and timeout — issue #240) and packet_stats.c (protocol
 * statistics — issue #240). The entry points below keep external linkage so
 * the units can call each other; they are not part of the public SDK ABI.
 * ======================================================================== */

/*
 * Issue #69: the analysis/classification "status" flags live on the SHARED
 * global protocol descriptors (each handler's configured_protocols[i].protocol
 * aliases the same global protocol_t). The enable/disable helpers write
 * them from mmt_init_handler(), while proto_packet_analyze() and
 * proto_packet_classify_next() read them LOCK-FREE on the per-packet hot path.
 * Creating the very first
 * handlers concurrently from cold therefore races on these flags.
 *
 * We make every access to these flags an atomic operation (relaxed ordering)
 * using the compiler __atomic_* builtins. This keeps the hot-path read
 * lock-free -- a relaxed atomic load of an int is a plain load on common
 * targets (no fence, no lock) -- while making the concurrent idempotent writes
 * plus reads race-free under the C memory model, which is exactly what TSan
 * checks. Relaxed ordering is sufficient because the flag only gates whether
 * analysis/classification runs for a protocol: the function pointers and
 * analyse/classify lists it guards are populated during single-threaded
 * init_extraction()/registration and are stable before any worker thread can
 * observe the flag, so no other data is published through it.
 *
 * The flag remains a plain int in the struct (no ABI/layout change); only the
 * accesses are made atomic.
 */
static inline int proto_status_load(const int *status) {
    return __atomic_load_n(status, __ATOMIC_RELAXED);
}
static inline void proto_status_store(int *status, int value) {
    __atomic_store_n(status, value, __ATOMIC_RELAXED);
}

/* packet_session.c — session lifecycle, called by packet_registry.c and
 * packet_pipeline.c. */
void force_sessions_timeout(void * timeout_milestone, void * milestone_sessions_list, void * args);
void process_timedout_sessions(mmt_handler_t *mmt_handler, uint32_t current_seconds);
int proto_session_management(ipacket_t * ipacket, protocol_instance_t * configured_protocol, unsigned index);

/* packet_stats.c — statistics, called by packet_registry.c,
 * packet_pipeline.c and packet_session.c. */
void free_handler_protocols_statistics(mmt_handler_t *mmt_handler);
proto_statistics_internal_t * update_proto_stats_on_packet(ipacket_t * ipacket, protocol_instance_t * configured_protocol, proto_statistics_internal_t * parent_stats, uint32_t proto_offset, unsigned index);
proto_statistics_internal_t * update_proto_stats_on_new_session(ipacket_t * ipacket, protocol_instance_t * configured_protocol, proto_statistics_internal_t * parent_stats, int new_session, uint32_t proto_offset, unsigned index);
void register_protocol_stats_attributes(protocol_t *proto);
void register_protocol_session_attributes(protocol_t *proto);

/**
 * Updates the protocol statistics on session timeout. It will basically increase the number
 * of timedout sessions for the protocols in the given session.
 * @param timed_out_session the timed out session.
 * @param parent_proto_stats pointer to the parent protocol statistics
 */
void update_proto_stats_on_session_timeout(mmt_session_t * timed_out_session, proto_statistics_internal_t * parent_proto_stats);

/* dpi_profiles.c — DPI profile registry (issue #87). Applies the
 * MMT_DPI_PROFILES_FILE / MMT_DPI_PROFILE environment selection onto a fresh
 * handler; called once by mmt_init_handler() (single-threaded init). */
void mmt_dpi_profile_apply_env(mmt_handler_t *mmt_handler);

/* packet_registry.c — registered-attribute bookkeeping, called by
 * packet_pipeline.c and packet_processing.c. */
bool attribute_ids_comparison_fct(uint32_t l_id, uint32_t r_id);
struct attribute_internal_struct * get_registered_attribute_internal_struct(const ipacket_t * ipacket, uint32_t proto_id, uint32_t attribute_id, unsigned index);
struct attribute_internal_struct * get_registered_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id);

/* Issue #245 (F-PERF-003/004/005/006): TCP-reassembly instrumentation. The
 * counters live in libmmt_core (packet_pipeline.c) — the one shared object
 * the protocol plugin resolves at dlopen() time — so the plugin increments
 * the SAME instance a harness reads through the linked library. They are
 * always-on relaxed-atomic counters: a handful of adds per segment is
 * negligible next to the segment payload copy itself, and keeping them
 * unconditional lets the phase-0 harness assert against a stock build.
 *   - visits: nodes examined by sorted-list insertion (O(n^2) tripwire)
 *   - moved:  payload bytes the flatten path memcpy()s into image buffers
 *   - dropped: payload bytes refused by the per-flow ceiling / late-arrival
 *   - packet_allocs: allocations performed by process_packet_with_reassembly()
 *     (slot creation or copy-buffer growth — steady-state must be 0) */
void mmt_tcp_reasm_stat_visit(void);
void mmt_tcp_reasm_stat_move(uint32_t bytes);
void mmt_tcp_reasm_stat_drop(uint32_t bytes);
/* Signed delta on the resident reassembly bytes (pending carves + image
 * bytes across all sessions) — the quantity the per-flow ceiling bounds. */
void mmt_tcp_reasm_stat_live(int64_t delta);
void mmt_reassembly_stat_packet_alloc(void);
uint64_t mmt_tcp_reasm_insert_visits(void);
uint64_t mmt_tcp_reasm_bytes_moved(void);
uint64_t mmt_tcp_reasm_bytes_dropped(void);
uint64_t mmt_tcp_reasm_resident_bytes(void);
uint64_t mmt_reassembly_packet_alloc_count(void);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_PROCESSING_H */

