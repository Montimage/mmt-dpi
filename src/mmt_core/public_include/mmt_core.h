/*
 * File:   mmt_core.h
 * Author: montimage
 *
 * Created on 27 mai 2011, 16:31
 */

#ifndef MMT_CORE_H
#define MMT_CORE_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "data_defs.h"
#include "mmt_exports.h"
#include "plugin_defs.h"
#include "proto_meta.h"
#include "dbg.h"
#include "mmt_utils.h"

/* NOTE: DLT/protocol constants (DLT_EN10MB, THALES_TDMA_PROTO, ECITIZ_PROTO) logically belong to protocol stacks
 * but are kept here for backward compatibility so existing callers need not include extra headers. */
#ifndef DLT_EN10MB
#define DLT_EN10MB              1       /**< Ethernet (10Mb) */
#endif
#ifndef THALES_TDMA_PROTO
#define THALES_TDMA_PROTO       0x1000  /**< Identifier of THALES_TDMA_PROTO */
#endif
#ifndef ECITIZ_PROTO
#define ECITIZ_PROTO       0x1001  /**< Identifier of ECITIZ_PROTO */
#endif

#define PROTO_MAX_IDENTIFIER    1000    /**< Maximum number of configured protocols */

#define PROTO_REGISTERED        1       /**< Registered protocol code */
#define PROTO_NOT_REGISTERED    0       /**< Not registered protocol code */

#define POSITION_NOT_KNOWN      -1      /**< Attribute position not known code. */

typedef enum {
    SCOPE_PACKET = 1,          /**< Packet scope attribute. May change with each packet. */
    SCOPE_SESSION = 2,         /**< Session scope attribute. Will not change during the session lifetime. */
    SCOPE_SESSION_CHANGING = 4,/**< Session scope attribute that might change during the session lifetime. */
    SCOPE_ON_DEMAND = 7,       /**< (SCOPE_PACKET | SCOPE_SESSION | SCOPE_SESSION_CHANGING) */
    SCOPE_EVENT = 0x10         /**< Event scope attribute. */
} mmt_attr_scope_t;
/* Macro aliases for ABI/source compatibility: keep #define for #ifdef checks */
#ifndef SCOPE_PACKET
#define SCOPE_PACKET            1
#endif
#ifndef SCOPE_SESSION
#define SCOPE_SESSION           2
#endif
#ifndef SCOPE_SESSION_CHANGING
#define SCOPE_SESSION_CHANGING  4
#endif
#ifndef SCOPE_ON_DEMAND
#define SCOPE_ON_DEMAND         7
#endif
#ifndef SCOPE_EVENT
#define SCOPE_EVENT             0x10
#endif

#define ATTRIBUTE_UNSET         0 /**< Code indicating the attribute is not set. */
#define ATTRIBUTE_SET           1 /**< Code indicating the attribute is set. */
#define ATTRIBUTE_CONSUMED      2 /**< Code indicating the attribute was consimed. This means the user program got its value. */

#define L2H_DIRECTION   1 /**< Indicates that the packet direction in the session is from the node with lower identifier to that of higher identifier */
#define H2L_DIRECTION   0 /**< Indicates that the packet direction in the session is from the node with higher identifier to that of lower identifier */

#define FROM_INITIATOR  1 /**< Indicates that the packet direction is from the session initiator to the server */
#define TO_INITIATOR    2 /**< Indicates that the packet direction is from the server to the session initiator */
#define FROM_SERVER     2 /**< Indicates that the packet direction is from the server to the session initiator */
#define TO_SERVER       1 /**< Indicates that the packet direction is from the session initiator to the server */

#define HAS_SESSION_CONTEXT     1 /**< Code for a protocol with session context */
#define NO_SESSION_CONTEXT      0 /**< Code for a protocol with no session context */

#define MMT_ERRBUF_SIZE 1024 /**< Maximum size of MMT error messages. */

#define STATS_RATES_REPORT      1
#define STATS_NO_RATES_REPORT   (0xFFFFFFFF - STATS_RATES_REPORT)

#define MMT_CONTINUE    0 /**< Defines the code for continue processing */
#define MMT_DROP        -1 /**< Defines the code for dropping the packet currently under processing */
#define MMT_SKIP        -2 /**< Defines the code for skipping further processing of the packet.
                            This means that processing at the current protocol will continue, but
                            the packet will be skipped afterwards. */
#define MMT_PRINT_INFO "\n\t* * * * * * * * * * * * * * * *\n\t*     M M T - L I B R A R Y   *\n\t* * * * * * * * * * * * * * * *\n\t\n\tWebsite: http://montimage.eu\n\tContact: contact@montimage.eu\n\n\n"
#ifndef VERSION
#define VERSION "1.9.0"
#endif

#ifdef GIT_VERSION
//GIT_VERSION is given by Makefile
#define MMT_VERSION VERSION " (" GIT_VERSION ")"
#else
#define MMT_VERSION VERSION
#endif

// EVASION TYPE

#define EVA_IP_FRAGMENT_PACKET 1 // Event: too many fragments in one packet
#define EVA_IP_FRAGMENT_SESSION 2 // Event: too many fragments in one session
#define EVA_IP_FRAGMENTED_PACKET_SESSION 3 // Event: too many fragmented packet in one session
#define EVA_IP_FRAGMENT_OVERLAPPED 4 // Event: IP fragmentation overlapping data
#define EVA_IP_FRAGMENT_DUPLICATED 5 // Event: IP fragmentation duplicated segments

/**
 * Generic packet handler callback
 */
// typedef void (*generic_packet_handler_callback) (const ipacket_t * ipacket, void * args);

/**
 * Generic packet handler callback
 */
typedef int (*generic_packet_handler_callback) (const ipacket_t * ipacket, mmt_opaque_t args);

/**
 * Generic evasion handler callback
 */
typedef void (*generic_evasion_handler_callback) (const ipacket_t * ipacket, mmt_proto_id_t proto_id, mmt_proto_index_t proto_index, unsigned evasion_id, mmt_opaque_t data, mmt_opaque_t args);

/**
 * Generic process_packet
 */
typedef int (*generic_process_packet_fct) (mmt_handler_t *mmt, struct pkthdr *header, const u_char * packet);

/**
 * Generic clean_packet
 */
typedef void (*generic_clean_packet_fct) (ipacket_t *ipacket);

/**
 * Signature of the session timeout handler.
 */
typedef void (*generic_session_timeout_handler_function)(const mmt_session_t * expired_session, mmt_opaque_t args);
/**
 * Signature of the session timer handler - call preodically.
 */
typedef void (*generic_session_timer_handler_function)(const mmt_session_t * head_session, mmt_opaque_t args);

/**
 * Signature of the attribute handler function
 */
typedef void (*attribute_handler_function)(const ipacket_t * ipacket, attribute_t * attribute, mmt_opaque_t user_args);

/**
 * Signature of the function that should be called when iterating between the entries of a map (hash map, list, map, whatever...).
 */
typedef void (*generic_mapspace_iteration_callback) (mmt_opaque_t key, mmt_opaque_t value, mmt_opaque_t args);

/**
 * Signature of the function that will be called by the protocol attribute iterator.
 */
typedef void (*generic_protocol_attribute_iteration_callback) (attribute_metadata_t * attribute, mmt_proto_id_t proto_id, mmt_opaque_t args);

/**
 * Signature of the function that will be called by the protocol iterator.
 */
typedef void (*generic_protocol_iteration_callback) (mmt_proto_id_t proto_id, mmt_opaque_t args);

/**
 * Signature of the function that will be called by the mmt handler iterator.
 */
typedef void (*generic_handler_iteration_callback) (mmt_handler_t *mmt_handler, mmt_opaque_t args);

/**
 * Start process packet handlers
 */
MMTAPI void MMTCALL process_packet_handler(ipacket_t *ipacket);

/**
 * Drop a packet - stop analysing the packet
*/
MMTAPI void MMTCALL mmt_drop_packet(ipacket_t *ipacket);

/**
 * Initializes the extraction. This function MUST be called first.
 * @return a positive value on success, 0 otherwise
 */
MMTAPI bool MMTCALL init_extraction();

/**
 * Update protocol
 * @param   proto_id    Protocol id
 * @param   action_id   Action id -> to update
 * @return a positive value on success, 0 otherwise
 */
MMTAPI bool MMTCALL update_protocol(mmt_proto_id_t proto_id, int action_id);

/**
 * Closes the extraction and frees any previously allocated memory.
 */
MMTAPI void MMTCALL close_extraction();

/**
 * Initializes a new MMT_ Extraction handler. This function MUST be called first in order to initialize the handler.
 * @param stacktype identifier of the stack type (this tells mmt about the type of the data to process)
 * @param options initialization options
 * @param errbuf buffer to hold the error message in case of initialization error
 * @return pointer to the initialized MMT Extraction handler on success, NULL on failure. If NULL is returned, errbuf is filled in
   with an appropriate error message. errbuf is assumed to be able to hold #MMT_ERRBUF_SIZE chars.
 */
MMTAPI mmt_handler_t* MMTCALL mmt_init_handler(
    uint32_t stacktype,
    uint32_t options,
    char * errbuf
);

/**
 * Closes the given MMT handler and frees any allocated objet.
 * @param mmt_handler pointer to the MMT handler to close.
 */
MMTAPI void MMTCALL mmt_close_handler(
    mmt_handler_t *mmt_handler
);


/**
 * Get number of active session
 * @param  mmt_handler MMT Handler
 * @return             number of active session
 *                     -1 if the mmt_handler is NULL
 */
MMTAPI uint64_t MMTCALL get_active_session_count(
    mmt_handler_t *mmt_handler
);

/**
 * Returns the protocol stack name given its identifier.
 * @param s_id The protocol stack identifier.
 * @return the name of the protocol stack corresponding to the given identifier if such a protocol stack is registered, NULL otherwise.
 */
MMTAPI const char* MMTCALL get_protocol_stack_name(
    uint32_t s_id
);

/**
 * Returns a positive value if the given packet handler id is already registered, 0 otherwise.
 * @param mmt_handler pointer to the mmt handler we want to check
 * @param packet_handler_id the identifier of the packet handler
 * @return a positive value if the given packet handler id is already registered, 0 otherwise.
 */
MMTAPI bool MMTCALL is_registered_packet_handler(
    mmt_handler_t *mmt_handler,
    int packet_handler_id
);

/**
 * Registers a packet handler. That is a callback that will be called at every received packet.
 * @param mmt_handler pointer to the mmt handler we want to register the packet handler with
 * @param packet_handler_id the identifier of the packet handler to register.
 * It should be unique, two packet handlers cannot have the same id
 * @param function the call back function
 * @param user a pointer to user argument that will be passed to the callback function.
 * @return a positive value upon success, a zaro value otherwise.
 */
MMTAPI bool MMTCALL register_packet_handler(
    mmt_handler_t *mmt_handler,
    int packet_handler_id,
    generic_packet_handler_callback function,
    mmt_opaque_t user
);

/**
 * Unregisters a packet handler, returns a positive value on success, 0 otherwise.
 * @param mmt_handler pointer to the mmt handler we want to unregister the packet handler from
 * @param packet_handler_id the identifier of the packet handler
 * @return a positive value on success, 0 otherwise. If there is no packet handler with the given identifier,
 * a positive value is returned. 0 is only returned when an error occurs.
 */
MMTAPI bool MMTCALL unregister_packet_handler(
    mmt_handler_t *mmt_handler,
    int packet_handler_id
);

/**
 * Registers a session timeout handler. The registered function will override any previously registered function. This function will be called whenever a session expires.
 * @param mmt_handler pointer to the mmt handler we want to register the session timeout handler with
 * @param session_expiry_handler_fct the session expiry callback function to register
 * @param user pointer to a user defined argument to be passed to the callback function
 * @return This function will always succeed; a positive value will be returned.
 */
MMTAPI bool MMTCALL register_session_timeout_handler(
    mmt_handler_t *mmt_handler,
    generic_session_timeout_handler_function session_expiry_handler_fct,
    mmt_opaque_t user
);

/**
 * Registers a session timer handler. The registered function will override any previously registered function.
 * This function will be called whenever the user want to process the session like after a prediod of time
 * @param mmt_handler pointer to the mmt handler we want to register the session timeout handler with
 * @param session_timer_handler_fct the session timer callback function to register
 * @param user pointer to a user defined argument to be passed to the callback function
 * @return This function will always succeed; a positive value will be returned.
 */
MMTAPI bool MMTCALL register_session_timer_handler(
    mmt_handler_t *mmt_handler,
    generic_session_timer_handler_function session_timer_handler_fct,
    mmt_opaque_t user,
    uint8_t no_fragmented
);


/**
 * Returns a positive value if the attribute identifier by the given protocol and attribute ids is already registered, 0 otherwise.
 * @param mmt_handler pointer to the mmt handler we want to check
 * @param proto_id the identifier of the protcol
 * @param attribute_id the identifier of the attribute
 * @return a positive value if the attribute identifier by the given protocol and attribute ids is already registered, 0 otherwise.
 */
MMTAPI bool MMTCALL is_registered_attribute(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id
);

/**
 * Registers the evasion handler
 * @param mmt_handler pointer to the mmt handler we want to register the extraction attribute with
 * @param evasion_handler the identifier of the protocol of the attribute.
 * @param attribute_id the identifier of the attribute itself.
 * @param user_args User data
 * @return a positive value upon success, a zero value otherwise.
 */
MMTAPI bool MMTCALL register_evasion_handler(
    mmt_handler_t *mmt_handler,
    generic_evasion_handler_callback evasion_handler,
    mmt_opaque_t user_args
);

/**
 * Registers an attribute to extract.
 * @param mmt_handler pointer to the mmt handler we want to register the extraction attribute with
 * @param proto_id the identifier of the protocol of the attribute.
 * @param attribute_id the identifier of the attribute itself.
 * @return a positive value upon success, a zero value otherwise.
 */
MMTAPI bool MMTCALL register_extraction_attribute(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id
);

/**
 * Registers an attribute to extract.
 * @param mmt_handler pointer to the mmt handler we want to register the extraction attribute with
 * @param protocol_name the name of the protocol of the attribute.
 * @param attribute_name the name of the attribute itself.
 * @return a positive value upon success, a zero value otherwise.
 */
MMTAPI bool MMTCALL register_extraction_attribute_by_name(
    mmt_handler_t *mmt_handler,
    const char *protocol_name,
    const char *attribute_name
);

/**
 * Unregisters an already registered extraction attribute.
 * @param mmt_handler pointer to the mmt handler we want to unregister the extraction attribute from
 * @param proto_id the identifier of the protocol of the attribute.
 * @param attribute_id the identifier of the attribute itself.
 * @return a positive value upon success, a zero value otherwise.
 * If there is no attribute with the given identifiers, a positive value is returned.
 */
MMTAPI bool MMTCALL unregister_extraction_attribute(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id
);

/**
 * Unregisters an already registered extraction attribute.
 * @param mmt_handler pointer to the mmt handler we want to unregister the extraction attribute from
 * @param protocol_name the name of the protocol of the attribute.
 * @param attribute_name the name of the attribute itself.
 * @return a positive value upon success, a zero value otherwise.
 * If there is no attribute with the given names, a positive value is returned
 */
MMTAPI bool MMTCALL unregister_extraction_attribute_by_name(
    mmt_handler_t *mmt_handler,
    const char *protocol_name,
    const char *attribute_name
);

/**
 * Indicates if the attribute defined by the given protocol and attribute identifiers has a registered handler.
 * @param mmt_handler pointer to the mmt handler we want to check
 * @param proto_id the identifier of the protocol
 * @param attribute_id the identifier of the attribute
 * @return a positive value if a handler is already registered; 0 otherwise.
 */
MMTAPI bool MMTCALL has_registered_attribute_handler(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id
);

/**
 * Indicates if \handler_fct is registered with the attribute defined by \protocol_id and \attribute_id.
 * @param mmt_handler pointer to the mmt handler we want to check
 * @param proto_id the identifier of the protocol
 * @param attribute_id the identifier of the attribute
 * @param handler_fct the attribute handler callback function to check
 * @return a positive value if \handler_fct handler is already registered; 0 otherwise.
 */
MMTAPI bool MMTCALL is_registered_attribute_handler(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id,
    attribute_handler_function handler_fct
);

/**
 * Registers an attribute handler with the attribute defined by the given protocol and attribute identifiers.
 * @param mmt_handler pointer to the mmt handler we want to register the attribute handler with
 * @param proto_id the protocol identifier.
 * @param attribute_id the attribute identifier.
 * @param handler_fct the attribute handler callback function to register.
 * @param handler_condition the condition on the attribute value. Can be NULL.
 * @param user pointer ot user defined argument to be passed to the handler.
 * @return a positive value on sucess and 0 on failure.
 */
MMTAPI bool MMTCALL register_attribute_handler(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id,
    attribute_handler_function handler_fct,
    mmt_opaque_t handler_condition,
    mmt_opaque_t user
);

/**
 * Registers an attribute handler with the attribute defined by the given protocol and attribute names.
 * @param mmt_handler pointer to the mmt handler we want to register the attribute handler with
 * @param protocol_name the protocol name.
 * @param attribute_name the attribute name.
 * @param handler_fct the attribute handler callback function to register.
 * @param handler_condition the condition on the attribute value. Can be NULL.
 * @param user pointer ot user defined argument to be passed to the handler.
 * @return a positive value on sucess and 0 on failure.
 */
MMTAPI bool MMTCALL register_attribute_handler_by_name(
    mmt_handler_t *mmt_handler,
    const char *protocol_name,
    const char *attribute_name,
    attribute_handler_function handler_fct,
    mmt_opaque_t handler_condition,
    mmt_opaque_t user
);

/**
 * Unregisters the attribute handler registered with the attribute defined by the given protocol and attribute identifiers.
 * @param mmt_handler pointer to the mmt handler we want to unregister the attribute handler from
 * @param proto_id the protocol identifier.
 * @param attribute_id the attribute identifier.
 * @param handler_fct the attribute handler callback function to unregister.
 * @return a positive value on sucess and 0 on failure. This function will always succeed.
 */
MMTAPI bool MMTCALL unregister_attribute_handler(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id,
    attribute_handler_function handler_fct
);

/**
 * Unregisters the attribute handler registered with the attribute defined by the given protocol and attribute names.
 * @param mmt_handler pointer to the mmt handler we want to unregister the attribute handler from
 * @param protocol_name the protocol name.
 * @param attribute_name the attribute name.
 * @param handler_fct the attribute handler callback function to unregister.
 * @return a positive value on sucess and 0 on failure. This function will always succeed.
 */
MMTAPI bool MMTCALL unregister_attribute_handler_by_name(
    mmt_handler_t *mmt_handler,
    const char *protocol_name,
    const char *attribute_name,
    attribute_handler_function handler_fct
);

/**
 * Set default timedout session - replace for value of CFG_DEFAULT_SESSION_TIMEDOUT
 * @param  mmt_handler    handler
 * @param  timedout_value value
 * @return                1 if successful
 *                          0 if failed
 */
MMTAPI bool MMTCALL set_default_session_timed_out(
    mmt_handler_t *mmt_handler,
    uint32_t timedout_value
);

/* Issue #245 (F-PERF-006, F-BUG-038): per-flow ceiling on TCP reassembly
 * bytes; segments beyond the ceiling are dropped (see the TCP session-payload
 * attributes). Issue #380 (F-PERF-002): the ceiling bounds RESERVED storage —
 * the pending-segment blocks including their headers plus both directions'
 * image capacities — so content <= reserved <= limit. */
#define MMT_TCP_REASSEMBLY_LIMIT_DEFAULT (4u * 1024u * 1024u)

/**
 * Set the per-flow ceiling on TCP reassembly storage. Only meaningful
 * for handlers running with enable_mmt_reassembly() plus TCP segment
 * reassembly (update_protocol(PROTO_TCP, TCP_ENABLE_REASSEMBLE)). Passing 0
 * restores MMT_TCP_REASSEMBLY_LIMIT_DEFAULT.
 *
 * Issue #380 (F-PERF-002) budget contract: a flow's reserved storage
 * (segment blocks incl. headers + both image capacities) never exceeds
 * `bytes`. A segment is admitted only while the reservations plus the image
 * growth still needed to flatten every pending byte fit; otherwise it is
 * dropped and counted by mmt_tcp_reasm_bytes_dropped(). Duplicate sequence
 * numbers are rejected before any storage is allocated (the first segment
 * wins). Speculative image growth takes at most half of the free budget,
 * and idle image capacity is reclaimed before a segment is refused, so one
 * direction cannot starve the other. Lowering the ceiling mid-flow refuses new reservations until usage
 * falls below it; the next flatten keeps what fits and drops (counts) the
 * rest. Transient realloc() copies and the small per-flow state record are
 * metadata outside the budget. Session teardown releases all of it.
 * @param  mmt_handler    handler
 * @param  bytes          ceiling in bytes
 * @return                1 if successful
 *                          0 if failed
 */
MMTAPI bool MMTCALL set_tcp_reassembly_limit(
    mmt_handler_t *mmt_handler,
    uint32_t bytes
);


/**
 * Set default timedout session - replace for value of CFG_LONG_SESSION_TIMEDOUT
 * @param  mmt_handler    handler
 * @param  timedout_value value
 * @return                1 if successful
 *                          0 if failed
 */
MMTAPI bool MMTCALL set_long_session_timed_out(
    mmt_handler_t *mmt_handler,
    uint32_t timedout_value
);

/**
 * Set default timedout session - replace for value of CFG_SHORT_SESSION_TIMEDOUT
 * @param  mmt_handler    handler
 * @param  timedout_value value
 * @return                1 if successful
 *                          0 if failed
 */
MMTAPI bool MMTCALL set_short_session_timed_out(
    mmt_handler_t *mmt_handler,
    uint32_t timedout_value
);

/**
 * Set default timedout session - replace for value of CFG_LIVE_SESSION_TIMEDOUT
 * @param  mmt_handler    handler
 * @param  timedout_value value
 * @return                1 if successful
 *                          0 if failed
 */
MMTAPI bool MMTCALL set_live_session_timed_out(
    mmt_handler_t *mmt_handler,
    uint32_t timedout_value
);

// IP fragmentation paramters

/**
 * Set value for number of fragment in one packet
 * @param  mmt_handler    handler
 * @param  frag_in_packet value
 * @return                1 if successful
 *                          0 if failed
 */
MMTAPI bool MMTCALL set_fragment_in_packet(
    mmt_handler_t *mmt_handler,
    uint32_t frag_in_packet
);

/**
 * Set value for number of fragmented packet in one session
 * @param  mmt_handler    handler
 * @param  frag_packet_in_session value
 * @return                1 if successful
 *                          0 if failed
 */
MMTAPI bool MMTCALL set_fragmented_packet_in_session(
    mmt_handler_t *mmt_handler,
    uint32_t frag_packet_in_session
);

/**
 * Set value for number of fragments in one session
 * @param  mmt_handler    handler
 * @param  frag_in_session value
 * @return                1 if successful
 *                          0 if failed
 */
MMTAPI bool MMTCALL set_fragment_in_session(
    mmt_handler_t *mmt_handler,
    uint32_t frag_in_session
);

//
/**
 * A debug function that can be used as a packet handler callback. It will print out the
 * extracted attributes.
 * @param user user argument. It has no impact at all in this function.
 */
MMTAPI int MMTCALL debug_extracted_attributes_printout_handler(
    const ipacket_t *ipacket,
    mmt_opaque_t user
);

/**
 * Fires an attribute detection event. If the attribute is registered, this function will extract its value.
 * If the attribute has any registered handlers, they will be called. This function will do nothing if the
 * attribute is not registered.
 * @param ipacket pointer to the current internal packet
 * @param proto_id protocol identifier of the attribute
 * @param attribute_id attribute identifier
 * @param index index of the protocol in the path
 * @param data pointer to the attribute data
 */
MMTAPI void MMTCALL fire_attribute_event(
    ipacket_t *ipacket,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id,
    unsigned index,
    mmt_opaque_t data
);

/**
 * Fires an evasion detection event. If the attribute is registered, this function will extract its value.
 * @param ipacket pointer to the current internal packet
 * @param proto_id protocol identifier of the attribute
 * @param proto_index index of the protocol in the path
 * @param evasion_id the number indicates the type of evasion
 * @param data pointer to the extra data
 */
MMTAPI void MMTCALL fire_evasion_event(
    ipacket_t *ipacket,
    mmt_proto_id_t proto_id,
    mmt_proto_index_t proto_index,
    unsigned evasion_id,
    mmt_opaque_t data
);

/**
 * This is the main API function. It should be called for every packet/event to process.
 * @param mmt_handler pointer to the mmt handler we want to process the packet with
 * @param header pointer to the packet header.
 * @param packet a pointer to the actual packet data.
 * @return a positive value if the process is successful, a zero value if an internal error occurs.
 */
MMTAPI bool MMTCALL packet_process(
    mmt_handler_t *mmt_handler,
    struct pkthdr *header,
    const u_char *packet
);

/**
 * Print out pretty list all attributes of all protocol
 * @return [description]
 * @deprecated Debug helper with 0 callers in src/sdk/tests/examples
 *             (exported via nm -D but never used); prefer
 *             iterate_through_protocols(). Removal is scheduled for
 *             release 2.0.0 (issue #149).
 */
MMTAPI void MMTCALL mmt_print_all_protocols() __attribute__((deprecated("debug helper; prefer iterate_through_protocols; removal in 2.0.0")));
/**
 * This will be call from probe when probe want to do something from library
 * @param  mmt_handler pointer to the mmt_handler we want to do the action
 * @param  user_data   [description]
 */
MMTAPI void MMTCALL process_session_timer_handler(
    mmt_handler_t *mmt_handler
);

/**
 * Register mmt_reassembly library
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL enable_mmt_reassembly(
    mmt_handler_t *mmt_handler
);

/**
 * Unregister mmt_reassembly library
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL disable_mmt_reassembly(
    mmt_handler_t *mmt_handler
);

/**
 * Enable classification by port number
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL enable_port_classify(
    mmt_handler_t *mmt_handler
);

/**
 * Disable classification by port number
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL disable_port_classify(
    mmt_handler_t *mmt_handler
);

/**
 * Enable payload-confirmed port-only demotion (M9, issue #75).
 *
 * When port classification is enabled (see enable_port_classify), a port-based
 * protocol guess is normally accepted unconditionally as a last resort. With
 * this flag enabled, such a guess is only accepted when the packet payload
 * carries a signature consistent with the guessed protocol; otherwise the
 * port-only guess is demoted and the protocol stays unknown. Disabled by
 * default, so the bundled classification behaviour is unchanged.
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL enable_port_classify_payload_confirm(
    mmt_handler_t *mmt_handler
);

/**
 * Disable payload-confirmed port-only demotion (the default, M9 issue #75).
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL disable_port_classify_payload_confirm(
    mmt_handler_t *mmt_handler
);

/**
 * Enable classification by hostname
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL enable_hostname_classify(
    mmt_handler_t *mmt_handler);

/**
 * Disable classification by hostname
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL disable_hostname_classify(
    mmt_handler_t *mmt_handler);

/**
 * Enable classification by IP address (only ipv4)
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL enable_ip_address_classify(
    mmt_handler_t *mmt_handler);

/**
 * Disable classification by IP address (only ipv4)
 * @param  mmt_handler mmt handler
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL disable_ip_address_classify(
    mmt_handler_t *mmt_handler);

/* -------------------- DPI profiles (issue #87) ---------------------------
 *
 * A DPI profile bundles the four independent detection levers of the engine
 * so a deployment can trade detection depth for throughput with one call:
 *
 *   - classification_max_depth: deepest index the classifier may write in
 *     the protocol path — i.e. how many layers deep payload inspection runs.
 *     The path layout is index 0 = PROTO_META, 1 = link layer (ETH), 2 =
 *     network (IP), 3 = transport (TCP/UDP), 4 = first application protocol,
 *     5+ = encapsulated / tunnelled protocols. A profile with max depth 4
 *     inspects "up to 4 levels" and never runs the deeper checker walks.
 *     PROTO_PATH_SIZE - 1 is the compiled-in ceiling ("unlimited" — the
 *     historical behaviour); 0 stops classification at PROTO_META.
 *   - app_protocol_classify: application-protocol detection from TLS SNI /
 *     HTTP Host header and the hostname fingerprint table (the
 *     hostname_classify flag).
 *   - port_classify: protocol attribution from well-known port numbers,
 *     consulted as a last resort after payload classification fails.
 *   - ip_address_classify: protocol attribution from compiled-in or
 *     externally-loaded (MMT_DPI_IP_RANGES_FILE) IP address ranges.
 *
 * Selection: call mmt_apply_dpi_profile() / mmt_apply_dpi_profile_by_name()
 * on a handler, or set the MMT_DPI_PROFILE environment variable to a
 * predefined or file-defined profile name before mmt_init_handler().
 * MMT_DPI_PROFILES_FILE points at a data file adding custom named profiles —
 * one per line:
 *     <name> <max_depth> <app_protocol_classify> <port_classify> <ip_address_classify>
 * (e.g. "edge 4 1 0 0"; '#' starts a comment). Predefined names are
 * reserved: a file entry reusing one is skipped with a diagnostic.
 *
 * The default handler configuration is unchanged — equivalent to
 * MMT_DPI_PROFILE_DEFAULT — so the bundled classification output stays
 * byte-identical unless a profile is explicitly applied.
 */

/**
 * A named set of per-level detection toggles. All fields are read at
 * mmt_apply_dpi_profile() time; invalid combinations are clamped
 * (max_depth) or normalised to 0/1 (the toggles). */
typedef struct mmt_dpi_profile_struct {
    uint8_t classification_max_depth; /**< deepest proto-path index (0..PROTO_PATH_SIZE-1) */
    uint8_t app_protocol_classify;    /**< 0/1 — SNI/hostname/fingerprint application detection */
    uint8_t port_classify;            /**< 0/1 — well-known port attribution */
    uint8_t ip_address_classify;      /**< 0/1 — IP-range attribution */
} mmt_dpi_profile_t;

/* The predefined profile objects are plain `extern` — never MMTAPI: inside
 * the SDK build MMTAPI is empty, which would turn these declarations into
 * one tentative definition per translation unit. */
/** Today's built-in defaults, spelled out: unlimited depth, application
 * detection on, IP-range on, port attribution off. Applying this profile
 * restores the stock configuration. */
extern const mmt_dpi_profile_t MMT_DPI_PROFILE_DEFAULT;
/** Everything on: unlimited depth plus all three heuristic levers,
 * including port attribution. */
extern const mmt_dpi_profile_t MMT_DPI_PROFILE_FULL;
/** Middle ground: inspect through the first application layer and one
 * encapsulation hop (depth 5, enough for TLS SNI attribution), application
 * and IP-range detection on, port attribution off. */
extern const mmt_dpi_profile_t MMT_DPI_PROFILE_BALANCED;
/** Maximum throughput: structural classification only — path stops at the
 * transport layer (depth 3), every heuristic lever off. Sessions and
 * L2–L4 statistics still work; no application protocol is detected. */
extern const mmt_dpi_profile_t MMT_DPI_PROFILE_MINIMAL;

/**
 * Apply a DPI profile to a handler: sets classification_max_depth and the
 * three detection toggles in one call. May be called any time after
 * mmt_init_handler(); mid-stream application only affects subsequent
 * classification (layers already recorded in existing session paths stay).
 * @param  mmt_handler mmt handler
 * @param  profile     profile to apply (must not be NULL)
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL mmt_apply_dpi_profile(
    mmt_handler_t *mmt_handler,
    const mmt_dpi_profile_t *profile
);

/**
 * Apply a named DPI profile: searches the four predefined profiles first,
 * then the custom names loaded via mmt_load_dpi_profiles_file() (or
 * MMT_DPI_PROFILES_FILE). Name matching is case-insensitive.
 * @param  mmt_handler mmt handler
 * @param  name        profile name, e.g. "minimal"
 * @return             0 - unsuccessful (NULL args or unknown name)
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL mmt_apply_dpi_profile_by_name(
    mmt_handler_t *mmt_handler,
    const char *name
);

/**
 * Load custom named DPI profiles from a data file — one profile per line:
 *   <name> <max_depth> <app_protocol_classify> <port_classify> <ip_address_classify>
 * '#' starts a comment; blank and malformed lines are skipped. Names are
 * case-insensitive, must not collide with a predefined profile or an
 * already-loaded name, and are truncated at 31 chars. Loaded profiles are
 * registered process-wide (init-time data, read-only afterwards — same
 * contract as the M9 external tables).
 * @param  path profile file path (NULL/empty is a no-op returning 0)
 * @return      number of profiles loaded, or -1 when the file cannot be opened
 */
MMTAPI int MMTCALL mmt_load_dpi_profiles_file(
    const char *path
);

/**
 * Bound how deep payload inspection walks the protocol path (see the DPI
 * profile block above for the index layout). Values above
 * PROTO_PATH_SIZE - 1 clamp to the unlimited ceiling.
 * @param  mmt_handler mmt handler
 * @param  max_depth   deepest proto-path index (0..PROTO_PATH_SIZE-1)
 * @return             0 - unsuccessful
 *                       1 - sucessful
 */
MMTAPI bool MMTCALL set_classification_max_depth(
    mmt_handler_t *mmt_handler,
    uint8_t max_depth
);

/**
 * Read the current classification depth bound of a handler.
 * @param  mmt_handler mmt handler
 * @return             the bound (PROTO_PATH_SIZE-1 = unlimited), or 0 on NULL handler
 */
MMTAPI uint8_t MMTCALL get_classification_max_depth(
    const mmt_handler_t *mmt_handler
);

/**
 * Sets the timeout delay for the given session.
 * @param session pointer to the session to set its timeout delay
 * @param timeout_delay timeout delay value in seconds
 */
MMTAPI void MMTCALL set_session_timeout_delay(
    mmt_session_t *session,
    uint32_t timeout_delay
);

/**
 * Returns a pointer to the extracted data of the attribute identified by its protocol and field ids. The extracted
 * data is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param proto_id the identifier of the protocol of the attribute.
 * @param attribute_id the identifier of the attribute itself.
 * @return a pointer to the extracted data if it exists, NULL otherwise.
 */
MMTAPI void* MMTCALL get_attribute_extracted_data(
    const ipacket_t *ipacket,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id
);

/**
 * Returns a pointer to the extracted data of the attribute identified by its protocol and field ids. The extracted
 * data is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param proto_id the identifier of the protocol of the attribute.
 * @param attribute_id the identifier of the attribute itself.
 * @param encap_index   The index of the encapsulation layer: for example, if we have: ETH.IP.IP.IP, then encap_index of IP can be: 0, 1, 2
 * @return a pointer to the extracted data if it exists, NULL otherwise.
 * @deprecated Prefer get_attribute_extracted_data_at_index(); this encap_index
 *             variant is uncalled (nm -D shows export, grep -r shows 0 callers
 *             outside definition/headers). Removal is scheduled for
 *             release 2.0.0 (issue #149).
 */
MMTAPI void* MMTCALL get_attribute_extracted_data_encap_index(
    const ipacket_t *ipacket,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id,
    unsigned encap_index
) __attribute__((deprecated("use get_attribute_extracted_data_at_index instead; removal in 2.0.0")));

/**
 * Returns a pointer to the extracted data of the attribute identified by its protocol and field names. The extracted
 * data is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param protocol_name the name of the protocol of the attribute.
 * @param attribute_name the name of the attribute itself.
 * @return a pointer to the extracted data if it exists, NULL otherwise.
 */
MMTAPI void* MMTCALL get_attribute_extracted_data_by_name(
    const ipacket_t *ipacket,
    const char *protocol_name,
    const char *attribute_name
);

/**
 * Returns a pointer to the extracted data of the attribute identified by its protocol and field ids. The extracted
 * data is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param proto_id the identifier of the protocol of the attribute.
 * @param attribute_id the identifier of the attribute itself.
 * @param index index of the protocol in the protocol path.
 * @return a pointer to the extracted data if it exists, NULL otherwise.
 */
MMTAPI void* MMTCALL get_attribute_extracted_data_at_index(
    const ipacket_t *ipacket,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id,
    unsigned index
);

/**
 * Returns a pointer to the extracted attribute structure. The attribute is identified by its protocol and field ids.
 * The returned value is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param proto_id the identifier of the protocol of the attribute.
 * @param attribute_id the identifier of the attribute itself.
 * @return a pointer to the extracted attribute structure if it exists, NULL otherwise.
 */
MMTAPI attribute_t* MMTCALL get_extracted_attribute(
    const ipacket_t *ipacket,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id
);

/**
 * Returns a pointer to the extracted attribute structure. The attribute is identified by its protocol and field names.
 * The returned value is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param protocol_name the name of the protocol of the attribute.
 * @param attribute_name the name of the attribute itself.
 * @return a pointer to the extracted attribute structure if it exists, NULL otherwise.
 */
MMTAPI attribute_t* MMTCALL get_extracted_attribute_by_name(
    const ipacket_t *ipacket,
    const char *protocol_name,
    const char *attribute_name
);

/**
 * Returns a pointer to the extracted attribute structure. The attribute is identified by its protocol and field ids.
 * The returned value is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param proto_id the identifier of the protocol of the attribute.
 * @param attribute_id the identifier of the attribute itself.
 * @param index index of the protocol in the protocol path.
 * @return a pointer to the extracted attribute structure if it exists, NULL otherwise.
 */
MMTAPI attribute_t* MMTCALL get_extracted_attribute_at_index(
    const ipacket_t *ipacket,
    mmt_proto_id_t proto_id,
    uint32_t attribute_id,
    unsigned index
);

/**
 * Returns a pointer to the extracted attribute structure. The attribute is identified by its protocol and field names.
 * The returned value is not NULL if the attribute existed in the last processed message.
 * @param ipacket pointer to the internal from which to extract the attribute.
 * @param protocol_name the name of the protocol of the attribute.
 * @param attribute_name the name of the attribute itself.
 * @param index index of the protocol in the protocol path.
 * @return a pointer to the extracted attribute structure if it exists, NULL otherwise.
 */
MMTAPI attribute_t* MMTCALL get_extracted_attribute_at_index_by_name(
    const ipacket_t *ipacket,
    const char *protocol_name,
    const char *attribute_name,
    unsigned index
);

/**
 * Returns a pointer to the list of the given protocol's statistics.
 * @param mmt_handler pointer to the MMT handler.
 * @param proto_id identifier of the protocol.
 * @return pointer to the list of the given protocol's statistics.
 */
MMTAPI proto_statistics_t* MMTCALL get_protocol_stats(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id
);

/**
 * Returns a pointer to the list of the given protocol's statistics.
 * @param parent_stats pointer to the parent statistics.
 * @param children_stats pointer to the structure where the children statistics will be reported.
 */
MMTAPI void MMTCALL get_children_stats(proto_statistics_t * parent_stats,
                                       proto_statistics_t * children_stats
                                      );

/**
 * Prints the protocol path corresponding to the given protocol statistics instance in the given path.
 * @param mmt_handler pointer to the MMT handler.
 * @param stats pointer to the protocol statistics instance.
 * @param proto_hierarchy pointer to the protocol hierarchy where the path would be printed.
 */
MMTAPI void MMTCALL get_protocol_stats_path(
    mmt_handler_t *mmt_handler,
    proto_statistics_t *stats,
    proto_hierarchy_t *proto_hierarchy
);

/**
 * Resets the given protocol statistics instance
 * @param stats protocol statistics to reset
 */
MMTAPI void MMTCALL reset_statistics(proto_statistics_t * stats);

/**
 * Sets the link type to indicate the nature of the lower layer protocol.
 * @param mmt_handler pointer to the mmt handler we want to register its data link type
 * @param dltype identifier of the data link type.
 * @deprecated This function is obsolete and should not be used; maintained only for
 *             backward compatibility. Removal is scheduled for release 2.0.0
 *             (issue #149).
 *             Evidence: exported in libmmt_core.so (nm -D) but 0 callers in
 *             src/sdk/tests/examples (grep -r "setDataLinkType" shows only definition + headers).
 */
MMTAPI void MMTCALL setDataLinkType(
    mmt_handler_t *mmt_handler,
    int dltype
) __attribute__((deprecated("obsolete - do not use; removal in 2.0.0")));

/**
 * Returns the data link type of the given mmt handler.
 * @param mmt_handler pointer to the mmt handler we want to get its data link type
 * @param dltype identifier of the data link type.
 * @return data identifier of data link type of \mmt_handler
 */
MMTAPI int MMTCALL get_data_link_type(
    mmt_handler_t *mmt_handler
);

/**
 * Enables the maintenance of protocol statistics for the given \mmt_handler
 * @param mmt_handler mmt handler
 */
MMTAPI void MMTCALL enable_protocol_statistics(
    mmt_handler_t *mmt_handler
);

/**
 * Disables the maintenance of protocol statistics for the given \mmt_handler
 * @param mmt_handler mmt handler
 */
MMTAPI void MMTCALL disable_protocol_statistics(
    mmt_handler_t *mmt_handler
);

/**
 * Enables the analysis sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
MMTAPI void MMTCALL enable_protocol_analysis(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id
);

/**
 * Disables the analysis sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
MMTAPI void MMTCALL disable_protocol_analysis(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id
);

/**
 * Enables the classification sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
MMTAPI void MMTCALL enable_protocol_classification(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id
);

/**
 * Disables the classification sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
MMTAPI void MMTCALL disable_protocol_classification(
    mmt_handler_t *mmt_handler,
    mmt_proto_id_t proto_id
);

/**
 * Returns a positive value if the value of the given protocol identifier is valid, 0 otherwise.
 * A protocol identifier MUST have a positive value less than the PROTO_MAX_IDENTIFIER
 * @param proto_id the identifier of the protocol
 * @return a positive value if the given identifier is valid, 0 otherwise.
 */
MMTAPI bool MMTCALL is_valid_protocol_id(
    mmt_proto_id_t proto_id
);

/**
 * Indicates if the protocol with the given identifier is already registered.
 * @param proto_id the identifier of the protocol
 * @return PROTO_REGISTERED if the protocol is already registered, PROTO_NOT_REGISTERED otherwise
 */
MMTAPI bool MMTCALL is_registered_protocol(
    mmt_proto_id_t proto_id
);

/**
 * Iterates through the given protocol's attributes. The given iterator_fct will be called for every attribute.
 * @param proto_id identifier of the protocol.
 * @param iterator_fct pointer to the user function that will be called for every attribute.
 * @param user pointer to the user argument. It will be passed to the iterator callback function.
 */
MMTAPI void MMTCALL iterate_through_protocol_attributes(
    mmt_proto_id_t proto_id,
    generic_protocol_attribute_iteration_callback iterator_fct,
    mmt_opaque_t user
);

/**
 * Iterates through the registered protocols. The given iterator_fct will be called for every protocol.
 * @param iterator_fct pointer to the user function that will be called for every registered protocol.
 * @param user pointer to the user argument. It will be passed to the iterator callback function.
 */
MMTAPI void MMTCALL iterate_through_protocols(
    generic_protocol_iteration_callback iterator_fct,
    mmt_opaque_t user
);

/**
 * Iterates through the registered mmt handlers. The given \iterator_fct will be called for every mmt handler.
 * @param iterator_fct pointer to the user function that will be called for every registered mmt handler.
 * @param user pointer to the user argument. It will be passed to the iterator callback function.
 */
MMTAPI void MMTCALL iterate_through_mmt_handlers(
    generic_handler_iteration_callback iterator_fct,
    mmt_opaque_t user
);

/**
 * Get the current version of mmt-sdk
 * @return current version of mmt-sdk
 */
MMTAPI char* MMTCALL mmt_version();

/**
 * Memory management helpers
 */
MMTAPI void* MMTCALL mmt_malloc  ( size_t size );
MMTAPI void* MMTCALL mmt_realloc ( mmt_opaque_t x, size_t size );
MMTAPI void  MMTCALL mmt_free    ( mmt_opaque_t x );

/**
 * Per-flow arena (slab) allocator.
 *
 * A bump-pointer block allocator intended for per-session/per-flow scratch
 * storage (e.g. the TCP segment list): allocations are carved from large blocks
 * and are NEVER individually freed - the whole arena is released in one shot
 * with mmt_arena_destroy(). This collapses per-packet malloc/free churn into a
 * single create/destroy pair per flow. Returned blocks are 16-byte aligned
 * carve-outs of a larger malloc() block, so they must not be passed to
 * mmt_free()/mmt_realloc() — only whole arenas are released.
 */
typedef struct mmt_arena_s mmt_arena_t;

/** Create an arena. block_size is the default block payload (0 -> 16 KiB). */
MMTAPI mmt_arena_t* MMTCALL mmt_arena_create ( size_t block_size );
/** Carve `size` aligned bytes from the arena (NULL on OOM). */
MMTAPI void*        MMTCALL mmt_arena_alloc  ( mmt_arena_t *arena, size_t size );
/** Release all but one block and rewind, so the arena can be reused. */
MMTAPI void         MMTCALL mmt_arena_reset  ( mmt_arena_t *arena );
/** Free the arena and every block carved from it. */
MMTAPI void         MMTCALL mmt_arena_destroy( mmt_arena_t *arena );

static inline int mmt_memcmp( mmt_const_opaque_t x, mmt_const_opaque_t y, size_t size ){
    const char *s1 = (char*)x, *s2 = (char*)y;
    int ret;
    ret = s1[0] - s2[0];
    if ( size == 1 || ret != 0 )
        return ret;

    ret = s1[1] - s2[1];
    if ( size == 2 || ret != 0 )
        return ret;

    ret = s1[2] - s2[2];
    if ( size == 3 || ret != 0 )
        return ret;

    ret = s1[3] - s2[3];
    if ( size == 4 || ret != 0 )
        return ret;

    ret = s1[4] - s2[4];
    if ( size == 5 || ret != 0 )
        return ret;

    ret = s1[5] - s2[5];
    if ( size == 6 || ret != 0 )
        return ret;

    ret = s1[6] - s2[6];
    if ( size == 7 || ret != 0 )
        return ret;

    ret = s1[7] - s2[7];
    if ( size == 8 || ret != 0 )
        return ret;

    ret = s1[8] - s2[8];
    if ( size == 9 || ret != 0 )
        return ret;

    ret = s1[9] - s2[9];
    if ( size == 10 || ret != 0 )
        return ret;

//0-20
    ret = s1[10] - s2[10];
    if ( size == 11 || ret != 0 )
        return ret;

    ret = s1[11] - s2[11];
    if ( size == 12 || ret != 0 )
        return ret;

    ret = s1[12] - s2[12];
    if ( size == 13 || ret != 0 )
        return ret;

    ret = s1[13] - s2[13];
    if ( size == 14 || ret != 0 )
        return ret;

    ret = s1[14] - s2[14];
    if ( size == 15 || ret != 0 )
        return ret;

    ret = s1[15] - s2[15];
    if ( size == 16 || ret != 0 )
        return ret;

    ret = s1[16] - s2[16];
    if ( size == 17 || ret != 0 )
        return ret;

    ret = s1[17] - s2[17];
    if ( size == 18 || ret != 0 )
        return ret;

    ret = s1[18] - s2[18];
    if ( size == 19 || ret != 0 )
        return ret;

   return memcmp( s1 + 19, s2 + 19, size - 19 );

   // ret = s1[19] - s2[19];
   // if ( size == 20 || ret != 0 )
   //     return ret;
   //
   // return memcmp( s1 + 20, s2 + 20, size - 20 );
}

/**
 * Print Montimage information
 */
void mmt_print_info();

/* Typed inline accessors for weak-type scope (ABI-compatible wrappers, file:line mmt_core.h) */
static inline mmt_attr_scope_t mmt_attr_get_scope_typed(const attribute_t *attr) {
    return (mmt_attr_scope_t)get_attr_scope((attribute_t*)attr);
}
static inline enum data_types mmt_attr_get_data_type_typed(const attribute_t *attr) {
    return (enum data_types)get_attr_data_type((attribute_t*)attr);
}
static inline mmt_attr_scope_t mmt_attribute_get_scope_typed(mmt_proto_id_t proto_id, uint32_t attribute_id) {
    return (mmt_attr_scope_t)get_attribute_scope((mmt_proto_id_t)proto_id, attribute_id);
}
static inline enum data_types mmt_attribute_get_data_type_typed(mmt_proto_id_t proto_id, uint32_t attribute_id) {
    return (enum data_types)get_attribute_data_type((mmt_proto_id_t)proto_id, attribute_id);
}
static inline mmt_proto_id_t mmt_attr_get_proto_id_typed(const attribute_t *attr) {
    return (mmt_proto_id_t)get_attr_protocol_id((attribute_t*)attr);
}

#ifdef  __cplusplus
}
#endif

#endif /* MMT_CORE_H */

