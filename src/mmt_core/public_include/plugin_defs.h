/**
 * @file
 * Plugin-facing definitions: the callback types and structures a
 * protocol plugin uses to register protocols, attributes, sessions and
 * classification functions with the core.
 *
 * Author: montimage
 *
 * Created on 19 mai 2011, 16:33
 */

#ifndef PROTOCOL_EXTRACTION_DEFS_H
#define	PROTOCOL_EXTRACTION_DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif
#include <stdbool.h>

#include "data_defs.h"

/**
 * Generic packet field extraction function
 */
typedef int (*generic_attribute_extraction_function) (
        const ipacket_t * packet, mmt_proto_index_t proto_index,
        attribute_t * extracted_data);

/**
 * Signature of the function for returning the attribute extraction function given the attribute id
 */
typedef generic_attribute_extraction_function(*generic_get_attribute_extraction_function) (mmt_proto_id_t proto_id, uint32_t attribute_id);

/**
 * Releases a value adopted with mmt_packet_scratch_adopt() (free() for a
 * plain heap block).
 */
typedef void (*mmt_packet_scratch_release_function)(mmt_opaque_t value);

/**
 * Hands a heap value an attribute extraction function returns through
 * attribute_t.data over to the handler that processes ipacket (issue #506).
 *
 * The handler releases the value with release() when the next
 * packet_process() call on it starts, or when mmt_close_handler() runs — so
 * the value stays valid while the current packet is processed and its
 * handlers run, and the caller of the extraction function never frees it.
 * An extractor returns its value only when this returns true.
 *
 * @param ipacket the packet being processed (supplies the handler)
 * @param value   the heap value to adopt; NULL adopts nothing
 * @param release the function that frees value
 * @return true when the handler now owns value. false when value is NULL or
 *         release is NULL (nothing was done), or when the handler cannot take
 *         it — ipacket has no handler or the scratch record could not be
 *         allocated — in which case value has already been released.
 */
MMTAPI bool MMTCALL mmt_packet_scratch_adopt(
    const ipacket_t *ipacket,
    mmt_opaque_t value,
    mmt_packet_scratch_release_function release
);

/**
 * Defines the attribute meta data.
 */
typedef struct attribute_metadata_struct {
    int id; /**< identifier of the attribute. Must be unique for a given protocol. */
    char alias[Max_Alias_Len + 1]; /**< the alias(name) of the attribute */
    int data_type; /**< the data type of the attribute */
    int data_len; /**< the data length of the attribute */
    int position_in_packet; /**< the position in the packet of the attribute. */
    int scope; /**< the scope of the attribute (packet, session, ...). */
    generic_attribute_extraction_function extraction_function; /**< the extraction function for this attribute. */
} attribute_metadata_t;

/**
 * Signature of the function for returning attribute id given its name
 */
typedef int (*generic_get_attribute_id_by_name) (mmt_proto_id_t proto_id, const char * attribute_name);

/**
 * Signature of the function for returning attribute name given its id
 */
typedef const char * (*generic_get_attribute_name_by_id) (mmt_proto_id_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for returning attribute data type given its id
 */
typedef int (*generic_get_attribute_data_type_by_id) (mmt_proto_id_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for returning attribute data length given its id
 */
typedef int (*generic_get_attribute_data_length_by_id) (mmt_proto_id_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for returning attribute position in the packet if such a thing is known
 */
typedef int (*generic_get_attribute_position_by_id) (mmt_proto_id_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for returning if the given attribute id exists
 */
typedef int(*generic_is_valid_attribute) (mmt_proto_id_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function returning the scope of the given attribute
 */
typedef int (*generic_get_attribute_scope) (mmt_proto_id_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for cleaning up the protocol stack internal data.
 */
typedef void (*stack_internal_cleanup)(mmt_opaque_t stack_internal_context);

/**
 * Signature of the function that every plugin MUST implement. In the plugin, the function name MUST be "init_proto".
 * This is the function that the MMT-extraction core will call to load the plugin. The function should return a positive value on success, 0 otherwise.
 */
typedef int (*generic_init_proto) (void);

/**
* This is the function that the MMT-extraction core will call to cleanup the resource that plugin has used
*/
typedef int (*generic_cleanup_proto)(void);

/**
 * Defines a classified protocol including the identifier of the protocol and its offset in the packet.
 */
typedef struct classified_proto_struct {
    uint16_t offset; /**< offset of the protocol in the packet */
    uint16_t status; /**< the status of the classified protocol (classified, non-classified, ...) */
    mmt_proto_id_t proto_id; /**< identifier of the protocol */
} classified_proto_t;

/**
 * Signature of the function for classifying the base protocol corresponding to a defined protocol stack.
 */
typedef classified_proto_t(*generic_stack_classification_function)(ipacket_t * ipacket);

/**
 * Signature of the protocol's session data analysis function.
 */
typedef int (*generic_session_data_analysis_function)(ipacket_t * ipacket, unsigned index);

/**
 * Signature of a protocol's session data cleanup function.
 */
typedef void (*generic_session_data_cleanup_function)(mmt_session_t * session, unsigned index);

/**
 * Named verdicts of the classification pipeline (issue #150, F-DEAD-010).
 * Pre-classification and classification callbacks (generic_classification_function)
 * have always exchanged these integers with the core; the enum only names them.
 * Additive and ABI-safe: int-sized, values unchanged, existing binary plugins
 * keep working.
 */
typedef enum mmt_classify_verdict_enum {
    MMT_CLASSIFY_SKIP     = 0, /**< Pre-classifier: do not run the classifier chain for this packet.
                                    Classifier: protocol not recognised, try the next classifier.
                                    Post-classifier: do not process the deeper layers. */
    MMT_CLASSIFY_CONTINUE = 1, /**< Pre-classifier: run the classifier chain.
                                    Post-classifier: process the deeper layers (any nonzero value does). */
    MMT_CLASSIFY_MATCHED  = 1, /**< Classifier: protocol recognised, stop walking the chain
                                    (a positive verdict shares the value of MMT_CLASSIFY_CONTINUE). */
    /** Issue #546: not a verdict, never returned. A negative enumerator makes
     * GCC and Clang pick int as the enum's compatible type, so a classifier
     * declared `int fn(ipacket_t *, unsigned)` — every in-tree checker and
     * every plugin written before the typedef returned this enum — still
     * converts to generic_classification_function without a cast or an
     * -Wincompatible-pointer-types diagnostic. */
    MMT_CLASSIFY_VERDICT_INT_ANCHOR_ = -0x7fffffff - 1,
} mmt_classify_verdict_t;

/** A classifier verdict with any bit of this mask set (1, 2 or 3) counts as recognised: the chain stops.
 *  Only MMT_CLASSIFY_MATCHED is a named verdict; 2 and 3 are accepted for plugins built against the int typedef. */
#define MMT_CLASSIFY_MATCHED_MASK 3

/**
 * Signature of the pre-classification, classification and post-classification callbacks
 * (register_classification_function*, register_pre_post_classification_functions).
 * A classifier analyses the packet at @p previous_index to identify the encapsulated protocol
 * and returns MMT_CLASSIFY_MATCHED when it recognised it (it records the protocol itself,
 * e.g. through set_classified_proto()), MMT_CLASSIFY_SKIP otherwise. A pre-classifier returns
 * MMT_CLASSIFY_CONTINUE or MMT_CLASSIFY_SKIP; a post-classifier returns nonzero to process
 * the deeper layers. Issue #546: the return type was a bare int; in C a function declared with
 * an int return still converts to this type (see MMT_CLASSIFY_VERDICT_INT_ANCHOR_). C++ has no
 * such conversion between function-pointer types, so a C++ translation unit keeps the int view:
 * same ABI (the enum is int-compatible), and existing C++ plugins keep compiling.
 */
#ifdef __cplusplus
typedef int (*generic_classification_function)(ipacket_t * ipacket, unsigned previous_index);
#else
typedef mmt_classify_verdict_t (*generic_classification_function)(ipacket_t * ipacket, unsigned previous_index);
#endif

/**
 * Signature of the function for sessionizing a packet. That is, associating a packet to its communication session.
 */
typedef void * (*generic_sessionizer_function)(mmt_opaque_t protocol_context, ipacket_t * ipacket, unsigned previous_index, int * is_new);

/**
 * Signature of the function for initializing the protocol context.
 */
typedef void * (*generic_proto_context_init_function)(mmt_opaque_t protocol_context, mmt_opaque_t args);

/**
 * Signature of the function for cleaning up the protocol context.
 */
typedef void (*generic_proto_context_cleanup_function)(mmt_opaque_t protocol_context, mmt_opaque_t args);

/**
 * Signature of the function for cleaning up the protocol context (protocol struct).
 */
typedef int (*generic_session_context_cleanup_function)(mmt_opaque_t protocol_context, mmt_session_t * session_context, mmt_opaque_t args);

/**
 * Signature of a protocol's session data initialization function.
 */
typedef void (*generic_session_data_initialization_function)(ipacket_t * ipacket, unsigned index);

/**
 * Records @p classified_proto at position @p index of the packet's protocol hierarchy:
 * appends the layer when @p index is past the current tip, updates its offset when the
 * same protocol is already there, or reclassifies the layer otherwise.
 * @param ipacket the packet being classified
 * @param index the position in the protocol hierarchy to set
 * @param classified_proto the protocol identifier and header offset to record
 * @return nonzero when the hierarchy was set (appended, updated or reclassified); 0 when the
 *         protocol identifier is invalid, @p index is not below PROTO_PATH_SIZE or an append
 *         would go deeper than the handler's classification depth limit.
 */
MMTAPI int MMTCALL set_classified_proto(
    ipacket_t *ipacket,
    unsigned index,
    classified_proto_t classified_proto
);

/**
 * Registers a classification function for the protocol identified by the given @p proto_id. This function should
 * be used when a protocol wants to complement the classification of another protocol (HTTP adding a classification to TCP).
 * For protocols registering their own classification function, this function SHOULD BE AVOIDED, rather use "register_classification_function".
 * @param proto_id The identifier of the protocol that will use the classification function.
 * @param classification_fct The classification function.
 * @param weight The weight of this classification function. A classification function with a lower weight
 * will be executed before a classification function with a higher weight if the protocol corresponding to @p
 * proto_id has multiple registered classification functions. Must be either between 0 to 9 or 90 to 100.
 * @return a positive value on success, zero on failure.
 */
MMTAPI bool MMTCALL register_classification_function_with_parent_protocol(
    mmt_proto_id_t proto_id,
    generic_classification_function classification_fct,
    int weight
);

/**
 * Registers a classification function for the protocol identified by the given @p protocol_struct.
 * This function MUST only be used when a protocol registers its own classification function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param classification_fct The classification function.
 * @return a positive value on success, zero on failure.
 */
MMTAPI bool MMTCALL register_classification_function(
    protocol_t *protocol_struct,
    generic_classification_function classification_fct
);

/**
 * Registers a classification function for the protocol identified by the given @p protocol_struct.
 * This function MUST only be used when a protocol registers its own classification function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param classification_fct The classification function.
 * @param weight The weight of this classification function. A classification function with a lower weight
 * will be executed before a classification function with a higher weight if the protocol has multiple registered classification functions.
 * Must be between 10 and 80.
 * @param pre_classification The pre-classification routine.
 * @param post_classification The post-classification routine.
 * @return a positive value on success, zero value on failure.
 */
MMTAPI bool MMTCALL register_classification_function_full(
    protocol_t *protocol_struct,
    generic_classification_function classification_fct,
    int weight,
    generic_classification_function pre_classification,
    generic_classification_function post_classification
);

/**
 * Registers a pre and post classification functions for the protocol identified by the given @p protocol_struct.
 * This function MUST only be used when a protocol registers its own classification function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param pre_classification The pre-classification routine.
 * @param post_classification The post-classification routine.
 * @return a positive value on success, zero value on failure.
 */
MMTAPI bool MMTCALL register_pre_post_classification_functions(
    protocol_t *protocol_struct,
    generic_classification_function pre_classification,
    generic_classification_function post_classification
);

/**
 * Registers a sessionizer function along with the session context cleanup function for the protocol identified by the given @p protocol_struct.
 * @param protocol_struct The protocol structure.
 * @param sessionizer_fct The sessionizer function.
 * @param session_context_cleanup_fct The function responsible for cleaning session context. This is required for example when a session times out.
 * @param session_keys_comparison_fct The function for comparing two session keys.
 */
MMTAPI void MMTCALL register_sessionizer_function(
    protocol_t *protocol_struct,
    generic_sessionizer_function sessionizer_fct,
    generic_session_context_cleanup_function session_context_cleanup_fct,
    generic_comparison_fct session_keys_comparison_fct
);

/**
 * Registers the session key hash function for the protocol identified by the given @p protocol_struct.
 * The session store is a hash table keyed on a packed 5-tuple; this function supplies the hash used to
 * bucket sessions. It MUST be consistent with the comparison function registered via
 * register_sessionizer_function: any two keys that compare equal MUST hash to the same value.
 * If no hash function is registered, the session store falls back to a correct but slow constant hash.
 * @param protocol_struct The protocol structure.
 * @param session_key_hash_fct The function that hashes a session key.
 */
MMTAPI void MMTCALL register_session_hash_function(
    protocol_t *protocol_struct,
    generic_hash_fct session_key_hash_fct
);

/**
 * Registers the session key equality predicate for the protocol identified by the given @p protocol_struct.
 * When registered, the session store tests two keys for equality with this single call instead of invoking the
 * ordering comparator twice (!cmp(a,b) && !cmp(b,a)) on every probe — the per-packet session lookup's hot path
 * (issue #253, F-PERF-008). The predicate MUST agree with the comparison function registered via
 * register_sessionizer_function: equal(a,b) iff neither key orders before the other.
 * If no predicate is registered, the store falls back to the two-call comparator equivalence.
 * @param protocol_struct The protocol structure.
 * @param session_key_equal_fct The function that tests two session keys for equality.
 */
MMTAPI void MMTCALL register_session_equal_function(
    protocol_t *protocol_struct,
    generic_equal_fct session_key_equal_fct
);

/**
 * Registers a protocol context cleanup function for the protocol identified by the given @p protocol_struct.
 * @param protocol_struct The protocol structure.
 * @param context_init_fct The protocol context initialization function.
 * @param context_cleanup_fct The protocol context cleanup function.
 * @param args pointer to protocol specific argument.
 */
MMTAPI void MMTCALL register_proto_context_init_cleanup_function(
    protocol_t *protocol_struct,
    generic_proto_context_init_function context_init_fct,
    generic_proto_context_cleanup_function context_cleanup_fct,
    mmt_opaque_t args
);

/**
 * Registers the given session data initialization function with the given protocol structure
 * @param protocol_struct pointer to the protocol with which the function will be registered
 * @param session_data_init_fct the session data initialization function to register
 */
MMTAPI void MMTCALL register_session_data_initialization_function(
    protocol_t *protocol_struct,
    generic_session_data_initialization_function session_data_init_fct
);

/**
 * Registers the given session data cleanup function with the given protocol structure.
 * @param protocol_struct pointer to the protocol with which the function will be registered
 * @param session_data_cleanup_fct the session data cleanup function to register
 */
MMTAPI void MMTCALL register_session_data_cleanup_function(
    protocol_t *protocol_struct,
    generic_session_data_cleanup_function session_data_cleanup_fct
);

/**
 * Registers a session data analysis function for the protocol identified by the given @p proto_id. This function should
 * be used in order to complement the analysis of a protocol.
 * For protocols registering their own analysis function, this function SHOULD BE AVOIDED, rather use "register_session_data_analysis_function".
 * @param proto_id The identifier of the protocol that will use the classification function.
 * @param session_data_analysis_fct the session data analysis function to register.
 * @param weight The weight of this analysis function. An analysis function with a lower weight
 * will be executed before an analysis function with a higher weight if the protocol has multiple
 * registered analysis functions.
 * Must be either between 0 to 9 or 90 to 100.
 * @return a positive value on success, zero on failure.
 */
MMTAPI bool MMTCALL register_session_data_analysis_function_with_protocol(
    mmt_proto_id_t proto_id,
    generic_session_data_analysis_function session_data_analysis_fct,
    int weight
);

/**
 * Registers a session data analysis function for the protocol identified by the given @p protocol_struct.
 * This function MUST only be used when a protocol registers its own session data analysis function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param session_data_analysis_fct the session data analysis function to register.
 * @return a positive value on success, zero on failure.
 */
MMTAPI bool MMTCALL register_session_data_analysis_function(
    protocol_t *protocol_struct,
    generic_session_data_analysis_function session_data_analysis_fct
);

/**
 * Registers a session data analysis function for the protocol identified by the given @p protocol_struct.
 * This function MUST only be used when a protocol registers its own session data analysis function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param session_data_analysis_fct The classification function.
 * @param weight The weight of this analysis function. An analysis function with a lower weight
 * will be executed before an analysis function with a higher weight if the protocol has multiple
 * registered analysis functions.
 * Must be between 10 and 90.
 * @param pre_analysis The pre-analysis routine.
 * @param post_analysis The post-analysis routine.
 * @return a positive value on success, zero value on failure.
 */
MMTAPI bool MMTCALL register_session_data_analysis_function_full(
    protocol_t *protocol_struct,
    generic_session_data_analysis_function session_data_analysis_fct,
    int weight,
    generic_session_data_analysis_function pre_analysis,
    generic_session_data_analysis_function post_analysis
);

/**
 * Registers a pre and post analysis functions for the protocol identified by the given @p protocol_struct.
 * This function MUST only be used when a protocol registers its own analysis function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param pre_analysis The pre-analysis routine.
 * @param post_analysis The post-analysis routine.
 * @return a positive value on success, zero value on failure.
 */
MMTAPI bool MMTCALL register_pre_post_analysis_functions(
    protocol_t *protocol_struct,
    generic_session_data_analysis_function pre_analysis,
    generic_session_data_analysis_function post_analysis
);

/**
 * Registers the protocol's stack given by the stack identifier, name and base classification function. The registration fails
 * if a protocol stack is already registered with the given identifier.
 * @param s_id The unique identifier of the protocol stack to register.
 * @param s_name The name of the protocol stack to register.
 * @param fct The base classification function corresponding to the protocol stack to register.
 * @return a positive value on success, zero value on failure.
 */
MMTAPI bool MMTCALL register_protocol_stack(
    uint32_t s_id,
    char *s_name,
    generic_stack_classification_function fct
);

/**
 * Registers the protocol's stack given by the stack identifier, name, base classification function, internal data and cleanup function.
 * The registration fails if a protocol stack is already registered with the given identifier.
 * @param s_id The unique identifier of the protocol stack to register.
 * @param s_name The name of the protocol stack to register.
 * @param fct The base classification function corresponding to the protocol stack to register.
 * @param stack_cleanup The cleanup function responsible for freeing the stack internal data.
 * @param stack_internal_context The pointer to the stack internal context data.
 * @return a positive value on success, zero value on failure.
 */
MMTAPI bool MMTCALL register_protocol_stack_full(
    uint32_t s_id,
    char *s_name,
    generic_stack_classification_function fct,
    stack_internal_cleanup stack_cleanup,
    mmt_opaque_t stack_internal_context
);

/**
 * Unregisters a protocol stack given its identifier.
 * @param s_id The identifier of the protocol stack to unregister.
 * @return a positive value on success, zero value on failure.
 * <p> A positive value is returned if the given identifier does not correspond to any registered protocol stack. This is not considered as failure.
 */
MMTAPI bool MMTCALL unregister_protocol_stack(
    uint32_t s_id
);

/**
 * Tells whether no protocol is registered with the given identifier.
 * @param proto_id the identifier of the protocol
 * @return true if the identifier is valid and no protocol is registered with it, false otherwise.
 */
MMTAPI bool MMTCALL is_free_protocol_id_for_registration(
    mmt_proto_id_t proto_id
);

/**
 * @deprecated Misspelled name of is_free_protocol_id_for_registration(), kept
 * exported so plugins built against it still load (issue #546).
 */
MMTAPI bool MMTCALL is_free_protocol_id_for_registractionl(
    mmt_proto_id_t proto_id
) __attribute__((deprecated("use is_free_protocol_id_for_registration; removal in 2.0.0")));

/**
 * Returns a pointer to the structure with index equal to the given protocol identifier if not registered.
 * Returns NULL if a protocol with the same identifier is already registered.
 * @param proto_id the identifier of the protocol
 * @return a pointer to the protocol structure if the given identifier is not registered, NULL otherwise.
 */
MMTAPI protocol_t* MMTCALL get_protocol_struct_for_registration_if_free(
    mmt_proto_id_t proto_id
);

/**
 * Returns a pointer to a protocol structure with the given protocol id and name.
 * Returns NULL if a protocol with the same identifier is already registered.
 * @param proto_id the identifier of the protocol
 * @param protocol_name the name of the protocol
 * @return a pointer to the protocol if the given identifier is not registered, NULL otherwise.
 */
MMTAPI protocol_t* MMTCALL init_protocol_struct_for_registration(
    mmt_proto_id_t proto_id,
    const char *protocol_name
);

/**
 * Registers an attribute given by its metadata structure with the given protocol. The registration succeeds if
 *  the attribute metadata is valid and the attribute is not already registered, it fails otherwise.
 * @param protocol_struct the pointer to the protocol
 * @param attribute_meta_data the metadata structure of the attribute.
 * @return a positive value on success (valid attribute and not already registered), a zero value is returned on failure.
 */
MMTAPI bool MMTCALL register_attribute_with_protocol(
    protocol_t *protocol_struct,
    attribute_metadata_t *attribute_meta_data
);

/**
 * Registers the protocol defined by the given protocol structure and protocol identifier.
 * Once successfully registered, the protocol can be used.
 * @param protocol_struct the structure of the protocol to register
 * @param proto_id the identifier of the protocol to register
 * @return PROTO_REGISTERED on success, PROTO_NOT_REGISTERED on failure.
 */
MMTAPI bool MMTCALL register_protocol(
    protocol_t *protocol_struct,
    mmt_proto_id_t proto_id
);

/**
 * Unregisters the protocol defined by the given protocol identifier.
 * @param proto_id the identifier of the protocol to register
 * @return PROTO_REGISTERED on success, PROTO_NOT_REGISTERED on failure.
 */
MMTAPI bool MMTCALL unregister_protocol_by_id(
    mmt_proto_id_t proto_id
);

/**
 * Unregisters the protocol defined by the given protocol name (compared case-insensitively).
 * @param proto_name the name of the protocol to unregister
 * @return PROTO_REGISTERED on success, PROTO_NOT_REGISTERED on failure.
 */
MMTAPI bool MMTCALL unregister_protocol_by_name(
    char * proto_name
);

/**
 * Returns the pointer to the protocol structure with the given identifier. This function MUST only be used
 * when we are sure there is a protocol structure associated with the given identifier. If there is no protocol
 * associated with the given identifier, null will be returned. This function is to be used with high precautions.
 * @param proto_id identifier of the protocol
 * @return the pointer to the protocol structure with the given identifier
 */
MMTAPI protocol_t* MMTCALL get_protocol_struct_by_id(
    mmt_proto_id_t proto_id
);

//  - - - - - - - - - - - - - - - - - -
//  P R O T O C O L   A C C E S S O R S
//  - - - - - - - - - - - - - - - - - -

/**
 * Returns the position of the attribute in the protocol header, as reported by the protocol's get_attribute_position callback.
 * @param proto the protocol structure whose callback is called (not NULL)
 * @param proto_id the protocol identifier passed to the callback
 * @param attr_id the identifier of the attribute
 * @return the position of the attribute in the protocol header.
 */
MMTAPI int MMTCALL get_proto_attribute_position(
    protocol_t *proto,
    mmt_proto_id_t proto_id,
    uint32_t attr_id
);

/**
 * Returns the data length of the attribute, as reported by the protocol's get_attribute_data_length_by_id callback.
 * @param proto the protocol structure whose callback is called (not NULL)
 * @param proto_id the protocol identifier passed to the callback
 * @param attr_id the identifier of the attribute
 * @return the data length of the attribute.
 */
MMTAPI int MMTCALL get_proto_attribute_length(
    protocol_t *proto,
    mmt_proto_id_t proto_id,
    uint32_t attr_id
);

/**
 * Returns the identifier of the attribute named @p attr_name, as reported by the protocol's get_attribute_id_by_name callback.
 * @param proto the protocol structure whose callback is called (not NULL)
 * @param proto_id the protocol identifier passed to the callback
 * @param attr_name the name of the attribute
 * @return the identifier of the attribute named @p attr_name.
 */
MMTAPI int MMTCALL get_proto_attribute_id(
    protocol_t *proto,
    mmt_proto_id_t proto_id,
    const char *attr_name
);

/**
 * Returns the name of the attribute, as reported by the protocol's get_attribute_name_by_id callback.
 * @param proto the protocol structure whose callback is called (not NULL)
 * @param proto_id the protocol identifier passed to the callback
 * @param attr_id the identifier of the attribute
 * @return the name of the attribute.
 */
MMTAPI const char* MMTCALL get_proto_attribute_name(
    protocol_t *proto,
    mmt_proto_id_t proto_id,
    uint32_t attr_id
);

/**
 * Returns the data type (::data_types) of the attribute, as reported by the protocol's get_attribute_data_type_by_id callback.
 * @param proto the protocol structure whose callback is called (not NULL)
 * @param proto_id the protocol identifier passed to the callback
 * @param attr_id the identifier of the attribute
 * @return the data type (::data_types) of the attribute.
 */
MMTAPI int MMTCALL get_proto_attribute_type(
    protocol_t *proto,
    mmt_proto_id_t proto_id,
    uint32_t attr_id
);

/**
 * Returns the scope of the attribute, as reported by the protocol's get_attribute_scope callback.
 * @param proto the protocol structure whose callback is called (not NULL)
 * @param proto_id the protocol identifier passed to the callback
 * @param attr_id the identifier of the attribute
 * @return the scope of the attribute.
 */
MMTAPI int MMTCALL get_proto_attribute_scope(
    protocol_t *proto,
    mmt_proto_id_t proto_id,
    uint32_t attr_id
);

/**
 * Returns whether the attribute exists, as reported by the protocol's is_valid_attribute callback.
 * @param proto the protocol structure whose callback is called (not NULL)
 * @param proto_id the protocol identifier passed to the callback
 * @param attr_id the identifier of the attribute
 * @return whether the attribute exists.
 */
MMTAPI bool MMTCALL is_valid_proto_attribute(
    protocol_t *proto,
    mmt_proto_id_t proto_id,
    uint32_t attr_id
);

#ifdef	__cplusplus
}
#endif

#endif	/* PROTOCOL_EXTRACTION_DEFS_H */

