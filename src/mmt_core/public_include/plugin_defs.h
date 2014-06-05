/*
 * File:   protocol_extraction_defs.h
 * Author: montimage
 *
 * Created on 19 mai 2011, 16:33
 */

#ifndef PROTOCOL_EXTRACTION_DEFS_H
#define	PROTOCOL_EXTRACTION_DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif
#include "data_defs.h"

/**
 * Generic packet field extraction function
 */
typedef int (*generic_attribute_extraction_function) (
        const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data);

/**
 * Signature of the function for returning the attribute extraction function given the attribute id
 */
typedef generic_attribute_extraction_function(*generic_get_attribute_extraction_function) (uint32_t proto_id, uint32_t attribute_id);

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
typedef int (*generic_get_attribute_id_by_name) (uint32_t proto_id, const char * attribute_name);

/**
 * Signature of the function for returning attribute name given its id
 */
typedef const char * (*generic_get_attribute_name_by_id) (uint32_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for returning attribute data type given its id
 */
typedef int (*generic_get_attribute_data_type_by_id) (uint32_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for returning attribute data length given its id
 */
typedef int (*generic_get_attribute_data_length_by_id) (uint32_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for returning attribute position in the packet if such a thing is known
 */
typedef int (*generic_get_attribute_position_by_id) (uint32_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for returning if the given attribute id exists
 */
typedef int(*generic_is_valid_attribute) (uint32_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function returning the scope of the given attribute
 */
typedef int (*generic_get_attribute_scope) (uint32_t proto_id, uint32_t attribute_id);

/**
 * Signature of the function for cleaning up the protocol stack internal data.
 */
typedef void (*stack_internal_cleanup)(void * stack_internal_context);

/**
 * Signature of the function that every plugin MUST implement. In the plugin, the function name MUST be "init_proto".
 * This is the function that the MMT-extraction core will call to load the plugin. The function should return a positive value on success, 0 otherwise.
 */
typedef int (*generic_init_proto) (void);

/**
 * Defines a classified protocol including the identifier of the protocol and its offset in the packet.
 */
typedef struct classified_proto_struct {
    uint32_t proto_id; /**< identifier of the protocol */
    uint16_t offset; /**< offset of the protocol in the packet */
    uint16_t status; /**< the status of the classified protocol (classified, non-classified, ...) */
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
 * Signature of the function for classifying the protocol corresponding to the encapsulated data. Any implementing function
 * MUST analyze the @param packet and @param header parameters in order to identify the encapsulated protocol.
 * If such a classification is successful, the function MUST return the identifier of the classified protocol. If the
 * classification does not make it possible to identify the encapsulated protocol, the implementing function MUST return 0.
 */
typedef int (*generic_classification_function)(ipacket_t * ipacket, unsigned previous_index);

/**
 * Signature of the function for sessionizing a packet. That is, associating a packet to its communication session.
 */
typedef void * (*generic_sessionizer_function)(void * protocol_context, ipacket_t * ipacket, unsigned previous_index, int * is_new);

/**
 * Signature of the function for initializing the protocol context.
 */
typedef void * (*generic_proto_context_init_function)(void * protocol_context, void * args);

/**
 * Signature of the function for cleaning up the protocol context.
 */
typedef void (*generic_proto_context_cleanup_function)(void * protocol_context, void * args);

/**
 * Signature of the function for cleaning up the protocol context (protocol struct).
 */
typedef int (*generic_session_context_cleanup_function)(void * protocol_context, mmt_session_t * session_context, void * args);

/**
 * Signature of a protocol's session data initialization function.
 */
typedef void (*generic_session_data_initialization_function)(ipacket_t * ipacket, unsigned index);

/*
MMTAPI int MMTCALL get_attribute_id(
    protocol_t *proto,
    uint32_t proto_id,
    const char *attr_name
);

MMTAPI int MMTCALL get_attribute_name(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL get_attribute_type(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL get_attribute_position(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL get_attribute_length(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL get_attribute_scope(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL is_valid_attribute(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);
*/

MMTAPI int MMTCALL set_classified_proto(
    ipacket_t *ipacket,
    unsigned index,
    classified_proto_t classified_proto
);

/**
 * Registers a classification function for the protocol identified by the given @param proto_id. This function should
 * be used when a protocol wants to complement the classification of another protocol (HTTP adding a classification to TCP).
 * For protocols registering their own classification function, this function SHOULD BE AVOIDED, rather use "register_classification_function".
 * @param proto_id The identifier of the protocol that will use the classification function.
 * @param classification_fct The classification function.
 * @param weight The weight of this classification function. A classification function with a lower weight
 * will be executed before a classification function with a higher weight if the protocol corresponding to @param
 * proto_id has multiple registered classification functions. Must be either between 0 to 9 or 90 to 100.
 * @return a positive value on success, zero on failure.
 */
MMTAPI int MMTCALL register_classification_function_with_parent_protocol(
    uint32_t proto_id,
    generic_classification_function classification_fct,
    int weight
);

/**
 * Registers a classification function for the protocol identified by the given @param protocol_struct.
 * This function MUST only be used when a protocol registers its own classification function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param classification_fct The classification function.
 * @return a positive value on success, zero on failure.
 */
MMTAPI int MMTCALL register_classification_function(
    protocol_t *protocol_struct,
    generic_classification_function classification_fct
);

/**
 * Registers a classification function for the protocol identified by the given @param protocol_struct.
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
MMTAPI int MMTCALL register_classification_function_full(
    protocol_t *protocol_struct,
    generic_classification_function classification_fct,
    int weight,
    generic_classification_function pre_classification,
    generic_classification_function post_classification
);

/**
 * Registers a pre and post classification functions for the protocol identified by the given @param protocol_struct.
 * This function MUST only be used when a protocol registers its own classification function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param pre_classification The pre-classification routine.
 * @param post_classification The post-classification routine.
 * @return a positive value on success, zero value on failure.
 */
MMTAPI int MMTCALL register_pre_post_classification_functions(
    protocol_t *protocol_struct,
    generic_classification_function pre_classification,
    generic_classification_function post_classification
);

/**
 * Registers a sessionizer function along with the session context cleanup function for the protocol identified by the given @param protocol_struct.
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
 * Registers a protocol context cleanup function for the protocol identified by the given @param protocol_struct.
 * @param protocol_struct The protocol structure.
 * @param context_init_fct The protocol context initialization function.
 * @param context_cleanup_fct The protocol context cleanup function.
 * @param args pointer to protocol specific argument.
 */
MMTAPI void MMTCALL register_proto_context_init_cleanup_function(
    protocol_t *protocol_struct,
    generic_proto_context_init_function context_init_fct,
    generic_proto_context_cleanup_function context_cleanup_fct,
    void *args
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
 * Registers a session data analysis function for the protocol identified by the given @param proto_id. This function should
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
MMTAPI int MMTCALL register_session_data_analysis_function_with_protocol(
    uint32_t proto_id,
    generic_session_data_analysis_function session_data_analysis_fct,
    int weight
);

/**
 * Registers a session data analysis function for the protocol identified by the given @param protocol_struct.
 * This function MUST only be used when a protocol registers its own session data analysis function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param session_data_analysis_fct the session data analysis function to register.
 * @return a positive value on success, zero on failure.
 */
MMTAPI int MMTCALL register_session_data_analysis_function(
    protocol_t *protocol_struct,
    generic_session_data_analysis_function session_data_analysis_fct
);

/**
 * Registers a session data analysis function for the protocol identified by the given @param protocol_struct.
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
MMTAPI int MMTCALL register_session_data_analysis_function_full(
    protocol_t *protocol_struct,
    generic_session_data_analysis_function session_data_analysis_fct,
    int weight,
    generic_session_data_analysis_function pre_analysis,
    generic_session_data_analysis_function post_analysis
);

/**
 * Registers a pre and post analysis functions for the protocol identified by the given @param protocol_struct.
 * This function MUST only be used when a protocol registers its own analysis function. This function
 * will always perform what it is supposed to do.
 * @param protocol_struct The protocol structure.
 * @param pre_analysis The pre-analysis routine.
 * @param post_analysis The post-analysis routine.
 * @return a positive value on success, zero value on failure.
 */
MMTAPI int MMTCALL register_pre_post_analysis_functions(
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
MMTAPI int MMTCALL register_protocol_stack(
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
 * @param stack_internal_packet The pointer to the internal packet structure of the stack to register.
 * @param stack_internal_context The pointer to the stack internal context data.
 * @return a positive value on success, zero value on failure.
 */
MMTAPI int MMTCALL register_protocol_stack_full(
    uint32_t s_id,
    char *s_name,
    generic_stack_classification_function fct,
    stack_internal_cleanup stack_cleanup,
    void * stack_internal_context
);

/**
 * Unregisters a protocol stack given its identifier.
 * @param s_id The identifier of the protocol stack to unregister.
 * @return a positive value on success, zero value on failure.
 * <p> A positive value is returned if the given identifier does not correspond to any registered protocol stack. This is not considered as failure.
 */
MMTAPI int MMTCALL unregister_protocol_stack(
    uint32_t s_id
);

/**
 * Returns a positive value if their in no protocol registered with the given identifier. 0 otherwise.
 * @param proto_id the identifier of the protocol
 * @return a positive value if their in no protocol registered with the given identifier. 0 otherwise.
 */
MMTAPI int MMTCALL is_free_protocol_id_for_registractionl(
    uint32_t proto_id
);

/**
 * Returns a pointer to the structure with index equal to the given protocol identifier if not registered.
 * Returns NULL if a protocol with the same identifier is already registered.
 * @param proto_id the identifier of the protocol
 * @return a pointer to the protocol structure if the given identifier is not registered, NULL otherwise.
 */
MMTAPI protocol_t* MMTCALL get_protocol_struct_for_registration_if_free(
    uint32_t proto_id
);

/**
 * Returns a pointer to a protocol structure with the given protocol id and name.
 * Returns NULL if a protocol with the same identifier is already registered.
 * @param proto_id the identifier of the protocol
 * @param protocol_name the name of the protocol
 * @return a pointer to the protocol if the given identifier is not registered, NULL otherwise.
 */
MMTAPI protocol_t* MMTCALL init_protocol_struct_for_registration(
    uint32_t proto_id,
    const char *protocol_name
);

/**
 * Registers an attribute given by its metadata structure with the given protocol. The registration succeeds if
 *  the attribute metadata is valid and the attribute is not already registered, it fails otherwise.
 * @param protocol_struct the pointer to the protocol
 * @param attribute_meta_data the metadata structure of the attribute.
 * @return a positive value on success (valid attribute and not already registered), a zero value is returned on failure.
 */
MMTAPI int MMTCALL register_attribute_with_protocol(
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
MMTAPI int MMTCALL register_protocol(
    protocol_t *protocol_struct,
    uint32_t proto_id
);

/**
 * Returns the pointer to the protocol structure with the given identifier. This function MUST only be used
 * when we are sure there is a protocol structure associated with the given identifier. If there is no protocol
 * associated with the given identifier, null will be returned. This function is to be used with high precautions.
 * @param proto_id identifier of the protocol
 * @return the pointer to the protocol structure with the given identifier
 */
MMTAPI protocol_t* MMTCALL get_protocol_struct_by_id(
    uint32_t proto_id
);

//  - - - - - - - - - - - - - - - - - -
//  P R O T O C O L   A C C E S S O R S
//  - - - - - - - - - - - - - - - - - -

MMTAPI int MMTCALL get_proto_attribute_position(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL get_proto_attribute_length(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL get_proto_attribute_id(
    protocol_t *proto,
    uint32_t proto_id,
    const char *attr_name
);

MMTAPI const char* MMTCALL get_proto_attribute_name(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL get_proto_attribute_type(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL get_proto_attribute_scope(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

MMTAPI int MMTCALL is_valid_proto_attribute(
    protocol_t *proto,
    uint32_t proto_id,
    uint32_t attr_id
);

#ifdef	__cplusplus
}
#endif

#endif	/* PROTOCOL_EXTRACTION_DEFS_H */

