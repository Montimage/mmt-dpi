#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/ether.h>
#endif

#include "packet_processing.h"
#include "mmt_core.h"
#include "memory.h"
#include "plugins_engine.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "../../vendors/libntoh/install/include/libntoh/libntoh.h"

bool session_timeout_comp_fn_pt(uint32_t l_timeout, uint32_t r_timeout) {
    return (l_timeout < r_timeout);
}

bool pointer_comp_fn_pt(void * l_p, void * r_p) {
    return (l_p < r_p);
}

int proto_hierarchy_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest) {
    unsigned index = 0;
    int offset = 0;
    offset += sprintf(dest, "%s", get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
    index++;
    for (; index < proto_hierarchy->len; index++) {
        offset += sprintf(&dest[offset], ".%s", get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
    }
    return offset;
}

const char * get_application_name(const proto_hierarchy_t * proto_hierarchy) {
    return get_protocol_name_by_id(proto_hierarchy->proto_path[proto_hierarchy->len - 1]);
}

/**
 * Generic function that is used to extract data from a packet.
 * @param proto_id The identifier of the protocol.
 * @param header A pointer to the metadata associated with the packet.
 * @param packet The data packet starting from the protocol header corresponding to the provided @param proto_id.
 */
void generic_data_extraction(uint32_t proto_id, ipacket_t * ipacket);

/**
 * Updates the protocol statistics on session timeout. It will basically increase the number
 * of timedout sessions for the protocols in the given session.
 * @param timed_out_session the timed out session.
 * @param parent_proto_stats pointer to the parent protocol statistics
 */
void update_proto_stats_on_session_timeout(mmt_session_t * timed_out_session, proto_statistics_internal_t * parent_proto_stats);

/**
 * Resets the statistics for the given protocol
 * @param proto protocol to reset its statistics
 */
void reset_proto_stats(protocol_instance_t * proto);

// Dummy stack

classified_proto_t dummy_stack_classification(ipacket_t * ipacket) {
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;
    return retval;
}

void free_protocol_stack(protocol_stack_t * ps) {
    if (ps->stack_cleanup != NULL) {
        ps->stack_cleanup(ps->stack_internal_context);
    }
    mmt_free(ps);
}

void protocol_stack_callback_fct(void * key, void * value, void * args) {
    protocol_stack_t * ps = (protocol_stack_t *) value;
    free_protocol_stack(ps);
    return;
}

static protocol_stack_t dummy_stack = {
    0, "dummy", dummy_stack_classification, NULL, NULL
};

static protocol_t *configured_protocols[PROTO_MAX_IDENTIFIER];
static void * mmt_configured_handlers_map;

bool attribute_ids_comparison_fct(uint32_t l_id, uint32_t r_id) {
    return (l_id < r_id);
}

bool attribute_names_comparison_fct(void * l_name, void * r_name) {
    return (mmt_strncasecmp((char *) l_name, (char *) r_name, Max_Alias_Len) < 0) ? true : false;
}

int get_attribute_id_by_name_from_protocol_map(uint32_t proto_id, const char * attribute_name) {
    if (is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_key_value(configured_protocols[proto_id]->attributes_names_map, (void *) attribute_name);
        if (attr != NULL) {
            return attr->id;
        }
    }
    return 0;
}

const char * get_attribute_name_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->alias;
        }
    }
    return NULL;
}

int get_attribute_data_type_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->data_type;
        }
    }
    return MMT_UNDEFINED_TYPE;
}

int get_attribute_length_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->data_len;
        }
    }
    return 0;
}

int get_attribute_scope_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->scope;
        }
    }
    return 0;
}

int get_attribute_position_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->position_in_packet;
        }
    }
    return POSITION_NOT_KNOWN;
}

int is_protocol_valid_attribute(uint32_t proto_id, uint32_t attribute_id) {
    if (is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return true;
        }
    }
    return false;
}

generic_attribute_extraction_function get_attribute_extraction_fct_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->extraction_function;
        }
    }
    return silent_extraction;
}

protocol_t * get_protocol_struct_by_protocol_id(uint32_t proto_id) {
    if (is_valid_protocol_id(proto_id) > 0) {
        if (is_registered_protocol(proto_id) == PROTO_REGISTERED) {
            return configured_protocols[proto_id];
        }
    }

    return NULL;
}

int validate_attribute_metadata(attribute_metadata_t * attribute_meta_data) {
    //int retval = true;
    // The id must not be null
    if (attribute_meta_data->id == 0) return false;
    // The name must have a length of at least one and less than Max_Alias_Len
    if ((strlen(attribute_meta_data->alias) == 0) || (strlen(attribute_meta_data->alias) > Max_Alias_Len)) return false;
    // The data type should have a value greater than MMT_UNDEFINED_TYPE and less than MMT_HIGHER_VALUED_VALID_DATA_TYPE
    if ((attribute_meta_data->data_type <= MMT_UNDEFINED_TYPE)
            || (attribute_meta_data->data_type >= MMT_HIGHER_VALUED_VALID_DATA_TYPE))
        return false;
    // The scope should be one of SCOPE_PACKET, SCOPE_SESSION, SCOPE_SESSION_CHANGING
    if (!((attribute_meta_data->scope & SCOPE_ON_DEMAND) || (attribute_meta_data->scope & SCOPE_EVENT))) return false;
    //TODO: validate the datalen with respect to the datatype
    return true;
}

int register_attribute_with_protocol(protocol_t *proto, attribute_metadata_t *attribute_meta_data) {
    //validate the attribute
    if (validate_attribute_metadata(attribute_meta_data) == true) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(proto->attributes_map, (uint32_t) attribute_meta_data->id);
        attribute_metadata_t * attr_by_name = (attribute_metadata_t *) find_key_value(proto->attributes_names_map, attribute_meta_data->alias);
        if (attr == NULL && attr_by_name == NULL) {
            attr = (attribute_metadata_t *) mmt_malloc(sizeof (attribute_metadata_t));
            if (attr != NULL) {
                attr->id = attribute_meta_data->id;
                attr->data_len = attribute_meta_data->data_len;
                attr->data_type = attribute_meta_data->data_type;
                attr->extraction_function = attribute_meta_data->extraction_function;
                attr->position_in_packet = attribute_meta_data->position_in_packet;
                attr->scope = attribute_meta_data->scope;
                strncpy(attr->alias, attribute_meta_data->alias, Max_Alias_Len);
                attr->alias[Max_Alias_Len] = '\0';
                insert_int_key_value(proto->attributes_map, (uint32_t) attr->id, (void *) attr);
                insert_key_value(proto->attributes_names_map, (void *) attr->alias, (void *) attr);
                return 1;
            }
        }
    }
    return 0; // TODO: error handling
}

struct internal_attribute_iterator_struct {
    generic_protocol_attribute_iteration_callback iterator_fct;
    uint32_t proto_id;
    void * args;
};

struct internal_handler_iterator_struct {
    generic_handler_iteration_callback iterator_fct;
    void * args;
};

void internal_attribute_iterator_callback(void * key, void * value, void * args) {
    ((generic_protocol_attribute_iteration_callback) ((struct internal_attribute_iterator_struct *) args)->iterator_fct)((attribute_metadata_t *) value, ((struct internal_attribute_iterator_struct *) args)->proto_id, ((struct internal_attribute_iterator_struct *) args)->args);
}

void internal_handler_iterator_callback(void * key, void * value, void * args) {
    ((generic_handler_iteration_callback) ((struct internal_handler_iterator_struct *) args)->iterator_fct)(value, ((struct internal_attribute_iterator_struct *) args)->args);
}

void iterate_through_protocol_attributes(uint32_t proto_id, generic_protocol_attribute_iteration_callback iterator_fct, void * args) {
    if (is_registered_protocol(proto_id) == PROTO_REGISTERED) {
        protocol_t * proto = (protocol_t *) get_protocol_struct_by_id(proto_id);
        struct internal_attribute_iterator_struct temp_attribute_iterator_struct;
        temp_attribute_iterator_struct.iterator_fct = iterator_fct;
        temp_attribute_iterator_struct.proto_id = proto_id;
        temp_attribute_iterator_struct.args = args;
        int_mapspace_iteration_callback(proto->attributes_map, internal_attribute_iterator_callback, (void *) & temp_attribute_iterator_struct);
    }
}

void iterate_through_protocols(generic_protocol_iteration_callback iterator_fct, void * args) {
    int i;
    for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        if (configured_protocols[i]) {
            if (configured_protocols[i]->is_registered) {
                iterator_fct(configured_protocols[i]->proto_id, args);
            }
        }
    }
}

/**
 * Iterates through the registered mmt handlers. The given \iterator_fct will be called for every mmt handler.
 * @param iterator_fct pointer to the user function that will be called for every registered mmt handler.
 * @param args pointer to the user argument. It will be passed to the iterator callback function.
 */
void iterate_through_mmt_handlers(generic_handler_iteration_callback iterator_fct, void * args) {
    struct internal_handler_iterator_struct temp_handler_iterator_struct;
    temp_handler_iterator_struct.iterator_fct = iterator_fct;
    temp_handler_iterator_struct.args = args;
    mapspace_iteration_callback(mmt_configured_handlers_map, internal_handler_iterator_callback, (void *) & temp_handler_iterator_struct);
}

int register_session_timeout_handler(mmt_handler_t *mmt_h, generic_session_timeout_handler_function session_expiry_handler_fct, void * args) {
    mmt_h->session_expiry_handler.handler_fct = session_expiry_handler_fct;
    mmt_h->session_expiry_handler.args = args;
    return 1;
}

void base_packet_extraction(ipacket_t * ipacket, unsigned protocol_index);

void update_last_received_packet(packet_info_t * last_packet, ipacket_t * ipacket) {
    last_packet->packet_id += 1;
    last_packet->packet_len = ipacket->p_hdr->len;
    last_packet->time.tv_sec = ipacket->p_hdr->ts.tv_sec;
    last_packet->time.tv_usec = ipacket->p_hdr->ts.tv_usec;
    ipacket->packet_id = last_packet->packet_id;
}

int register_protocol_stack(uint32_t s_id, char * s_name, generic_stack_classification_function fct) {
    if (get_protocol_stack_from_map(s_id) == NULL) {
        protocol_stack_t * new_stack = (protocol_stack_t *) mmt_malloc(sizeof (protocol_stack_t));
        if (new_stack != NULL) {
            new_stack->stack_id = s_id;
            strncpy(new_stack->stack_name, s_name, Max_Alias_Len);
            new_stack->stack_name[Max_Alias_Len] = '\0';
            new_stack->stack_classify = fct;
            new_stack->stack_cleanup = NULL;
            //new_stack->stack_internal_packet = NULL;
            new_stack->stack_internal_context = NULL;

            if (insert_protocol_stack_into_map(s_id, new_stack) == 0) {
                // Registration failed
                // Free allocated memory
                free_protocol_stack(new_stack);
                return 0;
            }
            return 1;
        }
    }
    return 0;
}

int register_protocol_stack_full(uint32_t s_id, char * s_name, generic_stack_classification_function fct,
        stack_internal_cleanup stack_cleanup, void * stack_internal_context) {
    if (get_protocol_stack_from_map(s_id) == NULL) {
        protocol_stack_t * new_stack = (protocol_stack_t *) mmt_malloc(sizeof (protocol_stack_t));
        if (new_stack != NULL) {
            new_stack->stack_id = s_id;
            strncpy(new_stack->stack_name, s_name, Max_Alias_Len);
            new_stack->stack_name[Max_Alias_Len] = '\0';
            new_stack->stack_classify = fct;
            new_stack->stack_cleanup = stack_cleanup;
            //new_stack->stack_internal_packet = stack_internal_packet;
            new_stack->stack_internal_context = stack_internal_context;

            if (insert_protocol_stack_into_map(s_id, new_stack) == 0) {
                // Registration failed
                // Free allocated memory
                free_protocol_stack(new_stack);
                return 0;
            }
            return 1;
        }
    }
    return 0;
}

int unregister_protocol_stack(uint32_t s_id) {
    protocol_stack_t * temp_stack = get_protocol_stack_from_map(s_id);
    if (temp_stack != NULL && s_id != 0) {
        //The protocol stack is registered, remove it from the map, and free it
        delete_protocol_stack_from_map(s_id); //TODO: check the return value
        //Set link_layer_stack to dummy if it is the same as the stack to unregister
        free_protocol_stack(temp_stack);
    }
    return 1;
}

const char *get_protocol_stack_name(uint32_t s_id) {
    protocol_stack_t * temp_stack = get_protocol_stack_from_map(s_id);
    if (temp_stack != NULL) {
        return temp_stack->stack_name;
    }

    return NULL;
}

void cleanup_timedout_sessions(mmt_session_t * timed_out_session) {
    int i = 0;

    // Clean session data for the different protocols in the session's protocol path
    for (; i < timed_out_session->proto_path.len; i++) {
        if (is_registered_protocol(timed_out_session->proto_path.proto_path[i])) {
            if (configured_protocols[timed_out_session->proto_path.proto_path[i]]->session_data_cleanup != NULL) {
                ((generic_session_data_cleanup_function) configured_protocols[timed_out_session->proto_path.proto_path[i]]->session_data_cleanup)(timed_out_session, i);
            }
        }
    }

    //Update the protocol statistics to indicate the session timeout
    update_proto_stats_on_session_timeout(timed_out_session, NULL);

    // Clean the session context
    ((generic_session_context_cleanup_function) ((protocol_instance_t *) timed_out_session->protocol_container_context)->protocol->session_context_cleanup)((protocol_instance_t *) timed_out_session->protocol_container_context,
            timed_out_session, NULL);
}

void force_sessions_timeout(void * timeout_milestone, void * milestone_sessions_list, void * args) {
    mmt_handler_t * mmt_handler = (mmt_handler_t *) args;
    mmt_session_t * timed_out_session = (mmt_session_t *) milestone_sessions_list;
    mmt_session_t * safe_to_delete_session;
    while (timed_out_session != NULL) {
        safe_to_delete_session = timed_out_session;
        timed_out_session = timed_out_session->next;

        //Call user handler for timed out sessions
        if (mmt_handler->session_expiry_handler.handler_fct) {
            mmt_handler->session_expiry_handler.handler_fct(safe_to_delete_session, mmt_handler->session_expiry_handler.args);
        }

        cleanup_timedout_sessions(safe_to_delete_session);
    }
}

void process_outofmemory_force_sessions_timeout(mmt_handler_t * mmt_handler, ipacket_t * ipacket) {
    uint32_t timeout_slot_to_free = mmt_handler->last_expiry_timeout;
    uint32_t count = 0;
    while (count < 65000) {
        mmt_session_t * timed_out_session = get_timed_out_session_list(mmt_handler, timeout_slot_to_free);
        mmt_session_t * safe_to_delete_session;
        while (timed_out_session != NULL) {
            count++;
            safe_to_delete_session = timed_out_session;
            timed_out_session = timed_out_session->next;

            //Call user handler for timed out sessions
            if (mmt_handler->session_expiry_handler.handler_fct) {
                mmt_handler->session_expiry_handler.handler_fct(safe_to_delete_session, mmt_handler->session_expiry_handler.args);
            }

            cleanup_timedout_sessions(safe_to_delete_session);

        }
        //remove the timeout milestone from the hash
        delete_timeout_milestone(mmt_handler, timeout_slot_to_free);
        timeout_slot_to_free++;
    }
    mmt_handler->last_expiry_timeout = timeout_slot_to_free;
}

void process_timedout_sessions(mmt_handler_t * mmt_handler, uint32_t current_seconds) {
    if (current_seconds > mmt_handler->last_expiry_timeout && mmt_handler->last_expiry_timeout != 0) {
        uint32_t counter;
        for (counter = mmt_handler->last_expiry_timeout; counter < current_seconds; counter++) {
            mmt_session_t * timed_out_session = get_timed_out_session_list(mmt_handler, counter);
            mmt_session_t * safe_to_delete_session;
            while (timed_out_session != NULL) {
                safe_to_delete_session = timed_out_session;
                timed_out_session = timed_out_session->next;

                //Call user handler for timed out sessions
                if (mmt_handler->session_expiry_handler.handler_fct) {
                    mmt_handler->session_expiry_handler.handler_fct(safe_to_delete_session, mmt_handler->session_expiry_handler.args);
                }

                cleanup_timedout_sessions(safe_to_delete_session);

            }
            //remove the timeout milestone from the hash
            delete_timeout_milestone(mmt_handler, counter);
        }
    }
    mmt_handler->last_expiry_timeout = current_seconds;
}

int register_classification_function_internal(protocol_t * proto, generic_classification_function classification_fct, int weight) {
    if (weight < 0) weight = 0;
    if (weight > 100) weight = 100;
    mmt_classify_me_t * temp = (mmt_classify_me_t *) mmt_malloc(sizeof (mmt_classify_me_t));
    if (temp == NULL) {
        return 0;
    }
    memset(temp, 0, sizeof (mmt_classify_me_t));
    temp->weight = weight;
    temp->next = NULL;
    temp->previous = NULL;
    temp->classify_me = classification_fct;

    mmt_classify_me_t * temp_list = proto->classify_next.classify_protos;
    if (temp_list == NULL) {
        proto->classify_next.classify_protos = temp;
        temp->next = NULL;
        temp->previous = NULL;
    } else {
        if (temp->weight < temp_list->weight) {
            //The new element should be inserted at the head of the list
            temp->next = temp_list;
            temp->previous = NULL;
            temp_list->previous = temp;
            proto->classify_next.classify_protos = temp;
        } else {
            while (temp_list->next != NULL) {
                if (temp_list->next->weight > temp->weight) {
                    //Get out of the while loop
                    break;
                }
                temp_list = temp_list->next;
            }
            //Now we point to the element where we will insert the new elemnt
            temp->next = temp_list->next;
            temp->previous = temp_list;
            if (temp_list->next != NULL) {
                //temp_list is not the last element
                temp_list->next->previous = temp;
            }
            temp_list->next = temp;
        }
    }

    return 1;
}

int register_classification_function_with_parent_protocol(uint32_t proto_id, generic_classification_function classification_fct, int weight) {
    if (classification_fct != NULL) {
        protocol_t * proto = get_protocol_struct_by_protocol_id(proto_id);
        if (proto) {
            if (weight < 0) weight = 0;
            if (weight > 100) weight = 100;
            if ((weight > 10) && (weight < 90)) weight = 90;
            return register_classification_function_internal(proto, classification_fct, weight);
        }
    }
    return 0;
}

int register_classification_function(protocol_t *proto, generic_classification_function classification_fct) {
    if (classification_fct != NULL) {
        return register_classification_function_internal(proto, classification_fct, 50); //TODO: replace with a definition
    }
    return 0;
}

int register_pre_post_classification_functions(protocol_t *proto,
        generic_classification_function pre_classification,
        generic_classification_function post_classification) {

    proto->classify_next.pre_classify = pre_classification;
    proto->classify_next.post_classify = post_classification;

    return 1;

}

int register_classification_function_full(protocol_t *proto, generic_classification_function classification_fct, int weight,
        generic_classification_function pre_classification, generic_classification_function post_classification) {
    if (weight < 10) weight = 10;
    if (weight > 90) weight = 90;

    int retval = 1;
    if (classification_fct != NULL) {
        retval = register_classification_function_internal(proto, classification_fct, weight);
    }
    if (retval > 0) {
        proto->classify_next.pre_classify = pre_classification;
        proto->classify_next.post_classify = post_classification;
    }
    return retval;
}

void register_sessionizer_function(protocol_t *proto, generic_sessionizer_function sessionizer_fct,
        generic_session_context_cleanup_function session_context_cleanup_fct, generic_comparison_fct session_keys_comparison_fct) {
    proto->sessionize = (void *) sessionizer_fct;
    proto->session_context_cleanup = (void *) session_context_cleanup_fct;
    proto->has_session = HAS_SESSION_CONTEXT;
    proto->session_key_compare = session_keys_comparison_fct;
}

void register_proto_context_init_cleanup_function(protocol_t *proto, generic_proto_context_init_function context_init_fct,
        generic_proto_context_cleanup_function context_cleanup_fct, void * args) {
    proto->protocol_context_init = (void *) context_init_fct;
    proto->protocol_context_cleanup = (void *) context_cleanup_fct;
    proto->protocol_context_args = args;
}

void register_session_data_initialization_function(protocol_t *proto, generic_session_data_initialization_function session_data_init_fct) {
    proto->session_data_init = (void *) session_data_init_fct;
}

void register_session_data_cleanup_function(protocol_t *proto, generic_session_data_cleanup_function session_data_cleanup_fct) {
    proto->session_data_cleanup = (void *) session_data_cleanup_fct;
}

int register_data_analysis_function_internal(protocol_t * proto, generic_session_data_analysis_function analysis_fct, int weight) {
    if (weight < 0) weight = 0;
    if (weight > 100) weight = 100;
    mmt_analyse_me_t * temp = (mmt_analyse_me_t *) mmt_malloc(sizeof (mmt_analyse_me_t));
    if (temp == NULL) {
        return 0;
    }
    memset(temp, 0, sizeof (mmt_analyse_me_t));
    temp->weight = weight;
    temp->next = NULL;
    temp->previous = NULL;
    temp->analyse_me = analysis_fct;

    mmt_analyse_me_t * temp_list = proto->data_analyser.analyse;
    if (temp_list == NULL) {
        proto->data_analyser.analyse = temp;
        temp->next = NULL;
        temp->previous = NULL;
    } else {
        if (temp->weight < temp_list->weight) {
            //The new element should be inserted at the head of the list
            temp->next = temp;
            temp->previous = NULL;
            temp_list->previous = temp;
            proto->data_analyser.analyse = temp;
        } else {
            while (temp_list->next != NULL) {
                if (temp_list->next->weight > temp->weight) {
                    //Get out of the while loop
                    break;
                }
                temp_list = temp_list->next;
            }
            //Now we point to the element where we will insert the new elemnt
            temp->next = temp_list->next;
            temp->previous = temp_list;
            if (temp_list->next != NULL) {
                //temp_list is not the last element
                temp_list->next->previous = temp;
            }
            temp_list->next = temp;
        }
    }

    return 1;
}

int register_session_data_analysis_function_with_protocol(uint32_t proto_id,
        generic_session_data_analysis_function session_data_analysis_fct, int weight) {
    if (session_data_analysis_fct != NULL) {
        protocol_t * proto = get_protocol_struct_by_protocol_id(proto_id);
        if (proto) {
            if (weight < 0) weight = 0;
            if (weight > 100) weight = 100;
            if ((weight > 10) && (weight < 90)) weight = 90;
            return register_data_analysis_function_internal(proto, session_data_analysis_fct, weight);
        }
    }
    return 0;
}

int register_session_data_analysis_function(protocol_t *proto,
        generic_session_data_analysis_function session_data_analysis_fct) {
    if (session_data_analysis_fct != NULL) {
        return register_data_analysis_function_internal(proto, session_data_analysis_fct, 50); //TODO: replace with a definition
    }
    return 0;
}

int register_pre_post_analysis_functions(protocol_t *proto,
        generic_session_data_analysis_function pre_analysis,
        generic_session_data_analysis_function post_analysis) {

    proto->data_analyser.pre_analyse  = pre_analysis;
    proto->data_analyser.post_analyse = post_analysis;

    return 1;
}

int register_session_data_analysis_function_full(protocol_t *proto,
        generic_session_data_analysis_function session_data_analysis_fct,
        int weight,
        generic_session_data_analysis_function pre_analysis,
        generic_session_data_analysis_function post_analysis) {
    if (weight < 10) weight = 10;
    if (weight > 90) weight = 90;

    int retval = 1;
    if (session_data_analysis_fct != NULL) {
        retval = register_data_analysis_function_internal(proto, session_data_analysis_fct, weight);
    }
    if (retval > 0) {
        proto->data_analyser.pre_analyse = pre_analysis;
        proto->data_analyser.post_analyse = post_analysis;
    }
    return retval;
}

int is_valid_protocol_id(uint32_t proto_id) {
    return( proto_id < PROTO_MAX_IDENTIFIER );
}

int is_registered_protocol(uint32_t proto_id) {
    if (is_valid_protocol_id(proto_id) > 0)
        if (configured_protocols[proto_id]->is_registered && configured_protocols[proto_id]->proto_id == proto_id)
            return PROTO_REGISTERED;
    return PROTO_NOT_REGISTERED;
}

int is_free_protocol_id_for_registractionl(uint32_t proto_id) {
    if (proto_id > PROTO_MAX_IDENTIFIER) return 0; //The prtocol id is not valid

    protocol_t *proto = configured_protocols[proto_id];
    if( !proto ) return 1; // protocol just doesn't exist (plugin ?)
    if( proto->is_registered ) return 0; //The protocol is already registered

    return 1; // Cool we can use this protocol id
}

void init_protocol_struct(protocol_t * proto) {
    // TODO: complete this

    // register dummy sessionizer
    proto->sessionize = NULL;
    proto->has_session = NO_SESSION_CONTEXT;
    proto->session_timeout_delay = CFG_DEFAULT_SESSION_TIMEOUT;
    proto->attributes_map = init_int_map_space(attribute_ids_comparison_fct);
    proto->attributes_names_map = init_map_space(attribute_names_comparison_fct);
    proto->get_attribute_id_by_name = get_attribute_id_by_name_from_protocol_map;
    proto->get_attribute_name_by_id = get_attribute_name_by_id_from_protocol_map;
    proto->get_attribute_data_length_by_id = get_attribute_length_from_protocol_map;
    proto->get_attribute_data_type_by_id = get_attribute_data_type_by_id_from_protocol_map;
    proto->get_attribute_position = get_attribute_position_by_id_from_protocol_map;
    proto->get_attribute_scope = get_attribute_scope_by_id_from_protocol_map;
    proto->is_valid_attribute = is_protocol_valid_attribute;
    proto->get_attribute_extraction_function = get_attribute_extraction_fct_by_id_from_protocol_map;
    proto->protocol_context_init = NULL;
    proto->protocol_context_cleanup = NULL;
    proto->protocol_context_args = NULL;
}

protocol_t *get_protocol_struct_for_registration_if_free(uint32_t proto_id) {
    if (is_free_protocol_id_for_registractionl(proto_id)) {
        init_protocol_struct(configured_protocols[proto_id]);
        return configured_protocols[proto_id];
    }

    return NULL;
}

protocol_t *init_protocol_struct_for_registration(uint32_t proto_id, const char * protocol_name) {
    protocol_t *temp_proto = get_protocol_struct_for_registration_if_free(proto_id);
    if (temp_proto != NULL) {
        temp_proto->proto_id = proto_id;
        temp_proto->protocol_code = proto_id;
        temp_proto->protocol_name = protocol_name;
        return temp_proto;
    }

    return NULL;
}

protocol_t *get_protocol_struct_by_id(uint32_t proto_id) {
    if(is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id];
    }
    return NULL;
}

void free_registered_protocol_attribute(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
    mmt_free(attribute);
}

void free_registered_protocol(protocol_t * protocol) {
    if (protocol->attributes_map != NULL) {
        //First iterete over the attributes to free their allocated memory
        iterate_through_protocol_attributes(protocol->proto_id, free_registered_protocol_attribute, NULL);
        //Clear the map and set them to NULL
        clear_int_map_space(protocol->attributes_map);
        delete_int_map_space(protocol->attributes_map);
        protocol->attributes_map = NULL;
    }

    // Clear the names map and set it to NULL
    if (protocol->attributes_names_map != NULL) {
        clear_map_space(protocol->attributes_names_map);
        delete_map_space(protocol->attributes_names_map);
        protocol->attributes_names_map = NULL;
    }

    //Clear the classification function if it exists
    mmt_classify_me_t * temp_class = protocol->classify_next.classify_protos;
    mmt_classify_me_t * safe_to_delete_c = NULL;
    while(temp_class != NULL) {
        safe_to_delete_c = temp_class;
        temp_class = temp_class->next;
        mmt_free(safe_to_delete_c);
    }
    //Clear the classification function if it exists
    mmt_analyse_me_t * temp_analyse = protocol->data_analyser.analyse;
    mmt_analyse_me_t * safe_to_delete_a = NULL;
    while(temp_analyse != NULL) {
        safe_to_delete_a = temp_analyse;
        temp_analyse = temp_analyse->next;
        mmt_free(safe_to_delete_a);
    }
}

void free_registered_protocols() {
    int i = 0;
    for (; i < PROTO_MAX_IDENTIFIER; i++) {
        if (configured_protocols[i]) {
            if (configured_protocols[i]->is_registered) {
                free_registered_protocol(configured_protocols[i]);
            }
            mmt_free(configured_protocols[i]); // Then we free the protocol element structure
            configured_protocols[i] = NULL;
        }
    }
}

void free_protocols_contexts(mmt_handler_t *mmt_handler) {
    int i = 0;
    for (; i < PROTO_MAX_IDENTIFIER; i++) {
        if (mmt_handler->configured_protocols[i].protocol->is_registered) {
            if (mmt_handler->configured_protocols[i].protocol->has_session && mmt_handler->configured_protocols[i].sessions_map != NULL) {
                clear_sessions_from_protocol_context(&mmt_handler->configured_protocols[i]);
                delete_map_space(mmt_handler->configured_protocols[i].sessions_map);
                mmt_handler->configured_protocols[i].sessions_map = NULL;
            }

            //Cleanup the protocol context if such a function is registered
            if (mmt_handler->configured_protocols[i].protocol->protocol_context_cleanup != NULL) {
                ((generic_proto_context_cleanup_function) mmt_handler->configured_protocols[i].protocol->protocol_context_cleanup)(&mmt_handler->configured_protocols[i], mmt_handler->configured_protocols[i].protocol->protocol_context_args);
            }
        }
    }
}

int proto_packet_count_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += proto_stats->packets_count;
        proto_stats = proto_stats->next;
    }

    if (count) {
        *((uint64_t *) extracted_data->data) = count;
        return 1;
    }
    return 0;
}

int proto_data_volume_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += proto_stats->data_volume;
        proto_stats = proto_stats->next;
    }

    if (count) {
        *((uint64_t *) extracted_data->data) = count;
        return 1;
    }
    return 0;
}

int proto_payload_volume_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += proto_stats->payload_volume;
        proto_stats = proto_stats->next;
    }

    if (count) {
        *((uint64_t *) extracted_data->data) = count;
        return 1;
    }
    return 0;
}

int proto_sessions_count_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += proto_stats->sessions_count;
        proto_stats = proto_stats->next;
    }

    if (count) {
        *((uint64_t *) extracted_data->data) = count;
        return 1;
    }
    return 0;
}

int proto_active_sessions_count_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += (proto_stats->sessions_count - proto_stats->timedout_sessions_count);
        proto_stats = proto_stats->next;
    }

    if (count) {
        *((uint64_t *) extracted_data->data) = count;
        return 1;
    }
    return 0;
}

int proto_timedout_sessions_count_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += proto_stats->timedout_sessions_count;
        proto_stats = proto_stats->next;
    }

    if (count) {
        *((uint64_t *) extracted_data->data) = count;
        return 1;
    }
    return 0;
}

int proto_header_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    extracted_data->data = (void *) &packet->data[proto_offset];
    return 1;
}

int proto_data_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    extracted_data->data = (void *) &packet->data[proto_offset];
    return 1;
}

int proto_payload_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    int proto_offset;
    if (proto_index + 1 == packet->proto_hierarchy->len) {
        proto_offset = get_packet_offset_at_index(packet, proto_index);
    } else {
        proto_offset = get_packet_offset_at_index(packet, proto_index + 1);
    }

    extracted_data->data = (void *) &packet->data[proto_offset];
    return 1;
}

int proto_session_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if (packet->session == NULL) {
        extracted_data->data = NULL;
        return 0;
    }
    if (packet->session->packet_count == 1) {
        extracted_data->data = packet->session;
        return 1;
    }
    return 0;
}

int proto_session_id_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if (packet->session == NULL) {
        *((uint64_t *) extracted_data->data) = -1; //we should never get this id (-1)
        //extracted_data->data = NULL;
        return 0;
    }
    
    *((uint64_t *) extracted_data->data) = packet->session->session_id;
    return 1;
}

int proto_stats_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    mmt_handler_t *mmt_handler = packet->mmt_handler;
    protocol_instance_t proto = mmt_handler->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    extracted_data->data = (void *) proto.proto_stats;
    return 1;
}

static attribute_metadata_t proto_stats_attributes_metadata[PROTO_STATS_ATTRIBUTES_NB] = {
    {PROTO_HEADER, PROTO_HEADER_LABEL, MMT_DATA_POINTER, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_header_extraction},
    {PROTO_DATA, PROTO_DATA_LABEL, MMT_DATA_POINTER, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_data_extraction},
    {PROTO_PAYLOAD, PROTO_PAYLOAD_LABEL, MMT_DATA_POINTER, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_payload_extraction},

    {PROTO_PACKET_COUNT, PROTO_PACKET_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_packet_count_extraction},
    {PROTO_DATA_VOLUME, PROTO_DATA_VOLUME_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_data_volume_extraction},
    {PROTO_PAYLOAD_VOLUME, PROTO_PAYLOAD_VOLUME_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_payload_volume_extraction},
    {PROTO_SESSIONS_COUNT, PROTO_SESSIONS_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_sessions_count_extraction},
    {PROTO_ACTIVE_SESSIONS_COUNT, PROTO_ACTIVE_SESSIONS_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_active_sessions_count_extraction},
    {PROTO_TIMEDOUT_SESSIONS_COUNT, PROTO_TIMEDOUT_SESSIONS_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_timedout_sessions_count_extraction},
    {PROTO_STATISTICS, PROTO_STATISTICS_LABEL, MMT_STATS, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_stats_extraction},
};

static attribute_metadata_t proto_session_attr_metadata[PROTO_SESSION_ATTRIBUTES_NB] = {
    {PROTO_SESSION, PROTO_SESSION_LABEL, MMT_DATA_POINTER, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_EVENT, proto_session_extraction},
    {PROTO_SESSION_ID, PROTO_SESSION_ID_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_session_id_extraction},
};

void register_protocol_stats_attributes(protocol_t *proto) {
    int i = 0;
    for (; i < PROTO_STATS_ATTRIBUTES_NB; i++) {
        register_attribute_with_protocol(proto, &proto_stats_attributes_metadata[i]);
    }
}

void register_protocol_session_attributes(protocol_t *proto) {
    int i = 0;
    for (; i < PROTO_SESSION_ATTRIBUTES_NB; i++) {
        register_attribute_with_protocol(proto, &proto_session_attr_metadata[i]);
    }
}

int register_protocol(protocol_t *proto, uint32_t proto_id) {
    if (is_free_protocol_id_for_registractionl(proto_id)) {
        if (proto->proto_id == proto_id && proto == configured_protocols[proto_id]) {
            register_protocol_stats_attributes(proto);
            if (proto->has_session) {
                register_protocol_session_attributes(proto);
            }
            configured_protocols[proto_id]->is_registered = PROTO_REGISTERED;
            return PROTO_REGISTERED;
        }
    }
    return PROTO_NOT_REGISTERED;
}

int init_plugins() {
    if (!load_plugins()) {
        fprintf(stderr, "Error while loading plugins, Exiting\n");
        return 0;
    }

    return 1;
}

mmt_handler_t *mmt_init_handler( uint32_t stacktype, uint32_t options, char * errbuf )
{
    int i = 0;
    protocol_stack_t * temp_stack = get_protocol_stack_from_map(stacktype);
    if (temp_stack == NULL) {
        if( errbuf )
            strcpy(errbuf, "Unsupported stack type");
        return NULL;
    }

    mmt_handler_t * new_handler = mmt_malloc(sizeof (mmt_handler_t));
    if (new_handler == NULL) {
        if( errbuf )
            strcpy(errbuf, "Error while initializing mmt extraction handler");
        return NULL;
    }

    // Set the handler to zeros
    memset(new_handler, '\0', sizeof (mmt_handler_t));
    new_handler->packet_count = 0;
    new_handler->sessions_count = 0;
    new_handler->active_sessions_count = 0;
    new_handler->ip_streams = hashmap_alloc();

    new_handler->last_received_packet.packet_id = 0;
    new_handler->last_received_packet.packet_len = 0;
    new_handler->last_received_packet.time.tv_sec = 0;
    new_handler->last_received_packet.time.tv_usec = 0;

    new_handler->link_layer_stack = temp_stack;

    new_handler->timeout_milestones_map = init_int_map_space(session_timeout_comp_fn_pt);
    if (new_handler->timeout_milestones_map == NULL) {
        if( errbuf )
            strcpy(errbuf, "Error while initializing mmt extraction handler");
        mmt_free(new_handler);
        return NULL;
    }

    for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        new_handler->configured_protocols[i].protocol = configured_protocols[i];
        new_handler->configured_protocols[i].sessions_map = NULL;
        new_handler->configured_protocols[i].args = NULL;

        // Initialize the sessions context if the protocol has such context
        if (new_handler->configured_protocols[i].protocol->has_session == HAS_SESSION_CONTEXT) {
            new_handler->configured_protocols[i].sessions_map = init_map_space(new_handler->configured_protocols[i].protocol->session_key_compare);
        }

        // Initialize the protocol context if the protocol has such context
        if (new_handler->configured_protocols[i].protocol->protocol_context_init != NULL) {
            new_handler->configured_protocols[i].args =
                    (void *) ((generic_proto_context_init_function) new_handler->configured_protocols[i].protocol->protocol_context_init)((void *) &new_handler->configured_protocols[i], new_handler->configured_protocols[i].protocol->protocol_context_args);
        }
        new_handler->proto_registered_attributes[i] = NULL;
        new_handler->proto_registered_attribute_handlers[i] = NULL;

        enable_protocol_analysis((void *) new_handler, i);
        enable_protocol_classification((void *) new_handler, i);
    }

    new_handler->session_expiry_handler.handler_fct = NULL;
    new_handler->session_expiry_handler.args = NULL;

    //Enable protocol statistics (this is default config)
    enable_protocol_statistics((void *) new_handler);

    insert_key_value(mmt_configured_handlers_map, (void *) new_handler, (void *) new_handler);
    return (void *) new_handler;
}

/**
 * Returns the data link type of the given mmt handler.
 * @param mmt_handler pointer to the mmt handler we want to get its data link type
 * @param dltype identifier of the data link type.
 * @return data identifier of data link type of \mmt_handler
 */
int get_data_link_type(mmt_handler_t *mmt_handler) {
    if (!mmt_handler) return -1;
    return (mmt_handler)->link_layer_stack->stack_id;
}

struct timeval get_last_activity_time( mmt_handler_t * handler ) {
    return handler->last_received_packet.time;
}

void free_handler_protocol_statistics(mmt_handler_t *mmt_handler, protocol_instance_t * protocol) {
    proto_statistics_internal_t * temp = protocol->proto_stats;
    proto_statistics_internal_t * safe_to_delete = NULL;
    while(temp != NULL) {
        safe_to_delete = temp;
        temp = temp->next;
        delete_int_map_space(safe_to_delete->encap_proto_stats);
        mmt_free(safe_to_delete);
    }
    protocol->proto_stats = NULL;
}

void free_handler_protocols_statistics(mmt_handler_t *mmt_handler) {
    int i = 0;
    for(; i < PROTO_MAX_IDENTIFIER; i++) {
        free_handler_protocol_statistics(mmt_handler, &mmt_handler->configured_protocols[i]);
    }
}

void mmt_close_handler(mmt_handler_t *mmt_handler) {
    // Iterate over the timeout milestones and expticitly timeout all registered sessions
    timeout_iteration_callback(mmt_handler, force_sessions_timeout);
    // Clear timeout milestones
    clear_timeout_milestones(mmt_handler);
    // Free the attribute structs
    free_registered_extraction_attributes(mmt_handler);
    // Free the registered attribute handlers
    free_registered_attribute_handlers(mmt_handler);
    // Free the packet handlers structs
    free_registered_packet_handlers(mmt_handler);
    // Free the protocol structs
    free_protocols_contexts(mmt_handler);
    // Free protocol statistics
    free_handler_protocols_statistics(mmt_handler);
    // Free IP streams hashtable
    hashmap_free(mmt_handler->ip_streams);

    //Remove the handler from the registered handlers in the global context
    delete_key_value(mmt_configured_handlers_map, mmt_handler);
    // if(mmt_handler->clean_up_fct!=NULL){
    //     mmt_handler->clean_up_fct();
    // }
    mmt_free(mmt_handler);
}

/**
 * Enables the maintenance of protocol statistics for the given \mmt_handler
 * @param mmt_handler mmt handler
 */
void enable_protocol_statistics(mmt_handler_t *mmt_handler) {
    if (mmt_handler == NULL) return;
    mmt_handler->stats_reporting_status = 1;
}

/**
 * Disables the maintenance of protocol statistics for the given \mmt_handler
 * @param mmt_handler mmt handler
 */
void disable_protocol_statistics(mmt_handler_t *mmt_handler) {
    if (mmt_handler == NULL) return;
    int i;
    mmt_handler->stats_reporting_status = 0;
    for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        reset_proto_stats(&mmt_handler->configured_protocols[i]);
    }
}

/**
 * Enables the analysis sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void enable_protocol_analysis(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && is_valid_protocol_id(proto_id) > 0) {
        mmt_handler->configured_protocols[proto_id].protocol->data_analyser.status = 1;
    }
}

/**
 * Disables the analysis sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void disable_protocol_analysis(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && is_valid_protocol_id(proto_id) > 0) {
        mmt_handler->configured_protocols[proto_id].protocol->data_analyser.status = 0;
    }
}

/**
 * Enables the classification sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void enable_protocol_classification(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && is_valid_protocol_id(proto_id) > 0) {
        mmt_handler->configured_protocols[proto_id].protocol->classify_next.status = 1;
    }
}

/**
 * Disables the classification sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void disable_protocol_classification(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && is_valid_protocol_id(proto_id) > 0) {
        mmt_handler->configured_protocols[proto_id].protocol->classify_next.status = 0;
    }
}

int isProtocolStatisticsEnabled(mmt_handler_t *mmt_handler) {
    return mmt_handler->stats_reporting_status;
}

int init_extraction()
{
    int i = 0;
    for (; i < PROTO_MAX_IDENTIFIER; i++) {
        configured_protocols[i] = (protocol_t *) mmt_malloc(sizeof (protocol_t));
        if (!configured_protocols[i]) {
            fprintf(stderr, "Error during initialization, Exiting\n");
            exit(0);
        }
        memset(configured_protocols[i], '\0', sizeof (protocol_t));
        configured_protocols[i]->is_registered = PROTO_NOT_REGISTERED;
    }

    /////////// INITILIZING PROTO_META & PROTO_UNKNOWN //////////////////
    if (!init_proto_meta_struct() || !init_proto_unknown_struct()) {
        fprintf(stderr, "Error initializing meta and unkown protocols\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////

    package_dependent_init();

    init_plugins();
    mmt_configured_handlers_map = init_map_space(pointer_comp_fn_pt);
    return 1;
}

struct attribute_internal_struct * get_registered_attribute_internal_struct(const ipacket_t * ipacket, uint32_t proto_id, uint32_t attribute_id, unsigned index) {
    struct attribute_internal_struct * tmp_attr_ref;
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    tmp_attr_ref = mmt_handler->proto_registered_attributes[proto_id]; //This is safe as we are sure the protocol is registered

    while (tmp_attr_ref != NULL) {
        if (attribute_id == tmp_attr_ref->field_id) {
            return tmp_attr_ref;
        }
        tmp_attr_ref = tmp_attr_ref->next;
    }
    return NULL;
}

/**
 * Internal function for extracting attribute data.
 * @param ipacket pointer to internal packet structure
 * @param tmp_attr_ref pointer to the attribute structure
 * @param index index of the protocol in the path
 * @return a positive value if the extraction was done, zero otherwise
 */
int internal_extract_attribute(const ipacket_t * ipacket, struct attribute_internal_struct * tmp_attr_ref, unsigned index) {
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
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
void * get_attribute_extracted_data_at_index(const ipacket_t * ipacket, uint32_t proto_id, uint32_t attribute_id, unsigned index) {
    if ((int) index < 0 || index >= ipacket->proto_hierarchy->len) {
        //the given index is not valid
#ifdef DEBUG
        (void)fprintf( stderr, "get_attribute_extracted_data_at_index(): invalid index (%u)\n", index );
#endif /*DEBUG*/
        return NULL;
    }

    if (proto_id != ipacket->proto_hierarchy->proto_path[index]) {
        //the given protocol id does not match the protocol id at the given index
#ifdef DEBUG
        (void)fprintf( stderr, "get_attribute_extracted_data_at_index(): unexpected protocol_id (%u)\n", proto_id );
#endif /*DEBUG*/
        return NULL;
    }

    if (!is_registered_protocol(proto_id)) {
        //the given protocol id is not registered
#ifdef DEBUG
        (void)fprintf( stderr, "get_attribute_extracted_data_at_index(): unregistered protocol_id (%u)\n", proto_id );
#endif /*DEBUG*/
        return NULL;
    }

    struct attribute_internal_struct * tmp_attr_ref = get_registered_attribute_internal_struct(ipacket, proto_id, attribute_id, index);
    if (tmp_attr_ref == NULL) {
#ifdef DEBUG
        (void)fprintf( stderr, "get_attribute_extracted_data_at_index(): can't retrieve attribute internal structure\n" );
#endif /*DEBUG*/
        return NULL;
    }

    if (tmp_attr_ref->scope & SCOPE_ON_DEMAND) {
        if (internal_extract_attribute(ipacket, tmp_attr_ref, index)) {
            //return the attribute's data
#ifdef DEBUG
            (void)fprintf( stderr, "get_attribute_extracted_data_at_index(): attribute data is null (1/2)\n" );
#endif /*DEBUG*/
            return tmp_attr_ref->data;
        }
    }else {
        if(tmp_attr_ref->packet_id == (ipacket->mmt_handler)->last_received_packet.packet_id) {
#ifdef DEBUG
            (void)fprintf( stderr, "get_attribute_extracted_data_at_index(): attribute data is null (2/2)\n" );
#endif /*DEBUG*/
            return tmp_attr_ref->data;
        }
    }
#ifdef DEBUG
    (void)fprintf( stderr, "get_attribute_extracted_data_at_index(): unexpected failure\n" );
#endif /*DEBUG*/
    return NULL;
}

attribute_t * get_extracted_attribute_at_index(const ipacket_t * ipacket, uint32_t proto_id, uint32_t attribute_id, unsigned index) {
    if ((int) index < 0 || index >= ipacket->proto_hierarchy->len) {
        //the given index is not valid
#ifdef DEBUG
        (void)fprintf( stderr, "get_extracted_attribute_at_index(): invalid index (%u)\n", index );
#endif /*DEBUG*/
        return NULL;
    }

    if (proto_id != ipacket->proto_hierarchy->proto_path[index]) {
        //the given protocol id does not match the protocol id at the given index
#ifdef DEBUG
        (void)fprintf( stderr, "get_extracted_attribute_at_index(): unexpected protocol_id (%u)\n", proto_id );
#endif /*DEBUG*/
        return NULL;
    }

    if (!is_registered_protocol(proto_id)) {
        //the given protocol id is not registered
#ifdef DEBUG
        (void)fprintf( stderr, "get_extracted_attribute_at_index(): unregistered protocol_id (%u)\n", proto_id );
#endif /*DEBUG*/
        return NULL;
    }

    struct attribute_internal_struct * tmp_attr_ref = get_registered_attribute_internal_struct(ipacket, proto_id, attribute_id, index);
    if (tmp_attr_ref == NULL) {
#ifdef DEBUG
        (void)fprintf( stderr, "get_extracted_attribute_at_index(): can't retrieve attribute internal structure\n" );
#endif /*DEBUG*/
        return NULL;
    }

    if (tmp_attr_ref->scope & SCOPE_ON_DEMAND) {
        if (internal_extract_attribute(ipacket, tmp_attr_ref, index)) {
            //return the attribute's data
#ifdef DEBUG
            (void)fprintf( stderr, "get_extracted_attribute_at_index(): attribute data is null (1/2)\n" );
#endif /*DEBUG*/
            return (attribute_t *) tmp_attr_ref;
        }
    }else {
        if(tmp_attr_ref->packet_id == (ipacket->mmt_handler)->last_received_packet.packet_id) {
#ifdef DEBUG
            (void)fprintf( stderr, "get_extracted_attribute_at_index(): attribute data is null (2/2)\n" );
#endif /*DEBUG*/
            return (attribute_t *) tmp_attr_ref;
        }
    }
#ifdef DEBUG
    (void)fprintf( stderr, "get_extracted_attribute_at_index(): unexpected failure\n" );
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
void * get_attribute_extracted_data_at_index_by_name(const ipacket_t * ipacket, const char *protocol_name, const char *attribute_name, unsigned index) {
    if ((int) index < 0 || index >= ipacket->proto_hierarchy->len) {
        //the given index is not valid
#ifdef DEBUG
        (void)fprintf( stderr, "get_attribute_extracted_data_at_index_by_name(): invalid index (%u)\n", index );
#endif /*DEBUG*/
        return NULL;
    }

    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
#ifdef DEBUG
        (void)fprintf( stderr, "get_attribute_extracted_data_at_index_by_name(): unknown protocol name (\"%s\")\n", protocol_name );
#endif /*DEBUG*/
        return NULL;
    }

    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
#ifdef DEBUG
        (void)fprintf( stderr, "get_attribute_extracted_data_at_index_by_name(): unknown attribute name (\"%s\")\n", attribute_name );
#endif /*DEBUG*/
        return NULL;
    }
    return get_attribute_extracted_data_at_index(ipacket, proto_id, attribute_id, index);
}

attribute_t * get_extracted_attribute_at_index_by_name(const ipacket_t * ipacket, const char *protocol_name, const char *attribute_name, unsigned index) {
    if ((int) index < 0 || index >= ipacket->proto_hierarchy->len) {
        //the given index is not valid
#ifdef DEBUG
        (void)fprintf( stderr, "get_extracted_attribute_at_index_by_name(): invalid index (%u)\n", index );
#endif /*DEBUG*/
        return NULL;
    }

    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
#ifdef DEBUG
        (void)fprintf( stderr, "get_extracted_attribute_at_index_by_name(): unknown protocol name (\"%s\")\n", protocol_name );
#endif /*DEBUG*/
        return NULL;
    }

    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
#ifdef DEBUG
        (void)fprintf( stderr, "get_extracted_attribute_at_index_by_name(): unknown attribute name (\"%s\")\n", attribute_name );
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
        (void)fprintf( stderr, "get_attribute_extracted_data_by_name(): unknown protocol name (\"%s\")\n", protocol_name );
#endif /*DEBUG*/
        return NULL;
    }
    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
#ifdef DEBUG
        (void)fprintf( stderr, "get_attribute_extracted_data_by_name(): unknown attribute name (\"%s\")\n", attribute_name );
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
        (void)fprintf( stderr, "get_extracted_attribute_by_name(): unknown protocol name (\"%s\")\n", protocol_name );
#endif /*DEBUG*/
        return NULL;
    }
    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
#ifdef DEBUG
        (void)fprintf( stderr, "get_extracted_attribute_by_name(): unknown attribute name (\"%s\")\n", attribute_name );
#endif /*DEBUG*/
        return NULL;
    }
    return get_extracted_attribute(ipacket, proto_id, attribute_id);
}


//TODO: this function does not take into account protocol encapsulation where more than one occurrence of the same protocol exists in the path

void * get_attribute_extracted_data(const ipacket_t * ipacket, uint32_t proto_id, uint32_t field_id) {
    unsigned index = 0;
    for (; index < ipacket->proto_hierarchy->len; index++) {
        if (proto_id == ipacket->proto_hierarchy->proto_path[index]) {
            return get_attribute_extracted_data_at_index(ipacket, proto_id, field_id, index);
        }
    }

#ifdef DEBUG
    (void)fprintf( stderr, "get_attribute_extracted_data(): proto_id #%u not found in path\n", proto_id );
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
    (void)fprintf( stderr, "get_extracted_attribute(): proto_id #%u not found in path\n", proto_id );
#endif /*DEBUG*/
 
    return NULL;
}

void mmt_close_handler_internal(mmt_handler_t *mmt_handler, void * args) {
    mmt_close_handler(mmt_handler);
}

void close_extraction() {
    // Iterate over the registered protocol stacks
    iterate_through_protocol_stacks(protocol_stack_callback_fct, NULL);
    // Clear the protocol stacks map
    clear_protocol_stack_map();
    //Iterate over the registered handlers
    iterate_through_mmt_handlers(mmt_close_handler_internal, NULL);
    //Delete the handlers map
    delete_map_space(mmt_configured_handlers_map);
    // Free the protocol structs
    free_registered_protocols();
    // unload plugins
    close_plugins();

#ifdef DEBUG
    mmt_meminfo_t m;
    mmt_meminfo(&m);
    (void)fprintf( stderr, "*** MEMORY USAGE ***\n" );
    (void)fprintf( stderr, "allocated: %lu bytes\n", m.allocated );
    (void)fprintf( stderr, "    freed: %lu bytes\n", m.freed );
    (void)fprintf( stderr, "     lost: %lu bytes\n", m.allocated - m.freed );
#endif
}

void print_attributes_list(struct attribute_internal_struct * tmp_attribute) {
    (void) mmt_attr_format(stdout, (attribute_t *) tmp_attribute);
}

int is_registered_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id) {
    packet_handler_t * temp_handler = mmt_handler->packet_handlers;
    while (temp_handler != NULL) {
        if (temp_handler->packet_handler_id == packet_handler_id) return 1;
        temp_handler = temp_handler->next;
    }
    return 0;
}

int is_registered_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    int retval = 0;
    struct attribute_internal_struct * tmp_attribute = mmt_handler->proto_registered_attributes[proto_id];
    while (tmp_attribute != NULL) {
        if (proto_id == tmp_attribute->proto_id &&
                field_id == tmp_attribute->field_id) return 1;
        tmp_attribute = tmp_attribute->next;
    }
    return retval;
}

struct attribute_internal_struct * get_registered_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    if (is_registered_protocol(proto_id) > 0) {
        struct attribute_internal_struct * tmp_attribute = mmt_handler->proto_registered_attributes[proto_id];
        while (tmp_attribute != NULL) {
            if (proto_id == tmp_attribute->proto_id &&
                    field_id == tmp_attribute->field_id) return tmp_attribute;
            tmp_attribute = tmp_attribute->next;
        }
    }
    return NULL;
}

int has_registered_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t attribute_id) {
    if (!is_valid_protocol_id(proto_id)) {
        return 0;
    }
    attribute_internal_t * tmp_attribute = mmt_handler->proto_registered_attributes[proto_id];
    while (tmp_attribute != NULL) {
        if (proto_id == tmp_attribute->proto_id &&
                attribute_id == tmp_attribute->field_id &&
                tmp_attribute->attribute_handler != NULL /* The attribute has at least one registered handler */) {
            return 1;
        }
        tmp_attribute = tmp_attribute->next;
    }
    return 0;
}

int is_registered_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id,
        uint32_t attribute_id, attribute_handler_function handler_fct) {
    if (!is_valid_protocol_id(proto_id)) {
        return 0;
    }
    attribute_internal_t * tmp_attribute = mmt_handler->proto_registered_attributes[proto_id];
    while (tmp_attribute != NULL) {
        if (proto_id == tmp_attribute->proto_id &&
                attribute_id == tmp_attribute->field_id &&
                tmp_attribute->attribute_handler != NULL /* The attribute has at least one registered handler */) {
            attribute_handler_t * att_handler_fct = tmp_attribute->attribute_handler;
            while (att_handler_fct != NULL) {
                if (att_handler_fct->handler_fct == handler_fct) {
                    return 1;
                }
                att_handler_fct = att_handler_fct->next;
            }
        }
        tmp_attribute = tmp_attribute->next;
    }
    return 0;
}

void free_registered_extraction_attributes(mmt_handler_t *mmt_handler) {
    struct attribute_internal_struct * temp_attr;
    struct attribute_internal_struct * safe_to_delete_attr = NULL;
    int i = 0;
    for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        temp_attr = mmt_handler->proto_registered_attributes[i];
        while (temp_attr != NULL) {
            safe_to_delete_attr = temp_attr;
            temp_attr = temp_attr->next;
            mmt_free(safe_to_delete_attr); // we free the internal attribute struct
        }
        mmt_handler->proto_registered_attributes[i] = NULL;
    }
}

void free_registered_attribute_handlers(mmt_handler_t *mmt_handler) {
    attribute_handler_element_t * temp_attr_handler;
    attribute_handler_element_t * safe_to_delete_attr_handler = NULL;
    int i = 0;

    for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        temp_attr_handler = mmt_handler->proto_registered_attribute_handlers[i];
        while (temp_attr_handler != NULL) {
            safe_to_delete_attr_handler = temp_attr_handler;
            temp_attr_handler = temp_attr_handler->next;
            mmt_free(safe_to_delete_attr_handler); // we free the attribute handler struct
        }
        mmt_handler->proto_registered_attribute_handlers[i] = NULL;
    }
}

int unregister_extraction_attribute_by_name(mmt_handler_t *mmt_handler, const char *protocol_name, const char *attribute_name) {
    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
        return 1;
    }
    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
        return 1;
    }
    return unregister_extraction_attribute(mmt_handler, proto_id, attribute_id);
}

int unregister_extraction_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {

    struct attribute_internal_struct * temp_attr_proto_list;
    struct attribute_internal_struct * safe_to_delete_attr_for_proto = NULL;

    temp_attr_proto_list = get_registered_attribute(mmt_handler, proto_id, field_id);
    if (!temp_attr_proto_list) { //The attribute does not exist, return with no further action
        return 1;
    }

    // The attribute exists, two cases are possible
    //     1- The attribute registration count is positive, decrement its registration count, no further action
    //     2- The attribute registration count is equal to one, We decrement its registration count, two cases are possible
    //       2.1- the attribute's handlers_count equal to zero, the attribute can be safely deleted
    //       2.1- the attribute's handlers_count is positive, no further action is required.

    if (temp_attr_proto_list->registration_count) {
        // We decrement the value only if it is positive! to avoid negative values
        temp_attr_proto_list->registration_count--;
    }

    if (!temp_attr_proto_list->registration_count && !temp_attr_proto_list->handlers_count) { // Both values are non positive! we delete it
        temp_attr_proto_list = mmt_handler->proto_registered_attributes[proto_id];

        while (temp_attr_proto_list != NULL) {
            if ((temp_attr_proto_list->field_id == field_id) && (temp_attr_proto_list->proto_id == proto_id)) {
                //attr_found_in_proto_list = 1;
                break;
            }
            safe_to_delete_attr_for_proto = temp_attr_proto_list;
            temp_attr_proto_list = temp_attr_proto_list->next;
        }

        if (safe_to_delete_attr_for_proto == NULL) { //The attribute to delete is the first in the list
            mmt_handler->proto_registered_attributes[proto_id] = temp_attr_proto_list->next;
            safe_to_delete_attr_for_proto = temp_attr_proto_list;
        } else {
            safe_to_delete_attr_for_proto->next = temp_attr_proto_list->next; // We relink the elements
            safe_to_delete_attr_for_proto = temp_attr_proto_list;
        }

        mmt_free(safe_to_delete_attr_for_proto);
    }

    return 1;
}

int unregister_attribute_handler_by_name(mmt_handler_t *mmt_handler, const char *protocol_name,
        const char *attribute_name, attribute_handler_function handler_fct) {
    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
        return 1;
    }
    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
        return 1;
    }
    return unregister_attribute_handler(mmt_handler, proto_id, attribute_id, handler_fct);
}

int unregister_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t attribute_id, attribute_handler_function handler_fct) {
    attribute_handler_t * temp_attr_handler;
    attribute_handler_t * safe_to_delete_attr_handler = NULL;
    attribute_internal_t * temp_attr;
    if (!is_registered_attribute_handler(mmt_handler, proto_id, attribute_id, handler_fct)) {
        return 1;
    }

    //Get the attribute
    temp_attr = mmt_handler->proto_registered_attributes[proto_id];
    while (temp_attr != NULL) {
        if ((temp_attr->field_id == attribute_id) && (temp_attr->proto_id == proto_id)) {
            break;
        }
        temp_attr = temp_attr->next;
    }

    temp_attr_handler = temp_attr->attribute_handler;
    while (temp_attr_handler != NULL) {
        if (temp_attr_handler->handler_fct == handler_fct) {
            break;
        }
        safe_to_delete_attr_handler = temp_attr_handler;
        temp_attr_handler = temp_attr_handler->next;
    }

    if (safe_to_delete_attr_handler == NULL) { //The attribute handler to delete is the first in the list
        temp_attr->attribute_handler = temp_attr_handler->next;
        safe_to_delete_attr_handler = temp_attr_handler;
    } else {
        safe_to_delete_attr_handler->next = temp_attr_handler->next; // We relink the elements
        safe_to_delete_attr_handler = temp_attr_handler;
    }

    if ((temp_attr->attribute_handler == NULL) && !(temp_attr->scope & SCOPE_EVENT)) {
        //We need to delete the attribute handler element as there are no more registered handler functions
        attribute_handler_element_t * temp_attr_handler_elem = mmt_handler->proto_registered_attribute_handlers[proto_id];
        attribute_handler_element_t * safe_to_delete_attr_handler_elem = NULL;

        while (temp_attr_handler_elem != NULL) {
            if (temp_attr_handler_elem->attribute->proto_id == proto_id && temp_attr_handler_elem->attribute->field_id == attribute_id) {
                break;
            }
            safe_to_delete_attr_handler_elem = temp_attr_handler_elem;
            temp_attr_handler_elem = temp_attr_handler_elem->next;
        }

        if (safe_to_delete_attr_handler_elem == NULL) { //The attribute handler to delete is the first in the list
            mmt_handler->proto_registered_attribute_handlers[proto_id] = temp_attr_handler_elem->next;
            safe_to_delete_attr_handler_elem = temp_attr_handler_elem;
        } else {
            safe_to_delete_attr_handler_elem->next = temp_attr_handler_elem->next; // We relink the elements
            safe_to_delete_attr_handler_elem = temp_attr_handler_elem;
        }
        mmt_free(safe_to_delete_attr_handler_elem); // we free the attribute handler element struct
    }

    //Decrement by one the handlers count of the attribute
    temp_attr->handlers_count -= 1;
    // We unregister the attribute associated with this handler
    unregister_extraction_attribute(mmt_handler, proto_id, attribute_id);
    //Finally we free the attribute
    mmt_free(safe_to_delete_attr_handler); // we free the attribute handler struct
    return 1;
}

int register_extraction_attribute_by_name(mmt_handler_t *mmt_handler, const char *protocol_name, const char *attribute_name) {
    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
        return 0;
    }
    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
        return 0;
    }
    return register_extraction_attribute(mmt_handler, proto_id, attribute_id);
}

int register_extraction_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    protocol_t * proto = get_protocol_struct_by_protocol_id(proto_id);
    if (proto != NULL) {
        struct attribute_internal_struct * extract_attribute = get_registered_attribute(mmt_handler, proto_id, field_id);

        if (!extract_attribute) {
            int s0 = sizeof (struct attribute_internal_struct);
            int s1 = get_attribute_data_type(proto_id, field_id);
            int s2 = get_data_size_by_data_type(s1);
            int size = s0 + s2;
            //fprintf(stderr, "      size=%d\n",size);
            extract_attribute = (struct attribute_internal_struct *) mmt_malloc(size);
            if (extract_attribute == NULL) {
                return 0;
            } else {
                // We set the attribute structure content to zeros
                memset(extract_attribute, 0, size);
                extract_attribute->proto_id = proto_id;
                extract_attribute->field_id = field_id;
                extract_attribute->scope = get_attribute_scope(proto_id, field_id);
                extract_attribute->data_type = get_attribute_data_type(proto_id, field_id);
                extract_attribute->data_len = get_data_size_by_proto_and_field_ids(proto_id, field_id);
                extract_attribute->position_in_packet = get_field_position_by_protocol_and_field_ids(proto_id, field_id);
                extract_attribute->memsize = size;
                extract_attribute->extraction_function = proto->get_attribute_extraction_function(proto_id, field_id);

                extract_attribute->data = &((char *) extract_attribute)[sizeof (struct attribute_internal_struct) ];

                struct attribute_internal_struct * registered_attr = mmt_handler->proto_registered_attributes[extract_attribute->proto_id];

                if (registered_attr == NULL) {
                    extract_attribute->next = mmt_handler->proto_registered_attributes[extract_attribute->proto_id];
                    mmt_handler->proto_registered_attributes[extract_attribute->proto_id] = extract_attribute;
                } else {
                    if (extract_attribute->field_id < registered_attr->field_id) {
                        //This is the new head list
                        extract_attribute->next = mmt_handler->proto_registered_attributes[extract_attribute->proto_id];
                        mmt_handler->proto_registered_attributes[extract_attribute->proto_id] = extract_attribute;
                    } else {
                        while (registered_attr->next != NULL) {
                            if (extract_attribute->field_id < registered_attr->next->field_id) {
                                break;
                            }
                            registered_attr = registered_attr->next;
                        }
                        //The attribute to register should be inserted between registered_attr and registered_attr->next
                        extract_attribute->next = registered_attr->next;
                        registered_attr->next = extract_attribute;
                    }
                }
            }

            //Finally we increment the registration count of this attribute.
            extract_attribute->registration_count++;
            return 1;
        }
    }
    return 0;
}

int register_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t attribute_id, attribute_handler_function handler_fct, void * handler_condition, void * user_args) {
    int retval = 0;

    if (is_registered_attribute_handler(mmt_handler, proto_id, attribute_id, handler_fct)) {
        return 0; //TODO: error codes should be added to differentiate between registration failed and handler already exists.
    }

    struct attribute_internal_struct * attr = get_registered_attribute(mmt_handler, proto_id, attribute_id);
    if (!attr) {
        retval = register_extraction_attribute(mmt_handler, proto_id, attribute_id);
        if (!retval) {
            // An error occurred.
            return 0;
        }
    }

    attr = get_registered_attribute(mmt_handler, proto_id, attribute_id);
    if (attr == NULL) {
        return 0; //TODO: This is getting paranoiac! we MUST never get here
    }

    attribute_handler_t * new_attribute_handler = (attribute_handler_t *) mmt_malloc(sizeof (attribute_handler_t));
    if (new_attribute_handler == NULL) {
        if (retval) unregister_extraction_attribute(mmt_handler, proto_id, attribute_id); // If we get here then the attribute
        // handler creation failed, and previously in this function
        // the attribute was registered (retval was initially set to 0)
        // We unregister the registered attribute to undo any action done in this function
        return 0;
    }

    new_attribute_handler->args = user_args;
    new_attribute_handler->handler_fct = handler_fct;
    new_attribute_handler->condition = handler_condition;
    new_attribute_handler->next = NULL;

    if (attr->attribute_handler == NULL) {
        new_attribute_handler->next = NULL;
        attr->attribute_handler = new_attribute_handler;

        if (!(attr->scope & SCOPE_EVENT)) {
            //We should add an attribute handler element as this is the first handler for the attribute
            attribute_handler_element_t * attr_handler_elem = (attribute_handler_element_t *) mmt_malloc(sizeof (attribute_handler_element_t));
            attr_handler_elem->attribute = attr;
            attr_handler_elem->next = NULL;
            if (mmt_handler->proto_registered_attribute_handlers[proto_id] == NULL) {
                attr_handler_elem->next = NULL;
                mmt_handler->proto_registered_attribute_handlers[proto_id] = attr_handler_elem;
            } else {
                attribute_handler_element_t * registered_attr_handler = mmt_handler->proto_registered_attribute_handlers[proto_id];
                if (attr_handler_elem->attribute->field_id < registered_attr_handler->attribute->field_id) {
                    //This is the new head list
                    attr_handler_elem->next = mmt_handler->proto_registered_attribute_handlers[proto_id];
                    mmt_handler->proto_registered_attribute_handlers[proto_id] = attr_handler_elem;
                } else {
                    while (registered_attr_handler->next != NULL) {
                        if (attr_handler_elem->attribute->field_id < registered_attr_handler->next->attribute->field_id) {
                            break;
                        }
                        registered_attr_handler = registered_attr_handler->next;
                    }
                    //The attribute to register should be inserted between registered_attr and registered_attr->next
                    attr_handler_elem->next = registered_attr_handler->next;
                    registered_attr_handler->next = attr_handler_elem;
                }
            }
        }
    } else {
        new_attribute_handler->next = attr->attribute_handler;
        attr->attribute_handler = new_attribute_handler;
    }

    // The attribute handler was successfully created, we increment the handlers count of the attribute
    attr->handlers_count++;
    return 1;
}

int register_attribute_handler_by_name(mmt_handler_t *mmt_handler, const char *protocol_name, const char *attribute_name, attribute_handler_function handler_fct, void *handler_condition, void *user_args) {
    uint32_t proto_id, attribute_id;
    proto_id = get_protocol_id_by_name(protocol_name);
    if (!proto_id) {
        return 0;
    }
    attribute_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, attribute_name);
    if (!attribute_id) {
        return 0;
    }
    return register_attribute_handler(mmt_handler, proto_id, attribute_id, handler_fct, handler_condition, user_args);
}

void free_registered_packet_handlers(mmt_handler_t *mmt_handler) {
    packet_handler_t * temp_phandler = mmt_handler->packet_handlers;
    packet_handler_t * safe_to_delete_handler = NULL;
    while (temp_phandler != NULL) {
        safe_to_delete_handler = temp_phandler;
        temp_phandler = temp_phandler->next;
        mmt_free(safe_to_delete_handler); // we free the packet handler struct
    }

    mmt_handler->packet_handlers = NULL;
}

int register_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id, generic_packet_handler_callback function, void *args) {
    if (mmt_handler == NULL) { //The mmt_handler is null
        return 0;
    }
    if (!is_registered_packet_handler(mmt_handler, packet_handler_id)) {
        packet_handler_t * new_packet_handler = (packet_handler_t *) mmt_malloc(sizeof (packet_handler_t));
        if (new_packet_handler == NULL) {
            return 0;
        } else {
            new_packet_handler->packet_handler_id = packet_handler_id;
            new_packet_handler->function = function;
            new_packet_handler->args = args;

            new_packet_handler->next = mmt_handler->packet_handlers;
            mmt_handler->packet_handlers = new_packet_handler;
        }
    }
    return 1;
}

int unregister_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id) {
    int retval = 1;
    packet_handler_t * temp_handler = mmt_handler->packet_handlers;
    packet_handler_t * safe_to_delete = NULL;
    while (temp_handler != NULL) {
        if (temp_handler->packet_handler_id == packet_handler_id) {
            if (safe_to_delete == NULL) { //The handler to delete is the first in the list
                mmt_handler->packet_handlers = temp_handler->next;
                safe_to_delete = temp_handler;
                mmt_free(safe_to_delete); // we free the packet handler struct
                return retval;
            } else {
                safe_to_delete->next = temp_handler->next; // We relink the elements
                safe_to_delete = temp_handler;
                mmt_free(safe_to_delete); // we free the packet handler struct
                return retval;
            }
        }
        safe_to_delete = temp_handler;
        temp_handler = temp_handler->next;
    }
    return retval;
}

void setDataLinkType(mmt_handler_t *mmt_handler, int dltype) {
    protocol_stack_t * temp_stack = get_protocol_stack_from_map(dltype);
    if (temp_stack == NULL) {
        mmt_handler->link_layer_stack = &dummy_stack;
    } else {
        mmt_handler->link_layer_stack = temp_stack;
    }
}

void debug_extracted_attributes_printout_handler(const ipacket_t *ipacket, void *args) {
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    unsigned i = 0;
    int quiet = args ? *((int*)args) : 0;
    struct attribute_internal_struct * tmp_attribute;
    for (; i < ipacket->proto_hierarchy->len; i++) {
        if (is_registered_protocol(ipacket->proto_hierarchy->proto_path[i])) {
            tmp_attribute = mmt_handler->proto_registered_attributes[ipacket->proto_hierarchy->proto_path[i]];
        }
        while (tmp_attribute != NULL) {
            void * data = get_attribute_extracted_data_at_index(ipacket, tmp_attribute->proto_id, tmp_attribute->field_id, i);
            if (!quiet && data) {
                print_attributes_list(tmp_attribute);
            }

            tmp_attribute = tmp_attribute->next;
        }

    }
}

int register_attributes(mmt_handler_t *mmt_handler, struct attribute_description_struct * attributes_list) {
    int retval = 1;
    struct attribute_description_struct * temp_attr = attributes_list;
    while (temp_attr != NULL) {
        retval = retval * register_extraction_attribute(mmt_handler, temp_attr->proto_id, temp_attr->field_id);
        temp_attr = temp_attr->next;
    }
    return retval;
}

void set_session_timeout_delay(mmt_session_t * session, uint32_t timeout_delay) {
    session->session_timeout_delay = timeout_delay;
}

void set_ipacket_session_status(ipacket_t * ipacket, uint16_t status) {
    if (ipacket->session != NULL) {
        ipacket->session->status = (uint8_t) status;
    }
}

int proto_session_management(ipacket_t * ipacket, protocol_instance_t * configured_protocol, unsigned index) {
    int classify_status = ipacket->proto_classif_status->proto_path[index];
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    int is_new_session = 0;

    //TODO: addition of proper handling of embedded sessions.
    mmt_session_t * session = ipacket->session;
    if (configured_protocol->protocol->has_session) { // Sessionize packet only if such a function exists!
        session = (mmt_session_t *) ((generic_sessionizer_function) configured_protocol->protocol->sessionize)(configured_protocol, ipacket, index, & is_new_session);
        /*
         * When a protocol has a session context it is not always necessary that the packet being processed
         * will be put into a corresponding session. This is the case when IP fragmentation is encountered.
         * Therefore, always test the return value of the sessionizer function!
         * There is a valid reason to be paranoiac
         */
        if (session != NULL) { // Check if a session has been detected. This is
            if (is_new_session) {
                is_new_session = NEW_SESSION; //Enforce the use of "NEW_SESSION" value
                // init session data
                session->session_id = mmt_handler->sessions_count;
                session->packet_count = 0;
                session->data_volume = 0;
                session->status = NonClassified;
                session->protocol_container_context = configured_protocol;
                session->session_protocol_index = index;
                mmt_handler->sessions_count += 1;
                mmt_handler->active_sessions_count += 1;

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
                session->session_timeout_delay = configured_protocol->protocol->session_timeout_delay;
                session->session_timeout_milestone = session->session_timeout_delay + ipacket->p_hdr->ts.tv_sec;
                if (insert_session_timeout_milestone(mmt_handler, session->session_timeout_milestone, session) == 0) {
                    //If we get here, then there is an out of memory problem! we should deal with
                    process_outofmemory_force_sessions_timeout(ipacket->mmt_handler, ipacket);
                    insert_session_timeout_milestone(mmt_handler, session->session_timeout_milestone, session);
                }

                if (ipacket->session == NULL) {
                    //No session encapsulation; parent is NULL
                    session->parent_session = NULL; //TODO: parent should be set here. If the ipacket is alreay associated to a session, then it is the parent of this one!
                    ipacket->session = session;
                } else {
                    //Embedded session; set its parent
                    session->parent_session = ipacket->session;
                    // Share the session data from the parent session up to the index of the new detected encapsulated session
                    unsigned i;
                    for (i = 0; i < index; i++) {
                        session->session_data[i] = session->parent_session->session_data[i];
                    }
                }

                //Initialize its session data if such initialization function exists
                if (configured_protocol->protocol->session_data_init != NULL) {
                    ((generic_session_data_initialization_function) configured_protocol->protocol->session_data_init)(ipacket, index);
                }
                //Mark this protocol as done with the classification process
                ipacket->proto_classif_status->proto_path[index] = PROTO_CLASSIFICATION_DONE;
            } else {
                // session timeout update
                if (ipacket->p_hdr->ts.tv_sec > session->s_last_activity_time.tv_sec) {// No need to update the timeout if we are still in the same second
                    //if(!session->force_timeout) { //Sessions with force timeout should not be updated! they need to timeout :)
                    if (update_session_timeout_milestone(mmt_handler, session->session_timeout_delay + ipacket->p_hdr->ts.tv_sec,
                            session->session_timeout_milestone, session) == 0) {
                        process_outofmemory_force_sessions_timeout(ipacket->mmt_handler, ipacket);
                        insert_session_timeout_milestone(mmt_handler, session->session_timeout_delay + ipacket->p_hdr->ts.tv_sec, session);
                    }
                    session->session_timeout_milestone = session->session_timeout_delay + ipacket->p_hdr->ts.tv_sec;
                    //}
                }
            }

            //Now update the packet structure to point to the flow and the protocol hierarchy info
            ipacket->proto_hierarchy = &session->proto_path;
            ipacket->proto_headers_offset = &session->proto_headers_offset;
            ipacket->proto_classif_status = &session->proto_classif_status;
            ipacket->session = session;

            //update the session basic statistics
            session->packet_count++;
            session->data_volume += ipacket->p_hdr->len;

            session->s_last_activity_time.tv_sec = ipacket->p_hdr->ts.tv_sec;
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
        if ((ipacket->session != NULL) && ((classify_status == PROTO_CLASSIFICATION_DETECTION) || (classify_status == PROTO_RECLASSIFICATION))) {
            //Initialize its session data if such initialization function exists
            if (configured_protocol->protocol->session_data_init != NULL) {
                ((generic_session_data_initialization_function) configured_protocol->protocol->session_data_init)(ipacket, index);
            }
            is_new_session = NEW_PROTO_IN_SESSION; //This is not a new session, rather a new protocol in the session
        }
        //Mark this protocol as done with the classification process
        ipacket->proto_classif_status->proto_path[index] = PROTO_CLASSIFICATION_DONE;
    }
    return is_new_session;
}

int set_classified_proto(ipacket_t * ipacket, unsigned index, classified_proto_t classified_proto) {
    int retval = 0;
    if (classified_proto.proto_id == -1 || index >= PROTO_PATH_SIZE) return retval;

    if (index + 1 > ipacket->proto_hierarchy->len) {
        //Increment the length of the protocol path and protocol offsets
        ipacket->proto_hierarchy->len += 1;
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

    set_ipacket_session_status(ipacket, classified_proto.status);
    return retval;
}

/**
 * Creates a protocol statistics instance for the given protocol and the given parent stats
 * @param proto pointer to the protocol instance
 * @param parent_proto_stats pointer to the parent protocol stats
 * @return pointer to the created protocol statistics on success, NULL on failure
 */
proto_statistics_internal_t * create_protocol_stats_instance(protocol_instance_t * proto, proto_statistics_internal_t * parent_proto_stats) {
    proto_statistics_internal_t * proto_stats = (proto_statistics_internal_t *) mmt_malloc(sizeof (proto_statistics_internal_t));
    if (!proto_stats) {
        return NULL;
    } else {
        memset(proto_stats, '\0', sizeof (proto_statistics_internal_t));
        proto_stats->parent_proto_stats = parent_proto_stats;
        proto_stats->proto = proto;
        proto_stats->next = proto->proto_stats;
        proto->proto_stats = proto_stats;
        proto_stats->encap_proto_stats = init_int_map_space(attribute_ids_comparison_fct);
        if (parent_proto_stats) {
            insert_int_key_value(parent_proto_stats->encap_proto_stats, proto->protocol->proto_id, (void *) proto_stats);
        }
    }
    return proto_stats;
}

/**
 * Returns a pointer to the protocol statistics of the child protocol identified by \child_proto_id
 * @param proto_stats pointer to the protocol stats instance
 * @param child_proto_id identifier of the child protocol
 * @return pointer to the child protocol statistics if it exists, NULL otherwise.
 */
proto_statistics_internal_t * get_child_protocol_stats(proto_statistics_internal_t * proto_stats, uint32_t child_proto_id) {
    return (proto_statistics_internal_t *) find_int_key_value(proto_stats->encap_proto_stats, child_proto_id);
}

/**
 * Returns a pointer to the protocol statistics in the parent protocol encapsulated stats
 * @param proto pointer to the protocol instance
 * @param parent_proto_stats pointer to the parent protocol stats instance
 * @return pointer to the protocol statistics. If it does not exist, it will be created.
 */
proto_statistics_internal_t * get_protocol_stats_from_parent(protocol_instance_t * proto, proto_statistics_internal_t * parent_proto_stats) {
    proto_statistics_internal_t * proto_stats;
    if (parent_proto_stats == NULL /* Always the case for META protocol */) {
        proto_stats = proto->proto_stats;
        if (proto_stats == NULL) {
            proto_stats = create_protocol_stats_instance(proto, parent_proto_stats);
        }
    } else {
        proto_stats = get_child_protocol_stats(parent_proto_stats, proto->protocol->proto_id);
        if (proto_stats == NULL) {
            proto_stats = create_protocol_stats_instance(proto, parent_proto_stats);
        }
    }
    return proto_stats;
}

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
void print_protocol_stats(FILE * f, protocol_instance_t * proto) {
    proto_statistics_internal_t * proto_stats = proto->proto_stats;
    while (proto_stats) {
        fprintf(f, "Proto %u: \nnb\tpackets %"PRIu64" --- byte count %"PRIu64" --- sessions count %"PRIu64" --- timeout sessions count %"PRIu64"\n",
                proto_stats->proto->protocol->proto_id, proto_stats->packets_count, proto_stats->data_volume, proto_stats->sessions_count, proto_stats->timedout_sessions_count);
        proto_stats = proto_stats->next;
    }
}

proto_statistics_t * get_protocol_stats(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if(mmt_handler == NULL) return NULL;
    if(!is_valid_protocol_id(proto_id)) return NULL;
    return (proto_statistics_t *) mmt_handler->configured_protocols[proto_id].proto_stats;
}

void get_protocol_stats_path(mmt_handler_t *mmt_handler, proto_statistics_t * stats, proto_hierarchy_t * proto_hierarchy) {
    if ((mmt_handler == NULL) || (stats == NULL) || (proto_hierarchy == NULL)) {
        proto_hierarchy->len = 0;
        return;
    }
    proto_hierarchy_t temp_path = {0};
    proto_statistics_internal_t * temp_stats = (proto_statistics_internal_t *) stats;
    while(temp_stats) {
        temp_path.proto_path[temp_path.len] = temp_stats->proto->protocol->proto_id;
        temp_path.len ++;
        temp_stats = temp_stats->parent_proto_stats;
    }
    proto_hierarchy->len = temp_path.len;
    int i;
    for(i = 0; i < temp_path.len; i++) {
        proto_hierarchy->proto_path[temp_path.len - (i + 1)] = temp_path.proto_path[i];
    }
}

void update_proto_stats_on_session_timeout(mmt_session_t * timed_out_session, proto_statistics_internal_t * parent_proto_stats) {
    if (!isProtocolStatisticsEnabled(timed_out_session->mmt_handler)) {
        return;
    }
    proto_statistics_internal_t * proto_stats = parent_proto_stats;
    int i = 0;
    for (; i < timed_out_session->proto_path.len; i++) {
        proto_stats = get_protocol_stats_from_parent(&(timed_out_session->mmt_handler)->configured_protocols[timed_out_session->proto_path.proto_path[i]],
                proto_stats);
        if (i >= timed_out_session->session_protocol_index) {
            proto_stats->timedout_sessions_count += 1;
            proto_stats->touched = 1;
        }
    }
}

void reset_statistics(proto_statistics_t * stats) {
    stats->touched = 0;
    stats->data_volume = 0;
    stats->payload_volume = 0;
    stats->packets_count = 0;
    stats->packets_count_direction[0] = 0;
    stats->packets_count_direction[1] = 0;
    stats->data_volume_direction[0] = 0;
    stats->data_volume_direction[1] = 0;
    stats->payload_volume_direction[0] = 0;
    stats->payload_volume_direction[1] = 0;
    //stats->sessions_count = 0;
    //stats->timedout_sessions_count = 0;
}

void internal_protocol_children_stats_iterator(void * key, void * value, void * args) {
    proto_statistics_t * child_stats = (proto_statistics_t *) value;
    proto_statistics_t * children_stats = (proto_statistics_t *) args;
    children_stats->data_volume += child_stats->data_volume;
    children_stats->packets_count += child_stats->packets_count;
    children_stats->payload_volume += child_stats->payload_volume;
    children_stats->sessions_count += child_stats->sessions_count;
    children_stats->timedout_sessions_count += child_stats->timedout_sessions_count;
}

void get_children_stats(proto_statistics_t * parent_stats, proto_statistics_t * children_stats) {
    proto_statistics_t temp_stats = {0};
    int_mapspace_iteration_callback(((proto_statistics_internal_t *) parent_stats)->encap_proto_stats,
        internal_protocol_children_stats_iterator, (void *) (& temp_stats));
    children_stats->data_volume = temp_stats.data_volume;
    children_stats->packets_count = temp_stats.packets_count;
    children_stats->payload_volume = temp_stats.payload_volume;
    children_stats->sessions_count = temp_stats.sessions_count;
    children_stats->timedout_sessions_count = temp_stats.timedout_sessions_count;
}

void reset_proto_stats(protocol_instance_t * proto) {
    proto_statistics_internal_t * proto_stats = proto->proto_stats;
    while (proto_stats) {
        proto_stats->data_volume = 0;
        proto_stats->payload_volume = 0;
        proto_stats->packets_count = 0;
        proto_stats->sessions_count = 0;
        proto_stats->timedout_sessions_count = 0;
        proto_stats = proto_stats->next;
    }
}

proto_statistics_internal_t * update_proto_stats_on_packet(ipacket_t * ipacket, protocol_instance_t * configured_protocol, proto_statistics_internal_t * parent_stats, uint32_t proto_offset, int new_session) {
    if (!isProtocolStatisticsEnabled(ipacket->mmt_handler)) {
        return NULL;
    }

    /* TODO: Throughout metrics should be replaced by periodic handlers! */
    proto_statistics_internal_t * proto_stats = get_protocol_stats_from_parent(configured_protocol, parent_stats);

    if (proto_stats) {
        proto_stats->touched = 1;
        proto_stats->data_volume += ipacket->p_hdr->len;
        proto_stats->payload_volume += ipacket->p_hdr->len - proto_offset;
        proto_stats->packets_count += 1;
        if (new_session) {
            proto_stats->sessions_count += 1;
        }
    }
    return proto_stats;
}

void proto_packet_classify_next(ipacket_t * ipacket, protocol_instance_t * configured_protocol, unsigned index) {
    //TODO: review the exit codes; this depends on the return values of the sub-classification routines
    //TODO: why don't to enforce here a threshold on the classification?
    int classif_status = 1; //TODO: replace with a definition: CONTINUE, SKIP

    //Verify that classification is not disabled for this protocol
    if (!configured_protocol->protocol->classify_next.status) {
        return;
    }

    //Pre-classification
    if (configured_protocol->protocol->classify_next.pre_classify) {
        classif_status = configured_protocol->protocol->classify_next.pre_classify(ipacket, index);
    }
    //Classify next protocol
    if (configured_protocol->protocol->classify_next.classify_protos && classif_status) { // Classify next proto only when such a function exists!
        mmt_classify_me_t * temp = configured_protocol->protocol->classify_next.classify_protos;
        for (; temp != NULL; temp = temp->next) {
            temp->classify_me(ipacket, index); //TODO: check the return value and make the corresponding action accordingly!!!
        }

        //Post-classification! Post classification is only accessible if there is a classification function
        //And if the preclassification returned non zero which means: proceed with the classification routines.
        if (configured_protocol->protocol->classify_next.post_classify) {
            configured_protocol->protocol->classify_next.post_classify(ipacket, index);
        }
    }
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

int proto_packet_analyze(ipacket_t * ipacket, protocol_instance_t * configured_protocol, unsigned index) {
    //TODO: review the exit codes; this depends on the return values of the sub-analysis routines
    int retval = MMT_CONTINUE;
    //Verify that analysis is not disabled for this protocol
    if (!configured_protocol->protocol->data_analyser.status) {
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
        if (configured_protocol->protocol->classify_next.post_classify) {
            configured_protocol->protocol->classify_next.post_classify(ipacket, index);
        }
    }

    return retval;
}

/**
 * @brief Process packet_handler function 
 * 
 * @param ipacket Packet to process
 */
void process_packet_handler(ipacket_t *ipacket){
    packet_handler_t * temp_packet_handler = ipacket->mmt_handler->packet_handlers;            
    while (temp_packet_handler != NULL) {
        temp_packet_handler->function(ipacket, temp_packet_handler->args);
        temp_packet_handler = temp_packet_handler->next;
    }
    
    process_timedout_sessions(ipacket->mmt_handler, ipacket->p_hdr->ts.tv_sec);

    if ((ipacket->mmt_handler->link_layer_stack->stack_id == DLT_EN10MB)
            && (ipacket->data != ipacket->original_data)) {
        // data was dynamically allocated during the reassembly process:
        //   . free dynamically allocated ipacket->data
        //   . reset ipacket->data to its original value
        mmt_free((void *) ipacket->data);
        ipacket->data = ipacket->original_data;
    }

    if(ipacket->internal_packet){
        mmt_free(ipacket->internal_packet);
    }
    mmt_free((void *)ipacket->data);
    mmt_free(ipacket); 
}

int proto_packet_process(ipacket_t * ipacket, proto_statistics_internal_t * parent_stats, unsigned index) {
    protocol_instance_t * configured_protocol = &(ipacket->mmt_handler)
            ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
    int target = MMT_CONTINUE;
    int proto_offset = get_packet_offset_at_index(ipacket, index);
    //Make sure this protocol has data to analyse
    if (proto_offset >= ipacket->p_hdr->len || proto_offset >= ipacket->p_hdr->caplen) {
        //This is not an ubnormal behaviour, this can simply be an ACK packet in an HTTP session
        process_packet_handler(ipacket);
        return target;
    }
    //The protocol is registered: First we check if it requires to maintain a session
    int is_new_session = proto_session_management(ipacket, configured_protocol, index);
    if (is_new_session == NEW_SESSION) {
        fire_attribute_event(ipacket, configured_protocol->protocol->proto_id, PROTO_SESSION, index, (void *) ipacket->session);
    }
    //Update the protocol statistics
    parent_stats = update_proto_stats_on_packet(ipacket, configured_protocol, parent_stats, proto_offset, is_new_session);
    //Update next_process
    
    //Analyze packet data
    target = proto_packet_analyze(ipacket, configured_protocol, index);

    //Proceed with the extraction and the handlers notification for this protocol
    //if the target action is CONTINUE or SKIP (skip means continue with this proto but no further)
    if (target != MMT_DROP) {
        //Attributes extraction
        //generic_data_extraction(index, ipacket);

        //process attribute handlers
        proto_process_attribute_handlers(ipacket, index);
    }

    //Update next
    ipacket->extra->parent_stats = parent_stats;
    ipacket->extra->index = index+1;
    ipacket->extra->next_process = (next_process_function)proto_packet_process;
    

    //Proceed with the classification sub-process only if the target action is set to CONTINUE
    if (target == MMT_CONTINUE) {
        /* Try to classify the encapsulated data */
        proto_packet_classify_next(ipacket, configured_protocol, index);
        // send the packet to the next encapsulated protocol if an encapsulated protocol exists in the path
        if (ipacket->proto_hierarchy->len > (index + 1)) {
            if (is_registered_protocol(ipacket->proto_hierarchy->proto_path[index + 1])) {
                /* process the packet by the next encapsulated protocol */
                if(ipacket->extra->status == MMT_SKIP){
                    return target;
                }else{
                    return proto_packet_process(ipacket, parent_stats, index + 1);
                }
            }
        }
        process_packet_handler(ipacket);
    }
    return target;
} 



int packet_process(mmt_handler_t *mmt, struct pkthdr *header, const u_char * packet) {
    
    //Testing packet header and data integrity
    if (!header || !packet /* The header and packet must be not null */
            || !(header->caplen > 0) || !(header->len > 0) || !(header->len >= header->caplen) /* Packet data len must not be zero.
                                                                                               * Real data size MUST be greater or equal
                                                                                               * to the captured data len */
            ) {
        return 0;
    }

#ifdef CFG_OS_MAX_PACKET
    if( mmt->packet_count >= CFG_OS_MAX_PACKET ) {
        (void)fprintf( stderr, "This demo version of MMT is limited to %lu packets.\n", (unsigned long)CFG_OS_MAX_PACKET );
        return 0;
    }

    ++mmt->packet_count;
#endif /*CFG_OS_MAX_PACKET*/

    unsigned index = 0;

    ipacket_t *ipacket = prepare_ipacket(mmt, header, packet);

    proto_packet_process(ipacket, NULL, index);

    return 1;
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

    tmp_attr_ref = mmt_handler->proto_registered_attributes[proto_id]; //This is safe as we are sure the protocol is registered (check done in "packet_extract")

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

generic_attribute_extraction_function getExtractionFunctionByProtocolAndFieldIds(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering getExtractionFunctionByProtocolAndFieldIds proto %u --- field %u\n", proto_id, field_id );
#endif
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_extraction_function(proto_id, field_id);
    } else {
        return silent_extraction;
    }
}

int get_data_size_by_proto_and_field_ids(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering getExtractionDataSizeByProtocolAndFieldIds proto %u --- field %u\n", proto_id, field_id );
#endif
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_data_length_by_id(proto_id, field_id);
    }
    return 0;
}

int is_protocol_attribute(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering isProtocolAttribute proto %u --- field %u\n", proto_id, field_id );
#endif
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->is_valid_attribute(proto_id, field_id);
    }
    return false;
}

int get_field_position_by_protocol_and_field_ids(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering getFieldPositionByProtocolAndFieldIds proto %u --- field %u\n", proto_id, field_id );
#endif
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_position(proto_id, field_id);
    }
    return POSITION_NOT_KNOWN;
}

const char * get_attribute_name_by_protocol_and_attribute_ids(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering tips_proto_attr_find_by_id proto %u --- field %u\n", proto_id, field_id );
#endif
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_name_by_id(proto_id, field_id);
    }
    return NULL;
}

const char * get_protocol_name_by_id(uint32_t proto_id) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering tips_proto_find_by_id proto %u\n", proto_id );
#endif
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->protocol_name;
    }

    return NULL;
}

uint32_t get_protocol_id_by_name(const char * protocolalias) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering tips_proto_find_by_name proto %s\n", protocolalias );
#endif
    int i = 0;
    for (; i < PROTO_MAX_IDENTIFIER; i++) {
        if (is_registered_protocol(i)) {
            protocol_t * temp = configured_protocols[i];
            if (mmt_strcasecmp(temp->protocol_name, protocolalias) == 0)
                return temp->proto_id;
        }
    }
    return 0;
}

uint32_t get_attribute_id_by_protocol_and_attribute_names(const char *protocolalias, const char *fieldalias) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering tips_proto_attr_find_by_name proto %s --- field %s\n", protocolalias, fieldalias );
#endif
    uint32_t proto_id = get_protocol_id_by_name(protocolalias);
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_id_by_name(proto_id, fieldalias);
    }
    return 0;
}

uint32_t get_attribute_id_by_protocol_id_and_attribute_name(uint32_t proto_id, const char *field_name) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering tips_proto_attr_find_by_id_name proto %u --- field %s\n", proto_id, field_name );
#endif
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_id_by_name(proto_id, field_name);
    }
    return 0;
}

long get_attribute_data_type(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering tips_attr_get_data_type proto %u --- field %u\n", proto_id, field_id );
#endif
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_data_type_by_id(proto_id, field_id);
    }
    return MMT_UNDEFINED_TYPE;
}

int get_attribute_scope(uint32_t proto_id, uint32_t attribute_id) {
#ifdef DEBUG
    (void)fprintf( stderr, "Entering get_attribute_scope proto %u --- field %u\n", proto_id, attribute_id );
#endif
    if (is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_scope(proto_id, attribute_id);
    }
    return 0;
}

uint32_t get_classification_threshold() {
    return CFG_CLASSIFICATION_THRESHOLD;
}


//  - - - - - - - - - - - - - - - - - -
//  P R O T O C O L   A C C E S S O R S
//  - - - - - - - - - - - - - - - - - -


int get_proto_attribute_id( protocol_t *proto, uint32_t proto_id, const char *attr_name )
{ return proto->get_attribute_id_by_name( proto_id, attr_name ); }

const char * get_proto_attribute_name( protocol_t *proto, uint32_t proto_id, uint32_t attr_id )
{ return proto->get_attribute_name_by_id( proto_id, attr_id ); }

int get_proto_attribute_type( protocol_t *proto, uint32_t proto_id, uint32_t attr_id )
{ return proto->get_attribute_data_type_by_id( proto_id, attr_id ); }

int get_proto_attribute_position( protocol_t *proto, uint32_t proto_id, uint32_t attr_id)
{ return proto->get_attribute_position( proto_id, attr_id ); }

int get_proto_attribute_length( protocol_t *proto, uint32_t proto_id, uint32_t attr_id)
{ return proto->get_attribute_data_length_by_id( proto_id, attr_id ); }

int get_proto_attribute_scope( protocol_t *proto, uint32_t proto_id, uint32_t attr_id)
{ return proto->get_attribute_scope( proto_id, attr_id ); }

int is_valid_proto_attribute( protocol_t *proto, uint32_t proto_id, uint32_t attr_id)
{ return proto->is_valid_attribute( proto_id, attr_id ); }

//  - - - - - - - - - - - - - - - - - -
//  A T T R I B U T E   A C C E S S O R S
//  - - - - - - - - - - - - - - - - - -

uint32_t get_attr_protocol_id( attribute_t * attr)
{ return attr->proto_id; }

uint32_t get_attr_id( attribute_t * attr)
{ return attr->field_id; }

int get_attr_protocol_index( attribute_t * attr)
{ return attr->protocol_index; }

int get_attr_status( attribute_t * attr)
{ return attr->status; }

int get_attr_data_type( attribute_t * attr)
{ return attr->data_type; }

int get_attr_data_len( attribute_t * attr)
{ return attr->data_len; }

int get_attr_offset( attribute_t * attr)
{ return attr->position_in_packet; }

int get_attr_scope( attribute_t * attr)
{ return attr->scope; }

void * get_attr_data( attribute_t * attr)
{ return attr->data; }

//  - - - - - - - - - - - - - - - - - - - - -
//  A T T R I B U T E   F O R M A T T I N G
//  - - - - - - - - - - - - - - - - - - - - -
int get_type_formatted_len(int type_id);

#define MMT_FORMATTING_LENGTH_ERR -1

#define MMT_U8_STRLEN           5
#define MMT_U16_STRLEN          7
#define MMT_U32_STRLEN          12
#define MMT_U64_STRLEN          22
#define MMT_CHAR_STRLEN         2
#define MMT_POINTER_STRLEN      22
#define MMT_MAC_STRLEN          20
#define MMT_IP_STRLEN           16
#define MMT_IP6_STRLEN          46
#define MMT_PATH_STRLEN         512
#define MMT_TIMEVAL_STRLEN      24
#define MMT_BINARY_STRLEN       BINARY_64DATA_LEN*2 + 1
#define MMT_BINARYVAR_STRLEN    BINARY_1024DATA_LEN*2 + 1
#define MMT_STRING_STRLEN       BINARY_64DATA_LEN
#define MMT_STRINGLONG_STRLEN   STRING_DATA_TYPE_LEN

int mmt_char_sprintf(char * buff, size_t len, attribute_internal_t * attr) {
    if (len < MMT_CHAR_STRLEN) return -1;
    return snprintf(buff, len, "%c", *(char *) attr->data);
}

int mmt_uint8_sprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_U8_STRLEN) return -1;
    return snprintf(buff, len, "%hu", (uint16_t) *(uint8_t *) attr->data);
}

int mmt_uint16_sprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_U16_STRLEN) return -1;
    return snprintf(buff, len, "%hu", *(uint16_t *) attr->data);
}

int mmt_uint32_sprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_U32_STRLEN) return -1;
    return snprintf(buff, len, "%u", *(uint32_t *) attr->data);
}

int mmt_uint64_sprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_U64_STRLEN) return -1;
    return snprintf(buff, len, "%"PRIu64, *(uint64_t *) attr->data);
}

int mmt_pointer_sprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_POINTER_STRLEN) return -1;
    return snprintf(buff, len, "%p", (void *) attr->data);
}

int mmt_mac_sprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_MAC_STRLEN) return -1;
    const uint8_t *ea = attr->data;
    return snprintf( buff, MMT_MAC_STRLEN, "%02x:%02x:%02x:%02x:%02x:%02x", ea[0], ea[1], ea[2], ea[3], ea[4], ea[5] );
}

int mmt_ip_sprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_IP_STRLEN) return -1;
    return mmt_inet_ntop(AF_INET, (void *) attr->data, buff, INET_ADDRSTRLEN) == NULL ? -1 : strlen(buff);
}

int mmt_ip6_sprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_IP6_STRLEN) return -1;
    return mmt_inet_ntop(AF_INET6, (void *) attr->data, buff, INET6_ADDRSTRLEN) == NULL ? -1 : strlen(buff);
}

int mmt_path_sprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < 2) return -1; //not less than 1 character (".")
    //Print as much as it can into buff. If the len is less than the expected strlen, then the
    //return value will be higher than the given length and the user would be able to detect
    //the truncation.
    int offset = 0;
    proto_hierarchy_t * p = (proto_hierarchy_t *) attr->data;
    if (p->len < 1) {
        offset += snprintf(buff, len, ".");
    } else {
        int index = 1;
        offset += snprintf(buff, len - offset, "%u", p->proto_path[index]);
        index++;
        for (; (index < p->len) && (index < 16) && offset < len; index++) {
            offset += snprintf(&buff[offset], len - offset, ".%u", p->proto_path[index]);
        }
    }
    return offset;
}

int mmt_timeval_sprintf(char * buff, int len, attribute_internal_t * attr) {
    //Print as much as it can into buff. If the len is less than the expected strlen, then the
    //return value will be higher than the given length and the user would be able to detect
    //the truncation.
    return snprintf(buff, len, "%lu.%lu", ((struct timeval *) attr->data)->tv_sec, ((struct timeval *) attr->data)->tv_usec);
}

int mmt_binary_sprintf(char * buff, int len, attribute_internal_t * attr) {
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    if (len < (b->len * 2 + 1)) return -1;
    int index = 0, offset = 0;
    for (; index < (b->len) && offset < len; index++) {
        offset += snprintf((char *) &buff[offset], len - offset, "%02x", b->data[index]);
    }
    return offset;
}

int mmt_string_sprintf(char * buff, int len, attribute_internal_t * attr) {
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    return snprintf(buff, len, "%s", (char *) &b->data);
}

int mmt_string_pointer_sprintf(char * buff, int len, attribute_internal_t * attr) {
    return snprintf(buff, len, "%s", (char *) attr->data);
}

int mmt_stats_sprintf(char * buff, int len, attribute_internal_t * attr) {
    return snprintf(buff, len, "%s", "TODO");
}

int mmt_attr_sprintf(char * buff, int len, attribute_t * a) {
    attribute_internal_t * attr = (attribute_internal_t *) a;
    switch(attr->data_type) {
        case MMT_U8_DATA:
            return mmt_uint8_sprintf(buff, len, attr);
        case MMT_U16_DATA:
            return mmt_uint16_sprintf(buff, len, attr);
        case MMT_U32_DATA:
            return mmt_uint32_sprintf(buff, len, attr);
        case MMT_U64_DATA:
            return mmt_uint64_sprintf(buff, len, attr);
        case MMT_DATA_CHAR:
            return mmt_char_sprintf(buff, len, attr);
        case MMT_DATA_POINTER:
            return mmt_pointer_sprintf(buff, len, attr);
        case MMT_DATA_MAC_ADDR:
            return mmt_mac_sprintf(buff, len, attr);
        case MMT_DATA_IP_ADDR:
            return mmt_ip_sprintf(buff, len, attr);
        case MMT_DATA_IP6_ADDR:
            return mmt_ip6_sprintf(buff, len, attr);
        case MMT_DATA_PATH:
            return mmt_path_sprintf(buff, len, attr);
        case MMT_DATA_TIMEVAL:
            return mmt_timeval_sprintf(buff, len, attr);
        case MMT_BINARY_DATA:
            return mmt_binary_sprintf(buff, len, attr);
        case MMT_BINARY_VAR_DATA:
            return mmt_binary_sprintf(buff, len, attr);
        case MMT_STRING_DATA:
            return mmt_string_sprintf(buff, len, attr);
        case MMT_STRING_LONG_DATA:
            return mmt_string_sprintf(buff, len, attr);
        case MMT_STRING_DATA_POINTER:
            return mmt_string_pointer_sprintf(buff, len, attr);
        case MMT_STATS:
            return mmt_stats_sprintf(buff, len, attr);
        default:
            return mmt_stats_sprintf(buff, len, attr); //TODO
    }
}

int mmt_char_fprintf(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "%c", *(char *) attr->data);
}

int mmt_uint8_fprintf(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "%hu", (uint16_t) *(uint8_t *) attr->data);
}

int mmt_uint16_fprintf(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "%hu", *(uint16_t *) attr->data);
}

int mmt_uint32_fprintf(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "%u", *(uint32_t *) attr->data);
}

int mmt_uint64_fprintf(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "%"PRIu64, *(uint64_t *) attr->data);
}

int mmt_pointer_fprintf(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "%p", (void *) attr->data);
}

int mmt_mac_fprintf(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_MAC_STRLEN];
    if (mmt_mac_sprintf(buff, MMT_MAC_STRLEN, attr)) {
        return fprintf(f, "%s", buff);
    }
    return -1;
}

int mmt_ip_fprintf(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_IP_STRLEN];
    if (mmt_ip_sprintf(buff, MMT_IP_STRLEN, attr)) {
        return fprintf(f, "%s", buff);
    }
    return -1;
}

int mmt_ip6_fprintf(FILE * f, attribute_internal_t * attr){
    char buff[MMT_IP6_STRLEN];
    if (mmt_ip6_sprintf(buff, MMT_IP6_STRLEN, attr)) {
        return fprintf(f, "%s", buff);
    }
    return -1;
}

int mmt_path_fprintf(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_PATH_STRLEN];
    if (mmt_path_sprintf(buff, MMT_PATH_STRLEN, attr)) {
        return fprintf(f, "%s", buff);
    }
    return -1;
}
int mmt_timeval_fprintf(FILE * f, attribute_internal_t * attr){
    return fprintf(f, "%lu.%lu", ((struct timeval *) attr->data)->tv_sec, ((struct timeval *) attr->data)->tv_usec);
}
int mmt_binary_fprintf(FILE * f, attribute_internal_t * attr){
    char buff[MMT_BINARYVAR_STRLEN];
    if (mmt_binary_sprintf(buff, MMT_BINARY_STRLEN, attr)) {
        return fprintf(f, "%s", buff);
    }
    return -1;
}
int mmt_string_fprintf(FILE * f, attribute_internal_t * attr){
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    return fprintf(f, "%s", (char *) &b->data);
}
int mmt_string_pointer_fprintf(FILE * f, attribute_internal_t * attr){
    return fprintf(f, "%s", (char *) attr->data);
}

int mmt_stats_fprintf(FILE *f, attribute_internal_t * attr) {
    return fprintf(f, "%s", "TODO");
}

int mmt_attr_fprintf(FILE * f, attribute_t * a) {
    attribute_internal_t * attr = (attribute_internal_t *) a;
    switch(attr->data_type) {
        case MMT_U8_DATA:
            return mmt_uint8_fprintf(f, attr);
        case MMT_U16_DATA:
            return mmt_uint16_fprintf(f, attr);
        case MMT_U32_DATA:
            return mmt_uint32_fprintf(f, attr);
        case MMT_U64_DATA:
            return mmt_uint64_fprintf(f, attr);
        case MMT_DATA_CHAR:
            return mmt_char_fprintf(f, attr);
        case MMT_DATA_POINTER:
            return mmt_pointer_fprintf(f, attr);
        case MMT_DATA_MAC_ADDR:
            return mmt_mac_fprintf(f, attr);
        case MMT_DATA_IP_ADDR:
            return mmt_ip_fprintf(f, attr);
        case MMT_DATA_IP6_ADDR:
            return mmt_ip6_fprintf(f, attr);
        case MMT_DATA_PATH:
            return mmt_path_fprintf(f, attr);
        case MMT_DATA_TIMEVAL:
            return mmt_timeval_fprintf(f, attr);
        case MMT_BINARY_DATA:
            return mmt_binary_fprintf(f, attr);
        case MMT_BINARY_VAR_DATA:
            return mmt_binary_fprintf(f, attr);
        case MMT_STRING_DATA:
            return mmt_string_fprintf(f, attr);
        case MMT_STRING_LONG_DATA:
            return mmt_string_fprintf(f, attr);
        case MMT_STRING_DATA_POINTER:
            return mmt_string_pointer_fprintf(f, attr);
        case MMT_STATS:
            return mmt_stats_fprintf(f, attr);
        default:
            return mmt_stats_fprintf(f, attr);
    }
}

int mmt_char_format(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "Attribute %s.%s = %c\n",
            get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), *(char *) attr->data);
}

int mmt_uint8_format(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "Attribute %s.%s = %hu\n",
            get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), (uint16_t) *(uint8_t *) attr->data);
}

int mmt_uint16_format(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "Attribute %s.%s = %hu\n",
            get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), *(uint16_t *) attr->data);
}

int mmt_uint32_format(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "Attribute %s.%s = %u\n",
            get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), *(uint32_t *) attr->data);
}

int mmt_uint64_format(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "Attribute %s.%s = %"PRIu64"\n",
            get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), *(uint64_t *) attr->data);
}

int mmt_pointer_format(FILE * f, attribute_internal_t * attr) {
    return fprintf(f, "Attribute %s.%s = %p\n",
            get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), (void *) attr->data);
}

int mmt_mac_format(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_MAC_STRLEN];
    if (mmt_mac_sprintf(buff, MMT_MAC_STRLEN, attr)) {
        return fprintf(f, "Attribute %s.%s = %s\n",
                get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}

int mmt_ip_format(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_IP_STRLEN];
    if (mmt_ip_sprintf(buff, MMT_IP_STRLEN, attr)) {
        return fprintf(f, "Attribute %s.%s = %s\n",
                get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}

int mmt_ip6_format(FILE * f, attribute_internal_t * attr){
    char buff[MMT_IP6_STRLEN];
    if (mmt_ip6_sprintf(buff, MMT_IP6_STRLEN, attr)) {
        return fprintf(f, "Attribute %s.%s = %s\n",
                get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}

int mmt_path_format(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_PATH_STRLEN];
    if (mmt_path_sprintf(buff, MMT_PATH_STRLEN, attr)) {
        return fprintf(f, "Attribute %s.%s = %s\n",
                get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}
int mmt_timeval_format(FILE * f, attribute_internal_t * attr){
    return fprintf(f, "Attribute %s.%s  = %lu.%lu\n",
                get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), ((struct timeval *) attr->data)->tv_sec, ((struct timeval *) attr->data)->tv_usec);
}
int mmt_binary_format(FILE * f, attribute_internal_t * attr){
    char buff[MMT_BINARYVAR_STRLEN];
    if (mmt_binary_sprintf(buff, MMT_BINARY_STRLEN, attr)) {
        return fprintf(f, "Attribute %s.%s = %s\n",
                get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}
int mmt_string_format(FILE * f, attribute_internal_t * attr){
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    return fprintf(f, "Attribute %s.%s = %s\n",
                get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), (char *) &b->data);
}
int mmt_string_pointer_format(FILE * f, attribute_internal_t * attr){
    return fprintf(f, "Attribute %s.%s = %s\n",
                get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), (char *) attr->data);
}

int mmt_stats_format(FILE *f, attribute_internal_t * attr) {
    return fprintf(f, "Attribute %s.%s = %s\n",
                get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), "TODO");
}

int mmt_attr_format(FILE * f, attribute_t * a) {
    attribute_internal_t * attr = (attribute_internal_t *) a;
    switch(attr->data_type) {
        case MMT_U8_DATA:
            return mmt_uint8_format(f, attr);
        case MMT_U16_DATA:
            return mmt_uint16_format(f, attr);
        case MMT_U32_DATA:
            return mmt_uint32_format(f, attr);
        case MMT_U64_DATA:
            return mmt_uint64_format(f, attr);
        case MMT_DATA_CHAR:
            return mmt_char_format(f, attr);
        case MMT_DATA_POINTER:
            return mmt_pointer_format(f, attr);
        case MMT_DATA_MAC_ADDR:
            return mmt_mac_format(f, attr);
        case MMT_DATA_IP_ADDR:
            return mmt_ip_format(f, attr);
        case MMT_DATA_IP6_ADDR:
            return mmt_ip6_format(f, attr);
        case MMT_DATA_PATH:
            return mmt_path_format(f, attr);
        case MMT_DATA_TIMEVAL:
            return mmt_timeval_format(f, attr);
        case MMT_BINARY_DATA:
            return mmt_binary_format(f, attr);
        case MMT_BINARY_VAR_DATA:
            return mmt_binary_format(f, attr);
        case MMT_STRING_DATA:
            return mmt_string_format(f, attr);
        case MMT_STRING_LONG_DATA:
            return mmt_string_format(f, attr);
        case MMT_STRING_DATA_POINTER:
            return mmt_string_pointer_format(f, attr);
        case MMT_STATS:
            return mmt_stats_format(f, attr);
        default:
            return mmt_stats_format(f, attr);
    }
}
