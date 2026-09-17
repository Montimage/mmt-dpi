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

bool pointer_comp_fn_pt(void * l_p, void * r_p) {
    return (l_p < r_p);
}

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

/*
 * Issue #22 (thread safety) - global protocol registry.
 *
 * `configured_protocols` is the process-wide table of protocol descriptors. It
 * is populated at init time (init_extraction) and then mutated only at
 * (un)registration time: register_protocol / unregister_protocol_by_id /
 * unregister_protocol_by_name flip the per-protocol `is_registered` flag and
 * (for registration) insert into `configured_protocols_names_map`.
 *
 * The per-packet hot path NEVER reads this global table: mmt_init_handler()
 * snapshots the descriptor pointers into each handler's own
 * `mmt_handler->configured_protocols[]` array, and packet processing reads only
 * that per-handler snapshot. Therefore the registration mutex below is taken
 * only on the (un)registration mutation paths - never on the hot path - so the
 * lock-free read fast path is preserved.
 *
 * Threading contract (see docs/THREADING.md): init_extraction() and all
 * protocol/plugin (un)registration must complete on a single thread before any
 * worker thread starts. One mmt_handler_t per worker thread; handlers must not
 * be shared across threads. The mutex makes the registration mutations safe for
 * defensive callers that register concurrently, but the documented
 * init-before-workers ordering is what keeps the read path lock-free.
 */
static pthread_mutex_t configured_protocols_mutex = PTHREAD_MUTEX_INITIALIZER;
static protocol_t *configured_protocols[PROTO_MAX_IDENTIFIER];
static void * mmt_configured_handlers_map;
// Issue #67: mmt_configured_handlers_map is handler-lifecycle bookkeeping mutated
// by mmt_init_handler()/mmt_close_handler(). It is never touched on the per-packet
// hot path, so guarding it adds no read-path overhead. This dedicated mutex makes
// concurrent handler create/destroy race-free (mirrors the #22 registry pattern;
// kept separate from configured_protocols_mutex as it guards a different global and
// the two are never nested). The single-threaded init/teardown iteration over the
// map (init_extraction/close_extraction, see docs/THREADING.md) is exempt.
static pthread_mutex_t configured_handlers_map_mutex = PTHREAD_MUTEX_INITIALIZER;
// Issue #19: protocol-name -> protocol_t* index, built at registration. Replaces
// the O(PROTO_MAX_IDENTIFIER) strcasecmp linear scan in get_protocol_id_by_name
// with an O(log n) lookup. The comparison function is case-insensitive
// (mmt_strncasecmp), preserving the exact match semantics of the old scan.
static void * configured_protocols_names_map;

bool attribute_ids_comparison_fct(uint32_t l_id, uint32_t r_id) {
    return (l_id < r_id);
}

bool attribute_names_comparison_fct(void * l_name, void * r_name) {
    return (mmt_strncasecmp((char *) l_name, (char *) r_name, Max_Alias_Len) < 0) ? true : false;
}

// Issue #19: case-insensitive strict-weak ordering for the protocol name -> id
// map. Map equivalence (!cmp(a,b) && !cmp(b,a)) therefore equals a case-
// insensitive name match, reproducing exactly what the old mmt_strcasecmp scan
// in get_protocol_id_by_name() matched.
bool protocol_names_comparison_fct(void * l_name, void * r_name) {
    return (mmt_strncasecmp((char *) l_name, (char *) r_name, Max_Alias_Len) < 0) ? true : false;
}

/* Issue #254 (F-PERF-012): hash functions for the open-addressing void* maps.
 * Each must be consistent with its comparison's equivalence: keys equal under
 * !cmp(a,b) && !cmp(b,a) have to hash equally. */

/* The handler registry keys on the pointer value itself, so equivalence is
 * pointer equality — hash the address. */
static uint64_t pointer_hash_fn(void * p) {
    return (uint64_t) (uintptr_t) p;
}

/* The attribute/protocol name maps compare with
 * mmt_strncasecmp(..., Max_Alias_Len): two names are equivalent iff their
 * uppercase-folded bytes agree through Max_Alias_Len or a shared NUL. Hash
 * the same folded bytes over the same bounded span so equivalent aliases
 * always land in the same bucket. */
static uint64_t alias_names_hash(void * name) {
    const unsigned char * s = (const unsigned char *) name;
    uint64_t h = 1469598103934665603ULL; /* FNV-1a basis */
    for (int i = 0; i < Max_Alias_Len && s[i] != '\0'; i++) {
        h = (h ^ (uint64_t) (unsigned char) mmt_toupper((char) s[i])) * 1099511628211ULL;
    }
    return h;
}


#define _is_valid_protocol_id( proto_id ) ( proto_id < PROTO_MAX_IDENTIFIER )

bool is_valid_protocol_id(uint32_t proto_id) {
	return _is_valid_protocol_id( proto_id );
}

static inline int _is_registered_protocol(uint32_t proto_id) {
    if (likely(_is_valid_protocol_id(proto_id) > 0))
        if (configured_protocols[proto_id]->is_registered && configured_protocols[proto_id]->proto_id == proto_id)
            return PROTO_REGISTERED;
    return PROTO_NOT_REGISTERED;
}

bool is_registered_protocol(uint32_t proto_id) {
	return _is_registered_protocol( proto_id );
}

int get_attribute_id_by_name_from_protocol_map(uint32_t proto_id, const char * attribute_name) {
    if (_is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_key_value(configured_protocols[proto_id]->attributes_names_map, (void *) attribute_name);
        if (attr != NULL) {
            return attr->id;
        }
    }
    return 0;
}

const char * get_attribute_name_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (_is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->alias;
        }
    }
    return NULL;
}

int get_attribute_data_type_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (_is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->data_type;
        }
    }
    return MMT_UNDEFINED_TYPE;
}

int get_attribute_length_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (_is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->data_len;
        }
    }
    return 0;
}

int get_attribute_scope_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (_is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->scope;
        }
    }
    return 0;
}

int get_attribute_position_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (_is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->position_in_packet;
        }
    }
    return POSITION_NOT_KNOWN;
}

int is_protocol_valid_attribute(uint32_t proto_id, uint32_t attribute_id) {
    if (_is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return true;
        }
    }
    return false;
}

generic_attribute_extraction_function get_attribute_extraction_fct_by_id_from_protocol_map(uint32_t proto_id, uint32_t attribute_id) {
    if (_is_registered_protocol(proto_id)) {
        attribute_metadata_t * attr = (attribute_metadata_t *) find_int_key_value(configured_protocols[proto_id]->attributes_map, (uint32_t) attribute_id);
        if (attr != NULL) {
            return attr->extraction_function;
        }
    }
    return silent_extraction;
}

protocol_t * get_protocol_struct_by_protocol_id(uint32_t proto_id) {
    if (_is_valid_protocol_id(proto_id) > 0) {
        if (_is_registered_protocol(proto_id) == PROTO_REGISTERED) {
            return configured_protocols[proto_id];
        }
    }

    return NULL;
}

int validate_attribute_metadata(attribute_metadata_t * attribute_meta_data) {
    //int retval = true;
    // The id must not be 0
    if (attribute_meta_data->id == 0) return false;
    // The name must have a length of at least one and less than Max_Alias_Len - PVS V560: due to the decleration: char alias[Max_Alias_Len + 1]; -> but it could be a fault possitive because some time we have terminated character in the alias
    if ((strlen(attribute_meta_data->alias) == 0) || (strlen(attribute_meta_data->alias) > Max_Alias_Len)) return false;
    // The data type should have a value greater than MMT_UNDEFINED_TYPE and less than MMT_HIGHER_VALUED_VALID_DATA_TYPE
    if ((attribute_meta_data->data_type <= MMT_UNDEFINED_TYPE)
            || (attribute_meta_data->data_type >= MMT_HIGHER_VALUED_VALID_DATA_TYPE))
        return false;
    // The scope should be one of SCOPE_PACKET, SCOPE_SESSION, SCOPE_SESSION_CHANGING
    if (!((attribute_meta_data->scope & SCOPE_ON_DEMAND) || (attribute_meta_data->scope & SCOPE_EVENT))) return false;
    // Validate data_len against type size: inconsistent plugin metadata must not overflow generic extraction
    {
        uint32_t type_size = get_data_size_by_data_type(attribute_meta_data->data_type);
        if (type_size != 0 && (uint32_t)attribute_meta_data->data_len > type_size) {
            /* Issue #202 (F-BUG-010): name the offending attribute so a
             * rejected registration is diagnosable. */
            mmt_debug_log( "[error] validate_attribute_metadata - attribute '%s' (id=%u): declared data_len %d exceeds size %u of data type %u\n",
                    attribute_meta_data->alias, (unsigned) attribute_meta_data->id,
                    attribute_meta_data->data_len, (unsigned) type_size,
                    (unsigned) attribute_meta_data->data_type);
            return false;
        }
        if (type_size == 0 && attribute_meta_data->data_len != 0) {
            mmt_debug_log( "[error] validate_attribute_metadata - attribute '%s' (id=%u): declared data_len %d but data type %u has no fixed size\n",
                    attribute_meta_data->alias, (unsigned) attribute_meta_data->id,
                    attribute_meta_data->data_len,
                    (unsigned) attribute_meta_data->data_type);
            return false;
        }
    }
    return true;
}

bool register_attribute_with_protocol(protocol_t *proto, attribute_metadata_t *attribute_meta_data) {
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
                if(!insert_key_value(proto->attributes_names_map, (void *) attr->alias, (void *) attr)){
                    mmt_stderr_log( "[error] register_attribute_with_protocol - Failed to execute insert_key_value()\n");
                };
                return 1;
            }
        }
    }
    return 0; // TODO(#327): error handling
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
    ((generic_handler_iteration_callback) ((struct internal_handler_iterator_struct *) args)->iterator_fct)(value, ((struct internal_handler_iterator_struct *) args)->args);
}

void iterate_through_protocol_attributes(uint32_t proto_id, generic_protocol_attribute_iteration_callback iterator_fct, void * args) {
    if (_is_registered_protocol(proto_id) == PROTO_REGISTERED) {
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

bool register_session_timeout_handler(mmt_handler_t *mmt_h, generic_session_timeout_handler_function session_expiry_handler_fct, void * args) {
    mmt_h->session_expiry_handler.handler_fct = session_expiry_handler_fct;
    mmt_h->session_expiry_handler.args = args;
    return 1;
}

bool register_session_timer_handler(mmt_handler_t *mmt_h, generic_session_timer_handler_function session_timer_handler_fct, void * args, uint8_t no_fragmented) {
    mmt_h->session_timer_handler.session_timer_handler_fct = session_timer_handler_fct;
    mmt_h->session_timer_handler.args = args;
    mmt_h->session_timer_handler.no_fragmented = no_fragmented;
    return 1;
}

void base_packet_extraction(ipacket_t * ipacket, unsigned protocol_index);

bool register_protocol_stack(uint32_t s_id, char * s_name, generic_stack_classification_function fct) {
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

bool register_protocol_stack_full(uint32_t s_id, char * s_name, generic_stack_classification_function fct,
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

bool unregister_protocol_stack(uint32_t s_id) {
    protocol_stack_t * temp_stack = get_protocol_stack_from_map(s_id);
    if (temp_stack != NULL && s_id != 0) {
        //The protocol stack is registered, remove it from the map, and free it
        delete_protocol_stack_from_map(s_id); //TODO(#327): check the return value
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

/**
 * Register classificaiton function internal - insert this function into right position: for example: classify FTP after HTTP -> HTTP 10, FTP 50
 * @param  proto              Protocol ID
 * @param  classification_fct classify function
 * @param  weight             weight of this function
 * @return                    0 failed
 *                            1 successful
 */
int register_classification_function_internal(protocol_t * proto, generic_classification_function classification_fct, int weight) {
    if (weight < 0) weight = 0;
    if (weight > 100) weight = 100;
    mmt_classify_proto_t * temp = (mmt_classify_proto_t *) mmt_malloc(sizeof (mmt_classify_proto_t));
    if (temp == NULL) {
        return 0;
    }
    memset(temp, 0, sizeof (mmt_classify_proto_t));
    temp->weight = weight;
    temp->next = NULL;
    temp->previous = NULL;
    temp->classify_me = classification_fct;

    mmt_classify_proto_t * temp_list = proto->classify_next.classify_protos;
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

/**
 * Register classification function with parent protocol
 * For examples: register mmt_check_ftp for protocol FTP with parent protocol is TCP
 * @param  proto_id           protocol id (FTP)
 * @param  classification_fct classify function
 * @param  weight             weight of this function
 * @return                    0 if there is no classification function
 *                            call to register_classification_function_internal
 */
bool register_classification_function_with_parent_protocol(uint32_t proto_id, generic_classification_function classification_fct, int weight) {
    if (classification_fct != NULL) {
        protocol_t * proto = get_protocol_struct_by_protocol_id(proto_id);
        if (proto) {
            if (weight < 0) weight = 0;
            if (weight > 100) weight = 100;
            // if ((weight > 10) && (weight < 90)) weight = 90;// LN: Dont know why we do that????
            return register_classification_function_internal(proto, classification_fct, weight);
        }
    }
    return 0;
}
/**
 * Register classification function without parent protocol
 * @param  proto              protocol
 * @param  classification_fct classification function
 * @return                    0 if failed
 *                            go to #register_classification_function_internal
 */
/* Default weight for callbacks registered without an explicit one: the middle
 * of the 10..80 range register_classification_function_full() documents. */
#define MMT_DEFAULT_CALLBACK_WEIGHT 50

bool register_classification_function(protocol_t *proto, generic_classification_function classification_fct) {
    if (classification_fct != NULL) {
        return register_classification_function_internal(proto, classification_fct, MMT_DEFAULT_CALLBACK_WEIGHT);
    }
    return 0;
}

bool register_pre_post_classification_functions(protocol_t *proto,
        generic_classification_function pre_classification,
        generic_classification_function post_classification) {

    proto->classify_next.pre_classify = pre_classification;
    proto->classify_next.post_classify = post_classification;

    return 1;

}

bool register_classification_function_full(protocol_t *proto, generic_classification_function classification_fct, int weight,
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

void register_session_hash_function(protocol_t *proto, generic_hash_fct session_key_hash_fct) {
    proto->session_key_hash = session_key_hash_fct;
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
            temp->next = temp_list;
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

bool register_session_data_analysis_function_with_protocol(uint32_t proto_id,
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

bool register_session_data_analysis_function(protocol_t *proto,
        generic_session_data_analysis_function session_data_analysis_fct) {
    if (session_data_analysis_fct != NULL) {
        return register_data_analysis_function_internal(proto, session_data_analysis_fct, MMT_DEFAULT_CALLBACK_WEIGHT);
    }
    return 0;
}

bool register_pre_post_analysis_functions(protocol_t *proto,
        generic_session_data_analysis_function pre_analysis,
        generic_session_data_analysis_function post_analysis) {

    proto->data_analyser.pre_analyse  = pre_analysis;
    proto->data_analyser.post_analyse = post_analysis;

    return 1;
}

bool register_session_data_analysis_function_full(protocol_t *proto,
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


bool is_free_protocol_id_for_registractionl(uint32_t proto_id) {
    if (proto_id >= PROTO_MAX_IDENTIFIER) return 0; //The prtocol id is not valid

    protocol_t *proto = configured_protocols[proto_id];
    if ( !proto ) return 1; // protocol just doesn't exist (plugin ?)
    if ( proto->is_registered ) return 0; //The protocol is already registered

    return 1; // Cool we can use this protocol id
}

void init_protocol_struct(protocol_t * proto) {
    // TODO(#327): complete this

    // register dummy sessionizer
    proto->sessionize = NULL;
    proto->has_session = NO_SESSION_CONTEXT;
    proto->session_timeout_delay = CFG_DEFAULT_SESSION_TIMEOUT;
    proto->attributes_map = init_int_map_space(attribute_ids_comparison_fct);
    proto->attributes_names_map = init_map_space(attribute_names_comparison_fct, alias_names_hash);
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
    if (_is_registered_protocol(proto_id)) {
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
    mmt_classify_proto_t * temp_class = protocol->classify_next.classify_protos;
    mmt_classify_proto_t * safe_to_delete_c = NULL;
    while (temp_class != NULL) {
        safe_to_delete_c = temp_class;
        temp_class = temp_class->next;
        mmt_free(safe_to_delete_c);
    }
    //Clear the classification function if it exists
    mmt_analyse_me_t * temp_analyse = protocol->data_analyser.analyse;
    mmt_analyse_me_t * safe_to_delete_a = NULL;
    while (temp_analyse != NULL) {
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
    // Issue #19: tear down the protocol name->id index. The keys are the
    // protocol_name buffers owned by the protocol structs (freed above) and the
    // values are those structs, so the map owns nothing itself.
    if (configured_protocols_names_map != NULL) {
        clear_map_space(configured_protocols_names_map);
        delete_map_space(configured_protocols_names_map);
        configured_protocols_names_map = NULL;
    }
}

void free_protocols_contexts(mmt_handler_t *mmt_handler) {
    int i = 0;
    for (; i < PROTO_MAX_IDENTIFIER; i++) {
        if (mmt_handler->configured_protocols[i].protocol != NULL) {
            if (mmt_handler->configured_protocols[i].protocol->is_registered) {
                if (mmt_handler->configured_protocols[i].protocol->has_session && mmt_handler->configured_protocols[i].sessions_map != NULL) {
                    clear_sessions_from_protocol_context(&mmt_handler->configured_protocols[i]);
                    delete_session_map_space(mmt_handler->configured_protocols[i].sessions_map);
                    mmt_handler->configured_protocols[i].sessions_map = NULL;
                }

                //Cleanup the protocol context if such a function is registered
                if (mmt_handler->configured_protocols[i].protocol->protocol_context_cleanup != NULL) {
                    ((generic_proto_context_cleanup_function) mmt_handler->configured_protocols[i].protocol->protocol_context_cleanup)(&mmt_handler->configured_protocols[i], mmt_handler->configured_protocols[i].protocol->protocol_context_args);
                }
            }
        }
    }
}

bool register_protocol(protocol_t *proto, uint32_t proto_id) {
    // Issue #22: guard the global registry mutation. Held only on this
    // registration path, never on the per-packet hot path (which reads the
    // per-handler snapshot, see configured_protocols declaration).
    int retval = PROTO_NOT_REGISTERED;
    pthread_mutex_lock(&configured_protocols_mutex);
    if (is_free_protocol_id_for_registractionl(proto_id)) {
        if (proto->proto_id == proto_id && proto == configured_protocols[proto_id]) {
            register_protocol_stats_attributes(proto);
            if (proto->has_session) {
                register_protocol_session_attributes(proto);
            }
            configured_protocols[proto_id]->is_registered = PROTO_REGISTERED;
            // Issue #19: index this protocol's name for O(log n) name->id
            // lookup. Insert only if absent so re-registration is idempotent and
            // does not emit the duplicate-key diagnostic.
            if (configured_protocols_names_map != NULL && proto->protocol_name != NULL &&
                    find_key_value(configured_protocols_names_map, (void *) proto->protocol_name) == NULL) {
                insert_key_value(configured_protocols_names_map, (void *) proto->protocol_name, (void *) proto);
            }
            retval = PROTO_REGISTERED;
        }
    }
    pthread_mutex_unlock(&configured_protocols_mutex);
    return retval;
}

bool unregister_protocol_by_id(uint32_t proto_id) {
    // Issue #22: guard the global registry mutation (see register_protocol).
    int retval = 0;
    pthread_mutex_lock(&configured_protocols_mutex);
    if (!is_free_protocol_id_for_registractionl(proto_id)) {
        configured_protocols[proto_id]->is_registered = PROTO_NOT_REGISTERED;
        retval = 1;
    }
    pthread_mutex_unlock(&configured_protocols_mutex);
    return retval;
}

bool unregister_protocol_by_name(char* proto_name) {
    // Issue #22: guard the global registry mutation (see register_protocol).
    int i=0;
    int retval = 0;
    pthread_mutex_lock(&configured_protocols_mutex);
    for (i =0;i<PROTO_MAX_IDENTIFIER;i++){
        if (!is_free_protocol_id_for_registractionl(i)) {
            if(mmt_strcasecmp(configured_protocols[i]->protocol_name,proto_name) == 0){
                configured_protocols[i]->is_registered = PROTO_NOT_REGISTERED;
                retval = 1;
                break;
            }
        }

    }
    pthread_mutex_unlock(&configured_protocols_mutex);
    return retval;
}

int init_plugins() {
    if (!load_plugins()) {
        mmt_stderr_log( "Error while loading plugins, Exiting\n");
        return 0;
    }

    return 1;
}

void mmt_print_info() {
    mmt_stream_printf(stdout, "%s", MMT_PRINT_INFO);
}

mmt_handler_t *mmt_init_handler( uint32_t stacktype, uint32_t options, char * errbuf )
{
    // mmt_print_info();
    int i = 0;
    protocol_stack_t * temp_stack = get_protocol_stack_from_map(stacktype);
    if (temp_stack == NULL) {
        if ( errbuf )
            strcpy(errbuf, "Unsupported stack type");
        return NULL;
    }

    mmt_handler_t * new_handler = mmt_malloc(sizeof (mmt_handler_t));
    if (new_handler == NULL) {
        if ( errbuf )
            strcpy(errbuf, "Error while initializing mmt extraction handler");
        return NULL;
    }

    // Set the handler to zeros
    memset(new_handler, '\0', sizeof (mmt_handler_t));
    new_handler->packet_count = 0;
    new_handler->sessions_count = 0;
    new_handler->active_sessions_count = 0;
    new_handler->ip_streams = hashmap_alloc();
    if (new_handler->ip_streams == NULL) {
        if ( errbuf )
            strcpy(errbuf, "Error while initializing mmt extraction handler");
        mmt_free(new_handler);
        return NULL;
    }
    new_handler->ip6_streams = hashmap_alloc();
    if (new_handler->ip6_streams == NULL) {
        if ( errbuf )
            strcpy(errbuf, "Error while initializing mmt extraction handler");
        hashmap_free(new_handler->ip_streams);
        mmt_free(new_handler);
        return NULL;
    }

    new_handler->last_received_packet.packet_id = 0;
    new_handler->last_received_packet.packet_len = 0;
    new_handler->last_received_packet.time.tv_sec = 0;
    new_handler->last_received_packet.time.tv_usec = 0;

    new_handler->link_layer_stack = temp_stack;

    new_handler->has_reassembly = 0; // Disable TCP-reassembly by default
    new_handler->port_classify = 0; // Disable classification by port number by default
    new_handler->port_classify_payload_confirm = 0; // M9 (issue #75): accept any port-based guess by default (no payload confirmation required)
    new_handler->hostname_classify = 1; // Enable classification by Hostname by default
    new_handler->ip_address_classify = 1; // Enable classification by IP address by default
    new_handler->clean_packet = clean_packet;
    new_handler->process_packet = process_packet;

    // Initialize current_ipacket
    new_handler->current_ipacket.proto_headers_offset = NULL;
    new_handler->current_ipacket.proto_headers_offset_owned = 0;
    new_handler->current_ipacket.proto_classif_status = NULL;
    new_handler->current_ipacket.session = NULL;
    new_handler->current_ipacket.internal_packet = NULL;
    new_handler->current_ipacket.mmt_handler = NULL;
    new_handler->current_ipacket.p_hdr = NULL;
    new_handler->current_ipacket.data = NULL;
    new_handler->current_ipacket.original_data = NULL;

    new_handler->timeout_milestones_map = init_timeout_milestones_index();
    if (new_handler->timeout_milestones_map == NULL) {
        if ( errbuf )
            strcpy(errbuf, "Error while initializing mmt extraction handler");
        // F-BUG-012 (issue #199): the IP fragment maps were allocated above —
        // release them before abandoning the handler.
        hashmap_free(new_handler->ip_streams);
        hashmap_free(new_handler->ip6_streams);
        mmt_free(new_handler);
        return NULL;
    }

    for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        new_handler->configured_protocols[i].protocol = configured_protocols[i];
        new_handler->configured_protocols[i].sessions_map = NULL;
        new_handler->configured_protocols[i].args = NULL;

        // Initialize the sessions context if the protocol has such context
        if (new_handler->configured_protocols[i].protocol->has_session == HAS_SESSION_CONTEXT) {
            new_handler->configured_protocols[i].sessions_map = init_session_map_space(new_handler->configured_protocols[i].protocol->session_key_compare, new_handler->configured_protocols[i].protocol->session_key_hash);
            if (new_handler->configured_protocols[i].sessions_map == NULL) {
                // OOM: cleanup already allocated session maps
                for (int _j = 0; _j < i; _j++) {
                    if (new_handler->configured_protocols[_j].sessions_map) {
                        delete_session_map_space(new_handler->configured_protocols[_j].sessions_map);
                    }
                }
                hashmap_free(new_handler->ip_streams);
                hashmap_free(new_handler->ip6_streams);
                clear_timeout_milestones(new_handler);
                mmt_free(new_handler);
                if (errbuf) strcpy(errbuf, "Error while initializing mmt extraction handler");
                return NULL;
            }
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

    new_handler->session_timer_handler.session_timer_handler_fct = NULL;
    new_handler->session_timer_handler.args = NULL;
    new_handler->evasion_handler = NULL;
    /* Issue #201 (F-BUG-020): armed lazily by the TCP/IP plugin on the first
     * fragment seen (the ip_streams map exists but may stay empty forever). */
    new_handler->frag_map_sweep_fct = NULL;
    new_handler->frag_map_drain_fct = NULL;
    new_handler->fragment_in_packet = 0;
    new_handler->fragmented_packet_in_session = 0;
    new_handler->fragment_in_session = 0;
    new_handler->default_session_timed_out = CFG_DEFAULT_SESSION_TIMEOUT;
    new_handler->long_session_timed_out = CFG_LONG_SESSION_TIMEOUT;
    new_handler->short_session_timed_out = CFG_SHORT_LIFE_SESSION_TIMEOUT;
    new_handler->live_session_timed_out = CFG_LIVE_SESSION_TIMEOUT;

    //Enable protocol statistics (this is default config)
    enable_protocol_statistics((void *) new_handler);

    pthread_mutex_lock(&configured_handlers_map_mutex);
    if(!insert_key_value(mmt_configured_handlers_map, (void *) new_handler, (void *) new_handler)){
        mmt_stderr_log( "[error] mmt_init_handler - Failed to execute insert_key_value()\n");
    };
    pthread_mutex_unlock(&configured_handlers_map_mutex);

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


/* hashmap_walk() callback draining an ip_streams value through the
 * plugin-registered destructor — see mmt_close_handler() (issue #216). */
static void free_ip_stream_value(mmt_hashmap_t * map, mmt_hent_t * he, void * arg) {
    (void) map;
    void (*value_free)(void *) = (void (*)(void *)) arg;
    if (he->val != NULL)
        value_free(he->val);
}

void mmt_close_handler(mmt_handler_t *mmt_handler) {
    // Iterate over the timeout milestones and expticitly timeout all registered sessions
    timeout_iteration_callback(mmt_handler, force_sessions_timeout);
    // Clear timeout milestones
    clear_timeout_milestones(mmt_handler);
    // Free the protocol structs
    free_protocols_contexts(mmt_handler);
    // Free the attribute structs
    free_registered_extraction_attributes(mmt_handler);
    // Free the registered attribute handlers
    free_registered_attribute_handlers(mmt_handler);
    // Free the packet handlers structs
    free_registered_packet_handlers(mmt_handler);
    // Free protocol statistics
    free_handler_protocols_statistics(mmt_handler);
    // Free IP streams hashtables — first drain any values still held in them
    // (incomplete-fragment datagrams whose completion never arrived). The
    // owning plugin registers the destructor on the handler (issue #216;
    // supersedes the #201 frag_map_drain_fct hook, which stays disarmed).
    if (mmt_handler->ip_streams != NULL && mmt_handler->ip_streams_value_free != NULL) {
        hashmap_walk(mmt_handler->ip_streams, free_ip_stream_value,
                     (void *) mmt_handler->ip_streams_value_free);
    }
    hashmap_free(mmt_handler->ip_streams);
    if (mmt_handler->ip6_streams != NULL && mmt_handler->ip6_streams_value_free != NULL) {
        hashmap_walk(mmt_handler->ip6_streams, free_ip_stream_value,
                     (void *) mmt_handler->ip6_streams_value_free);
    }
    hashmap_free(mmt_handler->ip6_streams);

    // Free the registered evasion handler, if any
    if (mmt_handler->evasion_handler != NULL) {
        mmt_free(mmt_handler->evasion_handler);
        mmt_handler->evasion_handler = NULL;
    }

    //Remove the handler from the registered handlers in the global context
    pthread_mutex_lock(&configured_handlers_map_mutex);
    delete_key_value(mmt_configured_handlers_map, mmt_handler);
    pthread_mutex_unlock(&configured_handlers_map_mutex);

    mmt_free(mmt_handler);
}


/**
 * Enables the analysis sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void enable_protocol_analysis(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && _is_valid_protocol_id(proto_id) > 0) {
        // Add this condition checking to reduce conflict in multi-thread
        int *status = &mmt_handler->configured_protocols[proto_id].protocol->data_analyser.status;
        if (proto_status_load(status) == 0) {
            proto_status_store(status, 1);
        }
    }
}

/**
 * Disables the analysis sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void disable_protocol_analysis(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && _is_valid_protocol_id(proto_id) > 0) {
        // Add this condition checking to reduce conflict in multi-thread
        int *status = &mmt_handler->configured_protocols[proto_id].protocol->data_analyser.status;
        if (proto_status_load(status) == 1) {
            proto_status_store(status, 0);
        }
    }
}

/**
 * Enables the classification sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void enable_protocol_classification(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && _is_valid_protocol_id(proto_id) > 0) {
        // Add this condition checking to reduce conflict in multi-thread
        int *status = &mmt_handler->configured_protocols[proto_id].protocol->classify_next.status;
        if (proto_status_load(status) == 0) {
            proto_status_store(status, 1);
        }
    }
}

/**
 * Disables the classification sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void disable_protocol_classification(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && _is_valid_protocol_id(proto_id) > 0) {
        // Add this condition checking to reduce conflict in multi-thread
        int *status = &mmt_handler->configured_protocols[proto_id].protocol->classify_next.status;
        if (proto_status_load(status) == 1) {
            proto_status_store(status, 0);
        }
    }
}

bool update_protocol(uint32_t proto_id, int action_id){
    protocol_t * proto_struct = get_protocol_struct_by_id(proto_id);
    if (proto_struct && proto_struct->update_protocol_fct){
        return proto_struct->update_protocol_fct(action_id);
    }
    return 0;
}

bool init_extraction()
{
    int i = 0;
    for (; i < PROTO_MAX_IDENTIFIER; i++) {
        configured_protocols[i] = (protocol_t *) mmt_malloc(sizeof (protocol_t));
        if (!configured_protocols[i]) {
            // B5: allocation failed - report an error to the caller instead of
            // killing the host process with exit().
            mmt_stderr_log( "Error during initialization (out of memory)\n");
            return 0;
        }
        memset(configured_protocols[i], '\0', sizeof (protocol_t));
        configured_protocols[i]->is_registered = PROTO_NOT_REGISTERED;
        // Issue #69: keep all accesses to these flags atomic (relaxed) so the
        // hot-path reader and the enable_*/disable_* writers never mix atomic
        // and non-atomic accesses to the same location. This runs single-
        // threaded before any worker, but consistency keeps it well-defined.
        proto_status_store(&configured_protocols[i]->data_analyser.status, 0);
        proto_status_store(&configured_protocols[i]->classify_next.status, 0);
    }

    // Issue #19: create the protocol name -> id index before any protocol is
    // registered (init_proto_meta_struct/init_plugins below call
    // register_protocol, which populates this map).
    configured_protocols_names_map = init_map_space(protocol_names_comparison_fct, alias_names_hash);
    if (configured_protocols_names_map == NULL) {
        // Issue #200 (F-BUG-003): the map allocation failed — refuse to start
        // instead of registering protocols into a NULL map.
        mmt_stderr_log( "Error during initialization (out of memory)\n");
        return 0;
    }

    /////////// INITILIZING PROTO_META & PROTO_UNKNOWN //////////////////
    if (!init_proto_meta_struct() || !init_proto_unknown_struct()) {
        // B5: report initialization failure instead of exit()ing the host.
        mmt_stderr_log( "Error initializing meta and unknown protocols\n");
        return 0;
    }
    /////////////////////////////////////////////

    // B5: propagate a package_dependent_init() / plugin init failure to the
    // caller (init_extraction() returns bool; callers such as
    // simple_traffic_reporting already check it) rather than continuing blindly.
    if (!package_dependent_init()) {
        mmt_stderr_log( "Error during package-dependent initialization\n");
        return 0;
    }

    init_plugins();
    mmt_configured_handlers_map = init_map_space(pointer_comp_fn_pt, pointer_hash_fn);
    if (mmt_configured_handlers_map == NULL) {
        // Issue #200 (F-BUG-003): same unchecked-nothrow-new guard as above.
        mmt_stderr_log( "Error during initialization (out of memory)\n");
        return 0;
    }
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

void mmt_close_handler_internal(mmt_handler_t *mmt_handler, void * args) {
    mmt_close_handler(mmt_handler);
}

void close_extraction() {
    debug("CLOSE EXTRACTION!!!!!");
    //Iterate over the registered handlers
    iterate_through_mmt_handlers(mmt_close_handler_internal, NULL);
    //Delete the handlers map
    delete_map_space(mmt_configured_handlers_map);
    // Issue #200 (F-BUG-005): NULL the global after deleting it — a second
    // init_extraction()/close_extraction() cycle in one process must not
    // dereference the dangling pointer.
    mmt_configured_handlers_map = NULL;
    // Iterate over the registered protocol stacks
    iterate_through_protocol_stacks(protocol_stack_callback_fct, NULL);
    // Clear the protocol stacks map
    clear_protocol_stack_map();
    // Free the protocol structs
    free_registered_protocols();
    // unload plugins
    close_plugins();
}

bool is_registered_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id) {
    packet_handler_t * temp_handler = mmt_handler->packet_handlers;
    while (temp_handler != NULL) {
        if (temp_handler->packet_handler_id == packet_handler_id) return 1;
        temp_handler = temp_handler->next;
    }
    return 0;
}

bool is_registered_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    int retval = 0;
    struct attribute_internal_struct * tmp_attribute = mmt_handler->proto_registered_attributes[proto_id];
    while (tmp_attribute != NULL) {
        if (proto_id == mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute) &&
                field_id == tmp_attribute->field_id) return 1;
        tmp_attribute = tmp_attribute->next;
    }
    return retval;
}

struct attribute_internal_struct * get_registered_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    if (_is_registered_protocol(proto_id) > 0) {
        struct attribute_internal_struct * tmp_attribute = mmt_handler->proto_registered_attributes[proto_id];
        while (tmp_attribute != NULL) {
            if (proto_id == mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute) &&
                    field_id == tmp_attribute->field_id) return tmp_attribute;
            tmp_attribute = tmp_attribute->next;
        }
    }
    return NULL;
}

bool has_registered_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t attribute_id) {
    if (!_is_valid_protocol_id(proto_id)) {
        return 0;
    }
    attribute_internal_t * tmp_attribute = mmt_handler->proto_registered_attributes[proto_id];
    while (tmp_attribute != NULL) {
        if (proto_id == mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute) &&
                attribute_id == tmp_attribute->field_id &&
                tmp_attribute->attribute_handler != NULL /* The attribute has at least one registered handler */) {
            return 1;
        }
        tmp_attribute = tmp_attribute->next;
    }
    return 0;
}

bool is_registered_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id,
                                    uint32_t attribute_id, attribute_handler_function handler_fct) {
    if (!_is_valid_protocol_id(proto_id)) {
        return 0;
    }
    attribute_internal_t * tmp_attribute = mmt_handler->proto_registered_attributes[proto_id];
    while (tmp_attribute != NULL) {
        if (proto_id == mmt_attr_get_proto_id_typed((const attribute_t *) tmp_attribute) &&
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

bool register_evasion_handler(mmt_handler_t *mmt_handler, generic_evasion_handler_callback evasion_handler, void * user_args){
    if(mmt_handler){
        if (mmt_handler->evasion_handler != NULL) {
            mmt_stderr_log("[ERROR] register_evasion_handler - Evasion handler function has been registered already!");
            return 0;
        }
        evasion_handler_t * new_evasion_handler = (evasion_handler_t *) mmt_malloc(sizeof(evasion_handler_t));
        if (new_evasion_handler == NULL) {
            mmt_stderr_log("[ERROR] register_evasion_handler - Failed to allocate evasion handler!");
            return 0;
        }
        new_evasion_handler->function = evasion_handler;
        new_evasion_handler->args = user_args;
        mmt_handler->evasion_handler = new_evasion_handler;
        return 1;
    }
    return 0;
}


bool unregister_extraction_attribute_by_name(mmt_handler_t *mmt_handler, const char *protocol_name, const char *attribute_name) {
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

bool unregister_extraction_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {

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

bool unregister_attribute_handler_by_name(mmt_handler_t *mmt_handler, const char *protocol_name,
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

bool unregister_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t attribute_id, attribute_handler_function handler_fct) {
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

    if ((temp_attr->attribute_handler == NULL) && !(mmt_attr_get_scope_typed((const attribute_t *) temp_attr) & SCOPE_EVENT)) {
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

bool register_extraction_attribute_by_name(mmt_handler_t *mmt_handler, const char *protocol_name, const char *attribute_name) {
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

bool register_extraction_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    protocol_t * proto = get_protocol_struct_by_protocol_id(proto_id);
    if (proto != NULL) {
        struct attribute_internal_struct * extract_attribute = get_registered_attribute(mmt_handler, proto_id, field_id);

        if (!extract_attribute) {
            int s0 = sizeof (struct attribute_internal_struct);
            int s1 = mmt_attribute_get_data_type_typed(proto_id, field_id);
            int s2 = get_data_size_by_data_type(s1);
            /* Issue #202 (F-BUG-010): the scratch area must be at least
             * data_len wide. validate_attribute_metadata() already rejects
             * data_len > type size at protocol-registration time, but size
             * defensively here as well so a metadata inconsistency can never
             * turn into a heap overflow of the scratch buffer. */
            int s3 = get_data_size_by_proto_and_field_ids(proto_id, field_id);
            int size = s0 + ((s3 > s2) ? s3 : s2);
            //mmt_stderr_log( "      size=%d\n",size);
            extract_attribute = (struct attribute_internal_struct *) mmt_malloc(size);
            if (extract_attribute == NULL) {
                return 0;
            } else {
                // We set the attribute structure content to zeros
                memset(extract_attribute, 0, size);
                extract_attribute->proto_id = proto_id;
                extract_attribute->field_id = field_id;
                extract_attribute->scope = mmt_attribute_get_scope_typed(proto_id, field_id);
                extract_attribute->data_type = mmt_attribute_get_data_type_typed(proto_id, field_id);
                extract_attribute->data_len = get_data_size_by_proto_and_field_ids(proto_id, field_id);
                extract_attribute->position_in_packet = get_field_position_by_protocol_and_field_ids(proto_id, field_id);
                extract_attribute->memsize = size;
                extract_attribute->status = ATTRIBUTE_UNSET;
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

        }
        //Finally we increment the registration count of this attribute.
        extract_attribute->registration_count++;
        return 1;
    }
    return 0;
}

bool register_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t attribute_id, attribute_handler_function handler_fct, void * handler_condition, void * user_args) {
    int retval = 0;

    if (is_registered_attribute_handler(mmt_handler, proto_id, attribute_id, handler_fct)) {
        return 0; //TODO(#327): error codes should be added to differentiate between registration failed and handler already exists.
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
        return 0; //TODO(#327): This is getting paranoiac! we MUST never get here
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

        if (!(mmt_attr_get_scope_typed((const attribute_t *) attr) & SCOPE_EVENT)) {
            //We should add an attribute handler element as this is the first handler for the attribute
            attribute_handler_element_t * attr_handler_elem = (attribute_handler_element_t *) mmt_malloc(sizeof (attribute_handler_element_t));
            if (attr_handler_elem == NULL) {
                attr->attribute_handler = NULL;
                mmt_free(new_attribute_handler);
                if (retval) unregister_extraction_attribute(mmt_handler, proto_id, attribute_id);
                return 0;
            }
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

bool register_attribute_handler_by_name(mmt_handler_t *mmt_handler, const char *protocol_name, const char *attribute_name, attribute_handler_function handler_fct, void *handler_condition, void *user_args) {
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

bool register_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id, generic_packet_handler_callback function, void *args) {
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

bool unregister_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id) {
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

void print_string_upper(const char *str) {
    int i = 0;
    while (str[i]) {
        mmt_stream_printf(stdout, "%c", toupper(str[i]));
        i++;
    }
}

void mmt_print_proto_info(protocol_t * proto) {
    mmt_stream_printf(stdout, "\nProto ID: %d", proto->proto_id);
    mmt_stream_printf(stdout, "\nProto Name: PROTO_");
    print_string_upper(proto->protocol_name);
    mmt_stream_printf(stdout, "\nAttributes");
    mmt_stream_printf(stdout, "\nname,scope,value,description\n");
    int i = 0;
    for (i = 0; i < 300; i++) {
        const char * attributes_name = get_proto_attribute_name(proto, proto->proto_id, i);
        if (attributes_name != NULL) {
            print_string_upper(proto->protocol_name);
            mmt_stream_printf(stdout, "_");
            print_string_upper(attributes_name);
            mmt_stream_printf(stdout, ",");
            int attr_scope = get_proto_attribute_scope(proto, proto->proto_id, i);
            if (attr_scope == 1) {
                mmt_stream_printf(stdout, "SCOPE_PACKET");
            } else if (attr_scope == 2) {
                mmt_stream_printf(stdout, "SCOPE_SESSION");
            } else if (attr_scope == 4) {
                mmt_stream_printf(stdout, "SCOPE_SESSION_CHANGING");
            } else if (attr_scope == 7) {
                mmt_stream_printf(stdout, "SCOPE_ON_DEMAND");
            } else if (attr_scope == 0x10) {
                mmt_stream_printf(stdout, "SCOPE_EVENT");
            } else {
                mmt_stream_printf(stdout, "UNKNOWN");
            }
            mmt_stream_printf(stdout, ", val , desc\n");
        }
    }
    mmt_stream_printf(stdout, "\n");
}

void mmt_print_all_protocols() {
    mmt_print_info();
    mmt_stream_printf(stdout, "\nMMT-SDK version: %s\n", mmt_version());
    int i = 1;
    for (; i < PROTO_MAX_IDENTIFIER; i++) {
        if (_is_registered_protocol(i)) {
            protocol_t * temp = configured_protocols[i];
            mmt_print_proto_info(temp);
        }
    }
}

generic_attribute_extraction_function getExtractionFunctionByProtocolAndFieldIds(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering getExtractionFunctionByProtocolAndFieldIds proto %u --- field %u\n", proto_id, field_id );
#endif
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_extraction_function(proto_id, field_id);
    } else {
        return silent_extraction;
    }
}

int get_data_size_by_proto_and_field_ids(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering getExtractionDataSizeByProtocolAndFieldIds proto %u --- field %u\n", proto_id, field_id );
#endif
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_data_length_by_id(proto_id, field_id);
    }
    return 0;
}

bool is_protocol_attribute(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering isProtocolAttribute proto %u --- field %u\n", proto_id, field_id );
#endif
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->is_valid_attribute(proto_id, field_id);
    }
    return false;
}

int get_field_position_by_protocol_and_field_ids(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering getFieldPositionByProtocolAndFieldIds proto %u --- field %u\n", proto_id, field_id );
#endif
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_position(proto_id, field_id);
    }
    return POSITION_NOT_KNOWN;
}

const char * get_attribute_name_by_protocol_and_attribute_ids(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering tips_proto_attr_find_by_id proto %u --- field %u\n", proto_id, field_id );
#endif
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_name_by_id(proto_id, field_id);
    }
    return NULL;
}

const char * get_protocol_name_by_id(uint32_t proto_id) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering tips_proto_find_by_id proto %u\n", proto_id );
#endif
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->protocol_name;
    }

    return NULL;
}

uint32_t get_protocol_id_by_name(const char * protocolalias) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering tips_proto_find_by_name proto %s\n", protocolalias );
#endif
    // Issue #19: O(log n) lookup in the name->protocol_t* map built at
    // registration, replacing the previous O(PROTO_MAX_IDENTIFIER) mmt_strcasecmp
    // linear scan. The map comparison is case-insensitive, so a hit reproduces
    // the old strcasecmp match exactly. The _is_registered_protocol() guard
    // reproduces the old "registered only" semantics, so an unregistered (but
    // still indexed) protocol never matches — this also lets unregistration stay
    // a simple flag flip with no map maintenance.
    if (protocolalias == NULL || configured_protocols_names_map == NULL) {
        return 0;
    }
    protocol_t * temp = (protocol_t *) find_key_value(configured_protocols_names_map, (void *) protocolalias);
    if (temp != NULL && _is_registered_protocol(temp->proto_id)) {
        return temp->proto_id;
    }
    return 0;
}

uint32_t get_attribute_id_by_protocol_and_attribute_names(const char *protocolalias, const char *fieldalias) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering tips_proto_attr_find_by_name proto %s --- field %s\n", protocolalias, fieldalias );
#endif
    uint32_t proto_id = get_protocol_id_by_name(protocolalias);
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_id_by_name(proto_id, fieldalias);
    }
    return 0;
}

uint32_t get_attribute_id_by_protocol_id_and_attribute_name(uint32_t proto_id, const char *field_name) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering tips_proto_attr_find_by_id_name proto %u --- field %s\n", proto_id, field_name );
#endif
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_id_by_name(proto_id, field_name);
    }
    return 0;
}

long get_attribute_data_type(uint32_t proto_id, uint32_t field_id) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering tips_attr_get_data_type proto %u --- field %u\n", proto_id, field_id );
#endif
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_data_type_by_id(proto_id, field_id);
    }
    return MMT_UNDEFINED_TYPE;
}

int get_attribute_scope(uint32_t proto_id, uint32_t attribute_id) {
#ifdef DEBUG
    (void)mmt_debug_log( "Entering get_attribute_scope proto %u --- field %u\n", proto_id, attribute_id );
#endif
    if (_is_registered_protocol(proto_id)) {
        return configured_protocols[proto_id]->get_attribute_scope(proto_id, attribute_id);
    }
    return 0;
}

uint32_t get_classification_threshold() {
    return CFG_CLASSIFICATION_THRESHOLD;
}
