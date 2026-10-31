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


bool is_valid_protocol_id(uint32_t proto_id) {
	return _is_valid_protocol_id( proto_id );
}

static inline int _is_registered_protocol(uint32_t proto_id) {
    if (likely(_is_valid_protocol_id(proto_id) > 0))
        if (configured_protocols[proto_id] != NULL /* #505: NULL before/after init */ && configured_protocols[proto_id]->is_registered && configured_protocols[proto_id]->proto_id == proto_id)
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
            /* Issue #327: differentiate the failure kinds — the single 0
             * return covers invalid metadata (already logged by
             * validate_attribute_metadata), a duplicate registration and an
             * allocation failure; the last two get their own diagnostics. */
            mmt_stderr_log( "[error] register_attribute_with_protocol - Failed to allocate memory for attribute '%s' (id=%u)\n",
                    attribute_meta_data->alias, (unsigned) attribute_meta_data->id);
            return 0;
        }
        /* The attribute is already registered under this id or alias — a
         * benign caller error, not an engine failure: debug channel only. */
        mmt_debug_log( "[error] register_attribute_with_protocol - attribute '%s' (id=%u) is already registered\n",
                attribute_meta_data->alias, (unsigned) attribute_meta_data->id);
    }
    return 0;
}

struct internal_attribute_iterator_struct {
    generic_protocol_attribute_iteration_callback iterator_fct;
    uint32_t proto_id;
    void * args;
};

void internal_attribute_iterator_callback(void * key, void * value, void * args) {
    ((generic_protocol_attribute_iteration_callback) ((struct internal_attribute_iterator_struct *) args)->iterator_fct)((attribute_metadata_t *) value, ((struct internal_attribute_iterator_struct *) args)->proto_id, ((struct internal_attribute_iterator_struct *) args)->args);
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
        /* Issue #327: propagate the failure — freeing temp_stack while the
         * map still holds it would leave a dangling map entry. */
        if (delete_protocol_stack_from_map(s_id) == 0) {
            mmt_stderr_log( "[error] unregister_protocol_stack - failed to remove stack %u from the protocol stack map\n", (unsigned) s_id);
            return 0;
        }
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


bool is_free_protocol_id_for_registration(uint32_t proto_id) {
    if (proto_id >= PROTO_MAX_IDENTIFIER) return 0; //The prtocol id is not valid

    protocol_t *proto = configured_protocols[proto_id];
    if ( !proto ) return 1; // protocol just doesn't exist (plugin ?)
    if ( proto->is_registered ) return 0; //The protocol is already registered

    return 1; // Cool we can use this protocol id
}

/* Issue #546: the misspelled original, kept exported (deprecated) for plugins built against it. */
bool is_free_protocol_id_for_registractionl(uint32_t proto_id) {
    return is_free_protocol_id_for_registration(proto_id);
}

void init_protocol_struct(protocol_t * proto) {
    /* Issue #327: initialize every field explicitly. The struct is memset to
     * zero at allocation (init_extraction), so the NULL/0 assignments are
     * belt-and-suspenders guarding a future non-zeroed allocation path.
     * proto_id, protocol_name, protocol_code and is_registered are left to
     * the caller — they carry the caller-supplied identity, not a default. */
    proto->session_key_compare = NULL;
    proto->session_key_hash = NULL;
    proto->session_key_equal = NULL;
    proto->session_data_init = NULL;
    proto->session_data_cleanup = NULL;
    proto->session_context_cleanup = NULL;
    proto->classify_next.pre_classify = NULL;
    proto->classify_next.classify_protos = NULL;
    proto->classify_next.post_classify = NULL;
    proto->data_analyser.pre_analyse = NULL;
    proto->data_analyser.analyse = NULL;
    proto->data_analyser.post_analyse = NULL;
    proto->update_protocol_fct = NULL;

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
    if (is_free_protocol_id_for_registration(proto_id) && configured_protocols[proto_id] != NULL) { // #505: no slot to init
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

/* Issue #549: the raw descriptor slot, registered or not — the pointer
 * mmt_init_handler() snapshots into the handler's configured_protocols[]. */
protocol_t *get_protocol_slot(uint32_t proto_id) {
    return _is_valid_protocol_id(proto_id) ? configured_protocols[proto_id] : NULL;
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

bool register_protocol(protocol_t *proto, uint32_t proto_id) {
    // Issue #22: guard the global registry mutation. Held only on this
    // registration path, never on the per-packet hot path (which reads the
    // per-handler snapshot, see configured_protocols declaration).
    int retval = PROTO_NOT_REGISTERED;
    pthread_mutex_lock(&configured_protocols_mutex);
    if (is_free_protocol_id_for_registration(proto_id)) {
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

/* Issue #673: a registered slot, checked directly. is_free_protocol_id_for_registration()
 * returns 0 for an out-of-range id as well as for a registered one, so its 0 must
 * never be read as "registered": that indexed past configured_protocols[]. */
static inline bool _is_registered_slot(uint32_t proto_id) {
    return _is_valid_protocol_id(proto_id) && configured_protocols[proto_id] != NULL
            && configured_protocols[proto_id]->is_registered;
}

bool unregister_protocol_by_id(uint32_t proto_id) {
    // Issue #22: guard the global registry mutation (see register_protocol).
    int retval = 0;
    pthread_mutex_lock(&configured_protocols_mutex);
    if (_is_registered_slot(proto_id)) {
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
        if (_is_registered_slot(i)) {
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
        mmt_stderr_log( "Error while loading plugins\n");
        return 0;
    }

    return 1;
}

void mmt_print_info() {
    mmt_stream_printf(stdout, "%s", MMT_PRINT_INFO);
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

    if (!init_plugins()) return 0; // Issue #503: a plugin load/init failure fails init_extraction()
    if (!init_handlers_map()) {
        // Issue #200 (F-BUG-003): same unchecked-nothrow-new guard as above.
        mmt_stderr_log( "Error during initialization (out of memory)\n");
        return 0;
    }
    return 1;
}

void close_extraction() {
    debug("CLOSE EXTRACTION!!!!!");
    //Close the registered handlers and delete the handlers map
    close_handlers_map();
    // Iterate over the registered protocol stacks
    iterate_through_protocol_stacks(protocol_stack_callback_fct, NULL);
    // Clear the protocol stacks map
    clear_protocol_stack_map();
    // Free the protocol structs
    free_registered_protocols();
    // unload plugins
    close_plugins();
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
