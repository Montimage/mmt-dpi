/*
 * packet_registry_attr.c — per-handler extraction-attribute, attribute-handler
 * and packet-handler registration. Split out of packet_registry.c
 * (issue #549).
 */
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

/* Issue #252 (F-PERF-017): geometric growth for the frozen registration
 * arrays (proto_registered_attributes, proto_registered_attribute_handlers,
 * attribute_handlers, packet_handlers). Returns the array pointer — possibly
 * relocated — or NULL when growth was needed and the realloc failed, leaving
 * the caller's original pointer untouched. */
static void * grow_registration_array(void *arr, uint32_t *cap, uint32_t elem_size, uint32_t need) {
    if (*cap >= need) return arr;
    uint32_t new_cap = (*cap != 0) ? *cap : 4;
    while (new_cap < need) new_cap *= 2;
    void *grown = mmt_realloc(arr, (size_t) new_cap * elem_size);
    if (grown == NULL) return NULL;
    *cap = new_cap;
    return grown;
}

/* Issue #556 (F-PERF-003): the per-protocol index of mmt_handler_t
 * (proto_attr_index) maps an indexable attribute id straight to its slot in
 * the registry; every helper below looks attributes up through
 * mmt_find_registered_attribute() (packet_processing.h) instead of scanning
 * proto_registered_attributes. Ids the index does not cover fall back to
 * this binary search — the array is kept sorted by field_id (issue #252). */
attribute_internal_t * search_registered_attribute(const mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    if (proto_id >= PROTO_MAX_IDENTIFIER) return NULL;
    attribute_internal_t * const * attrs = mmt_handler->proto_registered_attributes[proto_id];
    uint32_t lo = 0, hi = mmt_handler->proto_registered_attributes_len[proto_id];
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (attrs[mid]->field_id < field_id) lo = mid + 1;
        else hi = mid;
    }
    return (lo < mmt_handler->proto_registered_attributes_len[proto_id] && attrs[lo]->field_id == field_id)
            ? attrs[lo] : NULL;
}

/* Issue #556: make the index of proto_id cover `slot` (new slots NULL).
 * Returns 0 when the growth failed, leaving the index untouched. */
static int reserve_attribute_index_slot(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t slot) {
    uint32_t len = mmt_handler->proto_attr_index[proto_id].len;
    if (slot == MMT_ATTR_INDEX_NONE || slot < len) return 1;
    uint32_t new_len = (slot + 8u) & ~7u; /* slot + 1, rounded up to 8 slots */
    attribute_internal_t ** grown = (attribute_internal_t **) mmt_realloc(mmt_handler->proto_attr_index[proto_id].slots,
            (size_t) new_len * sizeof(*grown));
    if (grown == NULL) return 0;
    memset(&grown[len], 0, (size_t) (new_len - len) * sizeof(*grown));
    mmt_handler->proto_attr_index[proto_id].slots = grown;
    mmt_handler->proto_attr_index[proto_id].len = new_len;
    return 1;
}

/* Issue #556: point the index slot of field_id at attr (NULL to clear). */
static void set_attribute_index_slot(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id,
        attribute_internal_t *attr) {
    uint32_t slot = mmt_attr_index_slot(field_id);
    if (slot != MMT_ATTR_INDEX_NONE && slot < mmt_handler->proto_attr_index[proto_id].len) {
        mmt_handler->proto_attr_index[proto_id].slots[slot] = attr;
    }
}

struct attribute_internal_struct * get_registered_attribute_internal_struct(const ipacket_t * ipacket, uint32_t proto_id, uint32_t attribute_id, unsigned index) {
    (void) index;
    return mmt_find_registered_attribute(ipacket->mmt_handler, proto_id, attribute_id);
}

bool is_registered_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id) {
    for (uint32_t i = 0; i < mmt_handler->packet_handlers_len; i++) {
        if (mmt_handler->packet_handlers[i].packet_handler_id == packet_handler_id) return 1;
    }
    return 0;
}

bool is_registered_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    return mmt_find_registered_attribute(mmt_handler, proto_id, field_id) != NULL;
}

struct attribute_internal_struct * get_registered_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    if (is_registered_protocol(proto_id) > 0) {
        return mmt_find_registered_attribute(mmt_handler, proto_id, field_id);
    }
    return NULL;
}

bool has_registered_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t attribute_id) {
    attribute_internal_t * attr = mmt_find_registered_attribute(mmt_handler, proto_id, attribute_id);
    return attr != NULL && attr->handlers_count > 0 /* The attribute has at least one registered handler */;
}

bool is_registered_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id,
                                    uint32_t attribute_id, attribute_handler_function handler_fct) {
    attribute_internal_t * attr = mmt_find_registered_attribute(mmt_handler, proto_id, attribute_id);
    if (attr == NULL) {
        return 0;
    }
    for (int j = 0; j < attr->handlers_count; j++) {
        if (attr->attribute_handlers[j].handler_fct == handler_fct) {
            return 1;
        }
    }
    return 0;
}

/* Issue #501 (F-BUG-004): release an attribute unlinked from the registry.
 * Inside an attribute dispatch loop the loop may still hold the pointer, so
 * the free waits for flush_deferred_attribute_frees(). */
static void release_registered_attribute(mmt_handler_t *mmt_handler, attribute_internal_t *attr) {
    if (mmt_handler->attr_dispatch_depth > 0) {
        attr->next = mmt_handler->attr_free_pending;
        mmt_handler->attr_free_pending = attr;
        return;
    }
    mmt_free(attr->attribute_handlers);
    mmt_free(attr);
}

void flush_deferred_attribute_frees(mmt_handler_t *mmt_handler) {
    attribute_internal_t *attr = mmt_handler->attr_free_pending;
    mmt_handler->attr_free_pending = NULL;
    while (attr != NULL) {
        attribute_internal_t *next = attr->next;
        mmt_free(attr->attribute_handlers);
        mmt_free(attr);
        attr = next;
    }
}

void free_registered_extraction_attributes(mmt_handler_t *mmt_handler) {
    flush_deferred_attribute_frees(mmt_handler);
    mmt_packet_scratch_destroy(mmt_handler); // issue #506: adopted attribute values
    for (int i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        attribute_internal_t ** attrs = mmt_handler->proto_registered_attributes[i];
        uint32_t n = mmt_handler->proto_registered_attributes_len[i];
        for (uint32_t j = 0; j < n; j++) {
            mmt_free(attrs[j]->attribute_handlers); // the frozen handler array of the attribute
            mmt_free(attrs[j]); // we free the internal attribute struct
        }
        mmt_free(attrs); // we free the contiguous attribute array itself
        mmt_handler->proto_registered_attributes[i] = NULL;
        mmt_handler->proto_registered_attributes_len[i] = 0;
        mmt_handler->proto_registered_attributes_cap[i] = 0;
        mmt_free(mmt_handler->proto_attr_index[i].slots); // issue #556: the attribute index
        mmt_handler->proto_attr_index[i].slots = NULL;
        mmt_handler->proto_attr_index[i].len = 0;
    }
}

void free_registered_attribute_handlers(mmt_handler_t *mmt_handler) {
    for (int i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        /* Issue #252 (F-PERF-017): the handler elements live in one contiguous
         * block — the per-attribute handler arrays are owned by the
         * attribute_internal_t elements and released by
         * free_registered_extraction_attributes(). */
        mmt_free(mmt_handler->proto_registered_attribute_handlers[i]);
        mmt_handler->proto_registered_attribute_handlers[i] = NULL;
        mmt_handler->proto_registered_attribute_handlers_len[i] = 0;
        mmt_handler->proto_registered_attribute_handlers_cap[i] = 0;
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

/* Issue #501 (F-BUG-017): drop_registration is false when the caller never
 * counted a registration — a handler that joined an existing slot — so the
 * count is left alone and the slot is only released once both counts are
 * zero. */
static void release_extraction_registration(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id,
        int drop_registration) {

    struct attribute_internal_struct * temp_attr_proto_list;
    struct attribute_internal_struct * safe_to_delete_attr_for_proto = NULL;

    temp_attr_proto_list = get_registered_attribute(mmt_handler, proto_id, field_id);
    if (!temp_attr_proto_list) { //The attribute does not exist, return with no further action
        return;
    }

    // The attribute exists, two cases are possible
    //     1- The attribute registration count is positive, decrement its registration count, no further action
    //     2- The attribute registration count is equal to one, We decrement its registration count, two cases are possible
    //       2.1- the attribute's handlers_count equal to zero, the attribute can be safely deleted
    //       2.1- the attribute's handlers_count is positive, no further action is required.

    if (drop_registration && temp_attr_proto_list->registration_count) {
        // We decrement the value only if it is positive! to avoid negative values
        temp_attr_proto_list->registration_count--;
    }

    if (!temp_attr_proto_list->registration_count && !temp_attr_proto_list->handlers_count) { // Both values are non positive! we delete it
        /* Issue #252 (F-PERF-017): remove the element from the contiguous
         * array — the slot is closed by memmove so the per-packet walk never
         * sees a gap. */
        struct attribute_internal_struct ** attrs = mmt_handler->proto_registered_attributes[proto_id];
        uint32_t n = mmt_handler->proto_registered_attributes_len[proto_id];

        for (uint32_t i = 0; i < n; i++) {
            if ((attrs[i]->field_id == field_id) && (attrs[i]->proto_id == proto_id)) {
                safe_to_delete_attr_for_proto = attrs[i];
                memmove(&attrs[i], &attrs[i + 1], (n - i - 1) * sizeof(*attrs));
                mmt_handler->proto_registered_attributes_len[proto_id] = n - 1;
                set_attribute_index_slot(mmt_handler, proto_id, field_id, NULL); // issue #556
                break;
            }
        }

        if (safe_to_delete_attr_for_proto != NULL) {
            release_registered_attribute(mmt_handler, safe_to_delete_attr_for_proto);
        }
    }
}

bool unregister_extraction_attribute(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t field_id) {
    release_extraction_registration(mmt_handler, proto_id, field_id, 1);
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
    attribute_internal_t * temp_attr = NULL;
    if (!is_registered_attribute_handler(mmt_handler, proto_id, attribute_id, handler_fct)) {
        return 1;
    }

    //Get the attribute (registered: is_registered_attribute_handler() found it)
    temp_attr = mmt_find_registered_attribute(mmt_handler, proto_id, attribute_id);

    /* Issue #252 (F-PERF-017): the handlers are a contiguous array on the
     * attribute — drop the matching slot with memmove. handlers_count is the
     * element count; it is decremented below as before. */
    {
        int hc = temp_attr->handlers_count;
        for (int i = 0; i < hc; i++) {
            if (temp_attr->attribute_handlers[i].handler_fct == handler_fct) {
                memmove(&temp_attr->attribute_handlers[i], &temp_attr->attribute_handlers[i + 1],
                        (hc - i - 1) * sizeof(attribute_handler_t));
                break;
            }
        }
    }

    if ((temp_attr->handlers_count <= 1) && !(mmt_attr_get_scope_typed((const attribute_t *) temp_attr) & SCOPE_EVENT)) {
        //We need to delete the attribute handler element as there are no more registered handler functions
        attribute_handler_element_t * elems = mmt_handler->proto_registered_attribute_handlers[proto_id];
        uint32_t n = mmt_handler->proto_registered_attribute_handlers_len[proto_id];
        for (uint32_t i = 0; i < n; i++) {
            if (elems[i].attribute->proto_id == proto_id && elems[i].attribute->field_id == attribute_id) {
                memmove(&elems[i], &elems[i + 1], (n - i - 1) * sizeof(*elems));
                mmt_handler->proto_registered_attribute_handlers_len[proto_id] = n - 1;
                break;
            }
        }
    }

    //Decrement by one the handlers count of the attribute
    temp_attr->handlers_count -= 1;
    /* Issue #501 (F-BUG-017): give back the extraction registration only if
     * this handler's registration created the slot (and counted it). */
    int owned = (temp_attr->extraction_owner == handler_fct);
    if (owned) {
        temp_attr->extraction_owner = NULL;
    }
    release_extraction_registration(mmt_handler, proto_id, attribute_id, owned);
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
    if (proto == NULL) {
        return 0;
    }
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
        }
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

        /* Issue #252 (F-PERF-017): insert into the contiguous array keeping
         * the field_id ascending order the old sorted-insert list kept. */
        uint32_t reg_proto = extract_attribute->proto_id;
        uint32_t n = mmt_handler->proto_registered_attributes_len[reg_proto];
        void *grown = grow_registration_array(mmt_handler->proto_registered_attributes[reg_proto],
                &mmt_handler->proto_registered_attributes_cap[reg_proto],
                sizeof(attribute_internal_t *), n + 1);
        if (grown == NULL) {
            mmt_free(extract_attribute);
            return 0;
        }
        struct attribute_internal_struct ** attrs = (struct attribute_internal_struct **) grown;
        mmt_handler->proto_registered_attributes[reg_proto] = attrs;
        /* Issue #556: reserve the index slot before linking the attribute,
         * so a failed growth leaves the registry as it was. */
        if (!reserve_attribute_index_slot(mmt_handler, reg_proto, mmt_attr_index_slot(field_id))) {
            mmt_free(extract_attribute);
            return 0;
        }

        uint32_t pos = 0;
        while (pos < n && attrs[pos]->field_id < field_id) pos++;
        memmove(&attrs[pos + 1], &attrs[pos], (n - pos) * sizeof(*attrs));
        attrs[pos] = extract_attribute;
        mmt_handler->proto_registered_attributes_len[reg_proto] = n + 1;
        set_attribute_index_slot(mmt_handler, reg_proto, field_id, extract_attribute);
    }
    //Finally we increment the registration count of this attribute.
    extract_attribute->registration_count++;
    return 1;
}

bool register_attribute_handler(mmt_handler_t *mmt_handler, uint32_t proto_id, uint32_t attribute_id, attribute_handler_function handler_fct, void * handler_condition, void * user_args) {
    int retval = 0;

    if (is_registered_attribute_handler(mmt_handler, proto_id, attribute_id, handler_fct)) {
        /* Issue #327: the handler is already registered for this attribute —
         * a caller error distinct from an engine failure; say so on the
         * debug channel instead of returning a silent 0. */
        mmt_debug_log( "[error] register_attribute_handler - handler already registered for attribute %u of protocol %u\n",
                (unsigned) attribute_id, (unsigned) proto_id);
        return 0;
    }

    struct attribute_internal_struct * attr = get_registered_attribute(mmt_handler, proto_id, attribute_id);
    if (!attr) {
        retval = register_extraction_attribute(mmt_handler, proto_id, attribute_id);
        if (!retval) {
            // An error occurred — the attribute could not be registered for extraction.
            mmt_stderr_log( "[error] register_attribute_handler - failed to register attribute %u of protocol %u for extraction\n",
                    (unsigned) attribute_id, (unsigned) proto_id);
            return 0;
        }
    }

    attr = get_registered_attribute(mmt_handler, proto_id, attribute_id);
    if (attr == NULL) {
        /* Issue #327: unreachable in practice — the lookup above either
         * found the attribute or registered it successfully. Kept as a
         * defensive check; treat it as an engine inconsistency if it fires. */
        mmt_stderr_log( "[error] register_attribute_handler - attribute %u of protocol %u vanished after registration\n",
                (unsigned) attribute_id, (unsigned) proto_id);
        return 0;
    }

    /* Issue #252 (F-PERF-017): handlers live in a contiguous array on the
     * attribute (index 0 = most recently registered, preserving the old
     * head-insert order) and the per-protocol handler elements in a
     * contiguous array sorted by field_id. Grow both before mutating so a
     * single allocation failure leaves registration state untouched. */
    int first_handler = (attr->handlers_count == 0);
    int needs_elem = first_handler &&
            !(mmt_attr_get_scope_typed((const attribute_t *) attr) & SCOPE_EVENT);

    void *grown_handlers = grow_registration_array(attr->attribute_handlers,
            &attr->attribute_handlers_cap, sizeof(attribute_handler_t),
            (uint32_t) attr->handlers_count + 1);
    if (grown_handlers == NULL) {
        if (retval) unregister_extraction_attribute(mmt_handler, proto_id, attribute_id); // If we get here then the attribute
        // handler creation failed, and previously in this function
        // the attribute was registered (retval was initially set to 0)
        // We unregister the registered attribute to undo any action done in this function
        return 0;
    }
    attr->attribute_handlers = (attribute_handler_t *) grown_handlers;

    if (needs_elem) {
        uint32_t elen = mmt_handler->proto_registered_attribute_handlers_len[proto_id];
        void *grown_elems = grow_registration_array(mmt_handler->proto_registered_attribute_handlers[proto_id],
                &mmt_handler->proto_registered_attribute_handlers_cap[proto_id],
                sizeof(attribute_handler_element_t), elen + 1);
        if (grown_elems == NULL) {
            if (retval) unregister_extraction_attribute(mmt_handler, proto_id, attribute_id);
            return 0;
        }
        attribute_handler_element_t * elems = (attribute_handler_element_t *) grown_elems;
        mmt_handler->proto_registered_attribute_handlers[proto_id] = elems;

        uint32_t pos = 0;
        while (pos < elen && elems[pos].attribute->field_id < attribute_id) pos++;
        memmove(&elems[pos + 1], &elems[pos], (elen - pos) * sizeof(*elems));
        elems[pos].attribute = attr;
        elems[pos].next = NULL;
        mmt_handler->proto_registered_attribute_handlers_len[proto_id] = elen + 1;
    }

    memmove(&attr->attribute_handlers[1], &attr->attribute_handlers[0],
            (uint32_t) attr->handlers_count * sizeof(attribute_handler_t));
    attr->attribute_handlers[0].args = user_args;
    attr->attribute_handlers[0].handler_fct = handler_fct;
    attr->attribute_handlers[0].condition = handler_condition;
    attr->attribute_handlers[0].next = NULL;

    // The attribute handler was successfully created, we increment the handlers count of the attribute
    attr->handlers_count++;
    if (retval) {
        /* Issue #501 (F-BUG-017): this registration created the slot. */
        attr->extraction_owner = handler_fct;
    }
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
    /* Issue #252 (F-PERF-017): packet handlers live in one contiguous
     * block — a single free releases them all. */
    mmt_free(mmt_handler->packet_handlers);
    mmt_handler->packet_handlers = NULL;
    mmt_handler->packet_handlers_len = 0;
    mmt_handler->packet_handlers_cap = 0;
}

bool register_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id, generic_packet_handler_callback function, void *args) {
    if (mmt_handler == NULL) { //The mmt_handler is null
        return 0;
    }
    if (!is_registered_packet_handler(mmt_handler, packet_handler_id)) {
        /* Issue #252 (F-PERF-017): prepend into the contiguous array —
         * element 0 stays the most recently registered handler, the order
         * the old head-insert list kept. */
        void *grown = grow_registration_array(mmt_handler->packet_handlers,
                &mmt_handler->packet_handlers_cap, sizeof(packet_handler_t),
                mmt_handler->packet_handlers_len + 1);
        if (grown == NULL) {
            return 0;
        }
        mmt_handler->packet_handlers = (packet_handler_t *) grown;
        memmove(&mmt_handler->packet_handlers[1], &mmt_handler->packet_handlers[0],
                mmt_handler->packet_handlers_len * sizeof(packet_handler_t));
        mmt_handler->packet_handlers[0].packet_handler_id = packet_handler_id;
        mmt_handler->packet_handlers[0].function = function;
        mmt_handler->packet_handlers[0].args = args;
        mmt_handler->packet_handlers[0].next = NULL;
        mmt_handler->packet_handlers_len++;
    }
    return 1;
}

bool unregister_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id) {
    int retval = 1;
    uint32_t n = mmt_handler->packet_handlers_len;
    for (uint32_t i = 0; i < n; i++) {
        if (mmt_handler->packet_handlers[i].packet_handler_id == packet_handler_id) {
            /* Issue #252 (F-PERF-017): close the slot with memmove. */
            memmove(&mmt_handler->packet_handlers[i], &mmt_handler->packet_handlers[i + 1],
                    (n - i - 1) * sizeof(packet_handler_t));
            mmt_handler->packet_handlers_len = n - 1;
            return retval;
        }
    }
    return retval;
}
