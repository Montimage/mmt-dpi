/*
 * packet_registry_classify.c — per-protocol callback registration: the
 * classification chain, the session-data analysis chain and the session
 * callbacks a plugin attaches to its protocol_t. Split out of
 * packet_registry.c (issue #549); the protocol table itself stays there.
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

/* Issue #562 (F-PERF-012): the checker-id table (packet_processing.h,
 * mmt_classifier_by_id()). Registration is rare and may come from several
 * plugins' init, so ids are handed out under a mutex; workers only load a
 * slot (acquire), never under the lock. */
mmt_classify_proto_t * mmt_classifier_slots[MMT_CLASSIFIER_ID_SLOTS];
static pthread_mutex_t mmt_classifier_slots_lock = PTHREAD_MUTEX_INITIALIZER;

uint16_t mmt_classifier_id_assign(mmt_classify_proto_t * node) {
    uint16_t id = 0;
    pthread_mutex_lock(&mmt_classifier_slots_lock);
    for (uint16_t i = 1; i < MMT_CLASSIFIER_ID_SLOTS; i++) {
        if (__atomic_load_n(&mmt_classifier_slots[i], __ATOMIC_RELAXED) == NULL) {
            __atomic_store_n(&mmt_classifier_slots[i], node, __ATOMIC_RELEASE);
            id = i;
            break;
        }
    }
    pthread_mutex_unlock(&mmt_classifier_slots_lock);
    node->id = id;
    return id;
}

void mmt_classifier_id_release(mmt_classify_proto_t * node) {
    if (node == NULL || node->id == 0 || node->id >= MMT_CLASSIFIER_ID_SLOTS) {
        return;
    }
    pthread_mutex_lock(&mmt_classifier_slots_lock);
    if (__atomic_load_n(&mmt_classifier_slots[node->id], __ATOMIC_RELAXED) == node) {
        __atomic_store_n(&mmt_classifier_slots[node->id], NULL, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&mmt_classifier_slots_lock);
    node->id = 0;
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
    (void) mmt_classifier_id_assign(temp); /* issue #562: 0 when the table is full */

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
    /* Issue #560: a registration after the freeze (a late plugin, an
     * embedder's own checker) drops the frozen copy; the walk uses the list
     * until the next mmt_init_handler() re-freezes it. */
    mmt_classify_chain_invalidate(&proto->classify_next);

    return 1;
}

/* Issue #560 (F-PERF-005, checker walk part 1): freezing. Serialises the
 * freezes of handlers created concurrently (docs/THREADING.md: creating
 * handlers from several threads is supported); never taken per packet. */
static pthread_mutex_t classify_freeze_mutex = PTHREAD_MUTEX_INITIALIZER;

static void classify_entry_fill(mmt_classify_entry_t *e, mmt_classify_proto_t *n) {
    e->classify_me = n->classify_me;
    e->node = n;
    e->selection_mask = n->selection_mask;
    e->excluded_proto = (uint16_t) n->excluded_proto;
    e->detection = n->detection;
    e->excluded_slot = n->excluded_slot;
    e->legacy = n->legacy;
}

/**
 * Freeze a chain: copy its weight-sorted list, in list order, into one
 * contiguous mmt_classify_chain_t and publish it. Every checker goes into
 * entries[]; the non-legacy ones, in the same relative order, also into
 * default_entries[], so both walks visit exactly the checkers — in exactly
 * the order — the list walk did.
 * @return 1 when the chain is frozen (or empty), 0 when out of memory — the
 *         walk then keeps using the list, so nothing is lost but speed
 */
int mmt_classify_chain_freeze(mmt_classify_next_t *cn) {
    mmt_classify_proto_t *n;
    mmt_classify_chain_t *chain;
    uint32_t count = 0, default_count = 0, i = 0, j = 0;

    if (__atomic_load_n(&cn->frozen, __ATOMIC_ACQUIRE) != NULL || cn->classify_protos == NULL) {
        return 1;
    }
    for (n = cn->classify_protos; n != NULL; n = n->next) {
        count++;
        default_count += n->legacy ? 0 : 1;
    }
    chain = mmt_malloc(sizeof (*chain) + (size_t) (count + default_count) * sizeof (chain->entries[0]));
    if (chain == NULL) {
        return 0;
    }
    chain->retired_next = NULL;
    chain->count = count;
    chain->default_count = default_count;
    chain->default_entries = chain->entries + count;
    for (n = cn->classify_protos; n != NULL; n = n->next) {
        classify_entry_fill(&chain->entries[i++], n);
        if (!n->legacy) {
            classify_entry_fill(&chain->default_entries[j++], n);
        }
    }
    __atomic_store_n(&cn->frozen, chain, __ATOMIC_RELEASE);
    return 1;
}

/* Freeze every registered protocol's chain that is not frozen yet. Called by
 * mmt_init_handler(): after init_extraction() and every plugin registration
 * (the docs/THREADING.md order), and again after a late registration. */
void mmt_classify_chains_freeze(void) {
    uint32_t i;
    pthread_mutex_lock(&classify_freeze_mutex);
    for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        protocol_t *proto = get_protocol_struct_by_id(i);
        if (proto != NULL) {
            (void) mmt_classify_chain_freeze(&proto->classify_next);
        }
    }
    pthread_mutex_unlock(&classify_freeze_mutex);
}

/* Free a chain's frozen copy and the copies later registrations retired. */
void mmt_classify_chain_release(mmt_classify_next_t *cn) {
    mmt_classify_chain_t *chain;
    mmt_classify_chain_invalidate(cn); /* the frozen copy joins the retired list */
    chain = cn->retired;
    cn->retired = NULL;
    while (chain != NULL) {
        mmt_classify_chain_t *next = chain->retired_next;
        mmt_free(chain);
        chain = next;
    }
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
    proto->sessionize = sessionizer_fct;
    proto->session_context_cleanup = session_context_cleanup_fct;
    proto->has_session = HAS_SESSION_CONTEXT;
    proto->session_key_compare = session_keys_comparison_fct;
}

void register_session_hash_function(protocol_t *proto, generic_hash_fct session_key_hash_fct) {
    proto->session_key_hash = session_key_hash_fct;
}

void register_session_equal_function(protocol_t *proto, generic_equal_fct session_key_equal_fct) {
    proto->session_key_equal = session_key_equal_fct;
}

void register_proto_context_init_cleanup_function(protocol_t *proto, generic_proto_context_init_function context_init_fct,
        generic_proto_context_cleanup_function context_cleanup_fct, void * args) {
    proto->protocol_context_init = context_init_fct;
    proto->protocol_context_cleanup = context_cleanup_fct;
    proto->protocol_context_args = args;
}

void register_session_data_initialization_function(protocol_t *proto, generic_session_data_initialization_function session_data_init_fct) {
    proto->session_data_init = session_data_init_fct;
}

void register_session_data_cleanup_function(protocol_t *proto, generic_session_data_cleanup_function session_data_cleanup_fct) {
    proto->session_data_cleanup = session_data_cleanup_fct;
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

/* Issue #116: the upgrade classifiers. A protocol that upgrades a session
 * to another one (HTTP after a 101 Switching Protocols) offers the session
 * to the classifiers registered for it, in weight order, through
 * mmt_session_offer_upgrade(); one claims it by calling
 * mmt_session_handover(). The registry is a sorted array, copy-on-write as
 * the frozen chains of issue #560 are: a registration builds a new copy
 * under the mutex and publishes it with a release store, an offer reads the
 * published copy with an acquire load and never locks, and the replaced
 * copies are freed only at teardown (a worker may still walk one). */
typedef struct mmt_upgrade_entry_struct {
    uint32_t parent_proto_id;
    int weight;
    generic_classification_function classify;
} mmt_upgrade_entry_t;

typedef struct mmt_upgrade_chain_struct {
    struct mmt_upgrade_chain_struct * retired_next;
    uint32_t count;
    mmt_upgrade_entry_t entries[];
} mmt_upgrade_chain_t;

static pthread_mutex_t mmt_upgrade_lock = PTHREAD_MUTEX_INITIALIZER;
static mmt_upgrade_chain_t * mmt_upgrade_chain = NULL;   /* published copy */
static mmt_upgrade_chain_t * mmt_upgrade_retired = NULL; /* replaced copies */

bool register_upgrade_classification_function(uint32_t parent_proto_id,
        generic_classification_function classification_fct, int weight) {
    mmt_upgrade_chain_t * old, * chain;
    uint32_t n, i, j = 0;
    if (classification_fct == NULL || !is_valid_protocol_id(parent_proto_id)) return false;
    if (weight < 0) weight = 0;
    if (weight > 100) weight = 100;
    pthread_mutex_lock(&mmt_upgrade_lock);
    old = __atomic_load_n(&mmt_upgrade_chain, __ATOMIC_RELAXED);
    n = (old != NULL) ? old->count : 0;
    chain = mmt_malloc(sizeof (*chain) + (size_t) (n + 1) * sizeof (chain->entries[0]));
    if (chain == NULL) {
        pthread_mutex_unlock(&mmt_upgrade_lock);
        return false;
    }
    chain->retired_next = NULL;
    chain->count = n + 1;
    /* after every entry of the same or a lower weight: equal weights keep
     * their registration order */
    for (i = 0; i < n && old->entries[i].weight <= weight; i++) chain->entries[j++] = old->entries[i];
    chain->entries[j].parent_proto_id = parent_proto_id;
    chain->entries[j].weight = weight;
    chain->entries[j].classify = classification_fct;
    j++;
    for (; i < n; i++) chain->entries[j++] = old->entries[i];
    __atomic_store_n(&mmt_upgrade_chain, chain, __ATOMIC_RELEASE);
    if (old != NULL) {
        old->retired_next = mmt_upgrade_retired;
        mmt_upgrade_retired = old;
    }
    pthread_mutex_unlock(&mmt_upgrade_lock);
    return true;
}

bool mmt_session_offer_upgrade(ipacket_t * ipacket, unsigned index) {
    const mmt_upgrade_chain_t * chain;
    uint32_t parent, i;
    if (ipacket == NULL || ipacket->session == NULL || ipacket->proto_hierarchy == NULL
            || index >= PROTO_PATH_SIZE || (int) index >= ipacket->proto_hierarchy->len) {
        return false;
    }
    /* a handover is already pending: nothing to offer */
    if (ipacket->session->handover_index != 0) return false;
    chain = __atomic_load_n(&mmt_upgrade_chain, __ATOMIC_ACQUIRE);
    if (chain == NULL) return false;
    parent = (uint32_t) ipacket->proto_hierarchy->proto_path[index];
    for (i = 0; i < chain->count; i++) {
        if (chain->entries[i].parent_proto_id != parent) continue;
        (void) chain->entries[i].classify(ipacket, index);
        /* the classifier claimed the session through mmt_session_handover() */
        if (ipacket->session->handover_index != 0) return true;
    }
    return false;
}

void mmt_upgrade_registry_release(void) {
    mmt_upgrade_chain_t * chain;
    pthread_mutex_lock(&mmt_upgrade_lock);
    chain = __atomic_load_n(&mmt_upgrade_chain, __ATOMIC_RELAXED);
    __atomic_store_n(&mmt_upgrade_chain, NULL, __ATOMIC_RELEASE);
    mmt_free(chain);
    chain = mmt_upgrade_retired;
    mmt_upgrade_retired = NULL;
    while (chain != NULL) {
        mmt_upgrade_chain_t * next = chain->retired_next;
        mmt_free(chain);
        chain = next;
    }
    pthread_mutex_unlock(&mmt_upgrade_lock);
}

bool mmt_protocol_set_process_claimed_layer(protocol_t * proto, bool on) {
    if (proto == NULL) return false;
    proto->process_claimed_layer = on ? 1 : 0;
    return true;
}

/* Issue #115: deferred parent registrations. Plugins load in file-name order
 * (plugins_engine.c), so a plugin can register a classifier under a protocol
 * that a plugin loaded after it provides. While mmt_classify_deferred_load()
 * runs the plugin load, such a registration is kept here, in registration
 * order, and attached when register_protocol() registers the parent; what is
 * left when the load ends fails it. The list never outlives the load: the
 * entries hold function pointers into plugins that close_plugins() unloads.
 * mmt_deferred_lock covers the list and the open flag and is never held with
 * configured_protocols_mutex or while a classifier is attached. */
typedef struct mmt_deferred_classify_struct {
    struct mmt_deferred_classify_struct * next;
    uint32_t parent_proto_id;
    uint32_t child_proto_id;
    int weight;
    generic_classification_function classify;
} mmt_deferred_classify_t;

static pthread_mutex_t mmt_deferred_lock = PTHREAD_MUTEX_INITIALIZER;
static mmt_deferred_classify_t * mmt_deferred_head = NULL;
static mmt_deferred_classify_t ** mmt_deferred_tail = &mmt_deferred_head;
static int mmt_deferred_open = 0; /* a plugin load is in progress */

/* Appends; called with mmt_deferred_lock held. The stores to the list
 * links are atomic for the unlocked emptiness check of
 * mmt_classify_deferred_attach(). */
static void deferred_append(mmt_deferred_classify_t * e) {
    e->next = NULL;
    __atomic_store_n(mmt_deferred_tail, e, __ATOMIC_RELAXED);
    mmt_deferred_tail = &e->next;
}

/* Detaches the whole list; called with mmt_deferred_lock held. */
static mmt_deferred_classify_t * deferred_take_all(void) {
    mmt_deferred_classify_t * list = mmt_deferred_head;
    __atomic_store_n(&mmt_deferred_head, NULL, __ATOMIC_RELAXED);
    mmt_deferred_tail = &mmt_deferred_head;
    return list;
}

bool register_classification_function_with_parent_protocol_deferred(uint32_t parent_proto_id,
        uint32_t child_proto_id, generic_classification_function classification_fct, int weight) {
    protocol_t * parent;
    mmt_deferred_classify_t * e;
    if (classification_fct == NULL || !is_valid_protocol_id(parent_proto_id)
            || !is_valid_protocol_id(child_proto_id)) {
        return false;
    }
    if (weight < 0) weight = 0;
    if (weight > 100) weight = 100;
    pthread_mutex_lock(&mmt_deferred_lock);
    /* checked under the lock: a parent registered after this check is
     * drained by mmt_classify_deferred_attach(), which takes the lock too */
    parent = get_protocol_struct_by_protocol_id(parent_proto_id);
    if (parent != NULL || !mmt_deferred_open) {
        pthread_mutex_unlock(&mmt_deferred_lock);
        return parent != NULL && register_classification_function_internal(parent, classification_fct, weight);
    }
    e = mmt_malloc(sizeof (*e));
    if (e != NULL) {
        e->parent_proto_id = parent_proto_id;
        e->child_proto_id = child_proto_id;
        e->weight = weight;
        e->classify = classification_fct;
        deferred_append(e);
    }
    pthread_mutex_unlock(&mmt_deferred_lock);
    return e != NULL;
}

void mmt_classify_deferred_attach(uint32_t parent_proto_id) {
    mmt_deferred_classify_t * list, * e, * keep = NULL, ** keep_tail = &keep, * mine = NULL, ** mine_tail = &mine;
    protocol_t * parent;
    /* every protocol registration comes here: no lock while nothing waits */
    if (__atomic_load_n(&mmt_deferred_head, __ATOMIC_RELAXED) == NULL) return;
    pthread_mutex_lock(&mmt_deferred_lock);
    list = deferred_take_all();
    while (list != NULL) {
        e = list;
        list = e->next;
        e->next = NULL;
        if (e->parent_proto_id == parent_proto_id) { *mine_tail = e; mine_tail = &e->next; }
        else { *keep_tail = e; keep_tail = &e->next; }
    }
    for (e = keep; e != NULL; e = keep) { keep = e->next; deferred_append(e); }
    pthread_mutex_unlock(&mmt_deferred_lock);
    parent = get_protocol_struct_by_protocol_id(parent_proto_id);
    while (mine != NULL) {
        e = mine;
        mine = e->next;
        if (parent != NULL && register_classification_function_internal(parent, e->classify, e->weight)) {
            mmt_free(e);
        } else {
            /* out of memory: left pending, so the load fails and reports it */
            pthread_mutex_lock(&mmt_deferred_lock);
            deferred_append(e);
            pthread_mutex_unlock(&mmt_deferred_lock);
        }
    }
}

static const char * deferred_name(uint32_t proto_id) {
    const char * name = get_protocol_name_by_id(proto_id);
    return (name != NULL) ? name : "unregistered";
}

int mmt_classify_deferred_load(int (*load)(void)) {
    mmt_deferred_classify_t * left, * e;
    int ok;
    pthread_mutex_lock(&mmt_deferred_lock);
    mmt_deferred_open = 1;
    pthread_mutex_unlock(&mmt_deferred_lock);
    ok = load();
    pthread_mutex_lock(&mmt_deferred_lock);
    mmt_deferred_open = 0;
    left = deferred_take_all();
    pthread_mutex_unlock(&mmt_deferred_lock);
    while (left != NULL) {
        e = left;
        left = e->next;
        if (get_protocol_struct_by_protocol_id(e->parent_proto_id) == NULL) {
            mmt_stderr_log("The classifier of protocol %u (%s) is registered under protocol %u (%s), "
                    "which no plugin registered\n", e->child_proto_id, deferred_name(e->child_proto_id),
                    e->parent_proto_id, deferred_name(e->parent_proto_id));
        } else {
            mmt_stderr_log("The classifier of protocol %u (%s) could not be attached to protocol %u (%s) "
                    "(out of memory)\n", e->child_proto_id, deferred_name(e->child_proto_id),
                    e->parent_proto_id, deferred_name(e->parent_proto_id));
        }
        mmt_free(e);
        ok = 0;
    }
    return ok;
}

void mmt_classify_deferred_release(void) {
    mmt_deferred_classify_t * list, * e;
    pthread_mutex_lock(&mmt_deferred_lock);
    mmt_deferred_open = 0;
    list = deferred_take_all();
    pthread_mutex_unlock(&mmt_deferred_lock);
    while (list != NULL) {
        e = list;
        list = e->next;
        mmt_free(e);
    }
}
