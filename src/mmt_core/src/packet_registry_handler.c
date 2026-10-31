/*
 * packet_registry_handler.c — the mmt_handler_t lifecycle: creation, the
 * handler bookkeeping map, teardown and the per-handler protocol analysis /
 * classification switches. Split out of packet_registry.c (issue #549);
 * init_extraction()/close_extraction() stay there and drive the bookkeeping
 * map through init_handlers_map()/close_handlers_map() below.
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

static protocol_stack_t dummy_stack = {
    0, "dummy", dummy_stack_classification, NULL, NULL
};
static void * mmt_configured_handlers_map;
// Issue #67: mmt_configured_handlers_map is handler-lifecycle bookkeeping mutated
// by mmt_init_handler()/mmt_close_handler(). It is never touched on the per-packet
// hot path, so guarding it adds no read-path overhead. This dedicated mutex makes
// concurrent handler create/destroy race-free (mirrors the #22 registry pattern;
// kept separate from configured_protocols_mutex as it guards a different global and
// the two are never nested). The single-threaded init/teardown iteration over the
// map (init_extraction/close_extraction, see docs/THREADING.md) is exempt.
static pthread_mutex_t configured_handlers_map_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Issue #254 (F-PERF-012): hash functions for the open-addressing void* maps.
 * Each must be consistent with its comparison's equivalence: keys equal under
 * !cmp(a,b) && !cmp(b,a) have to hash equally. */

/* The handler registry keys on the pointer value itself, so equivalence is
 * pointer equality — hash the address. */
static uint64_t pointer_hash_fn(void * p) {
    return (uint64_t) (uintptr_t) p;
}

struct internal_handler_iterator_struct {
    generic_handler_iteration_callback iterator_fct;
    void * args;
};

void internal_handler_iterator_callback(void * key, void * value, void * args) {
    ((generic_handler_iteration_callback) ((struct internal_handler_iterator_struct *) args)->iterator_fct)(value, ((struct internal_handler_iterator_struct *) args)->args);
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
                    mmt_handler->configured_protocols[i].protocol->protocol_context_cleanup(&mmt_handler->configured_protocols[i], mmt_handler->configured_protocols[i].protocol->protocol_context_args);
                }
            }
        }
    }
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
    /* Issue #245: bounded TCP reassembly ceiling + pooled reassembly packets. */
    new_handler->tcp_reassembly_limit = MMT_TCP_REASSEMBLY_LIMIT_DEFAULT;
    new_handler->tcp_reassembly_budget = 0; /* issue #563: unlimited by default */
    new_handler->tcp_reasm_committed = 0;
    new_handler->ipacket_pool = NULL;
    new_handler->port_classify = 0; // Disable classification by port number by default
    new_handler->port_classify_payload_confirm = 0; // M9 (issue #75): accept any port-based guess by default (no payload confirmation required)
    new_handler->hostname_classify = 1; // Enable classification by Hostname by default
    new_handler->ip_address_classify = 1; // Enable classification by IP address by default
    // Issue #87: unlimited inspection depth by default — keep in sync with
    // MMT_DPI_PROFILE_DEFAULT (dpi_profiles.c), the test suite pins it.
    new_handler->classification_max_depth = PROTO_PATH_SIZE - 1;
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

    /* Issue #560: every plugin has registered its checkers by now
     * (docs/THREADING.md), so freeze the classification chains the walk
     * reads; a no-op for the chains an earlier handler froze. */
    mmt_classify_chains_freeze();
    for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
        new_handler->configured_protocols[i].protocol = get_protocol_slot(i);
        new_handler->configured_protocols[i].sessions_map = NULL;
        new_handler->configured_protocols[i].args = NULL;

        // Initialize the sessions context if the protocol has such context
        if (new_handler->configured_protocols[i].protocol->has_session == HAS_SESSION_CONTEXT) {
            new_handler->configured_protocols[i].sessions_map = init_session_map_space(new_handler->configured_protocols[i].protocol->session_key_compare, new_handler->configured_protocols[i].protocol->session_key_hash, new_handler->configured_protocols[i].protocol->session_key_equal);
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
                new_handler->configured_protocols[i].protocol->protocol_context_init(&new_handler->configured_protocols[i], new_handler->configured_protocols[i].protocol->protocol_context_args);
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

    /* Issue #87: last step before publishing — apply the operator-selected
     * DPI profile (MMT_DPI_PROFILES_FILE then MMT_DPI_PROFILE). Both unset
     * is the common case and leaves the built-in defaults above untouched,
     * so classification stays byte-identical to the baseline. */
    mmt_dpi_profile_apply_env(new_handler);

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
    // Explicitly time out all registered sessions, tunnel children first (issue #499)
    expire_all_sessions(mmt_handler);
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

    /* Issue #245: drain the reassembly ipacket pool — every free slot owns
     * its grow-once copy buffer. Slots still held by user callbacks are not
     * on the freelist; they are released when their ipacket is cleaned (a
     * held packet past handler teardown was already a user-side lifetime
     * bug before the pool existed). */
    while (mmt_handler->ipacket_pool != NULL) {
        mmt_ipacket_slot_t *slot = mmt_handler->ipacket_pool;
        mmt_handler->ipacket_pool = slot->next_free;
        mmt_free(slot->data);
        mmt_free(slot);
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
        // Issue #549: this handler's own switch, never the shared protocol_t.
        proto_status_store(&mmt_handler->configured_protocols[proto_id].analysis_enabled, 1);
    }
}

/**
 * Disables the analysis sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void disable_protocol_analysis(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && _is_valid_protocol_id(proto_id) > 0) {
        // Issue #549: this handler's own switch, never the shared protocol_t.
        proto_status_store(&mmt_handler->configured_protocols[proto_id].analysis_enabled, 0);
    }
}

/**
 * Enables the classification sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void enable_protocol_classification(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && _is_valid_protocol_id(proto_id) > 0) {
        // Issue #549: this handler's own switch, never the shared protocol_t.
        proto_status_store(&mmt_handler->configured_protocols[proto_id].classify_enabled, 1);
    }
}

/**
 * Disables the classification sub-process for the protocol with the given id
 * @param mmt_handler mmt handler
 * @param proto_id protocol identifier
 */
void disable_protocol_classification(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler && _is_valid_protocol_id(proto_id) > 0) {
        // Issue #549: this handler's own switch, never the shared protocol_t.
        proto_status_store(&mmt_handler->configured_protocols[proto_id].classify_enabled, 0);
    }
}

void mmt_close_handler_internal(mmt_handler_t *mmt_handler, void * args) {
    mmt_close_handler(mmt_handler);
}

/* Issue #549: the handler-bookkeeping halves of init_extraction() and
 * close_extraction() (packet_registry.c), kept here with the map they own. */
bool init_handlers_map(void) {
    mmt_configured_handlers_map = init_map_space(pointer_comp_fn_pt, pointer_hash_fn);
    return mmt_configured_handlers_map != NULL;
}

void close_handlers_map(void) {
    //Iterate over the registered handlers
    iterate_through_mmt_handlers(mmt_close_handler_internal, NULL);
    //Delete the handlers map
    delete_map_space(mmt_configured_handlers_map);
    // Issue #200 (F-BUG-005): NULL the global after deleting it — a second
    // init_extraction()/close_extraction() cycle in one process must not
    // dereference the dangling pointer.
    mmt_configured_handlers_map = NULL;
}

void setDataLinkType(mmt_handler_t *mmt_handler, int dltype) {
    protocol_stack_t * temp_stack = get_protocol_stack_from_map(dltype);
    if (temp_stack == NULL) {
        mmt_handler->link_layer_stack = &dummy_stack;
    } else {
        mmt_handler->link_layer_stack = temp_stack;
    }
}
