#include "ip_session_id_management.h"
#include "packet_processing.h"
#include "hash_utils.h"
#include "../mmt_common_internal_include.h"
#include "mmt_common_internal_include.h"

bool ipv4_addr_comp(void * l_ip, void * r_ip) {
    /*
     * Issue #57: one of these pointers can be &iph->saddr/&iph->daddr, which
     * points into the byte-aligned packet buffer (build_ipv4_session_key stores
     * the raw header pointers before they are resolved to aligned id structs).
     * Dereferencing a uint32_t at a misaligned address is UB and aborts under
     * -fsanitize=alignment, so read the 4 octets with memcpy (a single load on
     * targets with native unaligned access — no hot-path cost).
     */
    uint32_t l, r;
    memcpy(&l, l_ip, sizeof(l));
    memcpy(&r, r_ip, sizeof(r));
    return (l < r);
}

bool ipv6_addr_comp(void * l_ip, void * r_ip) {
    /* Issue #57 (found via #375): l_ip/r_ip can point into the byte-aligned
     * packet buffer (session_key stores &ip6h->saddr/&ip6h->daddr before the
     * id structs are resolved). s6_addr is the only member of struct in6_addr
     * and sits at offset 0, so forming the member access through a cast —
     * which requires 4-byte alignment the packet buffer does not guarantee —
     * is gratuitous UB under -fsanitize=alignment; compare the 16 bytes
     * directly. */
    return (mmt_memcmp(l_ip, r_ip, IPv6_ALEN) < 0);
}

/* Issue #254 (F-PERF-012): hashes consistent with the comp functions above —
 * equal addresses must hash equal. Same unaligned-read precaution as
 * ipv4_addr_comp: the key may point into the byte-aligned packet buffer. */
static uint64_t ipv4_addr_hash(void * ip) {
    uint32_t v;
    memcpy(&v, ip, sizeof(v));
    return (uint64_t) v;
}

static uint64_t ipv6_addr_hash(void * ip) {
    uint64_t w[2];
    /* Same unaligned-read precaution: ip may be a packet-buffer pointer;
     * s6_addr is at offset 0 of struct in6_addr, so the member access is
     * gratuitous — hash the 16 address bytes directly. */
    memcpy(w, ip, sizeof(w));
    return w[0] ^ (w[1] << 1);
}

static inline int _insertID4(internal_ip_proto_context_t * tcpip_context, mmt_ip4_id_t * ip_id) {
    return insert_key_value(tcpip_context->ips_map, (void *) &ip_id->ip, (void *) ip_id);
}

int insertID4(internal_ip_proto_context_t * tcpip_context, mmt_ip4_id_t * ip_id) {
	return _insertID4( tcpip_context, ip_id );
}

static inline mmt_ip4_id_t * _findID4(internal_ip_proto_context_t * tcpip_context, uint32_t * ip) {
    return (mmt_ip4_id_t *) find_key_value(tcpip_context->ips_map, (void *) ip);
}

mmt_ip4_id_t * findID4(internal_ip_proto_context_t * tcpip_context, uint32_t * ip) {
	return _findID4( tcpip_context, ip );
}

static inline int _deleteID4(internal_ip_proto_context_t * tcpip_context, uint32_t * ip) {
    return delete_key_value(tcpip_context->ips_map, (void *) ip);
}

int deleteID4(internal_ip_proto_context_t * tcpip_context, uint32_t * ip) {
    return _deleteID4(tcpip_context, ip);
}

int insertID6(internal_ip_proto_context_t * tcpip_context, mmt_ip6_id_t * ip_id) {
    return insert_key_value(tcpip_context->ips_map, (void *) &ip_id->ip, (void *) ip_id);
}

mmt_ip6_id_t * findID6(internal_ip_proto_context_t * tcpip_context, struct in6_addr * ip) {
    return (mmt_ip6_id_t *) find_key_value(tcpip_context->ips_map, (void *) ip);
}

int deleteID6(internal_ip_proto_context_t * tcpip_context, struct in6_addr * ip) {
    return delete_key_value(tcpip_context->ips_map, (void *) ip);
}

internal_ip_proto_context_t * setup_ipv4_internal_context() {
    /* Issue #212 (F-BUG-029): the mmt_malloc result was memset unchecked. */
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *)mmt_malloc(sizeof (internal_ip_proto_context_t));
    if (tcpip_context == NULL) {
        return NULL;
    }
    memset(tcpip_context, 0, sizeof (internal_ip_proto_context_t));

    tcpip_context->ips_map = init_map_space(ipv4_addr_comp, ipv4_addr_hash);
    if (tcpip_context->ips_map == NULL) {
        mmt_free(tcpip_context);
        return NULL;
    }

    tcpip_context->ips_count = 0;
    tcpip_context->active_ips_count = 0;
    tcpip_context->sessions_count = 0;
    tcpip_context->active_sessions_count = 0;

    return tcpip_context;
}

internal_ip_proto_context_t * setup_ipv6_internal_context() {
    /* Issue #212 (F-BUG-029): the mmt_malloc result was memset unchecked. */
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *) mmt_malloc(sizeof (internal_ip_proto_context_t));
    if (tcpip_context == NULL) {
        return NULL;
    }
    memset(tcpip_context, 0, sizeof (internal_ip_proto_context_t));

    tcpip_context->ips_map = init_map_space(ipv6_addr_comp, ipv6_addr_hash);
    if (tcpip_context->ips_map == NULL) {
        mmt_free(tcpip_context);
        return NULL;
    }

    tcpip_context->ips_count = 0;
    tcpip_context->active_ips_count = 0;
    tcpip_context->sessions_count = 0;
    tcpip_context->active_sessions_count = 0;

    return tcpip_context;
}

void close_ipv6_internal_context(protocol_instance_t * proto_context) {
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *) proto_context->args;
    /* Issue #212 (F-BUG-029): args is NULL when the context setup failed. */
    if (tcpip_context != NULL) {
        delete_map_space(tcpip_context->ips_map);
        mmt_free(proto_context->args);
    }
}

void close_ipv4_internal_context(protocol_instance_t * proto_context) {
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *) proto_context->args;
    /* Issue #212 (F-BUG-029): args is NULL when the context setup failed. */
    if (tcpip_context != NULL) {
        delete_map_space(tcpip_context->ips_map);
        mmt_free(proto_context->args);
    }
}

int cleanup_ipv4_internal_context(internal_ip_proto_context_t * tcpip_context) {
    /* Issue #212 (F-BUG-029): NULL when the context setup failed. */
    if (tcpip_context == NULL) {
        return 0;
    }
    mapspace_iteration_callback(tcpip_context->ips_map, free_ipv4_data, NULL);
    clear_map_space(tcpip_context->ips_map);
    return 1;
}

int cleanup_ipv6_internal_context(internal_ip_proto_context_t * tcpip_context) {
    /* Issue #212 (F-BUG-029): NULL when the context setup failed. */
    if (tcpip_context == NULL) {
        return 0;
    }
    mapspace_iteration_callback(tcpip_context->ips_map, free_ipv6_data, NULL);
    clear_map_space(tcpip_context->ips_map);
    return 1;
}

/* Issue #327: renamed from close_session_id_lists — it frees session data,
 * not "id" lists. */
int close_session_lists(void * proto_context) {
    //clear_timeout_milestones(); // This is performed in the core in the function "close_extraction"! This is not the right place to do this.

    protocol_sessions_iteration_callback(proto_context, free_session_data, ((protocol_instance_t *) proto_context)->args);
    //id4_iteration_callback(free_ipv4_data, NULL);
    //id6_iteration_callback(free_ipv6_data, NULL);
    //clearID6s();
    //clearID4s();
    return 1;
}


static inline mmt_ip4_id_t * _get_ip4_id(internal_ip_proto_context_t * tcpip_context, uint32_t * ip, uint32_t * is_new) {
    mmt_ip4_id_t * retval = NULL;
    retval = _findID4(tcpip_context, ip);
    if (retval == NULL) {
        /*Initialize the memory for the IPv4 IDs */
        retval = mmt_malloc(sizeof (mmt_ip4_id_t));
        /* Issues #201/#212 (F-BUG-029): mmt_malloc may return NULL — memset
         * of NULL was UB; propagate failure so get_session() can clean up. */
        if (retval == NULL) {
            return NULL;
        }
        memset(retval, 0, sizeof (mmt_ip4_id_t));

        retval->count = 0;
        /* Issue #57: ip may point into the byte-aligned packet buffer
         * (&iph->saddr); copy the 4 octets instead of an aligned load. */
        memcpy(&retval->ip, ip, sizeof(retval->ip));
        if( _insertID4(tcpip_context, retval) == 0) {
            //The insertion of the IP failed. This is really bad.
            //We should free this IP, return NULL, otherwise the workflow will be corrupted
            //as the session is expected to have two ID structs in the map
            mmt_free(retval);
            retval = NULL;
            return retval;
        }
        tcpip_context->ips_count += 1;
        *is_new = 1;
    }
    return retval;
}
mmt_ip4_id_t * get_ip4_id(internal_ip_proto_context_t * tcpip_context, uint32_t * ip, uint32_t * is_new) {
	return _get_ip4_id( tcpip_context, ip, is_new );
}

mmt_ip6_id_t * get_ip6_id(internal_ip_proto_context_t * tcpip_context, struct in6_addr * ip, uint32_t * is_new) {
    mmt_ip6_id_t * retval;
    retval = findID6(tcpip_context, ip);

    if (retval == NULL) {
        /*Initialize the memory for the IPv6 IDs */
        retval = mmt_malloc(sizeof (mmt_ip6_id_t));
        /* Issues #201/#212 (F-BUG-029): mmt_malloc may return NULL — memset
         * of NULL was UB; propagate failure so get_session() can clean up. */
        if (retval == NULL) {
            return NULL;
        }
        memset(retval, 0, sizeof (mmt_ip6_id_t));

        retval->count = 0;
        /* ip can point into the byte-aligned packet buffer — read the 16
         * address bytes directly rather than through ->s6_addr member
         * access on a misaligned struct in6_addr (offset 0 — same bytes). */
        memcpy(&retval->ip.s6_addr, ip, IPv6_ALEN);
        if(insertID6(tcpip_context, retval) == 0) {
            //The insertion of the IP failed. This is really bad.
            //We should free this IP, return NULL, otherwise the workflow will be corrupted
            //as the session is expected to have two ID structs in the map
            mmt_free(retval);
            retval = NULL;
            return retval;
        }
        tcpip_context->ips_count += 1;
        *is_new = 1;
    }
    return retval;
}

void free_ipv4_data(void * key, void * value, void * args) {
    mmt_free((mmt_ip4_id_t *) value);
}

void free_ipv6_data(void * key, void * value, void * args) {
    mmt_free((mmt_ip6_id_t *) value);
}

void free_session_data(void * key, void * value, void * args) {
    mmt_session_key_t * session_key = (mmt_session_key_t *) key;
    struct mmt_session_struct * session = (struct mmt_session_struct *) value;
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *) args;

    tcpip_context->sessions_count -= 1;
    tcpip_context->active_sessions_count -= 1;

    if (session_key->ip_type == 4) {
        mmt_ip4_id_t * id_low = session_key->lower_ip;
        mmt_ip4_id_t * id_high = session_key->higher_ip;

        id_low->count -= 1;
        if (id_low->count == 0) {
            _deleteID4(tcpip_context, & id_low->ip);
            mmt_free(id_low);
        }
        id_high->count -= 1;

        if (id_high->count == 0) {
            _deleteID4(tcpip_context, & id_high->ip);
            mmt_free(id_high);
        }
    } else {
        mmt_ip6_id_t * id_low = session_key->lower_ip;
        mmt_ip6_id_t * id_high = session_key->higher_ip;

        id_low->count -= 1;
        if (id_low->count == 0) {
            deleteID6(tcpip_context, & id_low->ip);
            mmt_free(id_low);
        }
        id_high->count -= 1;

        if (id_high->count == 0) {
            deleteID6(tcpip_context, & id_high->ip);
            mmt_free(id_high);
        }
    }

    // Update pointers
    if(session->next != NULL){
        if(session->previous != NULL){
            session->previous->next = session->next;
            session->next->previous = session->previous;
        }else{
            session->next->previous = NULL;
        }
    }else{
        if(session->previous != NULL){
            session->previous->next = NULL;
        }
    }
    //Free the session key
    //mmt_free(session->session_key);
    //Free the internal structure used by DPI
    //mmt_free(session->internal_data);
    //Free the session data
    // mmt_debug_log("Session is going to be freed: %lu\n",session->session_id);
    /* Issue #255: release the lazily-allocated tunnel-parent extension (NULL
     * for leaf sessions; mmt_free(NULL) is a no-op). */
    mmt_free(session->children_stats);
    free(session);
}

mmt_session_t * get_session(void * protocol_context, mmt_session_key_t * session_key, ipacket_t * ipacket, int * is_new) {

    mmt_session_t * retval = NULL;
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *) ((protocol_instance_t *) protocol_context)->args;

    /* Issue #212 (F-BUG-029): context setup may have failed (NULL args) —
     * propagate as "no session" instead of dereferencing a missing map. */
    if (tcpip_context == NULL) {
        return NULL;
    }

    retval = (mmt_session_t *) get_session_from_protocol_context_by_session_key(protocol_context, (void *) session_key);
    
    if (retval == NULL) {
        *is_new = 1;

        uint32_t isl_new = 0, ish_new = 0;
        /* Initialize the memory for the session: 1024 bytes */
        retval = (mmt_session_t *) malloc( sizeof (mmt_session_t) + sizeof (mmt_session_key_t) + sizeof (struct mmt_internal_tcpip_session_struct) );
        if(retval == NULL){
            return NULL;
        }
        memset(retval, 0, sizeof (mmt_session_t) + sizeof (mmt_session_key_t) + sizeof (struct mmt_internal_tcpip_session_struct) );
        retval->session_key   = &retval[1]; //(mmt_session_key_t *) &((char *)retval)[sizeof(mmt_session_t)];
        retval->internal_data = (struct mmt_internal_tcpip_session_struct *) &((char *)retval)[sizeof(mmt_session_t) + sizeof (mmt_session_key_t)];
        /*
                memset(retval->internal_data, 0, sizeof (struct mmt_internal_tcpip_session_struct));
         */
        memcpy(retval->session_key, session_key, sizeof( mmt_session_key_t ));

        if (session_key->ip_type == 4) {
            ((mmt_session_key_t *) retval->session_key)->lower_ip = _get_ip4_id(tcpip_context, (uint32_t *) session_key->lower_ip, &isl_new);
            if ( unlikely( ((mmt_session_key_t *) retval->session_key)->lower_ip == NULL)) {
                //If we get here, then a memalloc problem occurred
                //free this session and return NULL
                // mmt_free(session_key->lower_ip);
                // mmt_free(session_key->higher_ip);
                free(retval);
                return NULL;
            }
            ((mmt_session_key_t *) retval->session_key)->higher_ip = _get_ip4_id(tcpip_context, (uint32_t *) session_key->higher_ip, &ish_new);
            if ( unlikely( ((mmt_session_key_t *) retval->session_key)->higher_ip == NULL )) {
                //If we get here, then a memalloc problem occurred
                //free this session and return NULL AND check if lower_is is new, if yes free it
                if (isl_new) {
                    /* Issue #201 (F-BUG-025): the id object was inserted into
                     * ips_map by _get_ip4_id — remove it from the map before
                     * freeing so no dangling entry stays reachable. */
                    mmt_ip4_id_t * id_low = (mmt_ip4_id_t *) ((mmt_session_key_t *) retval->session_key)->lower_ip;
                    _deleteID4(tcpip_context, & id_low->ip);
                    tcpip_context->ips_count -= 1;
                    mmt_free(id_low);
                }
                // mmt_free(session_key->lower_ip);
                // mmt_free(session_key->higher_ip);
                free(retval);
                return NULL;
            }
            ((mmt_ip4_id_t *) ((mmt_session_key_t *) retval->session_key)->lower_ip)->count++;
            ((mmt_ip4_id_t *) ((mmt_session_key_t *) retval->session_key)->higher_ip)->count++;
        } else {
            ((mmt_session_key_t *) retval->session_key)->lower_ip = get_ip6_id(tcpip_context, (struct in6_addr *) session_key->lower_ip, &isl_new);
            if ( unlikely( ((mmt_session_key_t *) retval->session_key)->lower_ip == NULL )) {
                //If we get here, then a memalloc problem occurred
                //free this session and return NULL
                // mmt_free(session_key->lower_ip);
                // mmt_free(session_key->higher_ip);
                free(retval);
                return NULL;
            }
            ((mmt_session_key_t *) retval->session_key)->higher_ip = get_ip6_id(tcpip_context, (struct in6_addr *) session_key->higher_ip, &ish_new);
            if ( unlikely( ((mmt_session_key_t *) retval->session_key)->higher_ip == NULL )) {
                //If we get here, then a memalloc problem occurred
                //free this session and return NULL AND check if lower_is is new, if yes free it
                if (isl_new) {
                    /* Issue #201 (F-BUG-025): remove the id from ips_map before
                     * freeing — it was inserted by get_ip6_id. */
                    mmt_ip6_id_t * id_low = (mmt_ip6_id_t *) ((mmt_session_key_t *) retval->session_key)->lower_ip;
                    deleteID6(tcpip_context, & id_low->ip);
                    tcpip_context->ips_count -= 1;
                    mmt_free(id_low);
                }
                // mmt_free(session_key->lower_ip);
                // mmt_free(session_key->higher_ip);
                free(retval);
                return NULL;
            }
            ((mmt_ip6_id_t *) ((mmt_session_key_t *) retval->session_key)->lower_ip)->count++;
            ((mmt_ip6_id_t *) ((mmt_session_key_t *) retval->session_key)->higher_ip)->count++;
        }

        retval->setup_packet_direction = session_key->is_lower_initiator;
        //retval->proto_stack = ipacket->proto_stack;

        if( unlikely( insert_session_into_protocol_context(protocol_context, retval->session_key, retval) == 0 )) {
            mmt_debug_log( "[error] get_session: insert_session_into_protocol_context return 0\n");
            //The session failed to be inserted into the MAP.
            //Cleanup what was created for this
            /* Issue #201 (F-BUG-025): these id objects were inserted into
             * ips_map by _get_ip4_id/get_ip6_id — delete the map entries
             * before freeing so no dangling pointer stays reachable. */
            if (isl_new)
            {
                if (session_key->ip_type == 4) {
                    mmt_ip4_id_t * id_low = (mmt_ip4_id_t *) ((mmt_session_key_t *)retval->session_key)->lower_ip;
                    _deleteID4(tcpip_context, & id_low->ip);
                    mmt_free(id_low);
                } else {
                    mmt_ip6_id_t * id_low = (mmt_ip6_id_t *) ((mmt_session_key_t *)retval->session_key)->lower_ip;
                    deleteID6(tcpip_context, & id_low->ip);
                    mmt_free(id_low);
                }
                tcpip_context->ips_count -= 1;
            }
            if (ish_new)
            {
                if (session_key->ip_type == 4) {
                    mmt_ip4_id_t * id_high = (mmt_ip4_id_t *) ((mmt_session_key_t *)retval->session_key)->higher_ip;
                    _deleteID4(tcpip_context, & id_high->ip);
                    mmt_free(id_high);
                } else {
                    mmt_ip6_id_t * id_high = (mmt_ip6_id_t *) ((mmt_session_key_t *)retval->session_key)->higher_ip;
                    deleteID6(tcpip_context, & id_high->ip);
                    mmt_free(id_high);
                }
                tcpip_context->ips_count -= 1;
            }
            // mmt_free(session_key->lower_ip);
            // mmt_free(session_key->higher_ip);
            free(retval);
            return NULL;
        }
        tcpip_context->sessions_count += 1;
        tcpip_context->active_sessions_count += 1;
        // mmt_free(session_key->lower_ip);
        // mmt_free(session_key->higher_ip);
        //*is_new = 1; //This is done at the beginning of this block
    } else {
        //Nothing else to do, just indicate this is not a new session!
        *is_new = 0;

        // mmt_free(session_key->lower_ip);
        // mmt_free(session_key->higher_ip);
    }

    return retval;
}

// LN: Move from packet_process

int proto_ip_frag_packet_count_extraction(const ipacket_t * packet, unsigned proto_index,
                                  attribute_t * extracted_data) {

    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += proto_stats->ip_frag_packets_count;
        proto_stats = proto_stats->next;
    }

    *((uint64_t *) extracted_data->data) = count;
    return 1;
}


int proto_ip_frag_data_volume_extraction(const ipacket_t * packet, unsigned proto_index,
                                 attribute_t * extracted_data) {
    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    
    // if(configured_protocol->protocol->proto_id != PROTO_ID){
    //     return 0;
    // }

    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += proto_stats->ip_frag_data_volume;
        proto_stats = proto_stats->next;
    }

    *((uint64_t *) extracted_data->data) = count;
    return 1;
}

int proto_ip_df_packet_count_extraction(const ipacket_t * packet, unsigned proto_index,
                                  attribute_t * extracted_data) {

    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += proto_stats->ip_df_packets_count;
        proto_stats = proto_stats->next;
    }

    *((uint64_t *) extracted_data->data) = count;
    return 1;
}


int proto_ip_df_data_volume_extraction(const ipacket_t * packet, unsigned proto_index,
                                 attribute_t * extracted_data) {
    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    
    // if(configured_protocol->protocol->proto_id != PROTO_ID){
    //     return 0;
    // }

    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    uint64_t count = 0;
    while (proto_stats) {
        count += proto_stats->ip_df_data_volume;
        proto_stats = proto_stats->next;
    }

    *((uint64_t *) extracted_data->data) = count;
    return 1;
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

    *((uint64_t *) extracted_data->data) = count;
    return 1;
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

    *((uint64_t *) extracted_data->data) = count;
    return 1;
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

    *((uint64_t *) extracted_data->data) = count;
    return 1;
}

// End of LN
