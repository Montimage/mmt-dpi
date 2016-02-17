#include "ip_session_id_management.h"
#include "packet_processing.h"
#include "hash_utils.h"
#include "../mmt_common_internal_include.h"
#include "mmt_common_internal_include.h"

bool ipv4_addr_comp(void * l_ip, void * r_ip) {
    return (*((uint32_t *) l_ip) < *((uint32_t *) r_ip));
}

bool ipv6_addr_comp(void * l_ip, void * r_ip) {
    return (memcmp(&((struct in6_addr *) l_ip)->s6_addr, &((struct in6_addr *) r_ip)->s6_addr, IPv6_ALEN) < 0);
}

int insertID4(internal_ip_proto_context_t * tcpip_context, mmt_ip4_id_t * ip_id) {
    return insert_key_value(tcpip_context->ips_map, (void *) &ip_id->ip, (void *) ip_id);
}

mmt_ip4_id_t * findID4(internal_ip_proto_context_t * tcpip_context, uint32_t * ip) {
    return (mmt_ip4_id_t *) find_key_value(tcpip_context->ips_map, (void *) ip);
}

int deleteID4(internal_ip_proto_context_t * tcpip_context, uint32_t * ip) {
    return delete_key_value(tcpip_context->ips_map, (void *) ip);
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
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *)mmt_malloc(sizeof (internal_ip_proto_context_t));
    memset(tcpip_context, 0, sizeof (internal_ip_proto_context_t));

    tcpip_context->ips_map = init_map_space(ipv4_addr_comp);

    tcpip_context->ips_count = 0;
    tcpip_context->active_ips_count = 0;
    tcpip_context->sessions_count = 0;
    tcpip_context->active_sessions_count = 0;

    return tcpip_context;
}

internal_ip_proto_context_t * setup_ipv6_internal_context() {
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *) mmt_malloc(sizeof (internal_ip_proto_context_t));
    memset(tcpip_context, 0, sizeof (internal_ip_proto_context_t));

    tcpip_context->ips_map = init_map_space(ipv6_addr_comp);

    tcpip_context->ips_count = 0;
    tcpip_context->active_ips_count = 0;
    tcpip_context->sessions_count = 0;
    tcpip_context->active_sessions_count = 0;

    return tcpip_context;
}

void close_ipv6_internal_context(protocol_instance_t * proto_context) {
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *) proto_context->args;
    delete_map_space(tcpip_context->ips_map);
    mmt_free(proto_context->args);
}

void close_ipv4_internal_context(protocol_instance_t * proto_context) {
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *) proto_context->args;
    delete_map_space(tcpip_context->ips_map);
    mmt_free(proto_context->args);
}

int cleanup_ipv4_internal_context(internal_ip_proto_context_t * tcpip_context) {
    mapspace_iteration_callback(tcpip_context->ips_map, free_ipv4_data, NULL);
    clear_map_space(tcpip_context->ips_map);
    return 1;
}

int cleanup_ipv6_internal_context(internal_ip_proto_context_t * tcpip_context) {
    mapspace_iteration_callback(tcpip_context->ips_map, free_ipv6_data, NULL);
    clear_map_space(tcpip_context->ips_map);
    return 1;
}

int setup_application_detection(void) { //TODO: to be deleted
    return 1; //TODO: failsafe
}

int setup_session_id_lists(void) {//TODO: to be deleted
    return 1;
}

int close_session_id_lists(void * proto_context) { //TODO: change the name of this function tor emove the "id" from it
    //clear_timeout_milestones(); // This is performed in the core in the function "close_extraction"! This is not the right place to do this.

    protocol_sessions_iteration_callback(proto_context, free_session_data, ((protocol_instance_t *) proto_context)->args);
    //id4_iteration_callback(free_ipv4_data, NULL);
    //id6_iteration_callback(free_ipv6_data, NULL);
    //clearID6s();
    //clearID4s();
    return 1;
}

mmt_ip4_id_t * get_ip4_id(internal_ip_proto_context_t * tcpip_context, uint32_t * ip, uint32_t * is_new) {
    mmt_ip4_id_t * retval;
    retval = findID4(tcpip_context, ip);

    if (retval == NULL) {
        /*Initialize the memory for the IPv4 IDs */
        retval = mmt_malloc(sizeof (mmt_ip4_id_t));
        memset(retval, 0, sizeof (mmt_ip4_id_t));

        retval->count = 0;
        retval->ip = *ip;
        if(insertID4(tcpip_context, retval) == 0) {
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

mmt_ip6_id_t * get_ip6_id(internal_ip_proto_context_t * tcpip_context, struct in6_addr * ip, uint32_t * is_new) {
    mmt_ip6_id_t * retval;
    retval = findID6(tcpip_context, ip);

    if (retval == NULL) {
        /*Initialize the memory for the IPv6 IDs */
        retval = mmt_malloc(sizeof (mmt_ip6_id_t));
        memset(retval, 0, sizeof (mmt_ip6_id_t));

        retval->count = 0;
        memcpy(&retval->ip.s6_addr, &ip->s6_addr, IPv6_ALEN);
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
            deleteID4(tcpip_context, & id_low->ip);
            mmt_free(id_low);
        }
        id_high->count -= 1;

        if (id_high->count == 0) {
            deleteID4(tcpip_context, & id_high->ip);
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
    // printf("Session is going to be freed: %lu\n",session->session_id);
    mmt_free(session);
}

mmt_session_t * get_session(void * protocol_context, mmt_session_key_t * session_key, ipacket_t * ipacket, int * is_new) {

    mmt_session_t * retval;
    internal_ip_proto_context_t * tcpip_context = (internal_ip_proto_context_t *) ((protocol_instance_t *) protocol_context)->args;

    retval = (mmt_session_t *) get_session_from_protocol_context_by_session_key(protocol_context, (void *) session_key);
    if (retval == NULL) {
        *is_new = 1;

        uint32_t isl_new = 0, ish_new = 0;
        /* Initialize the memory for the session */
        retval = (mmt_session_t *) mmt_malloc(sizeof (mmt_session_t) + sizeof (mmt_session_key_t) + sizeof (struct mmt_internal_tcpip_session_struct));
        memset(retval, 0, sizeof (mmt_session_t) + sizeof (mmt_session_key_t) + sizeof (struct mmt_internal_tcpip_session_struct));
        retval->session_key = (mmt_session_key_t *) &((char *)retval)[sizeof(mmt_session_t)];
        retval->internal_data = (struct mmt_internal_tcpip_session_struct *) &((char *)retval)[sizeof(mmt_session_t) + sizeof (mmt_session_key_t)];
        /*
                memset(retval->internal_data, 0, sizeof (struct mmt_internal_tcpip_session_struct));
         */

        ((mmt_session_key_t *) retval->session_key)->is_lower_initiator = session_key->is_lower_initiator;
        ((mmt_session_key_t *) retval->session_key)->is_lower_client = session_key->is_lower_client;

        ((mmt_session_key_t *) retval->session_key)->ip_type = session_key->ip_type;
        ((mmt_session_key_t *) retval->session_key)->next_proto = session_key->next_proto;
        ((mmt_session_key_t *) retval->session_key)->lower_ip_port = session_key->lower_ip_port;
        ((mmt_session_key_t *) retval->session_key)->higher_ip_port = session_key->higher_ip_port;

        if (session_key->ip_type == 4) {
            ((mmt_session_key_t *) retval->session_key)->lower_ip = get_ip4_id(tcpip_context, (uint32_t *) session_key->lower_ip, &isl_new);
            if (((mmt_session_key_t *) retval->session_key)->lower_ip == NULL) {
                //If we get here, then a memalloc problem occurred
                //free this session and return NULL
                mmt_free(retval);
                return NULL;
            }
            ((mmt_session_key_t *) retval->session_key)->higher_ip = get_ip4_id(tcpip_context, (uint32_t *) session_key->higher_ip, &ish_new);
            if (((mmt_session_key_t *) retval->session_key)->higher_ip == NULL) {
                //If we get here, then a memalloc problem occurred
                //free this session and return NULL AND check if lower_is is new, if yes free it
                if (isl_new) {
                    mmt_free(((mmt_session_key_t *) retval->session_key)->lower_ip);
                }
                mmt_free(retval);
                return NULL;
            }
            ((mmt_ip4_id_t *) ((mmt_session_key_t *) retval->session_key)->lower_ip)->count++;
            ((mmt_ip4_id_t *) ((mmt_session_key_t *) retval->session_key)->higher_ip)->count++;
        } else {
            ((mmt_session_key_t *) retval->session_key)->lower_ip = get_ip6_id(tcpip_context, (struct in6_addr *) session_key->lower_ip, &isl_new);
            if (((mmt_session_key_t *) retval->session_key)->lower_ip == NULL) {
                //If we get here, then a memalloc problem occurred
                //free this session and return NULL
                mmt_free(retval);
                return NULL;
            }
            ((mmt_session_key_t *) retval->session_key)->higher_ip = get_ip6_id(tcpip_context, (struct in6_addr *) session_key->higher_ip, &ish_new);
            if (((mmt_session_key_t *) retval->session_key)->higher_ip == NULL) {
                //If we get here, then a memalloc problem occurred
                //free this session and return NULL AND check if lower_is is new, if yes free it
                if (isl_new) {
                    mmt_free(((mmt_session_key_t *) retval->session_key)->lower_ip);
                }
                mmt_free(retval);
                return NULL;
            }
            ((mmt_ip6_id_t *) ((mmt_session_key_t *) retval->session_key)->lower_ip)->count++;
            ((mmt_ip6_id_t *) ((mmt_session_key_t *) retval->session_key)->higher_ip)->count++;
        }

        //TODO: we are not verifying the return value of the insert
        retval->setup_packet_direction = session_key->is_lower_initiator;
        //retval->proto_stack = ipacket->proto_stack;
        if(insert_session_into_protocol_context(protocol_context, retval->session_key, retval) == 0) {
            //The session failed to be inserted into the MAP.
            //Cleanup what was created for this
            if (session_key->ip_type == 4) {
                if (isl_new) {
                    mmt_free(((mmt_session_key_t *) retval->session_key)->lower_ip);
                }
                if (ish_new) {
                    mmt_free(((mmt_session_key_t *) retval->session_key)->lower_ip);
                }

            }else {
                if (isl_new) {
                    mmt_free(((mmt_session_key_t *) retval->session_key)->lower_ip);
                }
                if (ish_new) {
                    mmt_free(((mmt_session_key_t *) retval->session_key)->lower_ip);
                }
            }
            mmt_free(retval);
            return NULL;
        }
        tcpip_context->sessions_count += 1;
        tcpip_context->active_sessions_count += 1;
        //*is_new = 1; //This is done at the beginning of this block
    } else {
        //Nothing else to do, just indicate this is not a new session!
        is_new = 0;
    }

    return retval;
}


