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

/**
 * Resets the statistics for the given protocol
 * @param proto protocol to reset its statistics
 */
void reset_proto_stats(protocol_instance_t * proto);

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

int proto_first_packet_time_extraction(const ipacket_t * packet, unsigned proto_index,
                                       attribute_t * extracted_data) {
    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    if (proto_stats) {
        memcpy(extracted_data->data, &proto_stats->first_packet_time, sizeof (struct timeval));
        return 1;
    }
    return 0;
}

int proto_last_packet_time_extraction(const ipacket_t * packet, unsigned proto_index,
                                      attribute_t * extracted_data) {
    protocol_instance_t * configured_protocol = &(packet->mmt_handler)->configured_protocols[packet->proto_hierarchy->proto_path[proto_index]];
    proto_statistics_internal_t * proto_stats = configured_protocol->proto_stats;
    if (proto_stats) {
        memcpy(extracted_data->data, &proto_stats->last_packet_time, sizeof (struct timeval));
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

int proto_data_len_extraction(const ipacket_t * packet, unsigned proto_index,
                          attribute_t * extracted_data) {
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int next_offset  = packet->p_hdr->caplen;
    if( proto_index + 1 < packet->proto_hierarchy->len )
        next_offset = get_packet_offset_at_index(packet, proto_index+1);
    int len = next_offset - proto_offset;
    //occurs only if there exists errors??
    if( len < 0 )
       len = 0;
    *((uint64_t *) extracted_data->data) = len;
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
        extracted_data->data = (void*) packet->session;
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
    {PROTO_STATISTICS, PROTO_STATISTICS_LABEL, MMT_STATS, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_stats_extraction},
    {PROTO_FIRST_PACKET_TIME, PROTO_FIRST_PACKET_TIME_LABEL, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_first_packet_time_extraction},
    {PROTO_LAST_PACKET_TIME, PROTO_LAST_PACKET_TIME_LABEL, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_last_packet_time_extraction},
    {PROTO_DATA_LEN, PROTO_DATA_LEN_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_data_len_extraction},

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

void free_handler_protocol_statistics(mmt_handler_t *mmt_handler, protocol_instance_t * protocol) {
    proto_statistics_internal_t * temp = protocol->proto_stats;
    proto_statistics_internal_t * safe_to_delete = NULL;
    while (temp != NULL) {
        safe_to_delete = temp;
        temp = temp->next;
        delete_int_map_space(safe_to_delete->encap_proto_stats);
        mmt_free(safe_to_delete);
    }
    protocol->proto_stats = NULL;
}

void free_handler_protocols_statistics(mmt_handler_t *mmt_handler) {
    int i = 0;
    for (; i < PROTO_MAX_IDENTIFIER; i++) {
        free_handler_protocol_statistics(mmt_handler, &mmt_handler->configured_protocols[i]);
    }
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

static inline int isProtocolStatisticsEnabled(mmt_handler_t *mmt_handler) {
    return mmt_handler->stats_reporting_status;
}

/**
 * Creates a protocol statistics instance for the given protocol and the given parent stats
 * @param proto pointer to the protocol instance
 * @param parent_proto_stats pointer to the parent protocol stats
 * @return pointer to the created protocol statistics on success, NULL on failure
 */
static inline proto_statistics_internal_t * _create_protocol_stats_instance(protocol_instance_t * proto, proto_statistics_internal_t * parent_proto_stats) {
    proto_statistics_internal_t * proto_stats = (proto_statistics_internal_t *) mmt_malloc(sizeof (proto_statistics_internal_t));
    if (proto_stats == NULL) return NULL;
    memset(proto_stats, '\0', sizeof (proto_statistics_internal_t));
    proto_stats->parent_proto_stats = parent_proto_stats;
    proto_stats->proto = proto;
    proto_stats->next  = proto->proto_stats;
    proto->proto_stats = proto_stats;
    proto_stats->encap_proto_stats = init_int_map_space(attribute_ids_comparison_fct);
    if (proto_stats->encap_proto_stats == NULL) {
        proto->proto_stats = proto_stats->next;
        mmt_free(proto_stats);
        return NULL;
    }
    if (parent_proto_stats) {
   	 insert_int_key_value(parent_proto_stats->encap_proto_stats, proto->protocol->proto_id, (void *) proto_stats);
    }
    return proto_stats;
}

proto_statistics_internal_t * create_protocol_stats_instance(protocol_instance_t * proto, proto_statistics_internal_t * parent_proto_stats) {
	return _create_protocol_stats_instance( proto, parent_proto_stats);
}

/**
 * Returns a pointer to the protocol statistics of the child protocol identified by \child_proto_id
 * @param proto_stats pointer to the protocol stats instance
 * @param child_proto_id identifier of the child protocol
 * @return pointer to the child protocol statistics if it exists, NULL otherwise.
 */
static inline proto_statistics_internal_t * _get_child_protocol_stats(proto_statistics_internal_t * proto_stats, uint32_t child_proto_id) {
    return (proto_statistics_internal_t *) find_int_key_value(proto_stats->encap_proto_stats, child_proto_id);
}

proto_statistics_internal_t * get_child_protocol_stats(proto_statistics_internal_t * proto_stats, uint32_t child_proto_id) {
	return _get_child_protocol_stats( proto_stats, child_proto_id);
}
/**
 * Returns a pointer to the protocol statistics in the parent protocol encapsulated stats
 * @param proto pointer to the protocol instance
 * @param parent_proto_stats pointer to the parent protocol stats instance
 * @return pointer to the protocol statistics. If it does not exist, it will be created.
 */
static inline proto_statistics_internal_t * _get_protocol_stats_from_parent(protocol_instance_t * proto, proto_statistics_internal_t * parent_proto_stats) {
    proto_statistics_internal_t * proto_stats;
    if (parent_proto_stats != NULL /* Always the case for META protocol */) {
        proto_stats = _get_child_protocol_stats(parent_proto_stats, proto->protocol->proto_id);
        if (proto_stats == NULL) {
            proto_stats = _create_protocol_stats_instance(proto, parent_proto_stats);
        }
    } else {
        proto_stats = proto->proto_stats;
        if (proto_stats == NULL) {
            proto_stats = _create_protocol_stats_instance(proto, parent_proto_stats);
        }
    }
    return proto_stats;
}
proto_statistics_internal_t * get_protocol_stats_from_parent(protocol_instance_t * proto, proto_statistics_internal_t * parent_proto_stats) {
	return _get_protocol_stats_from_parent( proto, parent_proto_stats);
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
        mmt_stream_printf(f, "Proto %u: \nnb\tpackets %"PRIu64" --- byte count %"PRIu64" --- sessions count %"PRIu64" --- timeout sessions count %"PRIu64"\n",
                proto_stats->proto->protocol->proto_id, proto_stats->packets_count, proto_stats->data_volume, proto_stats->sessions_count, proto_stats->timedout_sessions_count);
        proto_stats = proto_stats->next;
    }
}

proto_statistics_t * get_protocol_stats(mmt_handler_t *mmt_handler, uint32_t proto_id) {
    if (mmt_handler == NULL) return NULL;
    if (!is_valid_protocol_id(proto_id)) return NULL;
    return (proto_statistics_t *) mmt_handler->configured_protocols[proto_id].proto_stats;
}

void get_protocol_stats_path(mmt_handler_t *mmt_handler, proto_statistics_t * stats, proto_hierarchy_t * proto_hierarchy) {
    if ((mmt_handler == NULL) || (stats == NULL) || (proto_hierarchy == NULL)) {
        // F-BUG-013 (issue #199): the old code dereferenced proto_hierarchy here
        // even when it was the NULL that triggered this guard.
        if (proto_hierarchy != NULL) proto_hierarchy->len = 0;
        return;
    }
    proto_hierarchy_t temp_path = {0};
    proto_statistics_internal_t * temp_stats = (proto_statistics_internal_t *) stats;
    // F-BUG-013 (issue #199): temp_path.proto_path holds PROTO_PATH_SIZE
    // entries — an over-deep stats chain must stop at the array bound.
    while (temp_stats && temp_path.len < PROTO_PATH_SIZE) {
        temp_path.proto_path[temp_path.len] = temp_stats->proto->protocol->proto_id;
        temp_path.len ++;
        temp_stats = temp_stats->parent_proto_stats;
    }
    proto_hierarchy->len = temp_path.len;
    int i;
    for (i = 0; i < temp_path.len; i++) {
        proto_hierarchy->proto_path[temp_path.len - (i + 1)] = temp_path.proto_path[i];
    }
}

void update_proto_stats_on_session_timeout(mmt_session_t * timed_out_session, proto_statistics_internal_t * parent_proto_stats) {
    // F-BUG-006 (issue #199): guard every level that can be missing — the
    // session, its handler, and each stats instance (the stats lookup allocates
    // on demand and returns NULL under OOM).
    if (timed_out_session == NULL || timed_out_session->mmt_handler == NULL) {
        return;
    }
    if (!isProtocolStatisticsEnabled(timed_out_session->mmt_handler)) {
        return;
    }
    proto_statistics_internal_t * proto_stats = parent_proto_stats;
    int i = 0;
    // proto_path[] holds PROTO_PATH_SIZE entries; a corrupt len must not walk past it.
    int path_len = timed_out_session->proto_path.len;
    if (path_len > PROTO_PATH_SIZE) path_len = PROTO_PATH_SIZE;
    for (; i < path_len; i++) {
        uint32_t proto_id = (uint32_t) timed_out_session->proto_path.proto_path[i];
        if (!is_valid_protocol_id(proto_id)) break; // corrupt path element
        proto_stats = _get_protocol_stats_from_parent(&(timed_out_session->mmt_handler)->configured_protocols[proto_id],
                      proto_stats);
        if (proto_stats == NULL) break; // OOM creating the stats instance
        if (i >= (int) timed_out_session->session_protocol_index) {
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
    stats->ip_df_packets_count = 0;
    stats->ip_frag_packets_count = 0;
    stats->ip_df_data_volume = 0;
    stats->ip_frag_data_volume = 0;
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
/**
* Update statistic of protocol on packet
* @ipacket                  packet with new data to update
* @configured_protocol      touched
* @parent_stats             Statistic of protocol parent
*/
proto_statistics_internal_t * update_proto_stats_on_packet(ipacket_t * ipacket, protocol_instance_t * configured_protocol, proto_statistics_internal_t * parent_stats, uint32_t proto_offset, unsigned index) {
    if (likely(isProtocolStatisticsEnabled(ipacket->mmt_handler))) {
        /* Cumulative per-packet counters; the application polls/resets them (docs/DECISIONS.md, #329). */
        proto_statistics_internal_t * proto_stats = _get_protocol_stats_from_parent(configured_protocol, parent_stats);

        if (likely(proto_stats)) {
            proto_stats->touched         = 1;
            proto_stats->packets_count  += 1;
            proto_stats->data_volume    += ipacket->p_hdr->original_len;
            proto_stats->payload_volume += ipacket->p_hdr->len - proto_offset;
            // Update the fist packet
            if (proto_stats->packets_count == 1) {
                proto_stats->first_packet_time = ipacket->p_hdr->ts;
                proto_stats->ip_frag_packets_count = 0;
                proto_stats->ip_frag_data_volume = 0;
                proto_stats->ip_df_packets_count = 0;
                proto_stats->ip_df_data_volume = 0;
            }
            proto_stats->last_packet_time = ipacket->p_hdr->ts;

            // Check if this is IP protocol, then update ip_fragment information
            if(likely(configured_protocol->protocol->proto_id == 178 || configured_protocol->protocol->proto_id == 179 || configured_protocol->protocol->proto_id == 182 )){
                if(ipacket->is_fragment[index]){
                    proto_stats->ip_frag_packets_count ++;
                    if(ipacket->is_completed[index]){
                        proto_stats->ip_frag_data_volume += ipacket->p_hdr->original_caplen;
                        proto_stats->ip_df_packets_count += ipacket->nb_reassembled_packets[index];
                        proto_stats->ip_df_data_volume += ipacket->total_caplen;
                    }else{
                        proto_stats->ip_frag_data_volume += ipacket->p_hdr->caplen;
                    }
                }
            }
        }
        return proto_stats;
    }else{
        return NULL;
    }
}
/**
 * Increase session_count of protocol
 * @param  ipacket             packet of new session
 * @param  configured_protocol instace of protocol
 * @param  parent_stats        statistic of parent protocol
 * @param  new_session         new session
 * @return                     updated protocol statistic
 */
proto_statistics_internal_t * update_proto_stats_on_new_session(ipacket_t * ipacket, protocol_instance_t * configured_protocol, proto_statistics_internal_t * parent_stats, int new_session, uint32_t proto_offset, unsigned index) {
    if (!isProtocolStatisticsEnabled(ipacket->mmt_handler)) {
        return NULL;
    }

    /* Cumulative per-packet counters; the application polls/resets them (docs/DECISIONS.md, #329). */
    proto_statistics_internal_t * proto_stats = _get_protocol_stats_from_parent(configured_protocol, parent_stats);

    if (likely(proto_stats)) {
        if (new_session) {
            proto_stats->sessions_count += 1;
            proto_stats->touched         = 1;
            proto_stats->packets_count  += 1;
            proto_stats->data_volume    += ipacket->p_hdr->original_len;
            proto_stats->payload_volume += ipacket->p_hdr->original_len - proto_offset;
            // Update the fist packet
            if (proto_stats->packets_count == 1) {
                proto_stats->first_packet_time = ipacket->p_hdr->ts;
                proto_stats->ip_frag_packets_count = 0;
                proto_stats->ip_frag_data_volume = 0;
                proto_stats->ip_df_packets_count = 0;
                proto_stats->ip_df_data_volume = 0;
            }
            proto_stats->last_packet_time = ipacket->p_hdr->ts;

            // Check if this is IP protocol, then update ip_fragment information
            if(likely(configured_protocol->protocol->proto_id == 178 || configured_protocol->protocol->proto_id == 179)){
                if(ipacket->is_fragment[index]){
                    proto_stats->ip_frag_packets_count ++;
                    if(ipacket->is_completed[index]){
                        proto_stats->ip_frag_data_volume += ipacket->p_hdr->original_caplen;
                        proto_stats->ip_df_packets_count += ipacket->nb_reassembled_packets[index];
                        proto_stats->ip_df_data_volume += ipacket->total_caplen;
                    }else{
                        proto_stats->ip_frag_data_volume += ipacket->p_hdr->caplen;
                    }
                }
            }
        }
    }
    return proto_stats;
}
