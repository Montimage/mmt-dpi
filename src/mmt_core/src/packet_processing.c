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

int proto_hierarchy_to_str_with_size(const proto_hierarchy_t * proto_hierarchy, char * dest, size_t dest_size) {
    if (proto_hierarchy == NULL || dest == NULL || dest_size == 0) return 0;
    if (proto_hierarchy->len <= 0) {
        dest[0] = '\0';
        return 0;
    }
    /* F-BUG-013 (issue #199): proto_path[] holds PROTO_PATH_SIZE entries — a
       len beyond that is corrupt state; clamp rather than read out of bounds. */
    int path_len = proto_hierarchy->len;
    if (path_len > PROTO_PATH_SIZE) path_len = PROTO_PATH_SIZE;
    size_t offset = 0;
    int n = snprintf(dest + offset, dest_size - offset, "%s",
                     get_protocol_name_by_id(proto_hierarchy->proto_path[0]));
    if (n < 0) return (int)offset;
    if ((size_t)n >= dest_size - offset) {
        /* truncated */
        return (int)(dest_size - 1);
    }
    offset += (size_t)n;
    for (int index = 1; index < path_len; index++) {
        if (offset >= dest_size) break;
        n = snprintf(dest + offset, dest_size - offset, ".%s",
                     get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
        if (n < 0) break;
        if ((size_t)n >= dest_size - offset) {
            /* truncated - ensure NUL and return truncated length */
            return (int)(dest_size - 1);
        }
        offset += (size_t)n;
    }
    return (int)offset;
}

int proto_hierarchy_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest) {
    /* Deprecated variant - kept for ABI compatibility.
       F-BUG-008 (issue #199): the old body performed unbounded formatted
       writes. The signature carries no dest size, so the write is capped at
       the largest output the function can legitimately produce:
       PROTO_PATH_SIZE protocol names of at most Max_Alias_Len chars plus
       separators.
       Callers should migrate to proto_hierarchy_to_str_with_size(). */
    return proto_hierarchy_to_str_with_size(proto_hierarchy, dest,
                                          (size_t)PROTO_PATH_SIZE * (Max_Alias_Len + 1));
}

const char * get_application_name(const proto_hierarchy_t * proto_hierarchy) {
    if (proto_hierarchy == NULL || proto_hierarchy->len <= 0) return NULL;
    /* proto_path[] holds PROTO_PATH_SIZE entries; a len beyond that is corrupt
       state — clamp rather than read out of bounds (issue #199). */
    int len = proto_hierarchy->len;
    if (len > PROTO_PATH_SIZE) len = PROTO_PATH_SIZE;
    return get_protocol_name_by_id(proto_hierarchy->proto_path[len - 1]);
}

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

int mmt_match_prefix(const u_int8_t *payload, size_t payload_len,
              const char *str, size_t str_len)
{
  return str_len <= payload_len
    ? mmt_memcmp(payload, str, str_len) == 0
    : 0;
}



/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char* mmt_strnstr(const char *s, const char *find, size_t slen) {
  char c, sc;
  size_t len;

  if((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
    if(slen-- < 1 || (sc = *s++) == '\0')
      return (NULL);
      } while (sc != c);
      if(len > slen)
    return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}

static inline
void cleanup_timedout_sessions(mmt_session_t * timed_out_session) {
    timed_out_session->mmt_handler->active_sessions_count--;
    int i = 0;

    // Clean session data for the different protocols in the session's protocol path
    // (bounded by PROTO_PATH_SIZE: a corrupt len must not read past proto_path[])
    int path_len = timed_out_session->proto_path.len;
    if (path_len > PROTO_PATH_SIZE) path_len = PROTO_PATH_SIZE;
    for (; i < path_len; i++) {
        protocol_t *cleanup_proto = get_protocol_struct_by_id(timed_out_session->proto_path.proto_path[i]);
        if (cleanup_proto != NULL && cleanup_proto->session_data_cleanup != NULL) {
            ((generic_session_data_cleanup_function) cleanup_proto->session_data_cleanup)(timed_out_session, i);
        }
    }

    //Update the protocol statistics to indicate the session timeout
    update_proto_stats_on_session_timeout(timed_out_session, NULL);

    // Clean the session context — F-BUG-014 (issue #199): the callback is
    // optional (register_sessionizer_function accepts NULL) and the container
    // context itself may be unset; never invoke through a NULL pointer.
    protocol_instance_t * container = (protocol_instance_t *) timed_out_session->protocol_container_context;
    if (container != NULL && container->protocol != NULL && container->protocol->session_context_cleanup != NULL) {
        ((generic_session_context_cleanup_function) container->protocol->session_context_cleanup)(container,
                timed_out_session, NULL);
    }
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

void session_timer_handler_callback(void * timeout_milestone, void * milestone_sessions_list, void * args) {
    mmt_handler_t * mmt_handler = (mmt_handler_t *) args;
    mmt_session_t * current_session = (mmt_session_t *) milestone_sessions_list;
    if (mmt_handler->session_timer_handler.session_timer_handler_fct != NULL) {
        while (current_session != NULL) {
            // mmt_stream_printf(stdout, "session_timer_handler_callback and session id: %"PRIu64"\n",current_session->session_id);
            if (mmt_handler->session_timer_handler.no_fragmented && current_session->is_fragmenting) {
                // Skip processing the session that contains a fragmented packet.
                current_session = current_session->next;
            } else {
                mmt_handler->session_timer_handler.session_timer_handler_fct(current_session, mmt_handler->session_timer_handler.args);
                current_session = current_session->next;
            }
        }
    } else {
        mmt_debug_log("There is not any session_timer_handler\n");
    }
}

void process_outofmemory_force_sessions_timeout(mmt_handler_t * mmt_handler, ipacket_t * ipacket) {
    uint32_t timeout_slot_to_free = mmt_handler->last_expiry_timeout;
    uint32_t count = 0;
    uint32_t scanned = 0;
    while (count < 65000 && scanned < 65000) {
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
            if (count >= 65000) break;

        }
        //remove the timeout milestone from the hash
        delete_timeout_milestone(mmt_handler, timeout_slot_to_free);
        timeout_slot_to_free++;
        scanned++;
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

                // if(safe_to_delete_session != NULL){
                //     safe_to_delete_session = NULL;
                // }
                // mmt_handler->active_sessions_count --;
            }
            //remove the timeout milestone from the hash
            delete_timeout_milestone(mmt_handler, counter);
        }
        /* Issue #201 (F-BUG-020): piggyback the fragment-map expiry sweep on
         * this existing once-per-second expiry pass — armed by the TCP/IP
         * plugin the first time a fragment is reassembled. */
        if (mmt_handler->frag_map_sweep_fct != NULL && mmt_handler->ip_streams != NULL) {
            mmt_handler->frag_map_sweep_fct(mmt_handler->ip_streams, current_seconds);
        }
    }
    mmt_handler->last_expiry_timeout = current_seconds;
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

uint64_t get_active_session_count(mmt_handler_t *mmt_handler) {
    if (mmt_handler == NULL) {
        return -1;
    } else {
        return mmt_handler->active_sessions_count;
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

bool set_default_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value){
    if(mmt_handler==NULL) return 0;
    mmt_handler->default_session_timed_out = timedout_value;
    return 1;
}

bool set_long_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value){
    if(mmt_handler==NULL) return 0;
    mmt_handler->long_session_timed_out = timedout_value;
    return 1;
}

bool set_short_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value){
    if(mmt_handler==NULL) return 0;
    mmt_handler->short_session_timed_out = timedout_value;
    return 1;
}

bool set_live_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value){
    if(mmt_handler==NULL) return 0;
    mmt_handler->live_session_timed_out = timedout_value;
    return 1;
}

bool set_fragment_in_packet(mmt_handler_t *mmt_handler,uint32_t fragment_in_packet){
    if ( mmt_handler == NULL ) return 0;
    mmt_handler->fragment_in_packet = fragment_in_packet;
    return 1;
}

bool set_fragmented_packet_in_session(mmt_handler_t *mmt_handler,uint32_t fragmented_packet_in_session){
    if ( mmt_handler == NULL ) return 0;
    mmt_handler->fragmented_packet_in_session = fragmented_packet_in_session;
    return 1;
}

bool set_fragment_in_session(mmt_handler_t *mmt_handler,uint32_t fragment_in_session){
    if ( mmt_handler == NULL ) return 0;
    mmt_handler->fragment_in_session = fragment_in_session;
    return 1;
}

void set_session_timeout_delay(mmt_session_t * session, uint32_t timeout_delay) {
    session->session_timeout_delay = timeout_delay;
}

/**
 * Manage session of this protocol
 * @param  ipacket             packet to process
 * @param  configured_protocol instance of protocol
 * @param  index               index of protocol
 * @return                     0 if this packet does not belong to a new session
 *                             1 if this packet does belong to a new session. New session will be created
 */
int proto_session_management(ipacket_t * ipacket, protocol_instance_t * configured_protocol, unsigned index) {
    int classify_status = ipacket->proto_classif_status->proto_path[index];
    mmt_handler_t * mmt_handler = ipacket->mmt_handler;
    int is_new_session = 0;

    //TODO(#327): addition of proper handling of embedded sessions.
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
                session->session_id = mmt_handler->sessions_count + 1;
                session->next = NULL;
                session->previous = NULL;

                session->fragmented_packet_count = 0;
                session->fragment_count = 0;
                session->is_fragmenting = 0;

                session->packet_count = 0;
                session->packet_cap_count = 0;
                session->data_packet_count = 0;
                session->data_volume = 0;
                session->data_cap_volume = 0;
                session->data_byte_volume = 0;

                session->packet_count_direction[1] = 0;
                session->data_volume_direction[1] = 0;
                session->packet_cap_count_direction[1] = 0;
                session->data_cap_volume_direction[1] = 0;
                session->data_packet_count_direction[1] = 0;
                session->data_byte_volume_direction[1] = 0;

                session->packet_count_direction[0] = 0;
                session->data_volume_direction[0] = 0;
                session->packet_cap_count_direction[0] = 0;
                session->data_cap_volume_direction[0] = 0;
                session->data_packet_count_direction[0] = 0;
                session->data_byte_volume_direction[0] = 0;

                session->sub_packet_count = 0;
                session->sub_packet_cap_count = 0;
                session->sub_data_packet_count = 0;
                session->sub_data_volume = 0;
                session->sub_data_cap_volume = 0;
                session->sub_data_byte_volume = 0;

                session->sub_packet_count_direction[1] = 0;
                session->sub_data_volume_direction[1] = 0;
                session->sub_packet_cap_count_direction[1] = 0;
                session->sub_data_cap_volume_direction[1] = 0;
                session->sub_data_packet_count_direction[1] = 0;
                session->sub_data_byte_volume_direction[1] = 0;

                session->sub_packet_count_direction[0] = 0;
                session->sub_data_volume_direction[0] = 0;
                session->sub_packet_cap_count_direction[0] = 0;
                session->sub_data_cap_volume_direction[0] = 0;
                session->sub_data_packet_count_direction[0] = 0;
                session->sub_data_byte_volume_direction[0] = 0;

                session->tcp_retransmissions = 0;
                session->tcp_outoforders = 0;
                session->status = NonClassified;
                session->protocol_container_context = configured_protocol;
                session->session_protocol_index = index;
                session->tcp_retransmissions = 0;
                session->tcp_outoforders = 0;
                session->session_payload_len[0] = 0;
                session->session_payload_len[1] = 0;
                session->session_payload[0] = NULL;
                session->session_payload[1] = NULL;
                session->tcp_segment_list[0] = NULL;
                session->tcp_segment_list[1] = NULL;
                session->segment_arena = NULL; // Issue #20: lazily created on first TCP segment
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
                // session->session_timeout_delay = configured_protocol->protocol->session_timeout_delay;
                session->session_timeout_delay = mmt_handler->default_session_timed_out;
                session->session_timeout_milestone = session->session_timeout_delay + ipacket->p_hdr->ts.tv_sec;
                if (insert_session_timeout_milestone(mmt_handler, session->session_timeout_milestone, session) == 0) {
                    //If we get here, then there is an out of memory problem! we should deal with
                    process_outofmemory_force_sessions_timeout(ipacket->mmt_handler, ipacket);
                    if (insert_session_timeout_milestone(mmt_handler, session->session_timeout_milestone, session) == 0) {
                        // Double OOM: remain without milestone => session never time-outable (F-BUG-023).
                        // Destroy session so we do not leak a non-time-outable flow.
                        if (configured_protocol->sessions_map) delete_session_from_protocol_context(configured_protocol, session->session_key);
                        if (configured_protocol->protocol->session_data_cleanup)
                            ((generic_session_data_cleanup_function)configured_protocol->protocol->session_data_cleanup)(session, session->session_protocol_index);
                        mmt_handler->active_sessions_count--;
                        mmt_handler->sessions_count--;
                        mmt_free(session);
                        return 0;
                    }
                }

                if (ipacket->session == NULL) {
                    //No session encapsulation; parent is NULL
                    session->parent_session = NULL; //TODO(#327): parent should be set here. If the ipacket is alreay associated to a session, then it is the parent of this one!
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
                    // debug("[PACKET_PROCESS-]> session_data_init - 0 : %"PRIu64" %p",ipacket->packet_id,(generic_session_data_initialization_function) configured_protocol->protocol->session_data_init);
                    ((generic_session_data_initialization_function) configured_protocol->protocol->session_data_init)(ipacket, index);
                }
                //Mark this protocol as done with the classification process
                ipacket->proto_classif_status->proto_path[index] = PROTO_CLASSIFICATION_DONE;

            } else {
                // session timeout update
                if (ipacket->p_hdr->ts.tv_sec > session->s_last_activity_time.tv_sec) {// No need to update the timeout if we are still in the same second
                    //if(!session->force_timeout) { //Sessions with force timeout should not be updated! they need to timeout :)
                    uint32_t old_milestone = session->session_timeout_milestone;
                    uint32_t new_milestone = session->session_timeout_delay + ipacket->p_hdr->ts.tv_sec;
                    if (update_session_timeout_milestone(mmt_handler, new_milestone, old_milestone, session) == 0) {
                        process_outofmemory_force_sessions_timeout(ipacket->mmt_handler, ipacket);
                        if (insert_session_timeout_milestone(mmt_handler, new_milestone, session) == 0) {
                            // Double OOM: keep old milestone so session stays time-outable (F-BUG-023).
                            insert_session_timeout_milestone(mmt_handler, old_milestone, session);
                            // do not advance milestone
                        } else {
                            session->session_timeout_milestone = new_milestone;
                        }
                    } else {
                        session->session_timeout_milestone = new_milestone;
                    }
                    //}
                }
            }

            //Now update the packet structure to point to the flow and the protocol hierarchy info
            if(likely(!ipacket->mmt_handler->has_reassembly)){
                ipacket->proto_headers_offset = &session->proto_headers_offset;
                ipacket->proto_headers_offset_owned = 0; // embedded in the session — never freed
                // Issue #19: offset buffer swapped to the session's stored
                // offsets — invalidate the memoized cumulative-offset cache.
                ipacket->internal_cumulative_offset_valid = 0;

            }else{
                // Copy the session offsets into a per-packet heap buffer.
                // proto_session_management runs once per protocol layer (see the
                // index+1 recursion in proto_packet_process), so without freeing
                // here every encapsulated/embedded session layer would leak the
                // buffer allocated by the previous layer (clean_packet_with_reassembly
                // frees only the final pointer). Keep old buffer on OOM.
                proto_hierarchy_t *new_off = (proto_hierarchy_t*)mmt_malloc(sizeof(proto_hierarchy_t));
                if (new_off != NULL) {
                    // F-BUG-002 (issue #199): ownership is tracked by the
                    // explicit flag, not by comparing against one known
                    // embedded address — the flag is authoritative for every
                    // non-heap alias (handler's last_received_packet, session).
                    if (ipacket->proto_headers_offset_owned) {
                        mmt_free(ipacket->proto_headers_offset);
                    }
                    ipacket->proto_headers_offset = new_off;
                    ipacket->proto_headers_offset_owned = 1; // single allocation site
                    memcpy(ipacket->proto_headers_offset,&session->proto_headers_offset,sizeof(proto_hierarchy_t));
                }
                // Issue #19: offset buffer replaced by a fresh per-packet copy —
                // invalidate the memoized cumulative-offset cache.
                ipacket->internal_cumulative_offset_valid = 0;
            }

            ipacket->proto_hierarchy = &session->proto_path;
            ipacket->proto_classif_status = &session->proto_classif_status;
            ipacket->session = session;

            //update the session basic statistics
            session->packet_count     ++;
            session->data_volume      += ipacket->p_hdr->len;
            session->data_cap_volume  += ipacket->total_caplen;
            session->packet_cap_count += ipacket->nb_reassembled_packets[index];
            mmt_session_t * p_session = session->parent_session;
            while(p_session) {
                p_session->sub_packet_count     ++;
                p_session->sub_data_volume      += ipacket->p_hdr->len;
                p_session->sub_data_cap_volume  += ipacket->total_caplen;
                p_session->sub_packet_cap_count += ipacket->nb_reassembled_packets[index];
                p_session = p_session->parent_session;
            }

            session->s_last_activity_time.tv_sec  = ipacket->p_hdr->ts.tv_sec;
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
        if ((ipacket->session != NULL) && ((classify_status == PROTO_CLASSIFICATION_DETECTION) || (classify_status == PROTO_RECLASSIFICATION)||(classify_status == PROTO_CLASSIFICATION_UPDATE))) {
            //Initialize its session data if such initialization function exists
            if (configured_protocol->protocol->session_data_init != NULL) {
                // debug("[PACKET_PROCESS-]> session_data_init - 1 : %"PRIu64" %p",ipacket->packet_id,(generic_session_data_initialization_function) configured_protocol->protocol->session_data_init);
                ((generic_session_data_initialization_function) configured_protocol->protocol->session_data_init)(ipacket, index);
            }
            is_new_session = NEW_PROTO_IN_SESSION; //This is not a new session, rather a new protocol in the session
        }
        //Mark this protocol as done with the classification process
        ipacket->proto_classif_status->proto_path[index] = PROTO_CLASSIFICATION_DONE;
    }

    return is_new_session;
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
        /* TODO(#329): Throughout metrics should be replaced by periodic handlers! */
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

    /* TODO(#329): Throughout metrics should be replaced by periodic handlers! */
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

void process_session_timer_handler(mmt_handler_t *mmt) {
    // mmt_stream_printf(stdout, "process_session_timer_handler \n");
    session_timer_iteration_callback(mmt, session_timer_handler_callback);
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

bool is_valid_proto_attribute( protocol_t *proto, uint32_t proto_id, uint32_t attr_id)
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

int mmt_char_snprintf(char * buff, size_t len, attribute_internal_t * attr) {
    if (len < MMT_CHAR_STRLEN) return -1;
    return snprintf(buff, len, "%c", *(char *) attr->data);
}

int mmt_uint8_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_U8_STRLEN) return -1;
    return snprintf(buff, len, "%hu", (uint16_t) * (uint8_t *) attr->data);
}

int mmt_uint16_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_U16_STRLEN) return -1;
    return snprintf(buff, len, "%hu", *(uint16_t *) attr->data);
}

int mmt_uint32_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_U32_STRLEN) return -1;
    return snprintf(buff, len, "%u", *(uint32_t *) attr->data);
}

int mmt_uint64_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_U64_STRLEN) return -1;
    return snprintf(buff, len, "%"PRIu64, *(uint64_t *) attr->data);
}

int mmt_float_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_U64_STRLEN) return -1;
    return snprintf(buff, len, "%.3f", *(float *) attr->data);
}

int mmt_pointer_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_POINTER_STRLEN) return -1;
    return snprintf(buff, len, "%p", (void *) attr->data);
}

int mmt_mac_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_MAC_STRLEN) return -1;
    const uint8_t *ea = attr->data;
    return snprintf( buff, MMT_MAC_STRLEN, "%02x:%02x:%02x:%02x:%02x:%02x", ea[0], ea[1], ea[2], ea[3], ea[4], ea[5] );
}

int mmt_ip_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_IP_STRLEN) return -1;
    return mmt_inet_ntop(AF_INET, (void *) attr->data, buff, INET_ADDRSTRLEN) == NULL ? -1 : strlen(buff);
}

int mmt_ip6_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < MMT_IP6_STRLEN) return -1;
    return mmt_inet_ntop(AF_INET6, (void *) attr->data, buff, INET6_ADDRSTRLEN) == NULL ? -1 : strlen(buff);
}

int mmt_path_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (len < 2) return -1; //not less than 1 character (".")
    //Print as much as it can into buff. If the len is less than the expected strlen, then the
    //return value will be higher than the given length and the user would be able to detect
    //the truncation.
    int offset = 0;
    proto_hierarchy_t * p = (proto_hierarchy_t *) attr->data;
    if (p == NULL) return -1;
    if (p->len < 1) {
        int n = snprintf(buff, (size_t)len, ".");
        if (n > 0) offset += n;
    } else {
        int index = 1;
        if (offset < len) {
            size_t rem = (size_t)(len - offset);
            int n = snprintf(buff, rem, "%u", p->proto_path[index]);
            if (n > 0) offset += n;
        }
        index++;
        for (; (index < p->len) && (index < 16) && offset < len; index++) {
            if (offset >= len) break;
            size_t rem = (size_t)(len - offset);
            int n = snprintf(&buff[offset], rem, ".%u", p->proto_path[index]);
            if (n < 0) break;
            offset += n;
            if (offset >= len) break;
        }
    }
    return offset;
}

int mmt_timeval_snprintf(char * buff, int len, attribute_internal_t * attr) {
    //Print as much as it can into buff. If the len is less than the expected strlen, then the
    //return value will be higher than the given length and the user would be able to detect
    //the truncation.
    return snprintf(buff, len, "%lu.%06lu", ((struct timeval *) attr->data)->tv_sec, ((struct timeval *) attr->data)->tv_usec);
}

int mmt_binary_snprintf(char * buff, int len, attribute_internal_t * attr) {
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    if (len < (b->len * 2 + 1)) return -1;
    int index = 0, offset = 0;
    for (; index < (b->len) && offset < len; index++) {
        offset += snprintf((char *) &buff[offset], len - offset, "%02x", b->data[index]);
    }
    return offset;
}

int mmt_string_snprintf(char * buff, int len, attribute_internal_t * attr) {
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    if (buff == NULL || len <= 0) return -1;
    if (b == NULL) { buff[0] = '\0'; return 0; }
    /* F-BUG-025: use %.*s with recorded length to avoid reading past packet-derived buffer */
    return snprintf(buff, (size_t)len, "%.*s", (int)b->len, (char *) &b->data);
}

int mmt_string_pointer_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (buff == NULL || len <= 0) return -1;
    if (attr == NULL || attr->data == NULL) { buff[0] = '\0'; return 0; }
    /* packet-derived pointer string is expected NUL-terminated; still bounded by dest len via snprintf */
    return snprintf(buff, (size_t)len, "%s", (char *) attr->data);
}

int mmt_stats_snprintf(char * buff, int len, attribute_internal_t * attr) {
    return snprintf(buff, len, "%s", "TODO"); /* unimplemented report output — issue #328 */
}

int mmt_header_line_pointer_snprintf(char * buff, int len, attribute_internal_t * attr) {
    mmt_header_line_t * data = (mmt_header_line_t *) attr->data;
    int copy_len = (data->len > (len - 1)) ? len - 1 : data->len;
    memcpy((void *) buff, (void *) data->ptr, copy_len);
    buff[copy_len] = '\0';
    return copy_len;
}

int mmt_u16_array_snprintf(char * buff, int len, attribute_internal_t * attr) {
    mmt_u16_array_t * b = (mmt_u16_array_t *) attr->data;
    int i, total=0;
    if (buff == NULL || len <= 0 || b == NULL) return -1;
    for( i=0; i<(int)b->len; i++ ) {
       if (total >= len) break;
       size_t rem = (size_t)(len - total);
       int n = snprintf(&buff[total], rem, (i==0?"%hu":",%hu"), b->data[i]);
       if (n < 0) break;
       total += n;
       if (total >= len) break;
    }
    return total;
}
int mmt_u32_array_snprintf(char * buff, int len, attribute_internal_t * attr) {
    mmt_u32_array_t * b = (mmt_u32_array_t *) attr->data;
    int i, total=0;
    if (buff == NULL || len <= 0 || b == NULL) return -1;
    for( i=0; i<(int)b->len; i++ ) {
       if (total >= len) break;
       size_t rem = (size_t)(len - total);
       int n = snprintf(&buff[total], rem, (i==0?"%u":",%u"), b->data[i]);
       if (n < 0) break;
       total += n;
       if (total >= len) break;
    }
    return total;
}
int mmt_u64_array_snprintf(char * buff, int len, attribute_internal_t * attr) {
    mmt_u64_array_t * b = (mmt_u64_array_t *) attr->data;
    int i, total=0;
    if (buff == NULL || len <= 0 || b == NULL) return -1;
    for( i=0; i<(int)b->len; i++ ) {
       if (total >= len) break;
       size_t rem = (size_t)(len - total);
       /* F-BUG-018: single conversion per iteration, one argument */
       int n = snprintf(&buff[total], rem, (i==0?"%"PRIu64:",%"PRIu64), b->data[i]);
       if (n < 0) break;
       total += n;
       if (total >= len) break;
    }
    return total;
}

int mmt_attr_snprintf(char * buff, int len, attribute_t * a) {
    attribute_internal_t * attr = (attribute_internal_t *) a;
    switch (mmt_attr_get_data_type_typed(a)) {
    case MMT_U8_DATA:
        return mmt_uint8_snprintf(buff, len, attr);
    case MMT_U16_DATA:
        return mmt_uint16_snprintf(buff, len, attr);
    case MMT_U32_DATA:
        return mmt_uint32_snprintf(buff, len, attr);
    case MMT_U64_DATA:
        return mmt_uint64_snprintf(buff, len, attr);
    case MMT_DATA_FLOAT:
         return mmt_float_snprintf(buff, len, attr);
    case MMT_DATA_CHAR:
        return mmt_char_snprintf(buff, len, attr);
    case MMT_DATA_POINTER:
        return mmt_pointer_snprintf(buff, len, attr);
    case MMT_DATA_MAC_ADDR:
        return mmt_mac_snprintf(buff, len, attr);
    case MMT_DATA_IP_ADDR:
        return mmt_ip_snprintf(buff, len, attr);
    case MMT_DATA_IP6_ADDR:
        return mmt_ip6_snprintf(buff, len, attr);
    case MMT_DATA_PATH:
        return mmt_path_snprintf(buff, len, attr);
    case MMT_DATA_TIMEVAL:
        return mmt_timeval_snprintf(buff, len, attr);
    case MMT_BINARY_DATA:
        return mmt_binary_snprintf(buff, len, attr);
    case MMT_BINARY_VAR_DATA:
        return mmt_binary_snprintf(buff, len, attr);
    case MMT_STRING_DATA:
        return mmt_string_snprintf(buff, len, attr);
    case MMT_STRING_LONG_DATA:
        return mmt_string_snprintf(buff, len, attr);
    case MMT_STRING_DATA_POINTER:
        return mmt_string_pointer_snprintf(buff, len, attr);
    case MMT_HEADER_LINE:
        return mmt_header_line_pointer_snprintf(buff, len, attr);
    case MMT_STATS:
        return mmt_stats_snprintf(buff, len, attr);
    case MMT_U16_ARRAY:
        return mmt_u16_array_snprintf( buff, len, attr );
    case MMT_U32_ARRAY:
        return mmt_u32_array_snprintf( buff, len, attr );
    case MMT_U64_ARRAY:
        return mmt_u64_array_snprintf( buff, len, attr );
    default:
        return mmt_stats_snprintf(buff, len, attr); //TODO(#328)
    }
}

int mmt_char_fprintf(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "%c", *(char *) attr->data);
}

int mmt_uint8_fprintf(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "%hu", (uint16_t) * (uint8_t *) attr->data);
}

int mmt_uint16_fprintf(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "%hu", *(uint16_t *) attr->data);
}

int mmt_uint32_fprintf(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "%u", *(uint32_t *) attr->data);
}

int mmt_uint64_fprintf(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "%"PRIu64, *(uint64_t *) attr->data);
}

int mmt_pointer_fprintf(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "%p", (void *) attr->data);
}

int mmt_mac_fprintf(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_MAC_STRLEN];
    if (mmt_mac_snprintf(buff, MMT_MAC_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "%s", buff);
    }
    return -1;
}

int mmt_ip_fprintf(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_IP_STRLEN];
    if (mmt_ip_snprintf(buff, MMT_IP_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "%s", buff);
    }
    return -1;
}

int mmt_ip6_fprintf(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_IP6_STRLEN];
    if (mmt_ip6_snprintf(buff, MMT_IP6_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "%s", buff);
    }
    return -1;
}

int mmt_path_fprintf(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_PATH_STRLEN];
    if (mmt_path_snprintf(buff, MMT_PATH_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "%s", buff);
    }
    return -1;
}
int mmt_timeval_fprintf(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "%lu.%06lu", ((struct timeval *) attr->data)->tv_sec, ((struct timeval *) attr->data)->tv_usec);
}
int mmt_binary_fprintf(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_BINARYVAR_STRLEN];
    if (mmt_binary_snprintf(buff, MMT_BINARY_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "%s", buff);
    }
    return -1;
}
int mmt_string_fprintf(FILE * f, attribute_internal_t * attr) {
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    if (b == NULL) return -1;
    return mmt_stream_printf(f, "%.*s", (int)b->len, (char *) &b->data);
}
int mmt_string_pointer_fprintf(FILE * f, attribute_internal_t * attr) {
    if (attr == NULL || attr->data == NULL) return -1;
    return mmt_stream_printf(f, "%s", (char *) attr->data);
}

int mmt_header_line_pointer_fprintf(FILE * f, attribute_internal_t * attr) {
    char buff[8096 + 1]; //Max accepted header line length is 8K (default for Apache)
    if (mmt_header_line_pointer_snprintf(buff, 8096, attr) > 0) {
        return mmt_stream_printf(f, "%s", buff);
    }
    return -1;
}

int mmt_stats_fprintf(FILE *f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "%s", "TODO"); /* unimplemented report output — issue #328 */
}

int mmt_attr_fprintf(FILE * f, attribute_t * a) {
    attribute_internal_t * attr = (attribute_internal_t *) a;
    switch (mmt_attr_get_data_type_typed(a)) {
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
    case MMT_HEADER_LINE:
        return mmt_header_line_pointer_fprintf(f, attr);
    case MMT_STATS:
        return mmt_stats_fprintf(f, attr);
    default:
        return mmt_stats_fprintf(f, attr);
    }
}

int mmt_char_format(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "Attribute %s.%s = %c\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), *(char *) attr->data);
}

int mmt_uint8_format(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "Attribute %s.%s = %hu\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), (uint16_t) * (uint8_t *) attr->data);
}

int mmt_uint16_format(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "Attribute %s.%s = %hu\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), *(uint16_t *) attr->data);
}

int mmt_uint32_format(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "Attribute %s.%s = %u\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), *(uint32_t *) attr->data);
}

int mmt_uint64_format(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "Attribute %s.%s = %"PRIu64"\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), *(uint64_t *) attr->data);
}

int mmt_pointer_format(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "Attribute %s.%s = %p\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), (void *) attr->data);
}

int mmt_mac_format(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_MAC_STRLEN];
    if (mmt_mac_snprintf(buff, MMT_MAC_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "Attribute %s.%s = %s\n",
                       get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}

int mmt_ip_format(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_IP_STRLEN];
    if (mmt_ip_snprintf(buff, MMT_IP_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "Attribute %s.%s = %s\n",
                       get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}

int mmt_ip6_format(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_IP6_STRLEN];
    if (mmt_ip6_snprintf(buff, MMT_IP6_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "Attribute %s.%s = %s\n",
                       get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}

int mmt_path_format(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_PATH_STRLEN];
    if (mmt_path_snprintf(buff, MMT_PATH_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "Attribute %s.%s = %s\n",
                       get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}
int mmt_timeval_format(FILE * f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "Attribute %s.%s  = %lu.%06lu\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), ((struct timeval *) attr->data)->tv_sec, ((struct timeval *) attr->data)->tv_usec);
}

int mmt_binary_format(FILE * f, attribute_internal_t * attr) {
    char buff[MMT_BINARYVAR_STRLEN];
    if (mmt_binary_snprintf(buff, MMT_BINARY_STRLEN, attr) > 0) {
        return mmt_stream_printf(f, "Attribute %s.%s = %s\n",get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}
int mmt_string_format(FILE * f, attribute_internal_t * attr) {
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    if (b == NULL) return -1;
    return mmt_stream_printf(f, "Attribute %s.%s = %.*s\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), (int)b->len, (char *) &b->data);
}
int mmt_string_pointer_format(FILE * f, attribute_internal_t * attr) {
    int ret = mmt_stream_printf(f, "Attribute %s.%s = %s\n",
                      get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), (char *) attr->data);
    // free((char*)attr->data);
    return ret;
}

int mmt_header_line_pointer_format(FILE * f, attribute_internal_t * attr) {
    char buff[8096 + 1]; //Max accepted header line length is 8K (default for Apache)
    if (mmt_header_line_pointer_snprintf(buff, 8096, attr) > 0) {
        return mmt_stream_printf(f, "Attribute %s.%s = %s\n",
                       get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    return -1;
}

int mmt_stats_format(FILE *f, attribute_internal_t * attr) {
    return mmt_stream_printf(f, "Attribute %s.%s = %s\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), "TODO"); /* unimplemented report output — issue #328 */
}

int mmt_attr_format(FILE * f, attribute_t * a) {
    attribute_internal_t * attr = (attribute_internal_t *) a;
    switch (mmt_attr_get_data_type_typed(a)) {
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
    case MMT_HEADER_LINE:
        return mmt_header_line_pointer_format(f, attr);
    case MMT_STATS:
        return mmt_stats_format(f, attr);
    default:
        return mmt_stats_format(f, attr);
    }
}

char * mmt_version() {
    return MMT_VERSION;
}