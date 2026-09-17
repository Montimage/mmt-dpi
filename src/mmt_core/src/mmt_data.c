
#include "data_defs.h"
#include "packet_processing.h"

int get_packet_offset_at_index(const ipacket_t * ipacket, unsigned index) {
    // Issue #19: memoized cumulative offsets. The per-layer header offsets in
    // proto_headers_offset->proto_path[] are summed once into a prefix-sum cache
    // and reused, so each call is O(1) instead of O(index) — turning the
    // per-packet cost from O(N^2) (re-summed on every call) into O(N) (built
    // once, then O(1) lookups). The cache lives in the (otherwise const) ipacket
    // and is invalidated by set_classified_proto() and every reassignment of
    // proto_headers_offset, so the value returned is byte-identical to the old
    // re-summation for the current offset state.
    ipacket_t * pkt = (ipacket_t *) ipacket; // mutable memoization cache only
    if (index >= (unsigned) PROTO_PATH_SIZE) {
        index = PROTO_PATH_SIZE - 1;
    }
    if (!pkt->internal_cumulative_offset_valid) {
        pkt->internal_cumulative_offset_hwm = -1; // nothing summed yet
        pkt->internal_cumulative_offset_valid = 1;
    }
    // Extend the prefix sum only as far as the queried index (high-water mark),
    // so across a packet the offsets are summed once in total (amortized O(1)
    // per call) instead of re-summed from 0 on every call.
    int hwm = pkt->internal_cumulative_offset_hwm;
    if ((int) index > hwm) {
        int sum = (hwm >= 0) ? pkt->internal_cumulative_offset[hwm] : 0;
        int i;
        for (i = hwm + 1; i <= (int) index; i++) {
            sum += ipacket->proto_headers_offset->proto_path[i];
            pkt->internal_cumulative_offset[i] = sum;
        }
        pkt->internal_cumulative_offset_hwm = (int) index;
    }
    return pkt->internal_cumulative_offset[index];
}

unsigned get_protocol_index_by_id(const ipacket_t * ipacket, uint32_t proto_id) {
    int retval = -1, i;
    int nb_proto = ipacket->proto_hierarchy->len;
    for (i = nb_proto - 1 ; i >= 0; i--) {
        if (ipacket->proto_hierarchy->proto_path[i] == proto_id) {
            retval = i;
            break;
        }
    }
    return retval;
}

unsigned get_protocol_index_by_name(const ipacket_t * ipacket, const char *proto_name) {
    uint32_t proto_id = get_protocol_id_by_name(proto_name);
    int retval = -1, i;
    if (proto_id) {
        int nb_proto = ipacket->proto_hierarchy->len;
        for (i = nb_proto - 1; i >= 0; i--) {
            if (ipacket->proto_hierarchy->proto_path[i] == proto_id) {
                retval = i;
                break;
            }
        }
    }

    return retval;
}

uint64_t get_session_id_from_packet( const ipacket_t *ipacket )
{
    if(ipacket->session) return ipacket->session->session_id;
    return -1;
}

mmt_session_t * get_session_from_packet( const ipacket_t *ipacket )
{ return ipacket->session; }

void *get_user_session_context_from_packet( const ipacket_t *ipacket )
{
    if(ipacket->session) return ipacket->session->user_data;
    return NULL;
}

void set_user_session_context_for_packet( const ipacket_t *ipacket, void *user_data )
{ if(ipacket->session) ipacket->session->user_data = user_data; }

void *get_proto_session_data_from_packet( const ipacket_t *ipacket , unsigned index )
{
  if(ipacket->session && index < PROTO_PATH_SIZE) return ipacket->session->session_data[index];
  return NULL;
}

uint64_t get_session_id(const mmt_session_t *session)
{ return session->session_id; }

void *get_proto_session_data( const mmt_session_t *session, unsigned index )
{
  if(index < PROTO_PATH_SIZE) return session->session_data[index];
  return NULL;
}

void set_proto_session_data( mmt_session_t *session, void * proto_data, unsigned index )
{
  if(index < PROTO_PATH_SIZE) session->session_data[index] = proto_data;
}

void *get_user_session_context( const mmt_session_t *session )
{ return session->user_data; }

void set_user_session_context( mmt_session_t *session, void *user_data )
{ session->user_data = user_data; }

mmt_session_t * get_session_parent( const mmt_session_t *session )
{ return session->parent_session; }

mmt_handler_t * get_session_handler( const mmt_session_t *session )
{ return session->mmt_handler; }

uint32_t get_session_protocol_index( const mmt_session_t *session )
{ return session->session_protocol_index; }

const proto_hierarchy_t * get_session_protocol_hierarchy( const mmt_session_t *session )
{ return &session->proto_path; }

/* Issue #255 (F-PERF-010): the subsession counters live in the lazily-
 * allocated tunnel-parent extension — a NULL children_stats means "no child
 * sessions", i.e. every sub_* counter reads as 0. */
#define SESSION_SUB(session, field) \
    ((session)->children_stats != NULL ? (session)->children_stats->field : 0)

uint64_t get_session_packet_count( const mmt_session_t *session )
{ return session->packet_count - SESSION_SUB(session, sub_packet_count); }

uint64_t get_session_packet_cap_count( const mmt_session_t *session )
{ return session->packet_cap_count - SESSION_SUB(session, sub_packet_cap_count); }

uint64_t get_session_data_cap_volume( const mmt_session_t *session )
{ return session->data_cap_volume - SESSION_SUB(session, sub_data_cap_volume); }

uint64_t get_session_ul_packet_count( const mmt_session_t *session )
{ return session->packet_count_direction[session->setup_packet_direction] - SESSION_SUB(session, sub_packet_count_direction[session->setup_packet_direction]); }

uint64_t get_session_ul_cap_packet_count( const mmt_session_t *session )
{ return session->packet_cap_count_direction[session->setup_packet_direction] - SESSION_SUB(session, sub_packet_cap_count_direction[session->setup_packet_direction]); }

uint64_t get_session_dl_packet_count( const mmt_session_t *session )
{ return session->packet_count_direction[!session->setup_packet_direction] - SESSION_SUB(session, sub_packet_count_direction[!session->setup_packet_direction]); }

uint64_t get_session_dl_cap_packet_count( const mmt_session_t *session )
{ return session->packet_cap_count_direction[!session->setup_packet_direction] - SESSION_SUB(session, sub_packet_cap_count_direction[!session->setup_packet_direction]); }

uint64_t get_session_byte_count( const mmt_session_t *session )
{ return session->data_volume - SESSION_SUB(session, sub_data_volume); }

uint64_t get_session_ul_byte_count( const mmt_session_t *session )
{ return session->data_volume_direction[session->setup_packet_direction] - SESSION_SUB(session, sub_data_volume_direction[session->setup_packet_direction]); }

uint64_t get_session_ul_cap_byte_count( const mmt_session_t *session )
{ return session->data_cap_volume_direction[session->setup_packet_direction] - SESSION_SUB(session, sub_data_cap_volume_direction[session->setup_packet_direction]); }

uint64_t get_session_dl_byte_count( const mmt_session_t *session )
{ return session->data_volume_direction[!session->setup_packet_direction] - SESSION_SUB(session, sub_data_volume_direction[!session->setup_packet_direction]); }

uint64_t get_session_dl_cap_byte_count( const mmt_session_t *session )
{ return session->data_cap_volume_direction[!session->setup_packet_direction] - SESSION_SUB(session, sub_data_cap_volume_direction[!session->setup_packet_direction]); }

uint64_t get_session_data_packet_count( const mmt_session_t *session )
{ return session->data_packet_count - SESSION_SUB(session, sub_data_packet_count); }

uint64_t get_session_ul_data_packet_count( const mmt_session_t *session )
{ return session->data_packet_count_direction[session->setup_packet_direction] - SESSION_SUB(session, sub_data_packet_count_direction[session->setup_packet_direction]); }

uint64_t get_session_dl_data_packet_count( const mmt_session_t *session )
{ return session->data_packet_count_direction[!session->setup_packet_direction] - SESSION_SUB(session, sub_data_packet_count_direction[!session->setup_packet_direction]); }

uint64_t get_session_data_byte_count( const mmt_session_t *session )
{ return session->data_byte_volume - SESSION_SUB(session, sub_data_byte_volume); }

uint64_t get_session_ul_data_byte_count( const mmt_session_t *session )
{ return session->data_byte_volume_direction[session->setup_packet_direction] - SESSION_SUB(session, sub_data_byte_volume_direction[session->setup_packet_direction]); }

uint64_t get_session_dl_data_byte_count( const mmt_session_t *session )
{ return session->data_byte_volume_direction[!session->setup_packet_direction] - SESSION_SUB(session, sub_data_byte_volume_direction[!session->setup_packet_direction]); }

#undef SESSION_SUB

// GET TOTAL STATISTICS
uint64_t get_session_total_packet_count( const mmt_session_t *session )
{ return session->packet_count; }

uint64_t get_session_total_packet_cap_count( const mmt_session_t *session )
{ return session->packet_cap_count; }

uint64_t get_session_total_data_cap_volume( const mmt_session_t *session )
{ return session->data_cap_volume; }

uint64_t get_session_total_ul_packet_count( const mmt_session_t *session )
{ return session->packet_count_direction[session->setup_packet_direction]; }

uint64_t get_session_total_ul_cap_packet_count( const mmt_session_t *session )
{ return session->packet_cap_count_direction[session->setup_packet_direction]; }

uint64_t get_session_total_dl_packet_count( const mmt_session_t *session )
{ return session->packet_count_direction[!session->setup_packet_direction]; }

uint64_t get_session_total_dl_cap_packet_count( const mmt_session_t *session )
{ return session->packet_cap_count_direction[!session->setup_packet_direction]; }

uint64_t get_session_total_byte_count( const mmt_session_t *session )
{ return session->data_volume; }

uint64_t get_session_total_ul_byte_count( const mmt_session_t *session )
{ return session->data_volume_direction[session->setup_packet_direction]; }

uint64_t get_session_total_ul_cap_byte_count( const mmt_session_t *session )
{ return session->data_cap_volume_direction[session->setup_packet_direction]; }

uint64_t get_session_total_dl_byte_count( const mmt_session_t *session )
{ return session->data_volume_direction[!session->setup_packet_direction]; }

uint64_t get_session_total_dl_cap_byte_count( const mmt_session_t *session )
{ return session->data_cap_volume_direction[!session->setup_packet_direction]; }

uint64_t get_session_total_data_packet_count( const mmt_session_t *session )
{ return session->data_packet_count; }

uint64_t get_session_total_ul_data_packet_count( const mmt_session_t *session )
{ return session->data_packet_count_direction[session->setup_packet_direction]; }

uint64_t get_session_total_dl_data_packet_count( const mmt_session_t *session )
{ return session->data_packet_count_direction[!session->setup_packet_direction]; }

uint64_t get_session_total_data_byte_count( const mmt_session_t *session )
{ return session->data_byte_volume; }

uint64_t get_session_total_ul_data_byte_count( const mmt_session_t *session )
{ return session->data_byte_volume_direction[session->setup_packet_direction]; }

uint64_t get_session_total_dl_data_byte_count( const mmt_session_t *session )
{ return session->data_byte_volume_direction[!session->setup_packet_direction]; }
// END OF GET TOTAL STATISTICS


struct timeval get_session_init_time( const mmt_session_t *session )
{ return session->s_init_time; }

struct timeval get_session_last_activity_time( const mmt_session_t *session )
{ return session->s_last_activity_time; }

struct timeval get_session_last_data_packet_time_by_direction( const mmt_session_t *session ,uint8_t direction)
{ return session->s_last_data_packet_time[direction]; }

struct timeval get_session_rtt( const mmt_session_t *session )
{ return session->rtt; }

uint16_t get_session_content_class_id( const mmt_session_t *session )
{ return session->content_info.content_class; }

uint16_t get_session_content_type_id( const mmt_session_t *session )
{ return session->content_info.content_type; }

uint32_t get_session_content_flags( const mmt_session_t *session )
{ return session->content_flags; }

uint32_t get_session_retransmission_count( const mmt_session_t *session )
{ return session->tcp_retransmissions; }

uint32_t get_session_outoforder_count( const mmt_session_t *session )
{ return session->tcp_outoforders; }

const mmt_session_t * get_session_next( const mmt_session_t *session )
{
    return session->next; }

const mmt_session_t * get_session_previous( const mmt_session_t *session )
{ return session->previous; }


const proto_hierarchy_t * get_session_proto_path_direction(const mmt_session_t *session, mmt_session_direction_t direction){
    /* Issue #255 (F-PERF-010): the per-direction copies moved into the
     * tunnel-parent extension. A leaf session (children_stats == NULL) has a
     * single protocol path shared by both directions — report proto_path
     * itself (identical to what the direction copies would hold). */
    if (session->children_stats == NULL)
        return &session->proto_path;
    const proto_hierarchy_t *paths = session->children_stats->proto_path_direction;
    // debug("[IP] setup_packet_direction: %d",session->setup_packet_direction);
    // debug("[IP] last_packet_direction: %d",session->last_packet_direction);
    if(direction == MMT_SESSION_DIRECTION_UPLINK){
        // Uplink path requested: the setup direction is the uplink one
        if(session->last_packet_direction == session->setup_packet_direction){
            // last packet went uplink -> uplink path
            return &paths[session->setup_packet_direction];
        }else{
            // last packet went downlink -> downlink path
            return &paths[!session->setup_packet_direction];
        }
    }else{
        // Downlink path requested
        if(session->last_packet_direction == session->setup_packet_direction){
            // last packet went uplink -> downlink path
            return &paths[!session->setup_packet_direction];
        }else{
            // last packet went downlink -> uplink path (issue #238: this
            // branch used to repeat the sibling's "downloading data" comment)
            return &paths[session->setup_packet_direction];
        }
    }

}

uint8_t get_session_last_packet_direction( const mmt_session_t *session )
{
    return session->last_packet_direction;
}

uint8_t get_session_setup_direction( const mmt_session_t *session )
{
    return session->setup_packet_direction;
}


uint32_t get_protocol_id_at_index(const ipacket_t * ipacket, unsigned index) {
    if (index >= PROTO_PATH_SIZE)
        return -1;
    if (index < ipacket->proto_hierarchy->len)
        return ipacket->proto_hierarchy->proto_path[index];

    return -1;
}

uint32_t get_data_size_by_data_type(uint32_t data_type) {
    switch (data_type) {
        case MMT_UNDEFINED_TYPE: /**< no type constant value */
            return 0;
        case MMT_U8_DATA: /**< unsigned 1-byte constant value */
            return sizeof (char);
        case MMT_U16_DATA: /**< unsigned 2-bytes constant value */
            return sizeof (short);
        case MMT_U32_DATA: /**< unsigned 4-bytes constant value */
            return sizeof (int);
        case MMT_U64_DATA: /**< unsigned 8-bytes constant value */
            return sizeof (long long);
        case MMT_DATA_FLOAT:
            return sizeof( float );
        case MMT_DATA_POINTER: /**< pointer constant value (size is CPU dependant) */
            return sizeof (void *);
        case MMT_DATA_MAC_ADDR: /**< ethernet mac address constant value */
            return ETH_ALEN;
        case MMT_DATA_IP_ADDR: /**< ip network address and mask constant value */
            return IPv4_ALEN;
        case MMT_DATA_PATH: /**< protocol path constant value */
            return sizeof (proto_hierarchy_t);
        case MMT_DATA_TIMEVAL: /**< number of seconds and microseconds constant value */
            return sizeof (struct timeval);
        case MMT_BINARY_DATA: /**< binary constant value */
        case MMT_STRING_DATA:
            return BINARY_64DATA_TYPE_LEN;
        case MMT_BINARY_VAR_DATA: /**< binary constant value */
            return BINARY_1024DATA_TYPE_LEN;
        case MMT_DATA_IP6_ADDR: /**< ip6 address constant value */
            return IPv6_ALEN;
        case MMT_STATS: /**< pointer to MMT Protocol statistics */
        case MMT_STRING_DATA_POINTER:
            return sizeof(void *);
        case MMT_STRING_LONG_DATA:
            return STRING_DATA_TYPE_LEN;
        case MMT_HEADER_LINE: /**< pointer to MMT header line structure. Used for HTTP like protocols header fields */
            return sizeof(void *);
        case MMT_U16_ARRAY:
             return U16_ARRAY_TYPE_LEN;
        case MMT_U32_ARRAY:
             return U32_ARRAY_TYPE_LEN;
        case MMT_U64_ARRAY:
             return U64_ARRAY_TYPE_LEN;
        default:
            return 0;
    }
}

unsigned htoi(char * chdata, size_t chdata_cap, const char *ptr, int len) {
    if(chdata == NULL || ptr == NULL) return 0;
    if(len <= 0 || chdata_cap == 0) return 0;
    /* len is the number of bytes requested; never write more than
     * chdata_cap and never read more than len*2 hex chars. */
    size_t max_bytes = (size_t)len;
    if(max_bytes > chdata_cap) max_bytes = chdata_cap;

    unsigned index_nb = 0;
    const char *p = ptr;
    int nibble = 0; /* 0 = high nibble, 1 = low nibble */

    for(size_t pos = 0; pos < max_bytes * 2; pos++){
        char ch = p[pos];
        int v;
        if(ch >= '0' && ch <= '9') v = ch - '0';
        else if(ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
        else if(ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
        else {
            /* non-hex terminates: if we stopped mid-byte, that byte is
             * incomplete — do not count it (keeps original semantics where
             * return is index_nb or index_nb+1 depending on alignment). */
            if(nibble == 1) return index_nb + 1;
            return index_nb;
        }
        if(nibble == 0){
            chdata[index_nb] = (char)v;
            nibble = 1;
        } else {
            chdata[index_nb] = (char)((chdata[index_nb] << 4) + v);
            nibble = 0;
            index_nb++;
            if(index_nb >= max_bytes){
                /* Consumed len bytes or filled capacity — need to verify
                 * the next char (if any) is not a stray hex that would have
                 * continued, but bounded return is index_nb. */
                return index_nb;
            }
        }
    }
    /* Reached len*2 chars cleanly: if we ended mid-byte, the partial byte
     * counts as one (mirrors original loop's index_nb+1 on odd length). */
    if(nibble == 1) return index_nb + 1;
    return index_nb;
}

uint32_t short_time_diff(struct timeval *starttime, struct timeval *finishtime) {
    uint32_t usec;
    usec = (finishtime->tv_sec - starttime->tv_sec)*1000000;
    usec += (finishtime->tv_usec - starttime->tv_usec);
    return usec;
}

static inline char _mmt_toupper(char in) {
    if ((in >= 97) && (in <= 122))
        in = in - 32;
    return in;
}

char mmt_toupper(char in) {
	return _mmt_toupper( in );
}

char mmt_tolower(char in) {
    if ((in >= 65) && (in <= 90))
        in = in + 32;
    return in;
}


int mmt_strcasecmp(const char *first, const char *second) {
    for(; _mmt_toupper(*first) == _mmt_toupper(*second); first++, second++) {
        if(*first == '\0') return 0; //complete match
    }
    //The strings do not match
    return ((_mmt_toupper(*first) > _mmt_toupper(*second))? +1 : -1);
}

int mmt_strncasecmp(const char *first, const char *second, size_t max) {
    while (max) {
        if (_mmt_toupper(*first) != _mmt_toupper(*second)) {
            return ((_mmt_toupper(*first) > _mmt_toupper(*second))? +1 : -1);
        }else if (*first == '\0') {
            return 0;
        }
        max--;
        first++;
        second++;
    }
    //We get here only when the 2 strings are case insensitive equal
    return 0;
}

int mmt_strcmp(const char *first, const char *second) {
    for(; *first == *second; first++, second++) {
        if(*first == '\0') return 0; //complete match
    }
    //The strings do not match
    return ((*first > *second)? +1 : -1);
}

int mmt_strncmp(const char *first, const char *second, size_t max) {
    while (max) {
        if (*first != *second) {
            return ((*first > *second)? +1 : -1);
        }else if (*first == '\0') {
            return 0;
        }
        max--;
        first++;
        second++;
    }
    //We get here only when the 2 strings are case insensitive equal
    return 0;
}

