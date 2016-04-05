
#include "data_defs.h"
#include "packet_processing.h"

int get_packet_offset_at_index(const ipacket_t * ipacket, unsigned index) {
    int retval = 0;
    int i = 0;
    for (; i <= index; i++) {
        retval += ipacket->proto_headers_offset->proto_path[i];
    }
    return retval;
}

unsigned get_protocol_index_by_id(const ipacket_t * ipacket, uint32_t proto_id) {
    int retval = -1, i;
    int nb_proto = ipacket->proto_hierarchy->len;
    for (i = 0; i < nb_proto; i++) {
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
        for (i = 0; i < nb_proto; i++) {
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

uint64_t get_session_packet_count( const mmt_session_t *session )
{ return session->packet_count; }

uint64_t get_session_ul_packet_count( const mmt_session_t *session )
{ return session->packet_count_direction[session->setup_packet_direction]; }

uint64_t get_session_dl_packet_count( const mmt_session_t *session )
{ return session->packet_count_direction[!session->setup_packet_direction]; }

uint64_t get_session_byte_count( const mmt_session_t *session )
{ return session->data_volume; }

uint64_t get_session_ul_byte_count( const mmt_session_t *session )
{ return session->data_volume_direction[session->setup_packet_direction]; }

uint64_t get_session_dl_byte_count( const mmt_session_t *session )
{ return session->data_volume_direction[!session->setup_packet_direction]; }

uint64_t get_session_data_packet_count( const mmt_session_t *session )
{ return session->data_packet_count; }

uint64_t get_session_ul_data_packet_count( const mmt_session_t *session )
{ return session->data_packet_count_direction[session->setup_packet_direction]; }

uint64_t get_session_dl_data_packet_count( const mmt_session_t *session )
{ return session->data_packet_count_direction[!session->setup_packet_direction]; }

uint64_t get_session_data_byte_count( const mmt_session_t *session )
{ return session->data_byte_volume; }

uint64_t get_session_ul_data_byte_count( const mmt_session_t *session )
{ return session->data_byte_volume_direction[session->setup_packet_direction]; }

uint64_t get_session_dl_data_byte_count( const mmt_session_t *session )
{ return session->data_byte_volume_direction[!session->setup_packet_direction]; }

struct timeval get_session_init_time( const mmt_session_t *session )
{ return session->s_init_time; }

struct timeval get_session_last_activity_time( const mmt_session_t *session )
{ return session->s_last_activity_time; }

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

const mmt_session_t * get_session_next( const mmt_session_t *session )
{   
    return session->next; }

const mmt_session_t * get_session_previous( const mmt_session_t *session )
{ return session->previous; }


uint32_t get_protocol_id_at_index(const ipacket_t * ipacket, unsigned index) {
    if (index > PROTO_PATH_SIZE)
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
        default:
            return 0;
    }
}

unsigned htoi(char * chdata, const char *ptr, int len) {
    unsigned index_nb = 0;
    char ch = *ptr;
    int i = 0;

    for (;;) {
        if (i == 0) {
            i = 1;
            chdata[index_nb] = '\0';
            if (ch >= '0' && ch <= '9') {
                chdata[index_nb] = (char) ((ch - '0'));
            } else if (ch >= 'A' && ch <= 'F') {
                chdata[index_nb] = (char) ((ch - 'A' + 10));
            } else if (ch >= 'a' && ch <= 'f') {
                chdata[index_nb] = (char) ((ch - 'a' + 10));
            } else {
                //*((int *) & chdata[0]) = index_nb;
                return index_nb;
            }
            ch = *(++ptr);
        } else {
            i = 0;
            if (ch >= '0' && ch <= '9') {
                chdata[index_nb] = ((char) (chdata[index_nb] << 4) + (ch - '0'));
            } else if (ch >= 'A' && ch <= 'F') {
                chdata[index_nb] = (char) ((chdata[index_nb] << 4) + (ch - 'A' + 10));
            } else if (ch >= 'a' && ch <= 'f') {
                chdata[index_nb] = (char) ((chdata[index_nb] << 4) + (ch - 'a' + 10));
            } else {
                //*((int *) & chdata[0]) = index_nb + 1;
                return index_nb + 1;
            }
            ch = *(++ptr);
            index_nb++;
        }
    }
}

uint32_t short_time_diff(struct timeval *starttime, struct timeval *finishtime) {
    uint32_t usec;
    usec = (finishtime->tv_sec - starttime->tv_sec)*1000000;
    usec += (finishtime->tv_usec - starttime->tv_usec);
    return usec;
}

char mmt_toupper(char in) {
    switch (in) {
        case 'a':
            return 'A';
        case 'b':
            return 'B';
        case 'c':
            return 'C';
        case 'd':
            return 'D';
        case 'e':
            return 'E';
        case 'f':
            return 'F';
        case 'g':
            return 'G';
        case 'h':
            return 'H';
        case 'i':
            return 'I';
        case 'j':
            return 'J';
        case 'k':
            return 'K';
        case 'l':
            return 'L';
        case 'm':
            return 'M';
        case 'n':
            return 'N';
        case 'o':
            return 'O';
        case 'p':
            return 'P';
        case 'q':
            return 'Q';
        case 'r':
            return 'R';
        case 's':
            return 'S';
        case 't':
            return 'T';
        case 'u':
            return 'U';
        case 'v':
            return 'V';
        case 'w':
            return 'W';
        case 'x':
            return 'X';
        case 'y':
            return 'Y';
        case 'z':
            return 'Z';
    }
    return in;
}

char mmt_tolower(char in) {
    switch (in) {
        case 'A':
            return 'a';
        case 'B':
            return 'b';
        case 'C':
            return 'c';
        case 'D':
            return 'd';
        case 'E':
            return 'e';
        case 'F':
            return 'f';
        case 'G':
            return 'g';
        case 'H':
            return 'h';
        case 'I':
            return 'i';
        case 'J':
            return 'j';
        case 'K':
            return 'k';
        case 'L':
            return 'l';
        case 'M':
            return 'm';
        case 'N':
            return 'n';
        case 'O':
            return 'o';
        case 'P':
            return 'p';
        case 'Q':
            return 'q';
        case 'R':
            return 'r';
        case 'S':
            return 's';
        case 'T':
            return 't';
        case 'U':
            return 'u';
        case 'V':
            return 'v';
        case 'W':
            return 'w';
        case 'X':
            return 'x';
        case 'Y':
            return 'y';
        case 'Z':
            return 'z';
    }
    return in;
}


int mmt_strcasecmp(const char *first, const char *second) {
    for(; mmt_toupper(*first) == mmt_toupper(*second); first++, second++) {
        if(*first == '\0') return 0; //complete match
    }
    //The strings do not match
    return ((mmt_toupper(*first) > mmt_toupper(*second))? +1 : -1);
}

int mmt_strncasecmp(const char *first, const char *second, size_t max) {
    while (max) {
        if (mmt_toupper(*first) != mmt_toupper(*second)) {
            return ((mmt_toupper(*first) > mmt_toupper(*second))? +1 : -1);
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

