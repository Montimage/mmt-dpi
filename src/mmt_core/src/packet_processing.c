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

/* Issue #328: an MMT_STATS attribute points at the protocol's chain of
 * per-path statistics instances (proto_stats_extraction). Report the totals
 * over the chain — the same aggregation the PROTO_PACKET_COUNT /
 * PROTO_DATA_VOLUME / PROTO_PAYLOAD_VOLUME extractors apply. A NULL chain
 * (no statistics yet) reports zeros. */
#define MMT_STATS_REPORT_FMT "packets=%"PRIu64",data_volume=%"PRIu64",payload_volume=%"PRIu64 \
                             ",sessions=%"PRIu64",timedout_sessions=%"PRIu64

typedef struct mmt_stats_report_struct {
    uint64_t packets, data_volume, payload_volume, sessions, timedout_sessions;
} mmt_stats_report_t;

static void mmt_stats_report_sum(const attribute_internal_t * attr, mmt_stats_report_t * r) {
    memset(r, 0, sizeof(*r));
    const proto_statistics_internal_t * s = (const proto_statistics_internal_t *) attr->data;
    for (; s != NULL; s = s->next) {
        r->packets += s->packets_count;
        r->data_volume += s->data_volume;
        r->payload_volume += s->payload_volume;
        r->sessions += s->sessions_count;
        r->timedout_sessions += s->timedout_sessions_count;
    }
}

int mmt_stats_snprintf(char * buff, int len, attribute_internal_t * attr) {
    if (buff == NULL || len <= 0 || attr == NULL) return -1;
    mmt_stats_report_t r;
    mmt_stats_report_sum(attr, &r);
    return snprintf(buff, (size_t) len, MMT_STATS_REPORT_FMT,
                    r.packets, r.data_volume, r.payload_volume, r.sessions, r.timedout_sessions);
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
        /* Issue #328: no text form for this data type — report "not
         * supported" (negative, empty string) instead of a placeholder. */
        if (buff != NULL && len > 0) buff[0] = '\0';
        return -1;
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
    if (attr == NULL) return -1;
    mmt_stats_report_t r;
    mmt_stats_report_sum(attr, &r);
    return mmt_stream_printf(f, MMT_STATS_REPORT_FMT,
                             r.packets, r.data_volume, r.payload_volume, r.sessions, r.timedout_sessions);
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
    default: {
        /* Issue #328: types without a dedicated stream writer (MMT_DATA_FLOAT,
         * MMT_U16/U32/U64_ARRAY) reuse their mmt_attr_snprintf() text form; a
         * type with no text form returns -1 and writes nothing. */
        char buff[MMT_BINARYVAR_STRLEN];
        buff[0] = '\0'; /* an empty MMT_U*_ARRAY writes no terminator */
        if (mmt_attr_snprintf(buff, (int) sizeof(buff), a) < 0) return -1;
        return mmt_stream_printf(f, "%s", buff);
    }
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
    if (attr == NULL) return -1;
    mmt_stats_report_t r;
    mmt_stats_report_sum(attr, &r);
    return mmt_stream_printf(f, "Attribute %s.%s = " MMT_STATS_REPORT_FMT "\n",
                   get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id),
                   r.packets, r.data_volume, r.payload_volume, r.sessions, r.timedout_sessions);
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
    default: {
        /* Issue #328: same text-form fallback as mmt_attr_fprintf(). */
        char buff[MMT_BINARYVAR_STRLEN];
        buff[0] = '\0'; /* an empty MMT_U*_ARRAY writes no terminator */
        if (mmt_attr_snprintf(buff, (int) sizeof(buff), a) < 0) return -1;
        return mmt_stream_printf(f, "Attribute %s.%s = %s\n",
                       get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id), buff);
    }
    }
}

char * mmt_version() {
    return MMT_VERSION;
}