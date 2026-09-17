    /*
    MMT_Security Copyright (C) 2013  Montimage

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Contact information:
    Montimage
    39 rue Bobillot
    75013 Paris
    contact@montimage.eu

    This program comes with ABSOLUTELY NO WARRANTY; for details type 'mmt_security --warning'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type 'mmt_security --licence' for details.

 ======================================================================================
 *       Filename:  tips_extract.c
 *    Description:  Open Source prototype version of the MMT_Security library
 *                  that allows analysing network traffic
 *                  to detect normal or abnormal behaviour.
 *
 *    Responsibility: pcap extraction — resolves rule operands into
 *    typed values (extracted attributes, stored tuples, embedded
 *    functions) and evaluates leaf expressions: compare_values,
 *    compute, exists_or_not, get_data_from_pcap.
 *        Version:  0.1
 *        Created:  12/June/2013 13:08:57
 *       Revision:  none
 *       Compiler:  gcc
 *         Author:  Edmo, contact@montimage.eu
 *   Organization:  Montimage
 ======================================================================================
*/

/* Split out of tips.c along the four-responsibility boundary
   (issue #235, F-CLEAN-003). Cross-unit declarations live in
   tips_internal.h; no extern declarations appear in the .c files. */

#define _GNU_SOURCE
#include <search.h>

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <dlfcn.h>

#include <libxml2/libxml/xmlreader.h>
#include "tips_internal.h"
#include "struct_defs.h"
#include "public_defs.h"
#include "data_defs.h"
#include "extraction_lib.h"
#include "mmt_core.h"
#include "plugin_defs.h"
#include "types_defs.h"
#define _STDC_FORMAT_MARCROS
#include <inttypes.h>

typedef struct COMPARE_VALUE_struct {
    int type;
    int size;
    int found;
    void *data;
} compare_value;

/* F-BUG-091 (#209): the int length prefix of an int-prefixed record
 * (MMT_STRING_DATA, MMT_STRING_LONG_DATA, MMT_DATA_PATH, MMT_BINARY_*_DATA)
 * is packet-controlled. Clamp it to the record's payload so a forged prefix
 * cannot drive a giant allocation or an over-reading memcpy. */
static int clamp_prefixed_size(int declared, int record_size) {
    int max_payload = record_size - (int)sizeof(int);
    if (declared < 0) return 0;
    if (max_payload < 0) max_payload = 0;
    if (declared > max_payload) return max_payload;
    return declared;
}

/* F-BUG-093 (#209): for MMT_DATA_PATH the prefix is an element *count*, not
 * a byte length — the record is [int count][count ints], so the count is
 * bounded by (record_size - prefix) / sizeof(int). */
static int clamp_path_count(int declared, int record_size) {
    int max_elems = (record_size - (int)sizeof(int)) / (int)sizeof(int);
    if (declared < 0 || max_elems < 0) return 0;
    if (declared > max_elems) return max_elems;
    return declared;
}

/* F-BUG-091/093 (#209): every write into the 100-byte destination is bounded
 * by the remaining capacity. For the int-prefixed records (MMT_STRING_DATA,
 * MMT_STRING_LONG_DATA, MMT_DATA_PATH, MMT_BINARY_*_DATA) `size` carries the
 * declared element/byte count and the copy is clamped to min(declared, 99) —
 * packet data is never assumed NUL-terminated. */
char *get_my_data(void *data1, short size, long type) {
    char *buff1 = xmalloc(100);
    if (buff1 == NULL)
        return NULL;
        
    void * data2 = NULL;
    struct timeval t1;
    unsigned long L1=0,L2=0,L3=0,L4=0;
    mmt_binary_data_t *db1 = NULL;
    //mmt_header_line_t *t;
    int data_size=0, j=0, stop=0;
    size_t off = 0;
    buff1[0] = '\0';
    switch (type) {
        case MMT_DATA_IP6_ADDR:
            // TODO(#326)
            break;
        case MMT_DATA_PORT:
            // TODO(#326)
            break;
        case MMT_DATA_PORT_RANGE:
            // TODO(#326)
            break;
        case MMT_DATA_DATE:
            // TODO(#326)
            break;
        case MMT_DATA_TIMEARG:
            // TODO(#326)
            break;
        case MMT_DATA_FLOAT:
            // TODO(#326)
            break;
        case MMT_DATA_IP_NET:
            // TODO(#326)
            break;
        case MMT_DATA_MAC_ADDR:
            // TODO(#326)
            convert_mac_bytes_to_string(&buff1, (unsigned char *) data1);
            break;
        case MMT_DATA_TIMEVAL:
            // TODO(#326)
            t1 = *(struct timeval *) (data1);
            (void)snprintf(buff1, 100, "%lu.%06lu", t1.tv_sec, (long) t1.tv_usec);
            break;
        case MMT_DATA_IP_ADDR:
            // TODO(#326)
            (void)snprintf(buff1, 100, "%d.%d.%d.%d", *(uint8_t*) (data1), *(uint8_t*) (data1+1), *(uint8_t*) (data1+2), *(uint8_t*) (data1+3));
            break;
        case MMT_U16_DATA:
            // TODO(#326)
            (void)snprintf(buff1, 100, "%d", *(unsigned short*) (data1));
            break;
        case MMT_U32_DATA:
            (void)snprintf(buff1, 100, "%lu", *(unsigned long*) (data1));
            break;
        case MMT_U64_DATA:
            // TODO(#326)
            break;
        case MMT_U8_DATA:
        case MMT_DATA_CHAR:
            (void)snprintf(buff1, 100, "%c", *(unsigned char*) (data1));
            break;
        case MMT_DATA_PATH:
            /* data1 is the record [int count][int elements] — a
             * proto_hierarchy_t: proto_path[] holds PROTO_PATH_SIZE ints at
             * most; `size` carries the declared element count (get_value
             * already clamped it to the record). */
            stop = (int) size;
            if (stop > PROTO_PATH_SIZE) stop = PROTO_PATH_SIZE;
            if (stop < 0) stop = 0;
            for (j = 0; j < stop && off < 99; j++) {
                int n = snprintf(buff1 + off, 100 - off, "%s%d",
                        j ? "." : "", *(int*) (data1 + sizeof (int) + j * sizeof (int)));
                if (n < 0) break;
                off += ((size_t) n < 100 - off) ? (size_t) n : (99 - off);
            }
            break;
        case MMT_HEADER_LINE: {
        	//parse_mmt_header_line( &data1, &data_size );
            mmt_header_line_t *hl = (mmt_header_line_t *) data1;
            int hl_len = (int) hl->len;
            if (hl->ptr == NULL || hl_len < 0) hl_len = 0;
            if (hl_len > 99) hl_len = 99;
            memcpy(buff1, hl->ptr, hl_len);
            buff1[hl_len] = '\0';
        	break;
        }
        case MMT_STRING_LONG_DATA:
        case MMT_STRING_DATA: {
            /* data1 is the record [int len][bytes]; `size` is the declared
             * byte count, clamped to the destination capacity. The source is
             * packet data — never assume it is NUL-terminated. */
            int slen = (int) size;
            if (slen < 0) slen = 0;
            if (slen > 99) slen = 99;
            memcpy(buff1, (char *) (data1 + sizeof (int)), slen);
            buff1[slen] = '\0';
            break;
        }
        case MMT_BINARY_DATA:
        case MMT_BINARY_VAR_DATA:

            // TODO(#326)
            db1 = (mmt_binary_data_t *) (data1);
            data_size = db1->len;
            data2 = db1->data;
            if (data_size == 4) {
                L1 = (*(unsigned long*)(data2)&0x000000ff);
                L2 = (*(unsigned long*)(data2)&0x0000ff00)>>8;
                L3 = (*(unsigned long*)(data2)&0x00ff0000)>>16;
                L4 = (*(unsigned long*)(data2)&0xff000000)>>24;
                (void)snprintf(buff1, 100, "%lu.%lu.%lu.%lu", L1, L2, L3, L4);
            } else {
                /* hex-dump into the remaining space: first element 2 chars,
                 * each further one 3 — stop when the buffer is full. */
                int max_elems = 1 + (99 - 2) / 3;
                if (data_size > max_elems) data_size = max_elems;
                for (j = 0; j < data_size && off < 99; j++) {
                    int n = snprintf(buff1 + off, 100 - off, "%s%02X",
                            j ? ":" : "", *(unsigned char*) (data2 + j));
                    if (n < 0) break;
                    off += ((size_t) n < 100 - off) ? (size_t) n : (99 - off);
                }
            }
            break;
        case MMT_DATA_LAYERID:
            // TODO(#326)
            break;
        case MMT_DATA_POINT:
            // TODO(#326)
            break;
        case MMT_DATA_FILTER_STATE:
            // TODO(#326)
            break;
        case MMT_UNDEFINED_TYPE:
        case MMT_DATA_POINTER:
        case MMT_DATA_BUFFER:
        case MMT_DATA_STRING_INDEX:
        case MMT_DATA_PARENT:
        case MMT_STATS:
        case MMT_GENERIC_HEADER_LINE:
        case MMT_STRING_DATA_POINTER:
            // TODO(#326) verify if OK
            //if(type == MMT_DATA_POINTER) (void)fprintf(stderr, "MMT_DATA_POINTER:5\n");
            break;
             
        default:
            (void)fprintf(stderr, "Error 15.1: Type not implemented yet. Data type unknown.\n");
            exit(-1);
    }//end of switch
    return buff1;
}

char * get_value( const ipacket_t *pkt, char *input, short *jump, short *size, tuple *list_of_tuples )
{
    int i = 0;
    char * output = NULL;
    char * temp2 = NULL;
    char * tempo = NULL;
    /* F-BUG-103 (#209): local token buffers — the globals were only allocated
     * by init_options() and sizeof(char*) capped them at 7 chars. */
    char token1[30], ltoken2[30], ltoken3[30];
    long protocol_id = 0;
    long field_id = 0;
    long data_type_id = 0;
    short event_id = 0;
    tuple *temp_tuple2 = NULL;

    token1[0] = '\0';
    ltoken2[0] = '\0';
    ltoken3[0] = '\0';

    output = xmalloc(200);
    if(output == NULL){
        return NULL;
    }
    tempo = output;

    temp2 = input;
    *jump = 0;

    while ((isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) && i < (int)sizeof(token1)-1) {
        token1[i] = *temp2;
        i++;
        temp2++;
    }
    token1[i] = '\0';
    // Skip remaining identifier chars beyond buffer to stay in sync
    while (isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) temp2++;
    if (*temp2 != '.') {
        (void)fprintf(stderr, "Error 22x: Incorrect name in: %s", input);
        xfree(output);
        return NULL;
    }
    temp2++; //skip the point
    i = 0;
    while ((isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) && i < (int)sizeof(ltoken2)-1) {
        ltoken2[i] = *temp2;
        temp2++;
        i++;
    }
    ltoken2[i] = '\0';
    while (isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) temp2++;
    if (*temp2 == '.') {//we have a reference to an event (event_id)
        temp2++;
        i = 0;
        while (isdigit(*temp2) && i < (int)sizeof(ltoken3)-1) {
            ltoken3[i] = *temp2;
            temp2++;
            i++;
        }
        ltoken3[i] = '\0';
        while (isdigit(*temp2)) temp2++;
    }
    //Got variable identifiers: token1.ltoken2.ltoken3 (e.g., META.PROTO.3)
    protocol_id = get_protocol_id_by_name(token1);
    field_id = get_attribute_id_by_protocol_id_and_attribute_name(protocol_id, ltoken2);
    data_type_id = mmt_attribute_get_data_type_typed(protocol_id, field_id);
    if (ltoken3[0] != '\0') event_id = atoi(ltoken3);
    if (event_id != 0) {
        //case variable is stored in list_of_tuples
        temp_tuple2 = list_of_tuples;
        while (temp_tuple2 != NULL) {
            if (protocol_id == temp_tuple2->protocol_id && field_id == temp_tuple2->field_id
                    && temp_tuple2->event_id == event_id && temp_tuple2->data_size > 0 && temp_tuple2->data != NULL) {
                long type = temp_tuple2->data_type_id;
                *size = temp_tuple2->data_size;
                void *data = temp_tuple2->data;
                if (type == MMT_STRING_DATA || type == MMT_STRING_LONG_DATA || type == MMT_BINARY_DATA || type == MMT_BINARY_VAR_DATA ) {
                    /* declared byte count from the record prefix — clamp it
                     * to the record's payload so a forged prefix cannot make
                     * the copy over-read the record (F-BUG-091, #209) */
                    *size = clamp_prefixed_size(*(int*) (data), temp_tuple2->data_size);
                }
                else if (type == MMT_DATA_PATH) {
                    /* prefix is an element count, not bytes (F-BUG-093) */
                    *size = clamp_path_count(*(int*) (data), temp_tuple2->data_size);
                }
                else if( type == MMT_HEADER_LINE ){
                    /* F-BUG-095: read the declared length from the struct —
                     * the previous code overwrote `data` with ->ptr first and
                     * then read ->len from the contents. */
                    *size = (int) (((mmt_header_line_t *)data)->len);
                }
                //Copy (data, size, type) to output
                char * d = NULL;
                char * td = NULL;
                d = get_my_data(data, *size, type);
                if (d != NULL) {
                    td = d;
                    while (*td != '\0') {
                        *tempo = *td;
                        tempo++;
                        td++;
                    }
                    xfree(d);
                }
                break;
            }
            temp_tuple2 = temp_tuple2->next;
        }
    } else {
        //case variable needs to be recovered from packet
        void *data = get_attribute_extracted_data( pkt, protocol_id, field_id );
        if (data != NULL) {
            long type = data_type_id;
            *size = get_data_size_by_proto_and_field_ids(protocol_id, field_id);
            if (type == MMT_STRING_DATA || type == MMT_STRING_LONG_DATA || type == MMT_BINARY_DATA || type == MMT_BINARY_VAR_DATA ) {
                /* same clamp: declared prefix bounded by the record size */
                *size = clamp_prefixed_size(*(int*) (data), *size);
            }
            else if (type == MMT_DATA_PATH) {
                *size = clamp_path_count(*(int*) (data), *size);
            }
            else if( type == MMT_HEADER_LINE ){
                /* F-BUG-095: same ordering fix — length from the struct. */
                *size = (int) (((mmt_header_line_t *)data)->len);
            }
            //Copy (data, size, type) to output
            char * d = NULL;
            char * td = NULL;
            d = get_my_data(data, *size, type);
            if (d != NULL) {
                td = d;
                while (*td != '\0') {
                    *tempo = *td;
                    tempo++;
                    td++;
                }
                xfree(d);
            }
        }
    }
    *jump = temp2 - input;
    *tempo = '\0';
    return output;
}

void * funct_get_params_and_execute( const ipacket_t *pkt, short skip_refs, char *lib_name, char *funct_name, int data_size, tuple *tt, tuple *list_of_tuples, short *found )
{
    void *lib_pointer = NULL;
    void *(*embedded_function)();
    void * ihandle = NULL;
    void * result_data = NULL;
    tuple *temp_tuple2;

    lib_pointer = dlopen(lib_name, RTLD_NOW);
    //lib_pointer = dlopen(lib_name, RTLD_LAZY);
    if (lib_pointer != NULL) {
        *(void **) (&embedded_function) = dlsym(lib_pointer, funct_name);
        short param_count = 0;
        void *data[4];
        while (tt != NULL) {
            if (tt->data == NULL && tt->event_id == 0) {
                data[param_count] = get_attribute_extracted_data( pkt, tt->protocol_id, tt->field_id );
            } else if (tt->data == NULL && tt->event_id != 0) {
                if (skip_refs == YES || list_of_tuples == NULL) {
                    *found = SKIP;
                    return NULL;
                } else {
                    temp_tuple2 = list_of_tuples;
                    while (temp_tuple2 != NULL) {
                        if (tt->protocol_id == temp_tuple2->protocol_id)
                            if (tt->field_id == temp_tuple2->field_id)
                                if (temp_tuple2->event_id == tt->event_id)
                                    if (temp_tuple2->data_size > 0)
                                        if (temp_tuple2->data != NULL) {
                                            data[param_count] = temp_tuple2->data;
                                            break;
                                        }
                        temp_tuple2 = temp_tuple2->next;
                    }
                }
            } else if (tt->data != NULL)data[param_count] = tt->data;
            param_count++;
            tt = tt->next;
        }
        switch (param_count) {
            case 0: ihandle = embedded_function();
                break;
            case 1: ihandle = embedded_function(data[0]);
                break;
            case 2: ihandle = embedded_function(data[0], data[1]);
                break;
            case 3: ihandle = embedded_function(data[0], data[1], data[2]);
                break;
            case 4: ihandle = embedded_function(data[0], data[1], data[2], data[3]);
                break;
        }
        result_data = (void *) xmalloc(data_size);
        if(result_data == NULL){
            xfree(ihandle);
            return NULL;
        }
        memcpy(result_data, ihandle, data_size);
        xfree(ihandle);
        dlclose(lib_pointer);
        *found = FOUND;
        //caller needs to free return value
        return result_data;
    }
    *found = NOT_FOUND;
    return NULL;
}

//#define THALES
#ifdef THALES
long get_seconds( const ipacket_t *pkt )
{
    struct timeval *t;
    void *data = NULL;
    long l = 0;
    data = get_attribute_extracted_data( pkt, op->timestamp_proto_id, op->timestamp_field_id);
    if (data == NULL) {
        data = get_attribute_extracted_data_by_name( pkt, "THALES_META", "TIME_SLOT");
        if (data == NULL) {
            fprintf(stderr, "Error 17: in attribute extraction of timestamp. Data is not available.\n");
            exit(-1);
        }
        l = (long) (*(int*) data);
        return l;
     }
     t = (struct timeval *) (data);
     if (t->tv_sec == 0) {
         data = get_attribute_extracted_data_by_name( pkt, "THALES_META", "TIME_SLOT");
         int i;
         memcpy((void*) (&i), (int*) data, sizeof (int));
         l = (long) i;
         return l;
     }
    return t->tv_sec;
}
#else
long get_seconds( const ipacket_t *pkt )
{
    struct timeval *t;
    void *data = NULL;
    data = get_attribute_extracted_data( pkt, op->timestamp_proto_id, op->timestamp_field_id);
    if (data == NULL) {
        (void)fprintf(stderr, "Error 17: in attribute extraction of timestamp. Data is not available.\n");
        exit(-1);
    }
    t = (struct timeval *) (data);
    if (t->tv_sec == 0) {
        (void)fprintf(stderr, "Error 17b: in attribute extraction of timestamp. Data is not available.\n");
        exit(-1);
    }
    return t->tv_sec;
}
#endif

long get_useconds( const ipacket_t *pkt )
{
    struct timeval *t;
    void *data = NULL;
    data = get_attribute_extracted_data( pkt, op->timestamp_proto_id, op->timestamp_field_id );
    if (data == NULL) {
        return 0;
    }
    t = (struct timeval *) (data);
    return t->tv_usec;
}

int compare_in_table(compare_value v1, compare_value v2, short ope)
{
    int i = 0, j = 0;
    unsigned short s1 = 0;
    unsigned long l1 = 0;
    unsigned long long ll1 = 0;
    double f1 = 0;
    unsigned char c1 = 0;
    int size = 0;

    //Special case: ope==XIN with v1 is some type and v2 is MMT_BINARY_VAR_DATA
    if (ope != XIN || v2.type != MMT_BINARY_VAR_DATA) {
        return NOT_VALID;
    }
    size = v2.size;

    switch (v1.type) {
        case MMT_DATA_CHAR:
            c1 = ((char *) (v1.data))[0];
            for (i = 0; i < size; i = i + sizeof (char)) {
                if (c1 == ((char *) (v2.data))[i])
                    return VALID;
            }
            break;
        case MMT_U8_DATA:
            c1 = *((unsigned char *) (v1.data));
            for (i = 0; i < size; i = i + sizeof (unsigned char)) {
                if (c1 == ((unsigned char *) (v2.data))[i])
                    return VALID;
            }
            break;
        case MMT_U16_DATA:
            s1 = *((unsigned short *) (v1.data));
            /* i counts bytes — the table index must be the element number,
             * and only complete elements may be read: indexing [i] read up to
             * 2*size bytes past v2.data and skipped odd elements (#209) */
            j = 0;
            for (i = 0; i + (int)sizeof(unsigned short) <= size; i = i + sizeof (unsigned short)) {
                if (s1 == ((unsigned short *) (v2.data))[j++])
                    return VALID;
            }
            break;
        case MMT_U32_DATA:
            l1 = *((unsigned long *) (v1.data));
            j = 0;
            for (i = 0; i + (int)sizeof(unsigned long) <= size; i = i + sizeof (unsigned long)) {
                if (l1 == ((unsigned long *) (v2.data))[j++])
                    return VALID;
            }
            break;
        case MMT_U64_DATA:
            ll1 = *((unsigned long long *) (v1.data));
            j = 0;
            for (i = 0; i + (int)sizeof(unsigned long long) <= size; i = i + sizeof (unsigned long long)) {
                if (ll1 == ((unsigned long long*) (v2.data))[j++])
                    return VALID;
            }
            break;
        case MMT_DATA_FLOAT:
            f1 = *((float *) (v1.data));
            j = 0;
            for (i = 0; i + (int)sizeof(float) <= size; i = i + sizeof (float)) {
                if (f1 == ((float *) (v2.data))[j++])
                    return VALID;
            }
            break;
        case MMT_DATA_LAYERID:
        case MMT_DATA_PORT:
        case MMT_DATA_POINT:
        case MMT_DATA_PORT_RANGE:
        case MMT_STRING_DATA:
        case MMT_STRING_LONG_DATA:
        case MMT_DATA_IP6_ADDR:
        case MMT_DATA_IP_ADDR:
        case MMT_DATA_IP_NET:
        case MMT_DATA_MAC_ADDR:
        case MMT_BINARY_DATA:
        case MMT_BINARY_VAR_DATA:
        case MMT_DATA_PATH:
        case MMT_DATA_FILTER_STATE:
        case MMT_DATA_TIMEARG:
        case MMT_DATA_TIMEVAL:
        case MMT_DATA_DATE:
        case MMT_UNDEFINED_TYPE:
        case MMT_DATA_BUFFER:
        case MMT_DATA_STRING_INDEX:
        case MMT_DATA_PARENT:
        case MMT_STATS:
        case MMT_GENERIC_HEADER_LINE:
        case MMT_HEADER_LINE:
        case MMT_STRING_DATA_POINTER:
            return NOT_VALID; //TODO(#326) verify if OK
            break;
        case MMT_DATA_POINTER:
            //(void)fprintf(stderr, "MMT_DATA_POINTER:1\n");
            return NOT_VALID; //TODO(#326) verify if OK
            break;
        default:
            (void)fprintf(stderr, "Error 36b: Comparing values is not possible. Type not implemented yet.\n");
            exit(-1);
    }//end of switch
    return NOT_VALID;
}

int compare_values(compare_value v1, compare_value v2, short ope)
{
    int idx = 0, needle = 0;
    unsigned short u16_1 = 0, u16_2 = 0;
    unsigned long u32_1 = 0, u32_2 = 0;
    unsigned long long u64_1 = 0, u64_2 = 0;
    double fval_1 = 0, fval_2 = 0;
    unsigned char u8_1 = 0, u8_2 = 0;
    mmt_date_t *date_1, *date_2;
    struct timeval *tv_1, *tv_2;
    int size = 0;
    char * data1 = NULL;
    char * data2 = NULL;
    //mmt_header_line_t *hl;

    //Special case: ope==XIN with v1 is some type and v2 is MMT_BINARY_VAR_DATA
    if (ope == XIN && v2.type == MMT_BINARY_VAR_DATA) {
        return compare_in_table(v1, v2, ope);
    }
    if((v1.type == MMT_U8_DATA || v1.type == MMT_U16_DATA || v1.type == MMT_U32_DATA || v1.type == MMT_U64_DATA) &&
      (v2.type == MMT_U8_DATA || v2.type == MMT_U16_DATA || v2.type == MMT_U32_DATA || v2.type == MMT_U64_DATA)){
      if     (v1.type == MMT_U64_DATA) u64_1 = *((uint64_t *) (v1.data));
      else if(v1.type == MMT_U32_DATA) u64_1 = *((uint32_t *)      (v1.data));
      else if(v1.type == MMT_U16_DATA) u64_1 = *((uint16_t *)     (v1.data));
      else u64_1 = *((uint8_t *)      (v1.data));
      if     (v2.type == MMT_U64_DATA) u64_2 = *((uint64_t *) (v2.data));
      else if(v2.type == MMT_U32_DATA) u64_2 = *((uint32_t *)      (v2.data));
      else if(v2.type == MMT_U16_DATA) u64_2 = *((uint16_t *)     (v2.data));
      else  u64_2 = *((uint8_t *)      (v2.data));
      if ((ope == NEQ && u64_1 != u64_2) || (ope == EQ && u64_1 == u64_2) || (ope == LT && u64_1 < u64_2) || (ope == LTE && u64_1 <= u64_2) || (ope == GT && u64_1 > u64_2) ||
                    (ope == GTE && u64_1 >= u64_2)) return VALID;
      else return NOT_VALID;
    }
    //Line not to be used if using XE (included in): if (v1.type != v2.type || v1.size != v2.size) return NOT_VALID;
    size = v1.size;
    data1 = (char*) v1.data;
    data2 = (char*) v2.data;

    switch (v1.type) {
        case MMT_DATA_TIMEVAL:
            tv_1 = (struct timeval *) (v1.data);
            tv_2 = (struct timeval *) (v2.data);
            if ((((ope == EQ) || (ope == LTE) || (ope == GTE)) && tv_1->tv_sec == tv_2->tv_sec && tv_1->tv_usec == tv_2->tv_usec)) return VALID;
            else if ((ope == NEQ) && (tv_1->tv_sec != tv_2->tv_sec || tv_1->tv_usec != tv_2->tv_usec)) return VALID;
            else if (((ope == LT) || (ope == LTE)) && ((tv_1->tv_sec < tv_2->tv_sec) || ((tv_1->tv_sec == tv_2->tv_sec) && (tv_1->tv_usec < tv_2->tv_usec)))) return VALID;
            else if (((ope == GT) || (ope == GTE)) && ((tv_1->tv_sec > tv_2->tv_sec) || ((tv_1->tv_sec == tv_2->tv_sec) && (tv_1->tv_usec > tv_2->tv_usec)))) return VALID;
            break;
        case MMT_DATA_DATE:
            date_1 = (mmt_date_t *) (v1.data);
            date_2 = (mmt_date_t *) (v2.data);
            if ((((ope == EQ) || (ope == LTE) || (ope == GTE)) && date_1->sec == date_2->sec && date_1->min == date_2->min && date_1->hour == date_2->hour && date_1->mday == date_2->mday &&
                    date_1->month == date_2->month && date_1->year == date_2->year && date_1->wday == date_2->wday)) return VALID;
            else if ((ope == NEQ) && (date_1->sec != date_2->sec || date_1->min != date_2->min || date_1->hour != date_2->hour || date_1->mday != date_2->mday ||
                    date_1->month != date_2->month || date_1->year != date_2->year || date_1->wday != date_2->wday)) return VALID;
            else if (((ope == LT) || (ope == LTE)) && ((date_1->year < date_2->year) || ((date_1->year == date_2->year) && (date_1->month < date_2->month)) ||
                    ((date_1->year == date_2->year) && (date_1->month == date_2->month) && (date_1->mday < date_2->mday)) ||
                    ((date_1->year == date_2->year) && (date_1->month == date_2->month) && (date_1->mday == date_2->mday) && (date_1->hour < date_2->hour)) ||
                    ((date_1->year == date_2->year) && (date_1->month == date_2->month) && (date_1->mday == date_2->mday) && (date_1->hour == date_2->hour) && (date_1->min < date_2->min)) ||
                    ((date_1->year == date_2->year) && (date_1->month == date_2->month) && (date_1->mday == date_2->mday) && (date_1->hour == date_2->hour) && (date_1->min == date_2->min) &&
                    (date_1->sec < date_2->sec))))
                return VALID;
            else if (((ope == GT) || (ope == GTE)) && ((date_1->year < date_2->year) || ((date_1->year == date_2->year) && (date_1->month > date_2->month)) ||
                    ((date_1->year == date_2->year) && (date_1->month == date_2->month) && (date_1->mday > date_2->mday)) ||
                    ((date_1->year == date_2->year) && (date_1->month == date_2->month) && (date_1->mday == date_2->mday) && (date_1->hour > date_2->hour)) ||
                    ((date_1->year == date_2->year) && (date_1->month == date_2->month) && (date_1->mday == date_2->mday) && (date_1->hour == date_2->hour) && (date_1->min > date_2->min)) ||
                    ((date_1->year == date_2->year) && (date_1->month == date_2->month) && (date_1->mday == date_2->mday) && (date_1->hour == date_2->hour) && (date_1->min == date_2->min) &&
                    (date_1->sec > date_2->sec))))
                return VALID;
            break;
        case MMT_DATA_FLOAT:
            fval_1 = *((float *) (v1.data));
            fval_2 = *((float *) (v2.data));
            if ((ope == NEQ && fval_1 != fval_2) || (ope == EQ && fval_1 == fval_2) || (ope == LT && fval_1 < fval_2) || (ope == LTE && fval_1 <= fval_2) || (ope == GT && fval_1 > fval_2) || (ope == GTE && fval_1 >= fval_2))
                return VALID;
            break;
        case MMT_U16_DATA:
        case MMT_DATA_LAYERID:
            u16_1 = *((unsigned short *) (v1.data));
            u16_2 = *((unsigned short *) (v2.data));
            if ((ope == NEQ && u16_1 != u16_2) || (ope == EQ && u16_1 == u16_2) || (ope == LT && u16_1 < u16_2) || (ope == LTE && u16_1 <= u16_2) || (ope == GT && u16_1 > u16_2) || (ope == GTE && u16_1 >= u16_2))
                return VALID;
            break;
        case MMT_U32_DATA:
        case MMT_DATA_PORT:
            u32_1 = (*((unsigned long *) (v1.data)));
            u32_2 = (*((unsigned long *) (v2.data)));
            if ((ope == NEQ && u32_1 != u32_2) || (ope == EQ && u32_1 == u32_2) || (ope == LT && u32_1 < u32_2) || (ope == LTE && u32_1 <= u32_2) || (ope == GT && u32_1 > u32_2) || (ope == GTE && u32_1 >= u32_2))
                return VALID;
            break;
        case MMT_U64_DATA:
        case MMT_DATA_POINT:
        case MMT_DATA_PORT_RANGE:
            u64_1 = *((unsigned long long *) (v1.data));
            u64_2 = *((unsigned long long *) (v2.data));
            if ((ope == NEQ && u64_1 != u64_2) || (ope == EQ && u64_1 == u64_2) || (ope == LT && u64_1 < u64_2) || (ope == LTE && u64_1 <= u64_2) || (ope == GT && u64_1 > u64_2) ||
                    (ope == GTE && u64_1 >= u64_2)) return VALID;
            break;
        case MMT_U8_DATA:
            u8_1 = *((unsigned char *) (v1.data));
            u8_2 = *((unsigned char *) (v2.data));
            if ((ope == NEQ && u8_1 != u8_2) || (ope == EQ && u8_1 == u8_2) || (ope == LT && u8_1 < u8_2) || (ope == LTE && u8_1 <= u8_2) || (ope == GT && u8_1 > u8_2) || (ope == GTE && u8_1 >= u8_2))
                return VALID;
            break;
        case MMT_DATA_CHAR:
            u8_1 = ((char *) (v1.data))[0];
            u8_2 = ((char *) (v2.data))[0];
            if ((ope == NEQ && u8_1 != u8_2) || (ope == EQ && u8_1 == u8_2) || (ope == LT && u8_1 < u8_2) || (ope == LTE && u8_1 <= u8_2) || (ope == GT && u8_1 > u8_2) || (ope == GTE && u8_1 >= u8_2))
                return VALID;
            break;
        case MMT_DATA_PATH:
            //TODO(#326): need to complete for other cases
            if (ope == XC || ope == XCE) {
              needle = atoi(data2);
              if(size>0 && size < 20){
                /* idx indexes int elements — bound the byte offset by the
                 * operand buffer (size bytes): read complete ints only
                 * (the old idx<size bound read up to 4x past it, #209) */
                for(idx=1; idx * (int)sizeof(int) + (int)sizeof(int) <= size; idx++){
                  if(needle == *(int*) (data1 + idx*sizeof (int))) return VALID;
                }
                return NOT_VALID;
              }
            }
            break;
        case MMT_HEADER_LINE:
        case MMT_DATA_POINTER:
        case MMT_STRING_DATA:
        case MMT_STRING_LONG_DATA:
        case MMT_DATA_IP6_ADDR:
        case MMT_DATA_IP_ADDR:
        case MMT_DATA_IP_NET:
        case MMT_DATA_MAC_ADDR:
        case MMT_BINARY_DATA:
        case MMT_BINARY_VAR_DATA:
            //if(v1.type == MMT_DATA_POINTER) (void)fprintf(stderr, "MMT_DATA_POINTER:2\n");
#ifdef DEBUG
        	printf("\n compare[%s] %d [%s], %d, %d\n", data1, ope, data2, v1.size, v2.size);
#endif
        	if (ope == EQ && v1.size != v2.size)
        		return NOT_VALID;
        	if(ope == NEQ && v1.size != v2.size)
        		return VALID;

        	size = v1.size > v2.size? v2.size : v1.size;

            if (ope == XC || ope == XCE) {
                if (strstr(data1, data2) != NULL)
                    return VALID;
                else
                    return NOT_VALID;
            } else if (ope == XD || ope == XDE) {
                if (strstr(data2, data1) != NULL)
                    return VALID;
                else
                    return NOT_VALID;
            } else if (ope == XE) {
                if (strcmp(data2, data1) == 0)
                    return VALID;
                else
                    return NOT_VALID;
            } else {
                for (idx = 0; idx < size; idx = idx + sizeof (char)) {
                    if (ope == EQ) {
                        if (((char *) (data1))[idx] != ((char *) (data2))[idx]) {
                            return NOT_VALID;
                        }
                        if (idx == size - 1) {
                            return VALID;
                        }
                    } else if (ope == NEQ) {
                        if (((char *) (data1))[idx] != ((char *) (data2))[idx]) {
                            return VALID;
                        }
                        if (idx == size - 1) {
                            return NOT_VALID;
                        }
                    } else if ((ope == LTE) || (ope == LT)) {
                        if (((char *) (data1))[idx] == ((char *) (data2))[idx]) {
                            if (idx == size - 1) {
                                if (ope == LTE) return VALID;
                                return NOT_VALID;
                            }
                            continue;
                        } else if (((char *) (data1))[idx] > ((char *) (data2))[idx]) {
                            return NOT_VALID;
                        } else if (((char *) (data1))[idx] < ((char *) (data2))[idx]) {
                            return VALID;
                        }
                    } else if ((ope == GTE) || (ope == GT)) {
                        if (((char *) (data1))[idx] == ((char *) (data2))[idx]) {
                            if (idx == size - 1) {
                                if (ope == GTE) return VALID;
                                return NOT_VALID;
                            }
                            continue;
                        } else if (((char *) (data1))[idx] < ((char *) (data2))[idx]) {
                            return NOT_VALID;
                        } else if (((char *) (data1))[idx] > ((char *) (data2))[idx]) {
                            return VALID;
                        }
                    }
                }
            }
            break;
        case MMT_DATA_FILTER_STATE:
        case MMT_DATA_TIMEARG:
        case MMT_UNDEFINED_TYPE:
        case MMT_DATA_BUFFER:
        case MMT_DATA_STRING_INDEX:
        case MMT_DATA_PARENT:
        case MMT_STATS:
        case MMT_GENERIC_HEADER_LINE:
        case MMT_STRING_DATA_POINTER:
            return NOT_VALID; //TODO(#326) verify if OK
            break;
        default:
            (void)fprintf(stderr, "Error 36: Comparing values is not possible. Type not implemented yet.\n");
            exit(-1);
    }//end of switch
    return NOT_VALID;
}

void * compute(compare_value v1, compare_value v2, short operator)
{
    unsigned char uc = 0, uc1 = 0, uc2 = 0, *uc0 = NULL;
    unsigned short us1 = 0, us2 = 0, *us0 = NULL;
    unsigned long ul1 = 0, ul2 = 0, *ul0 = NULL;
    unsigned long long ull1 = 0, ull2 = 0, *ull0 = NULL;
    void * data1 = NULL;
    void * data2 = NULL;

    if((v1.type == MMT_U8_DATA || v1.type == MMT_U16_DATA || v1.type == MMT_U32_DATA || v1.type == MMT_U64_DATA) &&
      (v2.type == MMT_U8_DATA || v2.type == MMT_U16_DATA || v2.type == MMT_U32_DATA || v2.type == MMT_U64_DATA)){
      if     (v1.type == MMT_U64_DATA) ull1 = *((uint64_t *) (v1.data));
      else if(v1.type == MMT_U32_DATA) ull1 = *((uint32_t *)      (v1.data));
      else if(v1.type == MMT_U16_DATA) ull1 = *((uint16_t *)     (v1.data));
      else ull1 = *((uint8_t *)      (v1.data));
      if     (v2.type == MMT_U64_DATA) ull2 = *((uint64_t *) (v2.data));
      else if(v2.type == MMT_U32_DATA) ull2 = *((uint32_t *)      (v2.data));
      else if(v2.type == MMT_U16_DATA) ull2 = *((uint16_t *)     (v2.data));
      else  ull2 = *((uint8_t *)      (v2.data));

      ull0 = xmalloc(sizeof (unsigned long long));
      if(ull0 == NULL){
          return NULL;
      }
       if (operator == ADD)
          *ull0 = ull1 + ull2;
       else if (operator == SUB)
          *ull0 = ull1 - ull2;
       else if (operator == DIV) {
           if (ull2 == 0) { xfree(ull0); return NULL; }
           *ull0 = ull1 / ull2;
       } else if (operator == MUL)
           *ull0 = ull1 * ull2;
       return (void *)ull0;
     }

    if (v1.type != v2.type) {
        return NULL;
    }

    data1 = v1.data;
    data2 = v2.data;

    switch (v1.type) {
        case MMT_DATA_TIMEVAL:
            // TODO(#326)
            (void)fprintf(stderr, "Error 36a1: Computation is not possible. Type not implemented yet or the operation on this type has no sense.\n");
            exit(-1);
            break;
        case MMT_DATA_DATE:
            // TODO(#326)
            (void)fprintf(stderr, "Error 36a2: Computation is not possible. Type not implemented yet or the operation on this type has no sense.\n");
            exit(-1);
            break;
        case MMT_DATA_FLOAT:
            // TODO(#326)
            (void)fprintf(stderr, "Error 36a3: Computation is not possible. Type not implemented yet or the operation on this type has no sense.\n");
            exit(-1);
            break;
        case MMT_U16_DATA:
        case MMT_DATA_LAYERID:
            us1 = *((unsigned short *) (data1));
            us2 = *((unsigned short *) (data2));
            us0 = xmalloc(sizeof (unsigned short));
            if(us0 == NULL){
                xfree(ull0);
                return NULL;
            }
            if (operator == ADD)
                *us0 = us1 + us2;
            else if (operator == SUB)
                *us0 = us1 - us2;
            else if (operator == DIV) {
                if (us2 == 0) { xfree(us0); xfree(ull0); return NULL; }
                *us0 = us1 / us2;
            } else if (operator == MUL)
                *us0 = us1 * us2;
            return (void *)us0;
            break;
        case MMT_U32_DATA:
        case MMT_DATA_PORT:
            ul1 = *((unsigned long *) (data1));
            ul2 = *((unsigned long *) (data2));
            ul0 = xmalloc(sizeof (unsigned long));
            if (ul0 == NULL)
            {
                xfree(ull0);
                return NULL;
            }
            if (operator == ADD)
                *ul0 = ul1 + ul2;
            else if (operator == SUB)
                *ul0 = ul1 - ul2;
            else if (operator == DIV) {
                if (ul2 == 0) { xfree(ul0); xfree(ull0); return NULL; }
                *ul0 = ul1 / ul2;
            } else if (operator == MUL)
                *ul0 = ul1 * ul2;
            return (void *)ul0;
            break;
        case MMT_U64_DATA:
        case MMT_DATA_POINT:
        case MMT_DATA_PORT_RANGE: // TODO(#326): to check
            ull1 = *((unsigned long long *) (data1));
            ull2 = *((unsigned long long *) (data2));
            ull0 = xmalloc(sizeof (unsigned long long));
            if (ull0 == NULL)
            {
                xfree(ull0);
                return NULL;
            }
            if (operator == ADD)
                *ull0 = ull1 + ull2;
            else if (operator == SUB)
                *ull0 = ull1 - ull2;
            else if (operator == DIV) {
                if (ull2 == 0) { xfree(ull0); return NULL; }
                *ull0 = ull1 / ull2;
            } else if (operator == MUL)
                *ull0 = ull1 * ull2;
            return (void *)ull0;
            break;
        case MMT_U8_DATA:
            uc1 = *((unsigned char *) (data1));
            uc2 = *((unsigned char *) (data2));
            uc0 = xmalloc(sizeof (unsigned char));
            if (uc0 == NULL)
            {
                xfree(ull0);
                return NULL;
            }
            if (operator == ADD) {
                // *i0 = i1 + i2;
                uc = uc1 + uc2;
                memcpy(uc0, &uc, sizeof (unsigned char));
            } else if (operator == SUB) {
                // *i0 = i1 - i2;
                uc = uc1 - uc2;
                memcpy(uc0, &uc, sizeof (unsigned char));
            } else if (operator == DIV) {
                if (uc2 != 0) {
                    // *i0 = i1 / i2;
                    uc = uc1 / uc2;
                    memcpy(uc0, &uc, sizeof (unsigned char));
                } else{
                    xfree(uc0);
                    xfree(ull0);
                    return NULL;
                }
            } else if (operator == MUL) {
                // *i0 = i1 * i2;
                uc = uc1 * uc2;
                memcpy(uc0, &uc, sizeof (unsigned char));
            }
            return (void *)uc0;
            break;
        case MMT_UNDEFINED_TYPE:
        case MMT_DATA_POINTER:
        case MMT_DATA_MAC_ADDR:
        case MMT_DATA_IP_NET:
        case MMT_DATA_IP_ADDR:
        case MMT_DATA_IP6_ADDR:
        case MMT_DATA_PATH:
        case MMT_DATA_BUFFER:
        case MMT_DATA_CHAR:
        case MMT_DATA_TIMEARG:
        case MMT_DATA_STRING_INDEX:
        case MMT_DATA_FILTER_STATE:
        case MMT_DATA_PARENT:
        case MMT_STATS:
        case MMT_BINARY_DATA:
        case MMT_BINARY_VAR_DATA:
        case MMT_STRING_DATA:
        case MMT_STRING_LONG_DATA:
        case MMT_HEADER_LINE:
        case MMT_GENERIC_HEADER_LINE:
        case MMT_STRING_DATA_POINTER:
            //if(v1.type == MMT_DATA_POINTER) (void)fprintf(stderr, "MMT_DATA_POINTER:3\n");
            return NULL; //TODO(#326) verify if OK
            break;
        default:
            (void)fprintf(stderr, "Error 36a: Computation is not possible. Type not implemented yet or the operation on this type has no sense.\n");
            exit(-1);
    }//end of switch
    return NULL;
}

int exists_or_not (const ipacket_t *pkt, short operator, rule *r) { 
    void *data = get_attribute_extracted_data( pkt, r->t.protocol_id, r->t.field_id );
    if (operator == DE && data != NULL) return VALID; 
    else if (operator == DNE && data == NULL) return VALID;
    return NOT_VALID;
}

int get_data_from_pcap( const ipacket_t *pkt, short skip_refs, short action, void** result_value, tuple *list_of_tuples, short operator, rule *r1, rule *r2)
{
    int ret = 0;
    tuple *temp_tuple = list_of_tuples;
    tuple *temp_tuple2 = NULL;
    compare_value v1;
    compare_value v2;
    compare_value *tmp_v;
    rule * tmp_r;

    v1.data = NULL;
    v1.type = 0;
    v1.found = NOT_FOUND;
    v1.size = 0;

    v2.data = NULL;
    v2.type = 0;
    v2.found = NOT_FOUND;
    v2.size = 0;

    //need to test if it is scalar data and treat accordingly (t.data_type gives the type and t.data is a string that needs to be converted)
    //                      or reference data and search in stored data
    //                      or current packet data
    if (r1->t.data != NULL) { //means that it is a scalar data of type given by data_type_id that was obtained from <protocol, field>
        v1.type = r1->t.data_type_id;
        v1.found = FOUND;
        v1.size = r1->t.data_size;
        void *data = r1->t.data;
        if (v1.type == MMT_STRING_DATA || v1.type == MMT_STRING_LONG_DATA || v1.type == MMT_BINARY_DATA || v1.type == MMT_BINARY_VAR_DATA || v1.type == MMT_DATA_PATH) {
            if (v1.type == MMT_DATA_PATH)
                v1.size = clamp_path_count(*(int*) (data), r1->t.data_size);
            else
                v1.size = clamp_prefixed_size(*(int*) (data), r1->t.data_size);
            data = r1->t.data + sizeof (int);
        }
        else if (v1.type == MMT_HEADER_LINE) {
            //parse_mmt_header_line( &data, &v1.size );
            v1.size = ((mmt_header_line_t *)data)->len;
            data = (void*)(((mmt_header_line_t *)data)->ptr);
        }

        v1.data = (void *) xcalloc(1, v1.size);
        if(v1.data == NULL){
            return 0;
        }
        if (data != NULL && v1.size > 0) memcpy(v1.data, data, v1.size);
    } else if (r1->t.event_id != 0) {
        if (skip_refs == YES) v1.found = SKIP;
        else {
            temp_tuple2 = temp_tuple;
            while (temp_tuple2 != NULL) {
                if (v1.found == NOT_FOUND && r1->t.protocol_id == temp_tuple2->protocol_id && r1->t.field_id == temp_tuple2->field_id
                        && temp_tuple2->event_id == r1->t.event_id && temp_tuple2->data_size > 0 && temp_tuple2->data != NULL) {
                    v1.type = temp_tuple2->data_type_id;
                    v1.found = FOUND;
                    v1.size = temp_tuple2->data_size;
                    void *data = temp_tuple2->data;
                    if (v1.type == MMT_STRING_DATA || v1.type == MMT_STRING_LONG_DATA || v1.type == MMT_BINARY_DATA || v1.type == MMT_BINARY_VAR_DATA || v1.type == MMT_DATA_PATH) {
                        if (v1.type == MMT_DATA_PATH)
                            v1.size = clamp_path_count(*(int*) (data), temp_tuple2->data_size);
                        else
                            v1.size = clamp_prefixed_size(*(int*) (data), temp_tuple2->data_size);
                        data = temp_tuple2->data + sizeof (int);
                    }
                    else if (v1.type == MMT_HEADER_LINE){
                    	//parse_mmt_header_line( &(temp_tuple2->data), & v1.size );
                        v1.size = ((mmt_header_line_t *)data)->len;
                        data = (void*)(((mmt_header_line_t *)data)->ptr);
                    }
                    v1.data = (void *) xcalloc(1, v1.size);
                    if (v1.data == NULL || data == NULL) {
                        (void)fprintf(stderr, "Error 18: Problem in stored reference. Data is not available.\n");
                        exit(-1);
                    }
                    memcpy(v1.data, data, v1.size);
                    break;
                }
                temp_tuple2 = temp_tuple2->next;
            }
        }
    }
    if (r2->t.data != NULL) { //means that it is a scalar data of type given by data_type_id that was obtained from <protocol, field>
        v2.type = r2->t.data_type_id;
        v2.found = FOUND;
        v2.size = r2->t.data_size;
        void *data = r2->t.data;
        if (v2.type == MMT_STRING_DATA || v2.type == MMT_STRING_LONG_DATA || v2.type == MMT_BINARY_DATA || v2.type == MMT_BINARY_VAR_DATA || v2.type == MMT_DATA_PATH) {
            if (v2.type == MMT_DATA_PATH)
                v2.size = clamp_path_count(*(int*) (data), r2->t.data_size);
            else
                v2.size = clamp_prefixed_size(*(int*) (data), r2->t.data_size);
            data = r2->t.data + sizeof (int);
        }
        else if (v2.type == MMT_HEADER_LINE){
            //parse_mmt_header_line( &(r2->t.data), &v2.size );
                        v2.size = ((mmt_header_line_t *)data)->len;
                        data = (void*)(((mmt_header_line_t *)data)->ptr);
        }

        v2.data = (void *) xcalloc(1, v2.size);
        if (v2.data == NULL)
        {
            return 0;
        }
        if (data != NULL && v2.size > 0) memcpy(v2.data, data, v2.size);
    } else if (r2->t.event_id != 0) {
        if (skip_refs == YES) v1.found = SKIP;
        else {
            temp_tuple2 = temp_tuple;
            while (temp_tuple2 != NULL) {
                if (v2.found == NOT_FOUND)
                    if (r2->t.protocol_id == temp_tuple2->protocol_id)
                        if (r2->t.field_id == temp_tuple2->field_id)
                            if (temp_tuple2->event_id == r2->t.event_id)
                                if (temp_tuple2->data_size > 0)
                                    if (temp_tuple2->data != NULL) {
                                        v2.type = temp_tuple2->data_type_id;
                                        v2.found = FOUND;
                                        v2.size = temp_tuple2->data_size;
                                        void *data = temp_tuple2->data;
                                        if (v2.type == MMT_STRING_DATA || v2.type == MMT_STRING_LONG_DATA || v2.type == MMT_BINARY_DATA || v2.type == MMT_BINARY_VAR_DATA || v2.type == MMT_DATA_PATH) {
                                            if (v2.type == MMT_DATA_PATH)
                                                v2.size = clamp_path_count(*(int*) (data), temp_tuple2->data_size);
                                            else
                                                v2.size = clamp_prefixed_size(*(int*) (data), temp_tuple2->data_size);
                                            data = temp_tuple2->data + sizeof (int);
                                        }
                                        else if (v2.type == MMT_HEADER_LINE){
                                            //parse_mmt_header_line( &data, &v2.size );
                        v2.size = ((mmt_header_line_t *)data)->len;
                        data = (void*)(((mmt_header_line_t *)data)->ptr);
                                        }
                                        v2.data = (void *) xcalloc(1, v2.size);
                                        if (v2.data == NULL || data == NULL) {
                                            (void)fprintf(stderr, "Error 19: Problem in stored reference. Data is not available.\n");
                                            exit(-1);
                                        }
                                        memcpy(v2.data, data, v2.size);
                                        break;
                                    }
                temp_tuple2 = temp_tuple2->next;
            }
        }
    }
    if (r1->value == XFUNCT) {
        tmp_r = r1;
        tmp_v = &v1;
    }
    if (r2->value == XFUNCT) {
        tmp_r = r2;
        tmp_v = &v2;
    }
    if (r1->value == XFUNCT || r2->value == XFUNCT) {
       short found = 0;
       tmp_v->found = NOT_FOUND;
            void *data = funct_get_params_and_execute( pkt, skip_refs, LIB_NAME, tmp_r->funct_name, tmp_r->t.data_size, tmp_r->t.next, list_of_tuples, &found);
            if(found != FOUND || data == NULL){
              if (skip_refs == YES) tmp_v->found = SKIP;
              else {
                (void)fprintf(stderr, "Error 123: Function %s not found or returned NULL\n", tmp_r->funct_name);
                exit(-1);
              }
            }
            if(tmp_v->found != SKIP){
              tmp_v->type = tmp_r->t.data_type_id;
              tmp_v->found = FOUND;
              tmp_v->size = tmp_r->t.data_size;
              tmp_v->data = (void *) xcalloc(1, tmp_v->size);
              if (tmp_v->data == NULL)
              {
                  xfree(data);
                  return 0;
              }
              memcpy(tmp_v->data, data, tmp_v->size);
            }
            xfree(data);
    }
    if (v1.found == NOT_FOUND) {
        tmp_r = r1;
        tmp_v = &v1;
        void *data = get_attribute_extracted_data( pkt, tmp_r->t.protocol_id, tmp_r->t.field_id );
        if (data != NULL) {
            tmp_v->type = tmp_r->t.data_type_id;
            tmp_v->found = FOUND;
            tmp_v->size = get_data_size_by_proto_and_field_ids(tmp_r->t.protocol_id, tmp_r->t.field_id);
            if (tmp_v->type == MMT_STRING_DATA || tmp_v->type == MMT_STRING_LONG_DATA || tmp_v->type == MMT_BINARY_DATA || tmp_v->type == MMT_BINARY_VAR_DATA || tmp_v->type == MMT_DATA_PATH) {
                /* same clamps as the scalar/tuple paths: the record prefix is
                 * packet-controlled — a forged value must not drive a giant
                 * xcalloc or an over-reading memcpy (F-BUG-091/093, #209) */
                if (tmp_v->type == MMT_DATA_PATH)
                    tmp_v->size = clamp_path_count(*(int*) (data), tmp_v->size);
                else
                    tmp_v->size = clamp_prefixed_size(*(int*) (data), tmp_v->size);
                data = data + sizeof (int);
            }
            else if (tmp_v->type == MMT_HEADER_LINE){
                //parse_mmt_header_line( &data, &tmp_v->size );
                        tmp_v->size = ((mmt_header_line_t *)data)->len;
                        data = (void*)(((mmt_header_line_t *)data)->ptr);
            }
            tmp_v->data = xcalloc(1, tmp_v->size);
            if(tmp_v->data == NULL){
                /* `data` is the attribute's internal storage — not ours to
                 * free (the old xfree(data) here also hit an interior
                 * pointer once the prefix was skipped) */
                return 0;
            }
            if (data != NULL && tmp_v->size > 0) memcpy(tmp_v->data, data, tmp_v->size);
        }
    }
    if (v2.found == NOT_FOUND) {
        tmp_r = r2;
        tmp_v = &v2;
        void *data = get_attribute_extracted_data( pkt, tmp_r->t.protocol_id, tmp_r->t.field_id );
        if (data != NULL) {
            tmp_v->type = tmp_r->t.data_type_id;
            tmp_v->found = FOUND;
            tmp_v->size = get_data_size_by_proto_and_field_ids(tmp_r->t.protocol_id, tmp_r->t.field_id);
            if (tmp_v->type == MMT_STRING_DATA || tmp_v->type == MMT_STRING_LONG_DATA || tmp_v->type == MMT_BINARY_DATA || tmp_v->type == MMT_BINARY_VAR_DATA || tmp_v->type == MMT_DATA_PATH) {
                /* same clamps as the scalar/tuple paths (F-BUG-091/093, #209) */
                if (tmp_v->type == MMT_DATA_PATH)
                    tmp_v->size = clamp_path_count(*(int*) (data), tmp_v->size);
                else
                    tmp_v->size = clamp_prefixed_size(*(int*) (data), tmp_v->size);
                data = data + sizeof (int);
            }
            else if (tmp_v->type == MMT_HEADER_LINE){
            	//parse_mmt_header_line( &data, &tmp_v->size );
                        tmp_v->size = ((mmt_header_line_t *)data)->len;
                        data = (void*)(((mmt_header_line_t *)data)->ptr);
            }
            tmp_v->data = (void *) xcalloc(1, tmp_v->size);
            if(tmp_v->data == NULL){
                xfree(v1.data);
                xfree(v2.data);
                return NOT_VALID;
            }
            if (data != NULL && tmp_v->size > 0) memcpy(tmp_v->data, data, tmp_v->size);
        }
    }

    if ((v1.found == SKIP) || (v2.found == SKIP)){
        xfree(v1.data);
        xfree(v2.data);
        return VALID;
    }
    if ((v1.found == NOT_FOUND) || (v2.found == NOT_FOUND)){
        xfree(v1.data);
        xfree(v2.data);
        return NOT_VALID;
    }
    if (action == COMPARE) {
        ret = compare_values(v1, v2, operator);
        //printf(" = %d\n\n", ret);
    } else if (action == COMPUTE) {
        *result_value = compute(v1, v2, operator);
    }
    xfree(v1.data);
    xfree(v2.data);
    // returns VALID or NOT_VALID
    return ret;
}
