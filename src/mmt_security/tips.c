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
    contact@montimage.com

    This program comes with ABSOLUTELY NO WARRANTY; for details type 'mmt_security --warning'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type 'mmt_security --licence' for details.

 ======================================================================================
 *       Filename:  tips.c
 *    Description:  Open Source prototype version of the MMT_Security library
 *                  that allows analysing network traffic
 *                  to detect normal or abnormal behaviour.
 *        Version:  0.1
 *        Created:  12/June/2013 13:08:57
 *       Revision:  none
 *       Compiler:  gcc
 *         Author:  Edmo, contact@montimage.com
 *   Organization:  Montimage
 ======================================================================================
*/

//*************************************************************************************
//*   Not included: repetition, negation, keep_state
//*************************************************************************************

#define _GNU_SOURCE
#include <search.h>

#include <ctype.h>
#include <errno.h>
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

#ifdef WIN32
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <dlfcn.h>
#endif

#include <libxml2/libxml/xmlreader.h>

#ifdef WIN32
#define LIB_NAME "libembedded_functions.dll"
#else
#define LIB_NAME "libembedded_functions.so"
#endif

#include "struct_defs.h"
#include "public_defs.h"
#include "data_defs.h"
#include "extraction_lib.h"
#include "mmt_core.h"
#include "plugin_defs.h"
#include "types_defs.h"

static FILE * OutputFile = NULL;
static long long packet_count = 0;
static short p_meta = 0;
static short a_utime = 0;
static char *token2;
static char *token3;

static long long corr_mess = 0;
#define SIZE_CAUSE 1000

FILE *open_file(char *name, char *mode)
{
    FILE *file = NULL;
    errno = 0;
    file = fopen(name, mode);
    int saveerrno = errno;
    if (file == NULL) {
        printf("Error 100: Can't open file \"%s\" using mode \"%s\" gives error: %s\n", name, mode, strerror(saveerrno));
        exit(1);
    }
    return file;
}
void close_file(FILE *file) {
    int ret=0;
    errno = 0;
    ret = fclose(file);
    int saveerrno = errno;
    if (ret != 0) {
        printf("Error 100b: Can't close file, returns: %d, gives error: %s\n", ret, strerror(saveerrno));
        exit(1);
    }
}

static unsigned int xallocated_memory_size;
void * xcalloc(unsigned long num, unsigned long size){
   void * retval = calloc(num, size);
   if (retval != NULL) {
       xallocated_memory_size += size;
   }
   return retval;
}

void * xmalloc(unsigned long size) {
   void * retval = malloc(size);
   if (retval != NULL) {
       xallocated_memory_size += size;
   }
   return retval;
}
void xfree(void *freeable) {
   if(freeable != NULL) free(freeable);
}

rule * create_rule()
{
    rule * a_rule = (rule *) xmalloc(sizeof (rule));
    a_rule->type = ROOT; //ROOT/SON/LEAF/ROOT_INSTANCE
    a_rule->value = THEN; //THEN/OR/AND/NOT/REPEAT/COMPUTE
    a_rule->event_id = 0; //Only if a LEAF in a EVENT
    a_rule->t.field_id = 0L; //Only if a LEAF in a EVENT
    a_rule->t.protocol_id = 0L; //Only if a LEAF in a EVENT
    a_rule->t.data_type_id = 0L; //Only if a LEAF in a EVENT
    a_rule->t.event_id = 0; //Only if a LEAF in a EVENT
    a_rule->keep_state = NULL; //Only if ROOT or ROOT_INSTANCE node (if <> NULL then keep rule even if satisfied,
                               //contains a list of event_ids whose state needs to be kept)
    a_rule->t.data_size = 0;
    a_rule->t.valid = NOT_YET;
    a_rule->t.data = NULL;
    a_rule->t.next = NULL;
    a_rule->description = NULL; //Only if ROOT or ROOT_INSTANCE node
    a_rule->funct_name = NULL; //Only if XFUNCT leaf node
    a_rule->if_satisfied = NULL; //Only if ROOT or ROOT_INSTANCE node
    a_rule->if_not_satisfied = NULL; //Only if ROOT or ROOT_INSTANCE node
    a_rule->already_satisfied = NO; //Only if ROOT_INSTANCE node
    a_rule->root = NULL; //Only if non-ROOT and non-ROOT_INSTANCE
    a_rule->type_rule = 0; //Only if ROOT node
    a_rule->property_id = 0; //Only if ROOT
    a_rule->json_history = NULL; //Only if ROOT_INSTANCE node
    a_rule->valid = NOT_YET; //VALID/NO_VALID/NOT_YET
    a_rule->delay_units = NULL; //Optional
    a_rule->delay_max = 0.0; //Optional
    a_rule->delay_min = 0.0; //Optional
    a_rule->not_equal_max = NO; //Optional
    a_rule->not_equal_min = NO; //Optional
    a_rule->counter_max = 0; //Optional
    a_rule->counter_min = 0; //Optional
    a_rule->repeat_times = 0; //Optional (used only for REPEAT node)
    a_rule->repeat_times_found = 0; //Counter (used only for REPEAT node)
    a_rule->timer.tv_usec = 0; //Receives current packet time when need to start calculating for a timeout
    a_rule->timer.tv_sec = 0; //Receives current packet time when need to start calculating for a timeout
    a_rule->counter = 0; //Set to 1 when need to start calculating number of packets
    a_rule->nb_satisfied = 0;
    a_rule->nb_not_satisfied = 0;

    a_rule->list_of_tuples_to_print = NULL; //Only used by a ROOT to list <protocol_id, field_id, data_type_id>
                                            //to printout when the rule is satisfied or not.
    a_rule->list_of_tuples = NULL; //Only used by a ROOT_INSTANCE to store all the values with a reference attribute in a EVENT.

    a_rule->list_of_sons = NULL; //Not used for LEAF
    a_rule->list_of_instances = NULL; //Only if ROOT node
    a_rule->prev = NULL;
    a_rule->next = NULL;
    a_rule->father = NULL; //Only used when creating computation tree or backtracking for NOT nodes
    return a_rule;
}

typedef struct COMPARE_VALUE_struct {
    int type;
    int size;
    int found;
    void *data;
} compare_value;

void create_father(rule *a_rule, short depth, short clean)
{
    father *temp = top_father;
    if (clean == CLEAN) {
        while (temp) {
            top_father = temp->next;
            xfree(temp);
            temp = top_father;
        }
    }
    if (top_father == NULL) {
        top_father = (father *) xmalloc(sizeof (father));
        top_father->node = a_rule;
        top_father->depth = depth;
        top_father->next = NULL;
        top_father->prev = NULL;
        bot_father = top_father;
    } else {
        temp = (father *) xmalloc(sizeof (father));
        temp->node = a_rule;
        temp->depth = depth;
        temp->next = NULL;
        temp->prev = bot_father;
        bot_father->next = temp;
        bot_father = temp;
    }
}

void eliminate_bot_father()
{
    if (bot_father == NULL) return;
    if (bot_father->prev == NULL) {
        xfree(bot_father);
        bot_father = NULL;
        top_father = NULL;
        return;
    }
    father *temp = bot_father->prev;
    if (temp != NULL) {
        temp->next = NULL;
        xfree(bot_father);
        bot_father = temp;
    } else {
        xfree(bot_father);
        bot_father = NULL;
        top_father = NULL;
    }
}

const char cSep = ':'; //Bytes separator in MAC address string like 00-aa-bb-cc-dd-ee

void convert_mac_string_to_byte(const char *pszMACAddress, unsigned char** pbyAddress)
{
    int iConunter = 0;
    for (iConunter = 0; iConunter < 6; ++iConunter) {
        unsigned int iNumber = 0;
        char ch;
        //Convert letter into lower case.
        ch = tolower(*pszMACAddress++);
        if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) {
            *(pbyAddress[0]) = '\0';
        }
        //Convert into number.
        //       a. If character is digit then ch - '0'
        //       b. else (ch - 'a' + 10) it is done
        //       because addition of 10 takes correct value.
        iNumber = isdigit(ch) ? (ch - '0') : (ch - 'a' + 10);
        ch = tolower(*pszMACAddress);
        if ((iConunter < 5 && ch != cSep) || (iConunter == 5 && ch != '\0' && !isspace(ch))) {
            ++pszMACAddress;
            if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) {
                *(pbyAddress[0]) = '\0';
            }
            iNumber <<= 4;
            iNumber += isdigit(ch) ? (ch - '0') : (ch - 'a' + 10);
            ch = *pszMACAddress;
            if (iConunter < 5 && ch != cSep) {
                *(pbyAddress[0]) = '\0';
            }
        }
        /* Store result.  */
        *(*pbyAddress + iConunter) = (unsigned char) iNumber;
        /* Skip cSep.  */
        ++pszMACAddress;
    }
}

void convert_mac_bytes_to_string(char **pszMACAddress, unsigned char *pbyMacAddressInBytes)
{
    (void)sprintf(*pszMACAddress, "%02x%c%02x%c%02x%c%02x%c%02x%c%02x", pbyMacAddressInBytes[0] & 0xff,
            cSep, pbyMacAddressInBytes[1]& 0xff,
            cSep, pbyMacAddressInBytes[2]& 0xff,
            cSep, pbyMacAddressInBytes[3]& 0xff,
            cSep, pbyMacAddressInBytes[4]& 0xff,
            cSep, pbyMacAddressInBytes[5]& 0xff);
}

void *get_xdata(long type, int size, void *str)
{
    //Only used when reading values from XML file
    unsigned char c = 0;
    unsigned short s = 0;
    unsigned long l = 0;
    unsigned long long ll = 0L;
    void * data = (void *) xmalloc(size);
    unsigned char *temp_MAC = NULL;
    mmt_string_data_t *tmp = NULL;
    switch (type) {
        case MMT_DATA_MAC_ADDR:
            temp_MAC = xmalloc(22);
            //str+4 to skip size of mmt_string_data_t structure
            convert_mac_string_to_byte((const char *) (str + 4), &temp_MAC);
            memcpy(data, (void *) temp_MAC, size);
            if (temp_MAC != NULL) xfree(temp_MAC);
            return (void *) data;
            break;
        case MMT_U16_DATA:
            s = (unsigned short) atoi((char*) str);
            memcpy(data, (void *) (&s), size);
            return (void *) data;
            break;
        case MMT_U32_DATA:
            l = (unsigned long) atol((char*) str);
            memcpy(data, (void *) (&l), size);
            return (void *) data;
            break;
        case MMT_U64_DATA:
            ll = (unsigned long long) atoll((char*) str);
            memcpy(data, (void *) (&ll), size);
            return (void *) data;
            break;
        case MMT_U8_DATA:
        case MMT_DATA_CHAR:
            c = (unsigned char) atoi((char*) str);
            memcpy(data, (void *) (&c), size);
            return (void *) data;
            break;
        case MMT_STRING_DATA:
        case MMT_DATA_PATH:
        case MMT_STRING_LONG_DATA:
        case MMT_BINARY_VAR_DATA:
        case MMT_BINARY_DATA:
            // TODO: BINARY needs to be corrected? Normally will contain an address that needs to be fitted in to the form short+void* where short is the
            //      length in bytes of void* and contains the address in 4 hex values
            memcpy(data, (void *) str, size);
            return (void *) data;
            break;
        case MMT_HEADER_LINE:
        	xfree (data);
        	//str is an instance of mmt_string_data_t
        	tmp = str;
        	mmt_header_line_t *hl = (mmt_header_line_t *) xmalloc( size );
        	hl->len = tmp->len;
        	char *str = xmalloc( hl->len);
        	memcpy(str, (void *)tmp->data, hl->len);
        	str[ hl->len - 1 ] = '\0';
        	hl->ptr = str;
        	return hl;
            break;
        case MMT_DATA_TIMEVAL:
        case MMT_DATA_IP_ADDR:
        case MMT_DATA_IP6_ADDR:
        case MMT_DATA_PORT:
        case MMT_DATA_PORT_RANGE:
        case MMT_DATA_DATE:
        case MMT_DATA_TIMEARG:
        case MMT_DATA_FLOAT:
        case MMT_DATA_IP_NET:
        case MMT_DATA_LAYERID:
        case MMT_DATA_POINT:
        case MMT_DATA_FILTER_STATE:
        case MMT_DATA_POINTER:
        case MMT_DATA_BUFFER:
        case MMT_DATA_STRING_INDEX:
        case MMT_DATA_PARENT:
        case MMT_STATS:
        case MMT_GENERIC_HEADER_LINE:
        case MMT_STRING_DATA_POINTER:
        case MMT_UNDEFINED_TYPE:
             return NULL;                 //TODO verify if OK
             break;
        default:
            (void)fprintf(stderr, "Error 2: Type [%ld], size [%d] not implemented yet, data type unknown.\n [%s]\n", type, size, (char *)data);
            exit(-1);
    }//end of switch
}

char *get_my_data(void *data1, short size, long type) {
    char *buff1 = xmalloc(100);
    char *buff0 = xmalloc(10);
    void * data2 = NULL;
    struct timeval t1;
    unsigned long L1=0,L2=0,L3=0,L4=0;
    mmt_binary_data_t *db1 = NULL;
    //mmt_header_line_t *t;
    int data_size=0, j=0, stop=0;
    buff1[0] = '\0';
    switch (type) {
        case MMT_DATA_IP6_ADDR:
            // TODO
            break;
        case MMT_DATA_PORT:
            // TODO
            break;
        case MMT_DATA_PORT_RANGE:
            // TODO
            break;
        case MMT_DATA_DATE:
            // TODO
            break;
        case MMT_DATA_TIMEARG:
            // TODO
            break;
        case MMT_DATA_FLOAT:
            // TODO
            break;
        case MMT_DATA_IP_NET:
            // TODO
            break;
        case MMT_DATA_MAC_ADDR:
            // TODO
            convert_mac_bytes_to_string(&buff1, (unsigned char *) data1);
            break;
        case MMT_DATA_TIMEVAL:
            // TODO
            t1 = *(struct timeval *) (data1);
            (void)sprintf(buff1, "%lu.%lu", t1.tv_sec, (long) t1.tv_usec);
            break;
        case MMT_DATA_IP_ADDR:
            // TODO
            (void)sprintf(buff1, "%d.%d.%d.%d", *(uint8_t*) (data1), *(uint8_t*) (data1+1), *(uint8_t*) (data1+2), *(uint8_t*) (data1+3));
            break;
        case MMT_U16_DATA:
            // TODO
            (void)sprintf(buff1, "%d", *(unsigned short*) (data1));
            break;
        case MMT_U32_DATA:
            (void)sprintf(buff1, "%lu", *(unsigned long*) (data1));
            break;
        case MMT_U64_DATA:
            // TODO
            break;
        case MMT_U8_DATA:
        case MMT_DATA_CHAR:
            (void)sprintf(buff1, "%c", *(unsigned char*) (data1));
            break;
        case MMT_DATA_PATH:
            stop = *(int*) (data1 + j*sizeof (int));
            if(stop>0 && stop < 20){
              for(j=1;j<stop;j++){
                (void)sprintf(buff0, "%d", *(int*) (data1 + j*sizeof (int)));
                if(j==1)strcpy(buff1, buff0);
                else {
                  strcat(buff1, ".");
                  strcat(buff1, buff0);
                }
              }
            }
            break;
        case MMT_HEADER_LINE:
        	//parse_mmt_header_line( &data1, &data_size );
            strncpy(buff1, ((mmt_header_line_t *)data1)->ptr, ((mmt_header_line_t *)data1)->len);
            buff1[((mmt_header_line_t *)data1)->len + 1] ='\0';
        	break;
        case MMT_STRING_LONG_DATA:
        case MMT_STRING_DATA:
            (void)sprintf(buff1, "%s", (char*) (data1 + sizeof (int)));
            break;
        case MMT_BINARY_DATA:
        case MMT_BINARY_VAR_DATA:

            // TODO
            db1 = (mmt_binary_data_t *) (data1);
            data_size = db1->len;
            data2 = db1->data;
            if (data_size == 4) {
                L1 = (*(unsigned long*)(data2)&0x000000ff);
                L2 = (*(unsigned long*)(data2)&0x0000ff00)>>8;
                L3 = (*(unsigned long*)(data2)&0x00ff0000)>>16;
                L4 = (*(unsigned long*)(data2)&0xff000000)>>24;
                (void)sprintf(buff1, "%lu.%lu.%lu.%lu", L1, L2, L3, L4);
            } else if (data_size == 6) {
                for (j = 0; j < data_size; j++) {
                    if (j == 0) {
                        (void)sprintf(buff1, "%2.2X", *(unsigned char*) (data2 + j));
                    } else {
                        (void)sprintf(buff1, ":%2.2X", *(unsigned char*) (data2 + j));
                    }
                }
            } else {
                for (j = 0; j < data_size; j++) {
                    if (j == 0) {
                        (void)sprintf(buff1, "%02X", *(unsigned char*) (data2 + j));
                    } else {
                        (void)sprintf(buff1, ":%02X", *(unsigned char*) (data2 + j));
                    }
                }
            }
            break;
        case MMT_DATA_LAYERID:
            // TODO
            break;
        case MMT_DATA_POINT:
            // TODO
            break;
        case MMT_DATA_FILTER_STATE:
            // TODO
            break;
        case MMT_UNDEFINED_TYPE:
        case MMT_DATA_POINTER:
        case MMT_DATA_BUFFER:
        case MMT_DATA_STRING_INDEX:
        case MMT_DATA_PARENT:
        case MMT_STATS:
        case MMT_GENERIC_HEADER_LINE:
        case MMT_STRING_DATA_POINTER:
            // TODO verify if OK
            break;
             
        default:
            (void)fprintf(stderr, "Error 15.1: Type not implemented yet. Data type unknown.\n");
            exit(-1);
    }//end of switch
    xfree(buff0);
    return buff1;
}

char * get_value( const ipacket_t *pkt, char *input, short *jump, short *size, tuple *list_of_tuples )
{
    int i = 0;
    char * output = NULL;
    char * temp2 = NULL;
    char * tempo = NULL;
    char token1[30];
    long protocol_id = 0;
    long field_id = 0;
    long data_type_id = 0;
    short event_id = 0;
    tuple *temp_tuple2 = NULL;

    token1[0] = '\0';
    token2[0] = '\0';
    token3[0] = '\0';

    output = xmalloc(200);
    tempo = output;

    temp2 = input;
    *jump = 0;

    while (isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) {
        token1[i] = *temp2;
        i++;
        temp2++;
    }
    token1[i] = '\0';
    if (*temp2 != '.') {
        (void)fprintf(stderr, "Error 22x: Incorrect name in: %s", input);
        return NULL;
    }
    temp2++; //skip the point
    i = 0;
    while (isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) {
        token2[i] = *temp2;
        temp2++;
        i++;
    }
    token2[i] = '\0';
    if (*temp2 == '.') {//we have a reference to an event (event_id)
        temp2++;
        i = 0;
        while (isdigit(*temp2)) {
            token3[i] = *temp2;
            temp2++;
            i++;
        }
        token3[i] = '\0';
    }
    //Got variable identifiers: token1.token2.token3 (e.g., META.PROTO.3)
    protocol_id = get_protocol_id_by_name(token1);
    field_id = get_attribute_id_by_protocol_id_and_attribute_name(protocol_id, token2);
    data_type_id = get_attribute_data_type(protocol_id, field_id);
    if (token3[0] != '\0') event_id = atoi(token3);
    if (event_id != 0) {
        //case variable is stored in list_of_tuples
        temp_tuple2 = list_of_tuples;
        while (temp_tuple2 != NULL) {
            if (protocol_id == temp_tuple2->protocol_id && field_id == temp_tuple2->field_id
                    && temp_tuple2->event_id == event_id && temp_tuple2->data_size > 0 && temp_tuple2->data != NULL) {
                long type = temp_tuple2->data_type_id;
                *size = temp_tuple2->data_size;
                void *data = temp_tuple2->data;
                if (type == MMT_STRING_DATA || type == MMT_STRING_LONG_DATA || type == MMT_BINARY_DATA || type == MMT_BINARY_VAR_DATA || type == MMT_DATA_PATH ) {
                    *size = *(int*) (data);
                    data = temp_tuple2->data + sizeof (int);
                }
                else if( type == MMT_HEADER_LINE ){
                    data  = (void*)(((mmt_header_line_t *)data)->ptr); 
                    *size = ((mmt_header_line_t *)data)->len;
                }
                //Copy (data, size, type) to output
                char * d = NULL;
                char * td = NULL;
                d = get_my_data(data, *size, type);
                td = d;
                while (*td != '\0') {
                    *tempo = *td;
                    tempo++;
                    td++;
                }
                xfree(d);
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
            if (type == MMT_STRING_DATA || type == MMT_STRING_LONG_DATA || type == MMT_BINARY_DATA || type == MMT_BINARY_VAR_DATA || type == MMT_DATA_PATH ) {
                *size = *(int*) (data);
                data = data + sizeof (int);
            }
            else if( type == MMT_HEADER_LINE ){
                data  = (void*)(((mmt_header_line_t *)data)->ptr); 
                *size = ((mmt_header_line_t *)data)->len;
            }
            //Copy (data, size, type) to output
            char * d = NULL;
            char * td = NULL;
            d = get_my_data(data, *size, type);
            td = d;
            while (*td != '\0') {
                *tempo = *td;
                tempo++;
                td++;
            }
            xfree(d);
        }
    }
    *jump = temp2 - input;
    *tempo = '\0';
    return output;
}

char *tokenize(char *temp, char **ltoken2, char **ltoken3, short *ref)
{
    //PROTO.FIELD.EVENT
    //note that _ is possible for proto
    //numbers in proto are also possible, but must start with a letter
    char token_tmp[30];
    char *temp2 = temp;
    short i = 0;
    while (*temp2 == ' ')temp2++;
    while (isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) {
        (*ltoken2)[i] = *temp2;
        i++;
        temp2++;
    }
    (*ltoken2)[i] = '\0';
    if (*temp2 != '.') {
        (void)fprintf(stderr, "Error 3b: Incorrect name in PROTO.FIELD.EVENT: %s", temp);
        exit(-1);
    }
    temp2++; //skip the point
    i = 0;
    while (isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) {
        (*ltoken3)[i] = *temp2;
        temp2++;
        i++;
    }
    (*ltoken3)[i] = '\0';
    if (*temp2 == '.') {//we have a reference to an event (event_id)
        temp2++;
        i = 0;
        while (isdigit(*temp2)) {
            token_tmp[i] = *temp2;
            temp2++;
            i++;
        }
        token_tmp[i] = '\0';
        *ref = atoi(token_tmp);
    }
    return temp2;
}

void register_tuple(mmt_handler_t *mmt, tuple * a_tuple)
{
    int ret = 1;
    if (is_registered_attribute(mmt, a_tuple->protocol_id, a_tuple->field_id) == 0) {
        ret = register_extraction_attribute(mmt, a_tuple->protocol_id, a_tuple->field_id);
    }
    if (ret <= 0) {
        (void)fprintf(stderr, "Error 9b: in register_extraction_attribute proto=%ld, field=%ld. Value not available.\n", a_tuple->protocol_id, a_tuple->field_id);
        exit(-1);
    }
}

void add_tuple_to_list_of_tuples(tuple *a_tuple)
{
    if (a_tuple->event_id > 0) {
        tuple * b_tuple = (tuple *) xmalloc(sizeof (tuple));
        b_tuple->protocol_id = a_tuple->protocol_id;
        b_tuple->field_id = a_tuple->field_id;
        b_tuple->data_type_id = a_tuple->data_type_id;
        b_tuple->data_size = a_tuple->data_size;
        b_tuple->event_id = a_tuple->event_id;
        b_tuple->valid = NOT_YET; //set to valid when new values arrive, else set to NOT_YET
        b_tuple->data = NULL;
        b_tuple->next = NULL;
        tuple *temp_tuple = root_rule->list_of_tuples; //add it to the ROOT (i.e. root_rule)
        int found = NO;
        while (temp_tuple != NULL) {
            if (b_tuple->protocol_id == temp_tuple->protocol_id && b_tuple->field_id == temp_tuple->field_id
                    && b_tuple->data_type_id == temp_tuple->data_type_id && b_tuple->event_id == temp_tuple->event_id) {
                found = YES;
                xfree(b_tuple);
                break;
            }
            temp_tuple = temp_tuple->next;
        }
        if (found == NO) {
            if (root_rule->list_of_tuples == NULL) {
                root_rule->list_of_tuples = b_tuple;
            } else {
                b_tuple->next = root_rule->list_of_tuples;
                root_rule->list_of_tuples = b_tuple;
            }
        }
    }
}

char * funct_extract_name(char * input)
{
    //input: funct_name(... or #funct_name(... or #funct_name (...
    char * output = NULL;
    char * start = input;
    char * end = input;
    while (*start == ' ' || *start == '#')start++;
    end = start;
    while (*end != '(' && *end != ' ')end++;
    output = xmalloc(end - start + 1);
    strncpy(output, start, end - start);
    output[end - start] = '\0';
    //caller needs to free return value
    return output;
}

int funct_get_return_type_and_size(int *size, char *lib_name, char *funct_name)
{
#ifdef WIN32
    HMODULE lib_pointer;
#else
    void * lib_pointer;
#endif
    void *(*embedded_function)();
    int type = 0;
#ifdef WIN32
    lib_pointer = LoadLibrary(lib_name);
    if (lib_pointer != NULL) {
        FARPROC initializer = GetProcAddress(lib_pointer, "get_data_type_of_funct_return_value");
        *(void **) (&embedded_function) = initializer;
        int * temph = (int*) embedded_function(funct_name, size);
        type = *temph;
        xfree(temph);
    }
#else
    lib_pointer = dlopen(lib_name, RTLD_LAZY);
    if (lib_pointer != NULL) {
        *(void **) (&embedded_function) = dlsym(lib_pointer, "get_data_type_of_funct_return_value");
        int * temph = (int*) embedded_function(funct_name, size);
        type = *temph;
        xfree(temph);
    }
#endif
    return type;
}

char * funct_get_info_param( mmt_handler_t *mmt, short reg_tuple, char * input, tuple *a_tuple)
{
    //input: param1,...) or param1) or )
    //output: NULL if no params left or paramx) or paramx,...)
    short ref = 0;
    char *start = input;
    char *end = strchr(input, ',');
    if (end == NULL) end = strchr(input, ')');
    while (*start == ' ')start++;
    if (isalpha(*start)) {
        //PROTO.FIELD or PROTO.FIELD.EVENT
        ref = 0;
        tokenize(input, &token2, &token3, &ref);
        a_tuple->protocol_id = get_protocol_id_by_name(token2);
        a_tuple->field_id = get_attribute_id_by_protocol_id_and_attribute_name(a_tuple->protocol_id, token3);
        a_tuple->data_type_id = get_attribute_data_type(a_tuple->protocol_id, a_tuple->field_id);
        a_tuple->data_size = get_data_size_by_proto_and_field_ids(a_tuple->protocol_id, a_tuple->field_id);
        a_tuple->event_id = ref;
        if (ref > 0 || reg_tuple == YES) {
            register_tuple( mmt, a_tuple );
            add_tuple_to_list_of_tuples(a_tuple);
        }
        //if not NULL then next param exists, if NULL then there is no next param
        if (*end == ',') {
            end++;
            return end;
        }
        return NULL;
    }

    if (isdigit(*start)) {
        a_tuple->data = xmalloc(end - start + 1);
        strncpy(a_tuple->data, start, end - start);
        ((char *) a_tuple->data)[end - start] = '\0';
        if (*end == ',') {
            end++;
            return end;
        }
        return NULL;
    }

    if (*end == ')')
        return NULL; // XXX well ?

    return NULL;
}

void * funct_get_params_and_execute( const ipacket_t *pkt, short skip_refs, char *lib_name, char *funct_name, int data_size, tuple *tt, tuple *list_of_tuples, short *found )
{
    void *lib_pointer = NULL;
    void *(*embedded_function)();
    void * ihandle = NULL;
    void * result_data = NULL;
    tuple *temp_tuple2;

#ifdef WIN32
    lib_pointer = LoadLibrary(lib_name);
#else
    lib_pointer = dlopen(lib_name, RTLD_LAZY);
#endif
    if (lib_pointer != NULL) {
#ifdef WIN32
        FARPROC initializer = GetProcAddress(lib_pointer, funct_name);
        *(void **) (&embedded_function) = initializer;
#else
        *(void **) (&embedded_function) = dlsym(lib_pointer, funct_name);
#endif
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
        memcpy(result_data, ihandle, data_size);
        xfree(ihandle);
#ifdef WIN32
        FreeLibrary(lib_pointer);
#else
        dlclose(lib_pointer);
#endif
        *found = FOUND;
        //caller needs to free return value
        return result_data;
    }
    *found = NOT_FOUND;
    return NULL;
}

void create_boolean_expression(mmt_handler_t *mmt, int first_time, rule *a_rule, char *expression)
{
    //parse expression and create sub-tree, a_rule->value = top operator
    //((ARP.OPCODE == 2)&&(ARP.SRC_PROTO == ARP.SRC_PROTO.1))
    //OR, AND, NEQ, EQ, GT, GTE, LT, LTE, THEN, COMPUTE, XC, XCE, XD, XDE, XE, ADD, SUB, MUL, DIV
    char *temp = expression;
    char *temp2 = expression;
    char token[30];
    int i;
    short ref = 0;
    rule *new_rule;

    while (isspace(*temp))temp++;

    if (*temp == '(') {
        temp2 = temp + 1;
        if (first_time == YES) {
            create_boolean_expression(mmt, NO, a_rule, temp2);
        } else {
            //create new_rule
            new_rule = create_rule();
            new_rule->type = SON;
            new_rule->value = NOP;
            if (a_rule->list_of_sons == NULL) {
                a_rule->list_of_sons = new_rule;
                new_rule->prev = NULL;
                new_rule->next = NULL;
            } else {
                rule *a_temp = a_rule->list_of_sons;
                while (a_temp->next != NULL) a_temp = a_temp->next;
                a_temp->next = new_rule;
                new_rule->prev = a_temp;
            }
            new_rule->father = a_rule;
            create_boolean_expression(mmt, NO, new_rule, temp2);
        }
    } else if (*temp == ')') {
        temp2 = temp + 1;
        //go up one
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '\0') {
        //do nothing
    } else if (*temp == 'X' && *(temp + 1) == 'E' && *(temp + 2) == ' ') {
        //XE (identical to a string)
        temp2 = temp + 2;
        //set value
        a_rule->father->value = XE;
        //go up one
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == 'X' && *(temp + 1) == 'C' && *(temp + 2) == ' ') {
        //XC
        temp2 = temp + 2;
        a_rule->father->value = XC;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == 'X' && *(temp + 1) == 'D' && *(temp + 2) == ' ') {
        //XD
        temp2 = temp + 2;
        a_rule->father->value = XD;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == 'X' && *(temp + 1) == 'C' && *(temp + 2) == 'E' && *(temp + 3) == ' ') {
        //XCE
        temp2 = temp + 3;
        a_rule->father->value = XCE;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == 'X' && *(temp + 1) == 'D' && *(temp + 2) == 'E' && *(temp + 3) == ' ') {
        //XDE
        temp2 = temp + 3;
        a_rule->father->value = XDE;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == 'I' && *(temp + 1) == 'N' && *(temp + 2) == ' ') {
        //IN+blank
        temp2 = temp + 3;
        a_rule->father->value = XIN;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '\'') {
        // 'string'
        temp++;
        temp2 = temp;
        i = 0;
        while (*temp2 != '\'' && i < 1000) {
            temp2++;
            i++;
        }
        if (i > 999) {
            (void)fprintf(stderr, "Error 3a: Incorrect string in boolean expression: %s", expression);
            exit(-1);
        }
        i = temp2 - temp;
        mmt_string_data_t s;
        strncpy((char*)s.data, temp, i);
        s.data[i] = '\0';
        temp2++; //skip the last '\''
        s.len = i + 1;
        //create new_rule
        new_rule = create_rule();
        new_rule->type = LEAF;
        new_rule->value = XCON;
        //need to find a right handed LEAF to determine the type
        rule * temp_rule = a_rule;
        while (temp_rule->list_of_sons != NULL) {
            temp_rule = temp_rule->list_of_sons;
        }
        new_rule->t.protocol_id = temp_rule->t.protocol_id;
        new_rule->t.field_id = temp_rule->t.field_id;
        new_rule->t.data_type_id = temp_rule->t.data_type_id;
        new_rule->t.event_id = temp_rule->t.event_id;
        new_rule->t.data_size = temp_rule->t.data_size;
        new_rule->t.valid = VALID;
        new_rule->t.data = (void *) get_xdata(new_rule->t.data_type_id, new_rule->t.data_size, (void *) (&s));
        ;
        if (a_rule->list_of_sons == NULL) {
            a_rule->list_of_sons = new_rule;
            new_rule->prev = NULL;
            new_rule->next = NULL;
        } else {
            rule *a_temp = a_rule->list_of_sons;
            while (a_temp->next != NULL) a_temp = a_temp->next;
            a_temp->next = new_rule;
            new_rule->prev = a_temp;
        }
        new_rule->father = a_rule;
        create_boolean_expression(mmt, NO, new_rule, temp2);
    } else if (isalpha(*temp) || *temp == '_') {
        //PROTO.FIELD.EVENT
        temp2 = tokenize(temp, &token2, &token3, &ref);
        //create new_rule
        new_rule = create_rule();
        new_rule->type = LEAF;
        new_rule->value = XVAR;
        new_rule->t.protocol_id = get_protocol_id_by_name(token2);
        new_rule->t.field_id = get_attribute_id_by_protocol_id_and_attribute_name(new_rule->t.protocol_id, token3);
        new_rule->t.data_type_id = get_attribute_data_type(new_rule->t.protocol_id, new_rule->t.field_id);
        int ret = 1;
        if (is_registered_attribute(mmt, new_rule->t.protocol_id, new_rule->t.field_id) == 0) {
            ret = register_extraction_attribute(mmt, new_rule->t.protocol_id, new_rule->t.field_id);
        }
        if (ret <= 0) {
            (void)fprintf(stderr, "Error 9: in register_extraction_attribute proto=%ld, field=%ld.Value not available.\n", new_rule->t.protocol_id, new_rule->t.field_id);
            exit(-1);
        }
        if (ref > 0) {
            new_rule->t.event_id = ref;
            tuple * a_tuple = (tuple *) xmalloc(sizeof (tuple));
            a_tuple->protocol_id = new_rule->t.protocol_id;
            a_tuple->field_id = new_rule->t.field_id;
            a_tuple->data_type_id = new_rule->t.data_type_id;
            a_tuple->data_size = new_rule->t.data_size;
            a_tuple->event_id = new_rule->t.event_id;
            a_tuple->valid = NOT_YET; //set to valid when new values arrive, else set to NOT_YET
            a_tuple->data = NULL;
            a_tuple->next = NULL;
            tuple *temp_tuple = top_rule->list_of_tuples;
            int found = NO;
            while (temp_tuple != NULL) {
                if (a_tuple->protocol_id == temp_tuple->protocol_id && a_tuple->field_id == temp_tuple->field_id
                        && a_tuple->data_type_id == temp_tuple->data_type_id && a_tuple->event_id == temp_tuple->event_id) {
                    found = YES;
                    xfree(a_tuple);
                    break;
                }
                temp_tuple = temp_tuple->next;
            }
            if (found == NO) {
                if (root_rule->list_of_tuples == NULL) {
                    root_rule->list_of_tuples = a_tuple;
                } else {
                    a_tuple->next = root_rule->list_of_tuples;
                    root_rule->list_of_tuples = a_tuple;
                }
            }
        }
        new_rule->t.data_size = get_data_size_by_proto_and_field_ids(new_rule->t.protocol_id, new_rule->t.field_id);
        new_rule->t.valid = NOT_YET;
        new_rule->t.data = NULL;
        if (a_rule->list_of_sons == NULL) {
            a_rule->list_of_sons = new_rule;
            new_rule->prev = NULL;
            new_rule->next = NULL;
        } else {
            rule *a_temp = a_rule->list_of_sons;
            while (a_temp->next != NULL) a_temp = a_temp->next;
            a_temp->next = new_rule;
            new_rule->prev = a_temp;
        }
        new_rule->father = a_rule;
        create_boolean_expression(mmt, NO, new_rule, temp2);
    } else if (*temp == '#') {
        //Embedded function: #function_name(param1,param2,...) where param is a numeric constant or of the form PROTO.FIELD.EVENT_ID
        char *what_to_do = temp;
        char * funct_name = funct_extract_name(what_to_do);
        //funct_name is a malloc that contains the name
        int data_size = 0;

        //create new_rule
        //new_rule->t contains info on return value and new_rule->t.next... contains info on parameters
        new_rule = create_rule();
        new_rule->type = LEAF;
        new_rule->value = XFUNCT;
        new_rule->funct_name = funct_name; //do not free funct_name

        int return_type = funct_get_return_type_and_size(&data_size, LIB_NAME, funct_name);
        char * command = strchr(what_to_do, '(');
        command++;
        while (*command == ' ') command++;
        //command contains param1,param2...) or param1) or )

        //tuple t holds info on return value
        new_rule->t.protocol_id = -1; //not used
        new_rule->t.field_id = -1; //not used
        new_rule->t.event_id = -1; //not used
        new_rule->t.data_type_id = return_type;
        new_rule->t.data_size = data_size;
        new_rule->t.valid = NOT_YET;
        new_rule->t.data = NULL; //will be calculated

        char * command2;
        tuple * top_tuple = (tuple *) xmalloc(sizeof (tuple)); //top of parameter list
        new_rule->t.next = top_tuple; //attach to list_of_tuples (first one is info on return value and the reste info on each param)
        top_tuple->protocol_id = -1;
        top_tuple->field_id = -1;
        top_tuple->data_type_id = -1;
        top_tuple->data_size = -1;
        top_tuple->event_id = -1;
        top_tuple->valid = NOT_YET; //not used in this context
        top_tuple->data = NULL;
        top_tuple->next = NULL;
        tuple * a_tuple = top_tuple;
        tuple * new_tuple;
        command2 = command;
        short reg_tuple = YES;

        command2 = funct_get_info_param( mmt, reg_tuple, command2, a_tuple );
        while( command2 ) {
            new_tuple = (tuple *)xmalloc(sizeof (tuple));
            new_tuple->protocol_id = -1;
            new_tuple->field_id = -1;
            new_tuple->data_type_id = -1;
            new_tuple->data_size = -1;
            new_tuple->event_id = -1;
            new_tuple->valid = NOT_YET; //not used in this context
            new_tuple->data = NULL;
            new_tuple->next = NULL;
            a_tuple->next = new_tuple;
            a_tuple = new_tuple;
            command2 = funct_get_info_param( mmt, reg_tuple, command2, a_tuple );
        }
        if (a_rule->list_of_sons == NULL) {
            a_rule->list_of_sons = new_rule;
            new_rule->prev = NULL;
            new_rule->next = NULL;
        } else {
            rule *a_temp = a_rule->list_of_sons;
            while (a_temp->next != NULL) a_temp = a_temp->next;
            a_temp->next = new_rule;
            new_rule->prev = a_temp;
        }
        new_rule->father = a_rule;
        create_boolean_expression(mmt, NO, new_rule, strchr(command, ')') + 1);
    } else if (isdigit(*temp)) {
        // 1.0
        temp2 = temp;
        while (isxdigit(*temp2) || *temp2 == '.')temp2++;
        i = temp2 - temp;
        strncpy(token, temp, i);
        token[i] = '\0';

        // create new_rule
        new_rule = create_rule();
        new_rule->type = LEAF;
        new_rule->value = XCON;
        // need to find a right handed LEAF to determine the type
        rule * temp_rule = a_rule;
        while (temp_rule->list_of_sons != NULL) {
            temp_rule = temp_rule->list_of_sons;
        }
        new_rule->t.protocol_id = temp_rule->t.protocol_id;
        new_rule->t.field_id = temp_rule->t.field_id;
        new_rule->t.data_type_id = temp_rule->t.data_type_id;
        new_rule->t.event_id = temp_rule->t.event_id;
        new_rule->t.data_size = temp_rule->t.data_size;
        new_rule->t.valid = VALID;
        new_rule->t.data = (void *) get_xdata(new_rule->t.data_type_id, new_rule->t.data_size, (void *) token);
        ;
        if (a_rule->list_of_sons == NULL) {
            a_rule->list_of_sons = new_rule;
            new_rule->prev = NULL;
            new_rule->next = NULL;
        } else {
            rule *a_temp = a_rule->list_of_sons;
            while (a_temp->next != NULL) a_temp = a_temp->next;
            a_temp->next = new_rule;
            new_rule->prev = a_temp;
        }
        new_rule->father = a_rule;
        create_boolean_expression(mmt, NO, new_rule, temp2);
    } else if (*temp == '=' && *(temp + 1) == '=') {
        // ==
        temp2 = temp + 2;
        // set value
        a_rule->father->value = EQ;
        // go up one
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '|' && *(temp + 1) == '|') {
        // ||
        temp2 = temp + 2;
        // set value
        a_rule->father->value = XOR;
        // go up one
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '!' && *(temp + 1) == '=') {
        // !=
        temp2 = temp + 2;
        a_rule->father->value = NEQ;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '>' && *(temp + 1) != '=') {
        // >
        temp2 = temp + 1;
        a_rule->father->value = GT;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '>' && *(temp + 1) == '=') {
        // >=
        temp2 = temp + 2;
        a_rule->father->value = GTE;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '<' && *(temp + 1) != '=') {
        // <
        temp2 = temp + 1;
        a_rule->father->value = LT;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '<' && *(temp + 1) == '=') {
        // <=
        temp2 = temp + 2;
        a_rule->father->value = LTE;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '&' && *(temp + 1) == '&') {
        // &&
        temp2 = temp + 2;
        a_rule->father->value = XAND;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '+') {
        // +
        temp2 = temp + 1;
        a_rule->father->value = ADD;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '-') {
        // -
        temp2 = temp + 1;
        a_rule->father->value = SUB;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '*') {
        // *
        temp2 = temp + 1;
        a_rule->father->value = MUL;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == '/') {
        // '/'
        temp2 = temp + 1;
        a_rule->father->value = DIV;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else {
        (void)fprintf(stderr, "Error 37: Illegal character found in boolean expression: %c%c.\n", *temp, *(temp + 1));
        exit(-1);
    }
    return;
}

double get_double_in_sec (char * units,long long ll)
{
  double dd = 0.0;
  if(units==NULL || units[0]=='s') dd = ll;
  else if(units[0]=='m'){
    if(units[1]=='s') dd = (((double)ll)/1000);
    else if(units[1]=='m') dd = (((double)ll)/1000000);
    else if(units[1]=='\0') dd = 60*ll;
  }
  else if(units[0]=='H') dd = 60*60*ll;
  else if(units[0]=='D') dd = 24*60*60*ll;
  else if(units[0]=='M') dd = 30L*24*60*60*ll;
  else if(units[0]=='Y') dd = 365L*24*60*60*ll;
  return dd;
}

short processNode( mmt_handler_t *mmt, xmlTextReaderPtr reader)
{
    static int first_time = YES;
    const xmlChar *name, *attribute_value[100], *attribute_name;
    rule *a_rule = NULL;
    rule *a_temp = NULL;
    int state = 0;
    int ret;
    short depth;
    attribute_name = NULL;
    for (ret = 0; ret < 100; ret++)attribute_value[ret] = NULL;
    name = xmlTextReaderConstName(reader);
    if (name == NULL) return 1;
        (void)xmlTextReaderConstValue(reader);
    if (name[0] != '#') {
        ret = xmlTextReaderNodeType(reader);
        depth = xmlTextReaderDepth(reader);
        if (ret == 15) {
            while (bot_father != NULL && bot_father->depth >= depth) eliminate_bot_father();
            return 0;
        }
        if (xmlStrcmp(name, (const xmlChar*)"beginning") == 0) {
        } else if (xmlStrcmp(name, (const xmlChar*)"property") == 0) {
            a_rule = create_rule();
            a_rule->type = ROOT;
            if (top_rule == NULL) {
                top_rule = a_rule;
                bot_rule = a_rule;
            } else {
                bot_rule->next = a_rule;
                a_rule->prev = bot_rule;
                bot_rule = a_rule;
            }
            root_rule = a_rule;
            state = ROOT;
            create_father(a_rule, depth, CLEAN);
        } else if (xmlStrcmp(name, (const xmlChar*)"operator") == 0) {
            a_rule = create_rule();
            a_rule->type = SON;
            state = SON;
        } else if (xmlStrcmp(name, (const xmlChar*)"event") == 0) {
            a_rule = create_rule();
            a_rule->type = SON;
            state = EVENT;
        }
    }
    int i;
    int count;
    count = xmlTextReaderAttributeCount(reader);
    for (i = 0; i < count; i++) {
        attribute_value[i] = xmlTextReaderGetAttributeNo(reader, i);
    }
    for (i = 0; i < count; i++) {
        xmlTextReaderMoveToAttributeNo(reader, i);
        attribute_name = xmlTextReaderConstName(reader);
        if (xmlStrcmp(attribute_name, (const xmlChar*)"value") == 0) {
            if (xmlStrcmp(attribute_value[i], (const xmlChar*)"THEN") == 0) a_rule->value = THEN;
            else if (xmlStrcmp(attribute_value[i], (const xmlChar*)"COMPUTE") == 0) a_rule->value = COMPUTE;
            else if (xmlStrcmp(attribute_value[i], (const xmlChar*)"OR") == 0) a_rule->value = OR;
            else if (xmlStrcmp(attribute_value[i], (const xmlChar*)"AND") == 0) a_rule->value = AND;
            else if (xmlStrcmp(attribute_value[i], (const xmlChar*)"NOT") == 0){
                a_rule->value = NOT;
            }
            else if (xmlStrcmp(attribute_value[i], (const xmlChar*)"REPEAT") == 0) a_rule->value = REPEAT;
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"event_id") == 0) {
            a_rule->event_id = atol((const char*)attribute_value[i]);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"keep_state") == 0) {
            a_rule->keep_state = strdup((const char*)attribute_value[i]);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"boolean_expression") == 0) {
            create_boolean_expression(mmt, YES, a_rule, (char *) attribute_value[i]);
            //register attributes needed:
            if (first_time == YES) {
                if (is_registered_attribute(mmt, p_meta, a_utime) != 1) {
                    ret = register_extraction_attribute(mmt, p_meta, a_utime);
                    if (ret <= 0) {
                        (void)fprintf(stderr, "Error 8: in register_extraction_attribute proto=META, field=UTIME. Timestamp not available.\n");
                        exit(-1);
                    }
                }
                first_time = NO;
            }
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"delay_units") == 0) {
            a_rule->delay_units = strdup((const char*)attribute_value[i]); //Y,M,D,H,m,s(default),ms,mms
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"delay_max") == 0) {
            //<num>,<num>-
            if(attribute_value[i][xmlStrlen(attribute_value[i])-1]=='-'){
              a_rule->not_equal_max = YES;
            }
            long long ll= atoll((const char*)attribute_value[i]);
            if(ll==0) a_rule->delay_max =0;
            else a_rule->delay_max = get_double_in_sec (a_rule->delay_units,ll);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"description") == 0) {
            a_rule->description = strdup((const char*)attribute_value[i]);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"property_id") == 0) {
            a_rule->property_id = atoi((const char*)attribute_value[i]);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"if_not_satisfied") == 0) {
            a_rule->if_not_satisfied = strdup((const char*)attribute_value[i]);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"if_satisfied") == 0) {
            a_rule->if_satisfied = strdup((const char*)attribute_value[i]);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"type_property") == 0) {
            if (xmlStrncmp(attribute_value[i], (const xmlChar*)"ATTACK", 3) == 0) a_rule->type_rule = ATTACK;
            else if (xmlStrncmp(attribute_value[i], (const xmlChar*)"EVASION", 3) == 0) a_rule->type_rule = EVASION;
            else if (xmlStrncmp(attribute_value[i], (const xmlChar*)"SECURITY_RULE", 3) == 0) a_rule->type_rule = SECURITY_RULE;
            else if (xmlStrncmp(attribute_value[i], (const xmlChar*)"TEST", 3) == 0) a_rule->type_rule = TEST;
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"delay_min") == 0) {
            //<num>,<num>+
            if(attribute_value[i][xmlStrlen(attribute_value[i])-1]=='+'){
              a_rule->not_equal_min = YES;
            }
            long long ll= atoll((const char*)attribute_value[i]);
            if(ll==0) a_rule->delay_min =0;
            else a_rule->delay_min = get_double_in_sec (a_rule->delay_units,ll);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"counter_max") == 0) {
            a_rule->counter_max = atoi((const char*)attribute_value[i]);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"counter_min") == 0) {
            a_rule->counter_min = atoi((const char*)attribute_value[i]);
        } else if (xmlStrcmp(attribute_name, (const xmlChar*)"repeat_times") == 0) {
            a_rule->repeat_times = atoi((const char*)attribute_value[i]);
        }
    }
    for (i = 0; i < count; i++) {
        if (attribute_value[i] != NULL) {
            xfree((char *) attribute_value[i]);
            attribute_value[i] = NULL;
        }
    }
    if (state == SON || state == LEAF || state == EVENT) {
        rule *los = NULL;
        if (bot_father != NULL) {
            if (bot_father->depth < depth) {
                los = bot_father->node;
                create_father(a_rule, depth, DONT_CLEAN);
            } else if (bot_father->depth == depth) {
                los = bot_father->prev->node;
                bot_father->node = a_rule;
            } else {
                los = bot_father->prev->prev->node;
                bot_father->prev->node = a_rule;
                eliminate_bot_father();
            }
        }
        if (los->list_of_sons == NULL) {
            los->list_of_sons = a_rule;
            a_rule->father = los;
        } else {
            a_temp = los->list_of_sons;
            while (a_temp->next != NULL) a_temp = a_temp->next;
            a_temp->next = a_rule;
            a_rule->father = los;
            a_rule->prev = a_temp;
        }
    }
    return 0;
}

void recuperate_attributes(rule* root, rule *r)
{
    rule *s = NULL;
    int found = NO;
    tuple *temp_tuple = NULL;
    tuple * a_tuple = NULL;
    if (r->t.protocol_id != 0 && r->t.field_id != 0) {
        //Create a tuple in ROOT. It will serve to indicate the attributes to printout when a rule is satisfied or not.
        a_tuple = (tuple *) xmalloc(sizeof (tuple));
        a_tuple->protocol_id = r->t.protocol_id;
        a_tuple->field_id = r->t.field_id;
        a_tuple->data_type_id = r->t.data_type_id;
        a_tuple->event_id = 0;
        a_tuple->valid = NOT_YET;
        a_tuple->data_size = 0;
        a_tuple->data = NULL;
        a_tuple->next = NULL;
        temp_tuple = root->list_of_tuples_to_print;
        found = NO;
        while (temp_tuple != NULL) {
            if (a_tuple->protocol_id == temp_tuple->protocol_id && a_tuple->field_id == temp_tuple->field_id
                    && a_tuple->data_type_id == temp_tuple->data_type_id) {
                found = YES;
                xfree(a_tuple);
                break;
            }
            temp_tuple = temp_tuple->next;
        }
        if (found == NO) {
            if (root->list_of_tuples_to_print == NULL) {
                root->list_of_tuples_to_print = a_tuple;
            } else {
                a_tuple->next = root->list_of_tuples_to_print;
                root->list_of_tuples_to_print = a_tuple;
            }
        }
    }
    s = r->list_of_sons;
    while (s) {
        recuperate_attributes(root, s);
        s = s->next;
    }
}

static OPTIONS_struct *op;

void read_rules( mmt_handler_t *mmt )
{
    LIBXML_TEST_VERSION
    xmlTextReaderPtr reader;
    int ret;

    op->timestamp_proto_id = p_meta;
    op->timestamp_field_id = a_utime;

    reader = xmlReaderForFile(op->RuleFileName, NULL, 0);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            processNode( mmt, reader );
            ret = xmlTextReaderRead(reader);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            (void)fprintf(stderr, "Error 13: in XML properties file: %s. Parsing failed.\n", op->RuleFileName);
            exit(-1);
        }
    } else {
        (void)fprintf(stderr, "Error 14: Unable to open the XML properties file: %s.\n", op->RuleFileName);
        exit(-1);
    }
    //Need to recuperate what attributes will need to be printed out (<proto_id, field_id, data_type_id>)
    rule * temp = top_rule;
    while (temp) {
        recuperate_attributes(temp, temp);
        temp = temp->next;
    }
}

rule *create_instance(rule **root_inst, rule *r, rule* father)
{
    rule *a_rule = create_rule();
    rule *temp_inst = NULL;
    rule *temp_sons = r->list_of_sons;
    rule *temp_next = r->next;
    rule *temp = NULL;
    tuple *temp_tuple = r->list_of_tuples;

    a_rule->type = r->type;
    a_rule->value = r->value;
    if (r->type == ROOT) {
        temp_inst = r;
        a_rule->type = ROOT_INSTANCE;
        *root_inst = a_rule;
        //add tuples to list_of_tuples
        tuple *temp_tuple2 = NULL;
        while (temp_tuple != NULL) {
            tuple * a_tuple = (tuple *) xmalloc(sizeof (tuple));
            a_tuple->protocol_id = temp_tuple->protocol_id;
            a_tuple->field_id = temp_tuple->field_id;
            a_tuple->data_type_id = temp_tuple->data_type_id;
            a_tuple->data_size = temp_tuple->data_size;
            a_tuple->event_id = temp_tuple->event_id;
            a_tuple->data = NULL;
            a_tuple->valid = NOT_YET; //set to valid when new values arrive, else set to NOT_YET
            a_tuple->next = NULL;
            if (temp_tuple2 == NULL) {
                a_rule->list_of_tuples = a_tuple;
                temp_tuple2 = a_tuple;
            } else {
                temp_tuple2->next = a_tuple;
                temp_tuple2 = a_tuple;
            }
            temp_tuple = temp_tuple->next;
        }
    } else {
        a_rule->root = *root_inst;
    }
    if (r->description != NULL) {
        a_rule->property_id = r->property_id;
        a_rule->description = strdup(r->description);
    }
    if (r->keep_state != NULL) {
        a_rule->keep_state = strdup(r->keep_state);
    }
    if (r->if_satisfied != NULL) {
        a_rule->if_satisfied = strdup(r->if_satisfied);
    }
    if (r->if_not_satisfied != NULL) {
        a_rule->if_not_satisfied = strdup(r->if_not_satisfied);
    }
    a_rule->event_id = r->event_id;
    a_rule->delay_units = r->delay_units;
    a_rule->delay_max = r->delay_max;
    a_rule->delay_min = r->delay_min;
    a_rule->not_equal_max = r->not_equal_max;
    a_rule->not_equal_min = r->not_equal_min;
    a_rule->counter_max = r->counter_max;
    a_rule->counter_min = r->counter_min;
    a_rule->repeat_times = r->repeat_times;
    a_rule->repeat_times_found = 0;
    if (r->type != ROOT && temp_next) {
        temp = create_instance(root_inst, temp_next, father);
        a_rule->next = temp;
        temp->father = father;
        temp->prev = a_rule;
    }
    if (temp_sons) {
        temp = create_instance(root_inst, temp_sons, a_rule);
        a_rule->list_of_sons = temp;
        temp->father = a_rule;
    }
    if (r->type == LEAF) {
        a_rule->t.protocol_id = r->t.protocol_id;
        a_rule->t.field_id = r->t.field_id;
        a_rule->t.data_type_id = r->t.data_type_id;
        a_rule->t.event_id = r->t.event_id;
        a_rule->t.data_size = r->t.data_size;
        a_rule->t.next = r->t.next;
        if (r->value == XFUNCT && r->funct_name != NULL) {
            a_rule->funct_name = strdup(r->funct_name);
        }
        if (r->value == XCON) {
            a_rule->t.data = xmalloc(a_rule->t.data_size);
            memcpy(a_rule->t.data, (void *) (r->t.data), a_rule->t.data_size);
            a_rule->t.valid = VALID;
        } else {
            a_rule->t.valid = NOT_YET;
            a_rule->t.data = NULL;
        }
    } else if (r->type == ROOT) {
        if (r->list_of_instances == NULL) {
            r->list_of_instances = a_rule;
        } else {
            a_rule->prev = NULL;
            a_rule->next = temp_inst->list_of_instances;
            temp_inst->list_of_instances->prev = a_rule;
            temp_inst->list_of_instances = a_rule;
        }
    }
    return a_rule;
}

short event_found(int buff_ids[100], short event_id)
{
  if(event_id > 0){
    short i=0;
    while(buff_ids[i] != 0){
      if(event_id == buff_ids[i]){
        return YES;
      }
      i++;
    }
  }
  return NO;
}

char * eliminate_from(char *pt)
{
  char * result = NULL;
  char * pt_tmp = NULL;
  char * pt2 = strstr(pt, "</event>");
  char * pt3 = strchr(pt2, '>');
  if(pt3 == NULL) return NULL;
  result = pt;
  pt_tmp = pt3 + 1;
  while(*pt_tmp != '\0'){
    *pt = *pt_tmp;
    pt_tmp++;
    pt++;
  }
  *pt = '\0';
  return result;
}

void set_events_to_not_yet(int buff_ids[100], rule * r, rule *orig_rule)
{
  rule *pt = r;
  rule *pt_orig = orig_rule;
  short all_valid = YES;
  while(pt != NULL){
    pt->timer.tv_sec = pt_orig->timer.tv_sec;
    pt->timer.tv_usec = pt_orig->timer.tv_usec;
    if(pt->event_id >0){
      if (event_found(buff_ids, pt->event_id) == NO){
        pt->valid = NOT_YET;
        all_valid = NO;
        pt->father->valid = NOT_YET;
        tuple *temp_tuple = &(pt->t);
        while(temp_tuple != NULL){
          temp_tuple->valid = NOT_YET;
          temp_tuple = temp_tuple->next;
        }
      }else{
        pt->valid = pt_orig->valid;
        tuple *temp_tuple = &(pt->t);
        tuple *temp_tuple_orig = &(pt_orig->t);
        while(temp_tuple != NULL){
          temp_tuple->valid = temp_tuple_orig->valid;
          if(temp_tuple_orig->data != NULL && temp_tuple_orig->data_size != 0){
            temp_tuple->data = xmalloc(temp_tuple_orig->data_size);
            memcpy(temp_tuple->data, (void *) (temp_tuple_orig->data), temp_tuple_orig->data_size);
          }
          temp_tuple = temp_tuple->next;
          temp_tuple_orig = temp_tuple_orig->next;
        }
      }
    }
    if(pt->list_of_sons != NULL){
      set_events_to_not_yet(buff_ids, pt->list_of_sons, pt_orig->list_of_sons);
    }
    pt = pt->next;
    pt_orig = pt_orig->next;
  }
  if(all_valid == YES){
    r->valid = VALID;
  }
}

rule *copy_instance(rule **root_inst, rule *r, rule* father, rule *orig_rule)
{
  char *pt = NULL, *pt2 = NULL, *pt3 = NULL;
  pt = orig_rule->keep_state;
  if(pt == NULL) return NULL;
  rule *new_rule = create_instance(root_inst, r, father);
  char *buff = xmalloc(10);
  int buff_ids[100];
  short i=0;
  for(i=0;i<100;i++)buff_ids[i]=0;
  i=0;
  while(*pt != '\0'){
    pt2 = pt;
    while(*pt2 != ',' && *pt2 != '\0'){
      pt2++;
    }
    if (pt != pt2){
       memcpy(buff,pt,pt2-pt);
       buff[pt2-pt]='\0';
       buff_ids[i++]=atoi(buff);
    }
    if(*pt2=='\0')break;
    pt=pt2+1;
  }

  if(new_rule != NULL){
    if(orig_rule->json_history != NULL){
      char * json_history = strdup(orig_rule->json_history);
      pt = strstr(json_history,"event");
      while (pt != NULL){
        pt2 = strstr(pt,"description");
        if(pt2 != NULL){
          pt2 = pt2 + 18;
          pt3 = strchr(pt2,':');
          if (pt3 != NULL){
            memcpy(buff,pt2,pt3-pt2);
            buff[pt3-pt2]='\0';
            if(event_found(buff_ids, atoi(buff)) == NO){
              pt2 = eliminate_from(pt);
            }
          }
        }
        pt = strstr(pt2,"event");
      }
      new_rule->json_history = json_history;
    }
    new_rule->timer.tv_sec = orig_rule->timer.tv_sec;
    new_rule->timer.tv_usec = orig_rule->timer.tv_usec;
    struct TUPLE_struct *temp_lot = new_rule->list_of_tuples;
    struct TUPLE_struct *temp_lot_orig = orig_rule->list_of_tuples;
    while(temp_lot != NULL){
      if(event_found(buff_ids, temp_lot->event_id) == NO){
        temp_lot->valid = NOT_YET;
        xfree(temp_lot->data);
      }else{
        temp_lot->data_size = temp_lot_orig->data_size;
        temp_lot->valid = temp_lot_orig->valid;
        temp_lot->data = NULL;
        if(temp_lot_orig->data!=NULL){
          temp_lot->data = xmalloc(temp_lot_orig->data_size);
          memcpy(temp_lot->data, (void *) (temp_lot_orig->data), temp_lot_orig->data_size);
        }
      }
      temp_lot = temp_lot->next;
      temp_lot_orig = temp_lot_orig->next;
    }

    rule * temp_rule = new_rule->list_of_sons;
    rule * temp_orig = orig_rule->list_of_sons;
    if(orig_rule->counter_min < 0 || orig_rule->delay_min < 0) {
      temp_rule = new_rule->list_of_sons->next;
      temp_orig = orig_rule->list_of_sons->next;
    }
    set_events_to_not_yet(buff_ids, temp_rule, temp_orig);
  }
  xfree(buff);
  return new_rule;
}

int eliminate_instance(rule **r, rule **i, char *type)
{
    if ((*i)->json_history != NULL) {
        xfree((*i)->json_history);
        (*i)->json_history = NULL;
    }
    if ((*i)->description != NULL) {
        xfree((*i)->description);
        (*i)->description = NULL;
    }
    if ((*i)->funct_name != NULL) {
        xfree((*i)->funct_name);
        (*i)->funct_name = NULL;
    }
    if ((*i)->keep_state != NULL) {
        xfree((*i)->keep_state);
        (*i)->keep_state = NULL;
    }
    if ((*i)->if_satisfied != NULL) {
        xfree((*i)->if_satisfied);
        (*i)->if_satisfied = NULL;
    }
    if ((*i)->if_not_satisfied != NULL) {
        xfree((*i)->if_not_satisfied);
        (*i)->if_not_satisfied = NULL;
    }
    if((*i)->t.data!=NULL){
        struct TUPLE_struct *tt=&(*i)->t;
        xfree(tt->data);
        tt->data = NULL;
        while(tt->next!=NULL){
            tt=tt->next;
            if(tt->data!=NULL){
                xfree(tt->data);
                tt->data=NULL;
            }
        }
    }
    if ((*i)->list_of_sons != NULL) {
        rule * temp_rule = (*i)->list_of_sons;
        rule *temp_r = NULL;
        rule *temp_rr = *i;
        while (temp_rule != NULL) {
            temp_r = temp_rule;
            temp_rule = temp_rule->next;
            eliminate_instance(&temp_rr, &temp_r, "son");
        }
    }
    if ((*i)->list_of_tuples != NULL) {
        tuple *temp_tuple = (*i)->list_of_tuples;
        tuple *temp_t = NULL;
        while (temp_tuple != NULL) {
            if (temp_tuple->data != NULL) {
                xfree(temp_tuple->data);
                temp_tuple->data = NULL;
            }
            temp_t = temp_tuple;
            temp_tuple = temp_tuple->next;
            xfree(temp_t);
            temp_t = NULL;
        }
    }
    if (type[0] == 'a') {
      xfree(*i);
      *i = NULL;
    }else if ((*i)->prev == NULL) {
        if (type[0] == 'i') {
            (*r)->list_of_instances = (*i)->next;
            if ((*r)->list_of_instances != NULL)(*r)->list_of_instances->prev = NULL;
        } else if (type[0] == 's'){
            (*r)->list_of_sons = (*i)->next;
            if ((*r)->list_of_sons != NULL) (*r)->list_of_sons->prev = NULL;
        } else {
        }
        xfree(*i);
        *i = NULL;
    } else {
        (*i)->prev->next = (*i)->next;
        if ((*i)->next != NULL) (*i)->next->prev = (*i)->prev;
        xfree(*i);
        *i = NULL;
    }
    return OK;
}

void store_history(const ipacket_t *pkt, short context, rule *curr_root, rule *curr_rule, char *cause, short event_id)
{
    unsigned long L1=0,L2=0,L3=0,L4=0;
    //store data on packet so that they can be printed if rule is satisfied
    void * data1 = NULL;
    void * data2 = NULL;
    long type = 0;
    char * buff =NULL;
    mmt_binary_data_t *db1;
    int data_size, j;
    struct timeval tvp;
    char *json_buff=xcalloc(7000,1);
    char *json_buff1=xcalloc(7000,1);
    char *temp_MAC;
    //mmt_header_line_t *hl;

    tvp.tv_sec=0;
    tvp.tv_usec=0;
    tvp = *(struct timeval *) get_attribute_extracted_data(pkt, PROTO_META, META_UTIME);

    (void)sprintf(json_buff, "\"timestamp\":%lu.%lu", tvp.tv_sec, (long) tvp.tv_usec);

    int having_ip_src = 0, having_ip_dst = 0, having_mac_src = 0, having_mac_dst = 0;
    const char *proto_name, *att_name;

    if (*cause != '\0') {
        (void)sprintf(json_buff1, ",\"description\":\"%s\"", cause);
        (void)strcat(json_buff, json_buff1);
        (void)strcat(json_buff, ",\"attributes\":[");

        int num_attr = 0;
        unsigned long tmp_lu=0;
        //printout all the attributes
        tuple * temp = curr_root->list_of_tuples_to_print;
        while (temp) {
            if(temp->protocol_id<1||temp->field_id<1){
              temp=temp->next;
              continue;
            }
            data1 = get_attribute_extracted_data(pkt, temp->protocol_id, temp->field_id);
            if(data1 == NULL){
              temp=temp->next;
              continue;
            }
            num_attr ++;

            data_size  = get_data_size_by_proto_and_field_ids(temp->protocol_id, temp->field_id);
            proto_name = get_protocol_name_by_id(temp->protocol_id);
            att_name   = get_attribute_name_by_protocol_and_attribute_ids(temp->protocol_id, temp->field_id);

            //protocol IP
            if( temp->protocol_id == 178 ){
            	if( temp->field_id == 12 )
            		having_ip_src = 1;
            	else if( temp->field_id == 13 )
            		having_ip_dst = 1;
            }else if( temp->protocol_id == 99 ){ //Ethernet
            	if( temp->field_id == 3 )
            		having_mac_src = 1;
            	else if( temp->field_id == 2 )
            		having_mac_dst = 1;
            }

            type = temp->data_type_id;
            switch (type) {
                case MMT_DATA_IP6_ADDR:
                    // TODO
                    break;
                case MMT_DATA_PORT:
                    // TODO
                    break;
                case MMT_DATA_PORT_RANGE:
                    // TODO
                    break;
                case MMT_DATA_DATE:
                    // TODO
                    break;
                case MMT_DATA_TIMEARG:
                    // TODO
                    break;
                case MMT_DATA_FLOAT:
                    // TODO
                    break;
                case MMT_DATA_IP_NET:
                    // TODO
                    break;
                case MMT_DATA_MAC_ADDR:
                    temp_MAC = xmalloc(22);
                    convert_mac_bytes_to_string(&temp_MAC, (unsigned char *) data1);
                    (void)sprintf(json_buff1, "{\"%s.%s\":\"%s\"},", proto_name, att_name, temp_MAC);
                    (void)strcat(json_buff, json_buff1);
                    xfree(temp_MAC);
                    break;
                case MMT_DATA_TIMEVAL:
                    // TODO
                    break;
                case MMT_DATA_IP_ADDR:
                    if(proto_name!=NULL && att_name!=NULL && data1!=NULL && *((char*)data1)!=0){
                       L1 = (*(unsigned long*)(data1)&0x000000ff);
                       L2 = (*(unsigned long*)(data1)&0x0000ff00)>>8;
                       L3 = (*(unsigned long*)(data1)&0x00ff0000)>>16;
                       L4 = (*(unsigned long*)(data1)&0xff000000)>>24;
                       (void)sprintf(json_buff1,"{\"%s.%s\":\"%lu.%lu.%lu.%lu\"},", proto_name, att_name, L1, L2, L3, L4);
                    }else
                       (void)sprintf(json_buff1,"{\"x.x\":\"0.0.0.0\"},");
                    (void)strcat(json_buff, json_buff1);
                    break;
                case MMT_U16_DATA:
                    (void)sprintf(json_buff1, "{\"%s.%s\":%u},", proto_name,
                            att_name, *(unsigned short*) (data1));
                    (void)strcat(json_buff, json_buff1);
                    break;
                case MMT_U32_DATA:
                    tmp_lu=*(uint32_t*) data1;
                    (void)sprintf(json_buff1, "{\"%s.%s\":%lu},", proto_name,
                            att_name, tmp_lu);
                    (void)strcat(json_buff, json_buff1);
                    break;
                case MMT_U64_DATA:
                    // TODO
                    break;
                case MMT_U8_DATA:
                case MMT_DATA_CHAR:
                    (void)sprintf(json_buff1, "{\"%s.%s\":\"%u\"},", proto_name,
                            att_name, *(unsigned char*) (data1));
                    (void)strcat(json_buff, json_buff1);
                    break;
                case MMT_HEADER_LINE:
                	//parse_mmt_header_line( &data1, & data_size );
                    buff = xmalloc ((((mmt_header_line_t *)data1)->len) + 1);
                    strncpy(buff, ((mmt_header_line_t *)data1)->ptr, ((mmt_header_line_t *)data1)->len);
                    buff[((mmt_header_line_t *)data1)->len] ='\0';
					(void)sprintf(json_buff1, "{\"%s.%s\":\"%s\"},", proto_name,
							att_name, (char *)buff);
                    xfree(buff);
					(void)strcat(json_buff, json_buff1);
					break;
                case MMT_DATA_PATH:
                case MMT_STRING_LONG_DATA:
                case MMT_STRING_DATA:
                    (void)sprintf(json_buff1, "{\"%s.%s\":\"%s\"},", proto_name, att_name, (char*) (data1 + sizeof (int)));
                    (void)strcat(json_buff, json_buff1);
                    break;
                case MMT_BINARY_DATA:
                case MMT_BINARY_VAR_DATA:
                    // TODO
                    db1 = (mmt_binary_data_t *) (data1);
                    data_size = db1->len;
                    data2 = db1->data;
                    if (data_size == 4) {
                        L1 = (*(unsigned long*)(data2)&0x000000ff);
                        L2 = (*(unsigned long*)(data2)&0x0000ff00)>>8;
                        L3 = (*(unsigned long*)(data2)&0x00ff0000)>>16;
                        L4 = (*(unsigned long*)(data2)&0xff000000)>>24;
                        (void)sprintf(json_buff1, "{\"%s.%s\":\"%lu.%lu.%lu.%lu\"},", proto_name, att_name, L1, L2, L3, L4);
                        (void)strcat(json_buff, json_buff1);
                    } else if (data_size == 6) {
                        int close_tag=NO;
                        for (j = 0; j < data_size; j++) {
                            if (j == 0) {
                                (void)sprintf(json_buff1, "{\"%s.%s\":%2.2X", proto_name,
                                        att_name, *(unsigned char*) (data2 + j));
                                close_tag=YES;
                            } else {
                                (void)sprintf(json_buff1, ":%2.2X", *(unsigned char*) (data2 + j));
                            }
                            (void)strcat(json_buff, json_buff1);
                        }
                        if(close_tag==YES)
                          (void)strcat(json_buff, "},");
                    } else {
                        int close_tag=NO;
                        for (j = 0; j < data_size; j++) {
                            if (j == 0) {
                                (void)sprintf(json_buff1, "attribute:{\"%s.%s\":%02X", proto_name,
                                        att_name, *(unsigned char*) (data2 + j));
                                close_tag=YES;
                            } else {
                                (void)sprintf(json_buff1, ":%02X", *(unsigned char*) (data2 + j));
                            }
                            (void)strcat(json_buff, json_buff1);
                        }
                        //end attribute
                        if(close_tag==YES)
                          (void)strcat(json_buff, "},");
                    }
                    break;
                case MMT_DATA_LAYERID:
                    // TODO
                    break;
                case MMT_DATA_POINT:
                    // TODO
                    break;
                case MMT_DATA_POINTER:
                    // TODO
                    break;
                case MMT_DATA_FILTER_STATE:
                    // TODO
                    break;
                case MMT_UNDEFINED_TYPE:
                case MMT_DATA_BUFFER:
                case MMT_DATA_STRING_INDEX:
                case MMT_DATA_PARENT:
                case MMT_STATS:
                case MMT_GENERIC_HEADER_LINE:
                case MMT_STRING_DATA_POINTER:
                    // TODO verify if OK
                    break;

                default:
                    (void)fprintf(stderr, "Error 15.2: Type not implemented yet. Data type unknown.\n");
                    exit(-1);
            }//end of switch
            temp = temp->next;
        }
        //ensure IP or MAC of src and dst are included in attribute
        if( having_ip_src == 0){
        	data1 = get_attribute_extracted_data(pkt, 178, 12);
            if(data1!= NULL && *((char*)data1)!=0){
                L1 = (*(unsigned long*)(data1)&0x000000ff);
                L2 = (*(unsigned long*)(data1)&0x0000ff00)>>8;
                L3 = (*(unsigned long*)(data1)&0x00ff0000)>>16;
                L4 = (*(unsigned long*)(data1)&0xff000000)>>24;
        		(void)sprintf(json_buff1,"{\"ip.src\":\"%lu.%lu.%lu.%lu\"},", L1, L2, L3, L4);
        	    (void)strcat(json_buff, json_buff1);
       	   }else if( having_mac_src == 0 ){
        		data1 = get_attribute_extracted_data(pkt, 99, 3);
        		temp_MAC = xmalloc(22);
				convert_mac_bytes_to_string(&temp_MAC, (unsigned char *) data1);
        		(void)sprintf(json_buff1,"{\"eth.src\":\"%s\"},", temp_MAC );
        		(void)strcat(json_buff, json_buff1);
        		xfree( temp_MAC );
        	}
        	num_attr ++;
        }

        if( having_ip_dst == 0){
            data1 = get_attribute_extracted_data(pkt, 178, 13);
            if(data1!=NULL && *((char*)data1)!=0){
                L1 = (*(unsigned long*)(data1)&0x000000ff);
                L2 = (*(unsigned long*)(data1)&0x0000ff00)>>8;
                L3 = (*(unsigned long*)(data1)&0x00ff0000)>>16;
                L4 = (*(unsigned long*)(data1)&0xff000000)>>24;
				(void)sprintf(json_buff1,"{\"ip.dst\":\"%lu.%lu.%lu.%lu\"},", L1, L2, L3, L4);
			    (void)strcat(json_buff, json_buff1);
		    }else if( having_mac_dst == 0 ){
				data1 = get_attribute_extracted_data(pkt, 99, 2);
				temp_MAC = xmalloc(22);
				convert_mac_bytes_to_string(&temp_MAC, (unsigned char *) data1);
				(void)sprintf(json_buff1,"{\"eth.dst\":\"%s\"},", temp_MAC);
				(void)strcat(json_buff, json_buff1);
				xfree( temp_MAC );
			}
			num_attr ++;
		}

        if( num_attr > 0 ){
        	//remove the last comma in "event: [{...},...,{..},"
        	json_buff[ strlen(json_buff) - 1 ] = '\0';
        }
        (void)strcat(json_buff, "]");
        sprintf( json_buff1, "\"event_%d\":{%s},", event_id, json_buff );
        strcpy(json_buff, json_buff1);

        short c = 0;
        if (context == BEFORE || context == AFTER || context == SAME) c = 1;
        int json_buff_size = strlen(json_buff) + 1 + c;
        if (curr_rule->json_history != NULL) {
            json_buff_size = json_buff_size + strlen(curr_rule->json_history);
            curr_rule->json_history = realloc(curr_rule->json_history, json_buff_size);
        } else {
            curr_rule->json_history = xcalloc(1, json_buff_size);
        }

        (void)strcat(curr_rule->json_history, json_buff);
    }
    xfree(json_buff);
    xfree(json_buff1);
}

void store_tuples( const ipacket_t *pkt, short context, rule *curr_root, rule *curr_rule, short event_id, char *cause )
{
    tuple * temp_tuple = NULL;
    if(curr_rule != NULL) temp_tuple = curr_rule->list_of_tuples;
    void *data = NULL;
    while (temp_tuple != NULL) {
        if (event_id != temp_tuple->event_id) {
            temp_tuple = temp_tuple->next;
            continue;
        }
        data = get_attribute_extracted_data( pkt, temp_tuple->protocol_id, temp_tuple->field_id );
        if (data == NULL) {
            (void)fprintf(stderr, "Error 16: in stored reference tuples. Data is not available. packet_id=%ju, protocol_id=%ld, field_id=%ld\n",
            		pkt->packet_id,
                    temp_tuple->protocol_id, temp_tuple->field_id);
            //exit(-1);
        } else {
            temp_tuple->data_size = get_data_size_by_proto_and_field_ids(temp_tuple->protocol_id, temp_tuple->field_id);
            temp_tuple->valid = FOUND;
            temp_tuple->data = (void *) xmalloc(temp_tuple->data_size);
            memcpy(temp_tuple->data, data, temp_tuple->data_size);
        }
        temp_tuple = temp_tuple->next;
    }
    store_history(pkt, context, curr_root, curr_rule, cause, event_id);
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
            for (i = 0; i < size; i = i + sizeof (unsigned short)) {
                if (s1 == ((unsigned short *) (v2.data))[i])
                    return VALID;
            }
            break;
        case MMT_U32_DATA:
            l1 = *((unsigned long *) (v1.data));
            j = 0;
            for (i = 0; i < size; i = i + sizeof (unsigned long)) {
                if (l1 == ((unsigned long *) (v2.data))[j++])
                    return VALID;
            }
            break;
        case MMT_U64_DATA:
            ll1 = *((unsigned long long *) (v1.data));
            for (i = 0; i < size; i = i + sizeof (unsigned long long)) {
                if (ll1 == ((unsigned long long*) (v2.data))[i])
                    return VALID;
            }
            break;
        case MMT_DATA_FLOAT:
            f1 = *((float *) (v1.data));
            for (i = 0; i < size; i = i + sizeof (float)) {
                if (f1 == ((float *) (v2.data))[i])
                    return VALID;
            }
            break;
        case MMT_DATA_LAYERID:
        case MMT_DATA_PORT:
        case MMT_DATA_POINT:
        case MMT_DATA_PORT_RANGE:
        case MMT_DATA_POINTER:
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
        //case MMT_DATA_POINTER:
        case MMT_DATA_BUFFER:
        case MMT_DATA_STRING_INDEX:
        case MMT_DATA_PARENT:
        case MMT_STATS:
        case MMT_GENERIC_HEADER_LINE:
        case MMT_HEADER_LINE:
        case MMT_STRING_DATA_POINTER:
            return NOT_VALID; //TODO verify if OK
            break;
        default:
            (void)fprintf(stderr, "Error 36b: Comparing values is not possible. Type not implemented yet.\n");
            exit(-1);
    }//end of switch
    return NOT_VALID;
}

int comp2(compare_value v1, compare_value v2, short ope)
{
    int i = 0, j = 0, ret = 0;
    unsigned short s1 = 0, s2 = 0;
    unsigned long l1 = 0, l2 = 0;
    unsigned long long ll1 = 0, ll2 = 0;
    double f1 = 0, f2 = 0;
    unsigned char c1 = 0, c2 = 0;
    mmt_date_t *d1, *d2;
    struct timeval *t1, *t2;
    int size = 0;
    char * data1 = NULL;
    char * data2 = NULL;
    //mmt_header_line_t *hl;

    //Special case: ope==XIN with v1 is some type and v2 is MMT_BINARY_VAR_DATA
    if (ope == XIN && v2.type == MMT_BINARY_VAR_DATA) {
        ret = compare_in_table(v1, v2, ope);
        return ret;
    }
    if((v1.type == MMT_U8_DATA || v1.type == MMT_U16_DATA || v1.type == MMT_U32_DATA || v1.type == MMT_U64_DATA) &&
      (v2.type == MMT_U8_DATA || v2.type == MMT_U16_DATA || v2.type == MMT_U32_DATA || v2.type == MMT_U64_DATA)){
      if     (v1.type == MMT_U64_DATA) ll1 = *((uint64_t *) (v1.data));
      else if(v1.type == MMT_U32_DATA) ll1 = *((uint32_t *)      (v1.data));
      else if(v1.type == MMT_U16_DATA) ll1 = *((uint16_t *)     (v1.data));
      else if(v1.type == MMT_U8_DATA)  ll1 = *((uint8_t *)      (v1.data));
      if     (v2.type == MMT_U64_DATA) ll2 = *((uint64_t *) (v2.data));
      else if(v2.type == MMT_U32_DATA) ll2 = *((uint32_t *)      (v2.data));
      else if(v2.type == MMT_U16_DATA) ll2 = *((uint16_t *)     (v2.data));
      else if(v2.type == MMT_U8_DATA)  ll2 = *((uint8_t *)      (v2.data));
      if ((ope == NEQ && ll1 != ll2) || (ope == EQ && ll1 == ll2) || (ope == LT && ll1 < ll2) || (ope == LTE && ll1 <= ll2) || (ope == GT && ll1 > ll2) ||
                    (ope == GTE && ll1 >= ll2)) return VALID;
      else return NOT_VALID;
    }
    //Line not to be used if using XE (included in): if (v1.type != v2.type || v1.size != v2.size) return NOT_VALID;
    size = v1.size;
    data1 = (char*) v1.data;
    data2 = (char*) v2.data;

    switch (v1.type) {
        case MMT_DATA_TIMEVAL:
            t1 = (struct timeval *) (v1.data);
            t2 = (struct timeval *) (v2.data);
            if ((((ope == EQ) || (ope == LTE) || (ope == GTE)) && t1->tv_sec == t2->tv_sec && t1->tv_usec == t2->tv_usec)) return VALID;
            else if ((ope == NEQ) && (t1->tv_sec != t2->tv_sec || t1->tv_usec != t2->tv_usec)) return VALID;
            else if (((ope == LT) || (ope == LTE)) && ((t1->tv_sec < t2->tv_sec) || ((t1->tv_sec == t2->tv_sec) && (t1->tv_usec < t2->tv_usec)))) return VALID;
            else if (((ope == GT) || (ope == GTE)) && ((t1->tv_sec > t2->tv_sec) || ((t1->tv_sec == t2->tv_sec) && (t1->tv_usec > t2->tv_usec)))) return VALID;
            break;
        case MMT_DATA_DATE:
            d1 = (mmt_date_t *) (v1.data);
            d2 = (mmt_date_t *) (v2.data);
            if ((((ope == EQ) || (ope == LTE) || (ope == GTE)) && d1->sec == d2->sec && d1->min == d2->min && d1->hour == d2->hour && d1->mday == d2->mday &&
                    d1->month == d2->month && d1->year == d2->year && d1->wday == d2->wday)) return VALID;
            else if ((ope == NEQ) && (d1->sec != d2->sec || d1->min != d2->min || d1->hour != d2->hour || d1->mday != d2->mday ||
                    d1->month != d2->month || d1->year != d2->year || d1->wday != d2->wday)) return VALID;
            else if (((ope == LT) || (ope == LTE)) && ((d1->year < d2->year) || ((d1->year == d2->year) && (d1->month < d2->month)) ||
                    ((d1->year == d2->year) && (d1->month == d2->month) && (d1->mday < d2->mday)) ||
                    ((d1->year == d2->year) && (d1->month == d2->month) && (d1->mday == d2->mday) && (d1->hour < d2->hour)) ||
                    ((d1->year == d2->year) && (d1->month == d2->month) && (d1->mday == d2->mday) && (d1->hour == d2->hour) && (d1->min < d2->min)) ||
                    ((d1->year == d2->year) && (d1->month == d2->month) && (d1->mday == d2->mday) && (d1->hour == d2->hour) && (d1->min == d2->min) &&
                    (d1->sec < d2->sec))))
                return VALID;
            else if (((ope == GT) || (ope == GTE)) && ((d1->year < d2->year) || ((d1->year == d2->year) && (d1->month > d2->month)) ||
                    ((d1->year == d2->year) && (d1->month == d2->month) && (d1->mday > d2->mday)) ||
                    ((d1->year == d2->year) && (d1->month == d2->month) && (d1->mday == d2->mday) && (d1->hour > d2->hour)) ||
                    ((d1->year == d2->year) && (d1->month == d2->month) && (d1->mday == d2->mday) && (d1->hour == d2->hour) && (d1->min > d2->min)) ||
                    ((d1->year == d2->year) && (d1->month == d2->month) && (d1->mday == d2->mday) && (d1->hour == d2->hour) && (d1->min == d2->min) &&
                    (d1->sec > d2->sec))))
                return VALID;
            break;
        case MMT_DATA_FLOAT:
            f1 = *((float *) (v1.data));
            f2 = *((float *) (v2.data));
            if ((ope == NEQ && f1 != f2) || (ope == EQ && f1 == f2) || (ope == LT && f1 < f2) || (ope == LTE && f1 <= f2) || (ope == GT && f1 > f2) || (ope == GTE && f1 >= f2))
                return VALID;
            break;
        case MMT_U16_DATA:
        case MMT_DATA_LAYERID:
            s1 = *((unsigned short *) (v1.data));
            s2 = *((unsigned short *) (v2.data));
            if ((ope == NEQ && s1 != s2) || (ope == EQ && s1 == s2) || (ope == LT && s1 < s2) || (ope == LTE && s1 <= s2) || (ope == GT && s1 > s2) || (ope == GTE && s1 >= s2))
                return VALID;
            break;
        case MMT_U32_DATA:
        case MMT_DATA_PORT:
            l1 = (*((unsigned long *) (v1.data)));
            l2 = (*((unsigned long *) (v2.data)));
            if ((ope == NEQ && l1 != l2) || (ope == EQ && l1 == l2) || (ope == LT && l1 < l2) || (ope == LTE && l1 <= l2) || (ope == GT && l1 > l2) || (ope == GTE && l1 >= l2))
                return VALID;
            break;
        case MMT_U64_DATA:
        case MMT_DATA_POINT:
        case MMT_DATA_PORT_RANGE:
            ll1 = *((unsigned long long *) (v1.data));
            ll2 = *((unsigned long long *) (v2.data));
            if ((ope == NEQ && ll1 != ll2) || (ope == EQ && ll1 == ll2) || (ope == LT && ll1 < ll2) || (ope == LTE && ll1 <= ll2) || (ope == GT && ll1 > ll2) ||
                    (ope == GTE && ll1 >= ll2)) return VALID;
            break;
        case MMT_U8_DATA:
            c1 = *((unsigned char *) (v1.data));
            c2 = *((unsigned char *) (v2.data));
            if ((ope == NEQ && c1 != c2) || (ope == EQ && c1 == c2) || (ope == LT && c1 < c2) || (ope == LTE && c1 <= c2) || (ope == GT && c1 > c2) || (ope == GTE && c1 >= c2))
                return VALID;
            break;
        case MMT_DATA_CHAR:
            c1 = ((char *) (v1.data))[0];
            c2 = ((char *) (v2.data))[0];
            if ((ope == NEQ && c1 != c2) || (ope == EQ && c1 == c2) || (ope == LT && c1 < c2) || (ope == LTE && c1 <= c2) || (ope == GT && c1 > c2) || (ope == GTE && c1 >= c2))
                return VALID;
            break;
        case MMT_DATA_PATH:
            //TODO: need to complete for other cases
            if (ope == XC || ope == XCE) {
              j = atoi(data2);
              if(size>0 && size < 20){
                for(i=1;i<size;i++){
                  if(j == *(int*) (data1 + i*sizeof (int))) return VALID;
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
                for (i = 0; i < size; i = i + sizeof (char)) {
                    if (ope == EQ) {
                        if (((char *) (data1))[i] != ((char *) (data2))[i]) {
                            return NOT_VALID;
                        }
                        if (i == size - 1) {
                            return VALID;
                        }
                    } else if (ope == NEQ) {
                        if (((char *) (data1))[i] != ((char *) (data2))[i]) {
                            return VALID;
                        }
                        if (i == size - 1) {
                            return NOT_VALID;
                        }
                    } else if ((ope == LTE) || (ope == LT)) {
                        if (((char *) (data1))[i] == ((char *) (data2))[i]) {
                            if (i == size - 1) {
                                if (ope == LTE) return VALID;
                                return NOT_VALID;
                            }
                            continue;
                        } else if (((char *) (data1))[i] > ((char *) (data2))[i]) {
                            return NOT_VALID;
                        } else if (((char *) (data1))[i] < ((char *) (data2))[i]) {
                            return VALID;
                        }
                    } else if ((ope == GTE) || (ope == GT)) {
                        if (((char *) (data1))[i] == ((char *) (data2))[i]) {
                            if (i == size - 1) {
                                if (ope == GTE) return VALID;
                                return NOT_VALID;
                            }
                            continue;
                        } else if (((char *) (data1))[i] < ((char *) (data2))[i]) {
                            return NOT_VALID;
                        } else if (((char *) (data1))[i] > ((char *) (data2))[i]) {
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
            return NOT_VALID; //TODO verify if OK
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
      else if(v1.type == MMT_U8_DATA)  ull1 = *((uint8_t *)      (v1.data));
      if     (v2.type == MMT_U64_DATA) ull2 = *((uint64_t *) (v2.data));
      else if(v2.type == MMT_U32_DATA) ull2 = *((uint32_t *)      (v2.data));
      else if(v2.type == MMT_U16_DATA) ull2 = *((uint16_t *)     (v2.data));
      else if(v2.type == MMT_U8_DATA)  ull2 = *((uint8_t *)      (v2.data));

      ull0 = xmalloc(sizeof (unsigned long long));
      if (operator == ADD)
         *ull0 = ull1 + ull2;
      else if (operator == SUB)
         *ull0 = ull1 - ull2;
      else if (operator == DIV)
          *ull0 = ull1 / ull2;
      else if (operator == MUL)
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
            // TODO
            (void)fprintf(stderr, "Error 36a1: Computation is not possible. Type not implemented yet or the operation on this type has no sense.\n");
            exit(-1);
            break;
        case MMT_DATA_DATE:
            // TODO
            (void)fprintf(stderr, "Error 36a2: Computation is not possible. Type not implemented yet or the operation on this type has no sense.\n");
            exit(-1);
            break;
        case MMT_DATA_FLOAT:
            // TODO
            (void)fprintf(stderr, "Error 36a3: Computation is not possible. Type not implemented yet or the operation on this type has no sense.\n");
            exit(-1);
            break;
        case MMT_U16_DATA:
        case MMT_DATA_LAYERID:
            us1 = *((unsigned short *) (data1));
            us2 = *((unsigned short *) (data2));
            us0 = xmalloc(sizeof (unsigned short));
            if (operator == ADD)
                *us0 = us1 + us2;
            else if (operator == SUB)
                *us0 = us1 - us2;
            else if (operator == DIV)
                *us0 = us1 / us2;
            else if (operator == MUL)
                *us0 = us1 * us2;
            return (void *)us0;
            break;
        case MMT_U32_DATA:
        case MMT_DATA_PORT:
            ul1 = *((unsigned long *) (data1));
            ul2 = *((unsigned long *) (data2));
            ul0 = xmalloc(sizeof (unsigned long));
            if (operator == ADD)
                *ul0 = ul1 + ul2;
            else if (operator == SUB)
                *ul0 = ul1 - ul2;
            else if (operator == DIV)
                *ul0 = ul1 / ul2;
            else if (operator == MUL)
                *ul0 = ul1 * ul2;
            return (void *)ul0;
            break;
        case MMT_U64_DATA:
        case MMT_DATA_POINT:
        case MMT_DATA_PORT_RANGE: // TODO: to check
            ull1 = *((unsigned long long *) (data1));
            ull2 = *((unsigned long long *) (data2));
            ull0 = xmalloc(sizeof (unsigned long long));
            if (operator == ADD)
                *ull0 = ull1 + ull2;
            else if (operator == SUB)
                *ull0 = ull1 - ull2;
            else if (operator == DIV)
                *ull0 = ull1 / ull2;
            else if (operator == MUL)
                *ull0 = ull1 * ull2;
            return (void *)ull0;
            break;
        case MMT_U8_DATA:
            uc1 = *((unsigned char *) (data1));
            uc2 = *((unsigned char *) (data2));
            uc0 = xmalloc(sizeof (unsigned char));
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
                } else
                    return NULL;
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
            return NULL; //TODO verify if OK
            break;
        default:
            (void)fprintf(stderr, "Error 36a: Computation is not possible. Type not implemented yet or the operation on this type has no sense.\n");
            exit(-1);
    }//end of switch
    return NULL;
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
            v1.size = *(int*) (data);
            data = r1->t.data + sizeof (int);
        }
        else if (v1.type == MMT_HEADER_LINE) {
            //parse_mmt_header_line( &data, &v1.size );
            v1.size = ((mmt_header_line_t *)data)->len;
            data = (void*)(((mmt_header_line_t *)data)->ptr);
        }

        v1.data = (void *) xcalloc(1, v1.size);
        memcpy(v1.data, data, v1.size);
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
                        v1.size = *(int*) (data);
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
            v2.size = *(int*) (data);
            data = r2->t.data + sizeof (int);
        }
        else if (v2.type == MMT_HEADER_LINE){
            //parse_mmt_header_line( &(r2->t.data), &v2.size );
                        v2.size = ((mmt_header_line_t *)data)->len;
                        data = (void*)(((mmt_header_line_t *)data)->ptr);
        }

        v2.data = (void *) xcalloc(1, v2.size);
        memcpy(v2.data, data, v2.size);
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
                                            v2.size = *(int*) (data);
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
        tmp_r = r1;
        tmp_v = &v1;
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
                tmp_v->size = *(int*) (data);
                data = data + sizeof (int);
            }
            else if (tmp_v->type == MMT_HEADER_LINE){
                //parse_mmt_header_line( &data, &tmp_v->size );
                        tmp_v->size = ((mmt_header_line_t *)data)->len;
                        data = (void*)(((mmt_header_line_t *)data)->ptr);
            }
            tmp_v->data = xcalloc(1, tmp_v->size);
            memcpy(tmp_v->data, data, tmp_v->size);
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
                tmp_v->size = *(int*) (data);
                data = data + sizeof (int);
            }
            else if (tmp_v->type == MMT_HEADER_LINE){
            	//parse_mmt_header_line( &data, &tmp_v->size );
                        tmp_v->size = ((mmt_header_line_t *)data)->len;
                        data = (void*)(((mmt_header_line_t *)data)->ptr);
            }
            tmp_v->data = (void *) xcalloc(1, tmp_v->size);
            memcpy(tmp_v->data, data, tmp_v->size);
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
        ret = comp2(v1, v2, operator);
        //printf(" = %d\n\n", ret);
    } else if (action == COMPUTE) {
        *result_value = compute(v1, v2, operator);
    }
    xfree(v1.data);
    xfree(v2.data);
    // returns VALID or NOT_VALID
    return ret;
}

void get_verdict( int t, int po, int state, char **str_verdict, char **str_type ){
	char verdict[100];
	char type[100];

	switch (t) {
		case TEST:
		case SECURITY_RULE:
			if (po == SATISFIED && state == SATISFIED) {
				(void)strcpy(verdict, "respected");
			} else if (po == NOT_SATISFIED && state == SATISFIED) {
				return;
			} else if (po == SATISFIED && state == NOT_SATISFIED) {
				return;
			} else if (po == NOT_SATISFIED && state == NOT_SATISFIED) {
				(void)strcpy(verdict, "not_respected");
			} else if (po == BOTH && state == SATISFIED) {
				(void)strcpy(verdict, "respected");
			} else if (po == BOTH && state == NOT_SATISFIED) {
				(void)strcpy(verdict, "not_respected");
			} else if (po == BOTH && state == NEITHER) {
				(void)strcpy(verdict, "unknown"); // TODO:????
			}
			break;
		case ATTACK:
		case EVASION:
			if (po == SATISFIED && state == SATISFIED) {
				(void)strcpy(verdict, "detected");
			} else if (po == NOT_SATISFIED && state == SATISFIED) {
				return;
			} else if (po == SATISFIED && state == NOT_SATISFIED) {
				return;
			} else if (po == NOT_SATISFIED && state == NOT_SATISFIED) {
				(void)strcpy(verdict, "not_detected");
			} else if (po == BOTH && state == SATISFIED) {
				(void)strcpy(verdict, "detected");
			} else if (po == BOTH && state == NOT_SATISFIED) {
				(void)strcpy(verdict, "not_detected");
			} else if (po == BOTH && state == NEITHER) {
				(void)strcpy(verdict, "unknown"); // TODO for inconclusive at begining or at end of input
			}
			break;
		default:
			(void)fprintf(stderr, "Error 22: Property type should be a security rule or an attack.\n");
			exit(-1);
	}//end of switch

	switch (t) {
			case TEST:
				(void)strcpy(type, "test");
				break;
			case SECURITY_RULE:
				(void)strcpy(type, "security");
				break;
		    case EVASION:
				(void)strcpy(type, "evasion");
				break;
			case ATTACK:
				(void)strcpy(type, "attack");
				break;
	}
	*str_verdict = xmalloc (strlen(verdict) + 1); 
	strcpy( *str_verdict, verdict );

	*str_type = xmalloc(strlen(type) +1);
	strcpy( *str_type, type );
}


void detected_corrupted_message(short print_option, rule *r, char *cause, short state, struct timeval packet_time_stamp)
{
    rule *temp = r;
    char *history;

    if(op->callback_funct != NULL){
    	char *verdict = NULL, *type = NULL;
    	get_verdict( ATTACK, print_option, state, &verdict, &type );

        //char * xml_string = xml_message(ATTACK, print_option, state, 0, cause);
      	if ( verdict == NULL) return;

      	if (temp->json_history == NULL)
    	  temp = temp->root;
      	if (temp->json_history != NULL)
      		history = temp->json_history;

      	corr_mess++;

      	//remove the last comma
		if( history[ strlen( history ) - 1 ] == ',')
			history[ strlen( history ) - 1 ] = '\0';

      	char *str = xmalloc( strlen( history ) + 3 );
      	sprintf( str, "{%s}", history );

      	((op->callback_funct))( 0, verdict, type, cause, str, packet_time_stamp,(void *) op->user_args);

        xfree( str );
      	xfree( verdict );
      	xfree( type );
    }
    return;
}


static int temptemp = 0;

int verify_segment( const ipacket_t *pkt, short skip_refs, tuple *list_of_tuples, rule *c, rule *curr_root )
{
    short result = 0;
    void *result_value = NULL;
    rule *temp1, *temp2;
    switch (c->value) {
        case XOR:
            //Need to analyse the sons
            temp1 = c->list_of_sons;
            while (temp1 != NULL) {
                result = verify_segment( pkt, skip_refs, list_of_tuples, temp1, curr_root );
                if (result == VALID) {
                    c->valid = VALID;
                    return VALID;
                }
                temp1 = temp1->next;
            }
            c->valid = NOT_VALID;
            return NOT_VALID;
            break;
        case XAND:
            //Need to analyse the sons
            temp1 = c->list_of_sons;
            while (temp1 != NULL) {
                result = verify_segment( pkt, skip_refs, list_of_tuples, temp1, curr_root );
                if (result == VALID) {
                    temp1 = temp1->next;
                    continue;
                } else {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
            }
            c->valid = VALID;
            return VALID;
            break;
        case EQ:
        case NEQ:
        case GT:
        case GTE:
        case LT:
        case LTE:
        case XC:
        case XCE:
        case XD:
        case XDE:
        case XE:
        case XIN:
            temp1 = c->list_of_sons;
            temp2 = c->list_of_sons->next;
            if (temp1->type != LEAF && temp1->t.valid == NOT_YET) {
                result = verify_segment( pkt, skip_refs, list_of_tuples, temp1, curr_root );
                if (result != VALID) {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
            }
            if (temp2->type != LEAF && temp2->t.valid == NOT_YET) {
                result = verify_segment( pkt, skip_refs, list_of_tuples, temp2, curr_root );
                if (result != VALID) {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
            }
            //Need to compare all the sons even if more than two (i.e. A > B > C)
            while (temp2) {
                uint64_t tmp=0;
                void *not_used = &tmp;
                result = get_data_from_pcap( pkt, skip_refs, COMPARE, &not_used, list_of_tuples, c->value, temp1, temp2 );
                if (result != VALID) {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
                temp1 = temp2;
                temp2 = temp2->next;
            }
            c->valid = VALID;
            return VALID;
            break;
        case ADD:
        case SUB:
        case MUL:
        case DIV:
            temp1 = c->list_of_sons;
            temp2 = c->list_of_sons->next;
            if (temp1->type != LEAF && temp1->t.valid == NOT_YET) {
                result = verify_segment( pkt, skip_refs, list_of_tuples, temp1, curr_root );
                if (result != VALID) {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
            }
            if (temp2->type != LEAF && temp2->t.valid == NOT_YET) {
                result = verify_segment( pkt, skip_refs, list_of_tuples, temp2, curr_root );
                if (result != VALID) {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
            }
            temptemp++;
            result = get_data_from_pcap( pkt, skip_refs, COMPUTE, &result_value, list_of_tuples, c->value, temp1, temp2 );
            if (result_value == NULL) {
                //changed so that considered as a violated property (corrupted message):
                c->valid = NOT_VALID;
                store_history(pkt, SAME, curr_root, c, NULL, 0);
                detected_corrupted_message(op->Print, c, "Corrupted message: due to an attack or error.", SATISFIED,pkt->p_hdr->ts);
                return NOT_VALID;
            }
            //Need to use result_value
            c->t.protocol_id = temp1->t.protocol_id;
            c->t.field_id = temp1->t.field_id;
            c->t.data_type_id = MMT_U64_DATA;//temp1->t.data_type_id;
            c->t.data_size = sizeof(uint64_t);//temp1->t.data_size;
            c->t.valid = VALID;
            c->t.data = xmalloc(c->t.data_size);
            memcpy(c->t.data, (void *)result_value, c->t.data_size);
            xfree(result_value);
            c->valid = VALID;
            return VALID;
            break;
        case XVAR:
        case XCON:
        case XFUNCT:
        case NOP:
            return VALID;
            break;
        default:
            (void)fprintf(stderr, "Error 20a: Should be an event_operator or a condition.\n");
    }//end of switch
    (void)fprintf(stderr, "Error 21: Problem verifying condition.\n");

    return NOT_VALID;
}

int print_message(int type, int po, int state, int num, char *desc)
{
    switch (type) {
        case TEST:
        case SECURITY_RULE:
            if (po == SATISFIED && state == SATISFIED) {
                (void)fprintf(stderr, "RESPECTED the security rule number %d: \"%s\"\n", num, desc);
            } else if (po == NOT_SATISFIED && state == SATISFIED) {
                return NOT_OK;
            } else if (po == SATISFIED && state == NOT_SATISFIED) {
                return NOT_OK;
            } else if (po == NOT_SATISFIED && state == NOT_SATISFIED) {
                (void)fprintf(stderr, "VIOLATED the security rule number %d: \"%s\"\n", num, desc);
            } else if (po == BOTH && state == SATISFIED) {
                (void)fprintf(stderr, "RESPECTED the security rule number %d: \"%s\"\n", num, desc);
            } else if (po == BOTH && state == NOT_SATISFIED) {
                (void)fprintf(stderr, "VIOLATED the security rule number %d: \"%s\"\n", num, desc);
            } else if (po == BOTH && state == NEITHER) {
                (void)fprintf(stderr, "The security rule number %d: \"%s\" was:\n", num, desc);
            }
            break;
        case ATTACK:
            if (po == SATISFIED && state == SATISFIED) {
                (void)fprintf(stderr, "DETECTED the possible attack number %d: \"%s\"\n", num, desc);
            } else if (po == NOT_SATISFIED && state == SATISFIED) {
                return NOT_OK;
            } else if (po == SATISFIED && state == NOT_SATISFIED) {
                return NOT_OK;
            } else if (po == NOT_SATISFIED && state == NOT_SATISFIED) {
                (void)fprintf(stderr, "OCCURRENCE FREE from attack number %d: \"%s\"\n", num, desc);
            } else if (po == BOTH && state == SATISFIED) {
                (void)fprintf(stderr, "DETECTED the possible attack number %d: \"%s\"\n", num, desc);
            } else if (po == BOTH && state == NOT_SATISFIED) {
                (void)fprintf(stderr, "OCCURRENCE FREE from attack number %d: \"%s\"\n", num, desc);
            } else if (po == BOTH && state == NEITHER) {
                (void)fprintf(stderr, "The analysis of attack number %d: \"%s\" resulted in:\n", num, desc);
            }
            break;
        case EVASION:
            if (po == SATISFIED && state == SATISFIED) {
                (void)fprintf(stderr, "DETECTED the possible evasion number %d: \"%s\"\n", num, desc);
            } else if (po == NOT_SATISFIED && state == SATISFIED) {
                return NOT_OK;
            } else if (po == SATISFIED && state == NOT_SATISFIED) {
                return NOT_OK;
            } else if (po == NOT_SATISFIED && state == NOT_SATISFIED) {
                (void)fprintf(stderr, "OCCURRENCE FREE from evasion number %d: \"%s\"\n", num, desc);
            } else if (po == BOTH && state == SATISFIED) {
                (void)fprintf(stderr, "DETECTED the possible evasion number %d: \"%s\"\n", num, desc);
            } else if (po == BOTH && state == NOT_SATISFIED) {
                (void)fprintf(stderr, "OCCURRENCE FREE from evasion number %d: \"%s\"\n", num, desc);
            } else if (po == BOTH && state == NEITHER) {
                (void)fprintf(stderr, "The analysis of evasion number %d: \"%s\" resulted in:\n", num, desc);
            }
            break;
        default:
            (void)fprintf(stderr, "Error 22: Property type should be a security rule or an attack.\n");
            exit(-1);
    }//end of switch
    return OK;
}

void print_nothing(short print_option, rule *curr_root, rule *r, char *cause, short state) {
    //(void)fprintf(stderr, "nothing\n");
}

static long counter_detection = 0;

char *generate_command( const ipacket_t *pkt, rule *r, char * input )
{
    //input: "name_of_script parameters" where parameters can be constants or variables (e.g., script(1,META.PROTO.3) )
    //output: idem but replacing variables with the value (e.g., script 1 801)
    char * output = NULL;
    char * tempi = NULL;
    char * tempo = NULL;
    int ibuff = 0;
    tuple *list_of_tuples = r->list_of_tuples;

    output = xmalloc(strlen(input) + 1000);

    if (output == NULL) {
        (void)fprintf(stderr, "Error 22x: Out of memory\n");
        return NULL;
    }

    //Copy input to output, replacing the variables with the values recovered below
    // use malloc to allocate output
    // if a value is not available then print an error and return NULL!

    tempi = input;
    tempo = output;
    *tempo='.';
    tempo++;
    *tempo='/';
    tempo++;
    while (*tempi == ' ') tempi++;
    while (*tempi != '(' && *tempi != '\0') { // && *tempi != ' ') {
        *tempo = *tempi;
        tempo++;
        tempi++;
    }
    if (*tempi == '\0') {
        (void)fprintf(stderr, "Error 22x: missing '(' in: %s\n", input);
        return NULL;
    }
    while (*tempi == ' ') tempi++;
    if (*tempi != '(') {
        (void)fprintf(stderr, "Error 22x: missing '(' in: %s\n", input);
        return NULL;
    }
    tempi++; //skip '('
    *tempo = ' ';
    tempo++;
    //we have: "script_name "
    counter_detection++;
    ibuff = snprintf(tempo, 20, "%ld", counter_detection);
    tempo = tempo + ibuff;
    *tempo = ' ';
    tempo++;

    while (*tempi == ' ') tempi++;

    while (isalpha(*tempi) || *tempi == '_' || isdigit(*tempi) || *tempi == ')') {
        if (isdigit(*tempi)) {
            //we have a constant that ends with ')' or ' ' or ',' or '\0'
            while (*tempi != ',' && *tempi != ')' && *tempi != ' ' && *tempi != '\0') {
                *tempo = *tempi;
                tempo++;
                tempi++;
            }
        }
        if (isalpha(*tempi) || *tempi == '_') {
            //we have a PROTO.FIELD.2
            //note that _ is possible for proto
            //numbers in proto are also possible, but must start with a letter
            char *data = NULL;
            short size = 0;
            short jump = 0;
            data = get_value( pkt, tempi, &jump, &size, list_of_tuples );
            tempi = tempi + jump;
            //Copy (data, size) to output
            char * td = NULL;
            td = data;
            while (*td != '\0') {
                *tempo = *td;
                tempo++;
                td++;
            }
            xfree(data);
        }
        while (*tempi == ' ') tempi++;
        if (*tempi == ',') {
            tempi++;
            while (*tempi == ' ') tempi++;
            *tempo = ' ';
            tempo++;
            if (isalpha(*tempi) || *tempi == '_' || isdigit(*tempi)) continue;
            else {
                (void)fprintf(stderr, "Error 22x: missing parameter\n");
                return NULL;
            }
        }
        if (*tempi == ')') {
            *tempo = '\0';
            break;
        }
        if (*tempi == '\0') {
            (void)fprintf(stderr, "Error 22x: missing ')' in: %s\n", input);
            return NULL;
        }
    }
    //Put data in file with name: detection_<counter_detection>.data
    //Will be used by python script
    FILE * pythonDataFile;
    char pythonDataFileName[50];
    rule * rr = NULL;
    snprintf(pythonDataFileName, 50, "detection_%ld.data", counter_detection);
    pythonDataFile = open_file(pythonDataFileName, "w+");
    if(r->root != NULL) rr = r->root;
    else rr = r;
    if(rr->type_rule == ATTACK)             fprintf(pythonDataFile,"attack\n"); 
    else if(rr->type_rule == EVASION)       fprintf(pythonDataFile,"evasion\n");
    else if(rr->type_rule == SECURITY_RULE) fprintf(pythonDataFile,"security rule\n");
    else                                    fprintf(pythonDataFile,"type\n");
    if(rr->description != NULL)             fprintf(pythonDataFile,"%s\n", rr->description);
    else                                    fprintf(pythonDataFile,"description\n");
    if(rr->json_history != NULL)            fprintf(pythonDataFile,"%s\n", rr->json_history);
    else                                    fprintf(pythonDataFile,"history\n");
    fprintf(pythonDataFile,"%d\n", rr->property_id);
    fprintf(pythonDataFile,"detected");
    close_file(pythonDataFile);
    return output;
}

char *my_strstr(char *texte, char* pattern, short reverse){
   char *pt1 = NULL;
   char *pt2 = NULL;
  if(reverse == YES){
    pt1 = strstr(texte, pattern);
    while(pt1 != NULL){
      pt2 = pt1;
      pt1 = pt1 + strlen(pattern);
      pt1 = strstr(pt1, pattern);
    }
  }else{
    pt2 = strstr(texte, pattern);
  }
  return pt2;
}

void get_time_value(char * history, char *a_time, short reverse, short direct)
{
        char *pt_j = NULL;
        char *pt_i = history;
        int len = 0;
        if(direct == NO){
          pt_i = my_strstr(history, "timestamp", reverse);
          if(pt_i != NULL){
            pt_i = pt_i + 38;
          }else{
            pt_i = my_strstr(history, "timeslot", reverse);
            if(pt_i != NULL){
              pt_i = pt_i + 37;
            }
          }
        }
        if(pt_i != NULL){
            while(*pt_i != '=') pt_i++;
            if (*pt_i != '='){
              (void)fprintf(stderr, "Error 22yyy: '=' not found: %s\n", pt_i);
              return;
            }
            pt_i++;
            pt_j = pt_i;
            while(*pt_j != '<') pt_j++;
            len = pt_j - pt_i;
            if (len<1 || len>99){
              (void)fprintf(stderr, "Error 22yyy1: length out of bounds in: %s\n", pt_i);
              return;
            }
            strncpy(a_time, pt_i, len);
            a_time[len]='\0';
        }
}

void rule_is_satisfied_or_not(const ipacket_t *pkt, short print_option, rule *curr_root, rule *r, char *cause, short state, short use_cause) {
    short result = 0;
    char *command = NULL;
    if (r->description == NULL) {
        //fprintf (stderr, "Missing description\n") ;
        //exit(-1);
        r = r->root;
    }

    if(op->callback_funct != NULL){
		char *verdict = NULL, *type = NULL;
		char *history;
		int prop_id = curr_root->property_id;
		char *des   = r->description;

		get_verdict( curr_root->type_rule, print_option, state, &verdict, &type );
		if( verdict == NULL) return;
		if (r->json_history != NULL)
			history = r->json_history;

		//remove the last comma
		if( history[ strlen( history ) - 1 ] == ',')
			history[ strlen( history ) - 1 ] = '\0';

		char *temp = xmalloc( strlen( history ) + 3 );
		sprintf( temp, "{%s}", history );

		((op->callback_funct))( prop_id, verdict, type, des, temp ,pkt->p_hdr->ts,(void *)op->user_args);

        xfree( temp );
		xfree( verdict );
		xfree( type );
    }

    // TODO: Folder where the scripts are installed is current folder
    void *data = NULL;
    short do_it = 0;
    char * what_to_do;
    if (state == SATISFIED) {
        do_it = 1;
        what_to_do = r->if_satisfied;
    } else if (state == NOT_SATISFIED) {
        do_it = 1;
        what_to_do = r->if_not_satisfied;
    }
    if (do_it == 1) {
        if (what_to_do != NULL) {
            if (strchr(what_to_do, '#') == NULL) {
                command = generate_command( pkt, r, what_to_do );
                if (command != NULL) {
                    fprintf(stderr, "EXECUTE FUNCTION:%s\n",command);
                    result = system(command);
                    xfree(command);
                    if (result == -1) fprintf(stderr, "Error 22a: Reaction \"%s\" failed.\n", what_to_do);
                } else {
                    (void)fprintf(stderr, "Error 22b: Reaction \"%s\" not executed.\n", what_to_do);
                }
            } else {
                char * funct_name = funct_extract_name(what_to_do);
                int data_size = 0;
                char * command = strchr(what_to_do, '(');
                command++;
                while (*command == ' ') command++;
                char * command2;
                tuple * top_tuple = (tuple *) xmalloc(sizeof (tuple));
                top_tuple->protocol_id = -1;
                top_tuple->field_id = -1;
                top_tuple->data_type_id = -1;
                top_tuple->data_size = -1;
                top_tuple->event_id = -1;
                top_tuple->valid = NOT_YET; //not used in this context
                top_tuple->data = NULL;
                top_tuple->next = NULL;
                tuple * a_tuple = top_tuple;
                tuple * new_tuple;

                command2 = funct_get_info_param( pkt->mmt_handler, NOT_USED, command, a_tuple);
                while( command2 ) {
                    new_tuple = (tuple *)xmalloc(sizeof (tuple));
                    new_tuple->protocol_id = -1;
                    new_tuple->field_id = -1;
                    new_tuple->data_type_id = -1;
                    new_tuple->data_size = -1;
                    new_tuple->event_id = -1;
                    new_tuple->valid = NOT_YET; //not used in this context
                    new_tuple->data = NULL;
                    new_tuple->next = NULL;
                    a_tuple->next = new_tuple;
                    a_tuple = new_tuple;
                    command2 = funct_get_info_param( pkt->mmt_handler, NOT_USED, command2, a_tuple);
                }
                short found = NOT_FOUND; //not used in this context
                data = funct_get_params_and_execute( pkt, NO, LIB_NAME, funct_name, data_size, top_tuple, r->list_of_tuples, &found);
                xfree(data);
                a_tuple = top_tuple;
                while (a_tuple != NULL) {
                    new_tuple = a_tuple;
                    a_tuple = a_tuple->next;
                    xfree(new_tuple->data);
                    xfree(new_tuple);
                }
                xfree(funct_name);
            }
        }
    }
    return;
}

int timeval_control(double delay_max, double delay_min, struct timeval start, struct timeval curr)
{
    struct timeval lapsed;
    if (curr.tv_usec < start.tv_usec) {
        int nsec = (start.tv_usec - curr.tv_usec) / 1000000 + 1;
        start.tv_usec -= 1000000 * nsec;
        start.tv_sec += nsec;
    }
    if (curr.tv_usec - start.tv_usec > 1000000) {
        int nsec = (curr.tv_usec - start.tv_usec) / 1000000;
        start.tv_usec += 1000000 * nsec;
        start.tv_sec -= nsec;
    }
    lapsed.tv_sec = curr.tv_sec - start.tv_sec;
    lapsed.tv_usec = curr.tv_usec - start.tv_usec;
    double lapsed_dd=(double)((curr.tv_sec - start.tv_sec) + ((double)curr.tv_usec - start.tv_usec)/1000000);

    if (lapsed.tv_sec < 0) {
        (void)fprintf(stderr, "Error 23: Problem in trace file. Should be ordered in time (line: %lld).\n", packet_count);
        //exit(-1);
    }
    if (delay_max >= 0 && delay_min >= 0) {
        if (delay_max > 0 && delay_max < lapsed_dd) {
            return TIMEOUT;
        }
        if (delay_min > 0 && delay_min > lapsed_dd) {
            return TIMEIN;
        }
    } else {
        if (delay_max < 0 && -1 * delay_max > lapsed_dd) {
            return TIMEIN;
        }
        if (delay_min < 0 && -1 * delay_min < lapsed_dd) {
            return TIMEOUT;
        }
    }
    return NOT_YET;
}

int check_for_countout(rule *r, int count)
{
    // TODO: increment counter
    int ret = 0;
    ret = COUNTIN;
    ret = COUNTOUT;
    return ret;
}

int check_for_timeout(rule *r, struct timeval start, struct timeval curr)
{
    int ret = 0;
    if (start.tv_sec != 0 && curr.tv_sec != 0 && (r->delay_max != 0 || r->delay_min != 0)) {
        ret = timeval_control(r->delay_max, r->delay_min, start, curr);
    }
    return ret;
}

short init_time(struct timeval *t, int *c, struct timeval curr)
{
    short result = SKIP2;
    //Start the timer if it has not been started
    if (t->tv_usec == 0 && t->tv_sec == 0) {
        t->tv_usec = curr.tv_usec;
        t->tv_sec = curr.tv_sec;
        (*c)++;
        result = VALID;
    }
    return result;
}

short check_time(rule *r, struct timeval curr)
{
    short result = SKIP2;
    //We need to check for timeout
    if (r->counter_min != 0 || r->counter_max != 0) {
        result = check_for_countout(r, r->counter);
    } else {
        result = check_for_timeout(r, r->timer, curr);
    }
    if (result == NOT_YET) return SKIP2;
    return result;
}

short action(short situation, short leftleft, rule *r)
{
    //result: VALID, NOT_VALID, NOT_YET
    //situation: BEFORE, AFTER, SAME
    //first_time: YES, NO (only for verify in a loop)
    //r->type: ROOT_INSTANCE or not
    //r->value, r->list_of_sons->value, r->list_of_sons->next->value: NOT, REPEAT, THEN
    if (r->type == ROOT_INSTANCE) {
        if (situation == AFTER || situation == SAME) {
            if (r->list_of_sons == NULL || r->list_of_sons->next == NULL) {
                (void)fprintf(stderr, "Error 24.1: Missing sons.\n");
                return ELIMINATE;
            }
            if (r->list_of_sons->valid == VALID && r->list_of_sons->next->valid == VALID) {
                r->valid = VALID;
                return COUNT_SATISFIED_ELIMINATE;
            } else if (r->list_of_sons->valid == VALID && r->list_of_sons->next->valid == NOT_YET) {
                r->valid = NOT_YET;
                return NOT_YET;
            } else if (r->list_of_sons->valid == NOT_YET) {
                r->valid = NOT_YET;
                return NOT_YET;
            } else if (r->list_of_sons->valid == NOT_VALID) {
                r->valid = NOT_VALID;
                return ELIMINATE;
            } else if (r->list_of_sons->valid == VALID && r->list_of_sons->next->valid == NOT_VALID) {
                if (situation == SAME) {
                    r->valid = NOT_VALID;
                    return COUNT_NOT_SATISFIED_ELIMINATE;
                //EDMO:Eliminated since not correct
                } else if (r->list_of_sons->next->value == NOT) {
                    r->valid = NOT_VALID;
                    return COUNT_NOT_SATISFIED_ELIMINATE;
                } else {
                    r->valid = NOT_YET;
                    return NOT_YET;
                }
            }
        } else if (situation == BEFORE) {
            if (r->list_of_sons == NULL || r->list_of_sons->next == NULL) {
                (void)fprintf(stderr, "Error 24.2: Missing sons.\n");
                return ELIMINATE;
            }
            if (r->list_of_sons->valid == VALID && r->list_of_sons->next->valid == VALID) {
                r->valid = VALID;
                return COUNT_SATISFIED_ELIMINATE;
            } else if (r->list_of_sons->valid == NOT_YET && r->list_of_sons->next->valid == VALID) {
                r->valid = NOT_YET;
                return NOT_YET;
            } else if (r->list_of_sons->valid == NOT_VALID && r->list_of_sons->next->valid == VALID) {
                r->valid = NOT_YET;
                return NOT_YET;
            } else if (r->list_of_sons->next->valid == NOT_YET) {
                r->valid = NOT_YET;
                return NOT_YET;
            } else if (r->list_of_sons->next->valid == NOT_VALID) {
                r->valid = NOT_VALID;
                return ELIMINATE;
            }
        }
    } else {
        if (situation == AFTER || situation == SAME) {
            if (r->list_of_sons == NULL || r->list_of_sons->next == NULL) {
                (void)fprintf(stderr, "Error 24.3: Missing sons.\n");
                return ELIMINATE;
            }
            if (r->list_of_sons->valid == VALID && r->list_of_sons->next->valid == VALID) {
                r->valid = VALID;
                return VALID;
            } else if (r->list_of_sons->valid == VALID && r->list_of_sons->next->valid == NOT_YET) {
                r->valid = NOT_YET;
                return NOT_YET;
            } else if (r->list_of_sons->valid == NOT_YET) {
                r->valid = NOT_YET;
                return NOT_YET;
            } else if (r->list_of_sons->valid == NOT_VALID) {
                if (leftleft == YES) {
                    r->valid = NOT_VALID;
                    return NOT_VALID;
                } else {
                    r->list_of_sons->valid = NOT_YET;
                    r->valid = NOT_YET;
                    return NOT_YET;
                }
            } else if (r->list_of_sons->valid == VALID && r->list_of_sons->next->valid == NOT_VALID) {
                if (situation == SAME) {
                    r->valid = NOT_VALID;
                    return NOT_VALID;
                //EDMO:Eliminated since not correct
                } else if (r->list_of_sons->next->value == NOT) {
                    r->valid = NOT_VALID;
                    return NOT_VALID;
                } else {
                    r->valid = NOT_YET;
                    return NOT_YET;
                }
            }
        } else if (situation == BEFORE) {
            if (r->list_of_sons == NULL || r->list_of_sons->next == NULL) {
                (void)fprintf(stderr, "Error 24.4: Missing sons.\n");
                return ELIMINATE;
            }
            if (r->list_of_sons->valid == VALID && r->list_of_sons->next->valid == VALID) {
                r->valid = VALID;
                return VALID;
            } else if (r->list_of_sons->valid == NOT_YET && r->list_of_sons->next->valid == VALID) {
                r->valid = NOT_YET;
                return NOT_YET;
            } else if (r->list_of_sons->valid == NOT_VALID && r->list_of_sons->next->valid == VALID) {
                r->valid = NOT_VALID;
                return NOT_VALID;
            } else if (r->list_of_sons->next->valid == NOT_YET) {
                r->valid = NOT_YET;
                return NOT_YET;
            } else if (r->list_of_sons->next->valid == NOT_VALID) {
                r->valid = NOT_VALID;
                return ELIMINATE;
            }
        }
    }

    return NOT_VALID;
}

int verify_left(const ipacket_t *pkt, char *cause, rule *r, rule *root)
{
    short result = 0;
    rule *temp_rule = NULL;
    switch (r->value) {
        case THEN:
                if (r->list_of_sons != NULL) {
                    result = verify_left(pkt, cause, r->list_of_sons, root);
                    return result;
                } else {
                    (void)fprintf(stderr, "Error 26: Encoutered incorrect sequence of events.\n");
                }
        case XFUNCT:
        case XAND:
        case XOR:
        case NEQ:
        case EQ:
        case GT:
        case GTE:
        case LT:
        case LTE:
        case XC:
        case XCE:
        case XD:
        case XDE:
        case XE:
        case XIN:
        case ADD:
        case SUB:
        case MUL:
        case DIV:
            temp_rule = r;
            result = verify_segment( pkt, YES, root->list_of_tuples, temp_rule, root );
            if(result == VALID){
              if(root->json_history != NULL){
                xfree (root->json_history);
                root->json_history = NULL;
              }
              store_history(pkt, SAME, root, root, cause, root->list_of_sons->event_id);
            }
            return result;
            break;
        default:
            (void)fprintf(stderr, "Error xx39: Should be a event. XML properties file: %s might be incorrect.\n", op->RuleFileName);
            break;
    }//end of switch THEN
    (void)fprintf(stderr, "Error xx40: Possible error in the XML properties file: %s.\n", op->RuleFileName);

    return NOT_VALID;
}

int verify( const ipacket_t *pkt, short leftleft, short context, rule *curr_root, tuple *list_of_tuples, short *reference,
        char *cause, rule *r, struct timeval current_packet_time)
{
    short result = 0, situation = 0, this = 0;
    rule *curr_r = NULL;
    rule *curr_r_NOT = NULL;
    rule *temp_rule = NULL;
    *cause = '\0';
    switch (r->value) {
        case THEN:
            situation = SAME;
            //Determine if we are in the situation AFTER or BEFORE and report errors in state of sons
            //  (e.g., if "A then AFTER B" and "A not_yet" and "B valid" => error because B can not be valid before A in this situation)
            if (r->counter_max > 0 || r->delay_max > 0) {
                situation = AFTER;
                if (r->list_of_sons != NULL && r->list_of_sons->valid == NOT_YET &&
                        r->list_of_sons->next != NULL && r->list_of_sons->next->valid == VALID) {
                    (void)fprintf(stderr, "Error 24.5: Encoutered incorrect sequence of events.\n");
                }
            } else if (r->counter_min < 0 || r->delay_min < 0) {
                situation = BEFORE;
                if (r->list_of_sons != NULL && r->list_of_sons->valid == VALID &&
                        r->list_of_sons->next != NULL && r->list_of_sons->next->valid == NOT_YET) {
                    (void)fprintf(stderr, "Error 25: Encoutered incorrect sequence of events.\n");
                }
            }
            if (situation == SAME) { //conditions to be tested on same packet
                if (r->list_of_sons != NULL) {
                    r->list_of_sons->father = r;
                    result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, r->list_of_sons, current_packet_time );
                    if (result == VALID) {
                        r->list_of_sons->next->father = r;
                        result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, r->list_of_sons->next, current_packet_time );
                        if (result == NOT_VALID)r->list_of_sons->next->valid = NOT_VALID;
                    }
                    this = action(situation, leftleft, r);
                    return this;
                } else {
                    (void)fprintf(stderr, "Error 26: Encoutered incorrect sequence of events.\n");
                }
            } else if (situation == AFTER) {
                if (r->list_of_sons != NULL) {
                    if (r->list_of_sons->valid == NOT_YET) {
                        //Need to verify left branch
                        r->list_of_sons->father = r;
                        result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, r->list_of_sons, current_packet_time );
                        if (result == VALID) {
                            //Left branch was found valid so need to start timer
                            result = init_time(&(r->timer), &(r->counter), current_packet_time);
                            if (r->delay_min == 0 && r->not_equal_min == NO) {
                                //Since there is no delay_min set we need to verify, for the same packet, the right branch
                                r->list_of_sons->next->father = r;
                                result = verify( pkt, NO, situation, curr_root, list_of_tuples, reference, cause, r->list_of_sons->next, current_packet_time );
                            }
                        }
                        this = action(situation, leftleft, r);
                        return this;
                    } else if (r->list_of_sons->valid == VALID) {
                        //Left branch already valid so need to check for timeout
                        result = check_time(r, current_packet_time); //returns SKIP2/TIMEOUT/TIMEIN/COUNTOUT/COUNTIN
                        if (result != SKIP2) {
                            //We have a timeout condition
                            if (result == TIMEIN){
                              return NOT_YET;
                            }
                            //EDMO:Eliminated since not correct
                            if (r->list_of_sons->next->value == NOT) {
                                r->valid = VALID;
                                if (r->type == ROOT_INSTANCE) {
                                  return COUNT_SATISFIED_ELIMINATE;
                                } else {
                                    return VALID;
                                }
                            } else {
                                r->valid = NOT_VALID;
                                if (r->type == ROOT_INSTANCE) {
                                    return COUNT_NOT_SATISFIED_ELIMINATE;
                                } else {
                                    return NOT_VALID;
                                }
                            }
                        }
                        //Need to verify right branch
                        r->list_of_sons->next->father = r;
                        result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, r->list_of_sons->next, current_packet_time );
                        this = action(situation, leftleft, r);
                        return this;
                    } else if (r->list_of_sons->valid == NOT_VALID) {
                        this = action(situation, leftleft, r);
                        return this;
                    } else {
                        (void)fprintf(stderr, "Error 27: Encoutered incorrect sequence of events.\n");
                    }
                }
                (void)fprintf(stderr, "Error 30: Encoutered incorrect sequence of events.\n");
            } else if (situation == BEFORE) {
                if (r->list_of_sons != NULL) {
                    if (r->list_of_sons->next->valid == NOT_YET) {
                        //Need to verify right branch
                        r->list_of_sons->next->father = r;
                        result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, r->list_of_sons->next, current_packet_time );
                        r->list_of_sons->next->valid = result;
                        if (result == VALID) {
                            //Right branch was found valid so need to start timer
                            result = init_time(&(r->timer), &(r->counter), current_packet_time);
                            if (r->delay_max == 0 && r->not_equal_max == NO) {
                                //Since there is no delay_max set we need to verify, for the same packet, the left branch
                                r->list_of_sons->father = r;
                                result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, r->list_of_sons, current_packet_time );
                            }
                        }
                        this = action(situation, leftleft, r);
                        return this;
                    } else if (r->list_of_sons->next->valid == VALID) {
                        //Right branch already valid so need to check for timeout
                        result = check_time(r, current_packet_time); //returns SKIP2/TIMEOUT/TIMEIN/COUNTOUT/COUNTIN
                        if (result != SKIP2) {
                            //We have a timeout condition
                            
                            //EDMO:Eliminated since not correct
                            if (r->list_of_sons->value == NOT) {
                                r->valid = VALID;
                                if (r->type == ROOT_INSTANCE) {
                                    return COUNT_SATISFIED_ELIMINATE;
                                } else {
                                    return VALID;
                                }
                            } else {
                                r->valid = NOT_VALID;
                                if (r->type == ROOT_INSTANCE) {
                                    return ELIMINATE;
                                } else {
                                    return NOT_VALID;
                                }
                            }
                        }
                        //Need to verify left branch
                        r->list_of_sons->father = r;
                        result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, r->list_of_sons, current_packet_time );
                        this = action(situation, leftleft, r);
                        return this;
                    } else if (r->list_of_sons->valid == NOT_VALID) {
                        this = action(situation, leftleft, r);
                        return this;
                    } else {
                        (void)fprintf(stderr, "Error 35: Encoutered incorrect sequence of events.\n");
                    }
                }
            }//end of if SAME/AFTER/BEFORE
            break;
        case OR:
            //No timer needed
            if (r->list_of_sons != NULL) {
                curr_r = r->list_of_sons;
                //assume none are valid
                while (curr_r != NULL) {
                    curr_r->father = r;
                    result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, curr_r, current_packet_time );
                    if (result == VALID) {
                        //Found valid
                        curr_r->valid = VALID;
                        r->valid = VALID;
                        return VALID;
                    }
                    curr_r->valid = NOT_VALID;
                    curr_r = curr_r->next;
                }
                r->valid = NOT_VALID;
                return NOT_VALID;
            }
            (void)fprintf(stderr, "Error 36: Encoutered incorrect sequence of events.\n");
            break;
        case AND:
            //Timer needed
            if (r->list_of_sons != NULL) {
                curr_r = r->list_of_sons;
                int one_already_valid = 0;
                while (curr_r != NULL) {
                    if (curr_r->valid == VALID) {
                        one_already_valid = 1;
                        break;
                    }
                    curr_r = curr_r->next;
                    continue;
                }
                if (one_already_valid == 1) {
                    //Case timer already started so need to control timeout
                    result = check_time(r, current_packet_time); //returns SKIP2/TIMEOUT/TIMEIN/COUNTOUT/COUNTIN
                    if (result != SKIP2) {
                        //EDMO:Eliminated since not correct
                        if ((r->list_of_sons->valid == VALID && r->list_of_sons->next->value == NOT) ||
                                (r->list_of_sons->next->valid == VALID && r->list_of_sons->value == NOT)) {
                            r->valid = VALID;
                            return VALID;
                        } else {
                            r->valid = NOT_VALID;
                            return NOT_VALID;
                        }
                    }
                }
                int all_valid = 1;
                curr_r = r->list_of_sons;
                while (curr_r != NULL) {
                    if (curr_r->valid != VALID) {
                        curr_r->father = r;
                        result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, curr_r, current_packet_time );
                        if (one_already_valid == 0) {
                            if (result == VALID) {
                                //Case found the first VALID son so timer needs to be started
                                init_time(&(r->timer), &(r->counter), current_packet_time);
                                one_already_valid = 1;
                            }
                        }
                        if (result == VALID) {
                            one_already_valid = 1;
                            curr_r->valid = VALID;
                        } else if (result == NOT_VALID) {
                            curr_r->valid = NOT_YET;
                            all_valid = 0;
                        } else if (result == NOT_YET) {
                            curr_r->valid = NOT_YET;
                            all_valid = 0;
                        }
                    }
                    curr_r = curr_r->next;
                    continue;
                }
                if (all_valid == 1) {
                    r->valid = VALID;
                    return VALID;
                } else if (one_already_valid == 0) {
                    r->valid = NOT_VALID;
                    return NOT_VALID;
                } else {
                    r->valid = NOT_YET;
                    return NOT_YET;
                }
            }
            (void)fprintf(stderr, "Error 37: Encoutered incorrect sequence of events.\n");
            break;
        case NOT:
            //Timer needed
            if (r->list_of_sons != NULL) {
                curr_r = r->list_of_sons;
                if (r->timer.tv_usec != 0 || r->timer.tv_sec != 0) {
                    //Case timer already started so need to control timeout
                    result = check_time(r, current_packet_time); //returns SKIP2/TIMEOUT/TIMEIN/COUNTOUT/COUNTIN
                    if (result != SKIP2) {
                        //Son never found VALID so the NOT node is VALID
                        r->valid = VALID;
                        return VALID;
                    }
                }
                curr_r->father = r;
                result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, curr_r, current_packet_time );
                if (result == NOT_VALID && r->timer.tv_usec == 0 && r->timer.tv_sec == 0) {
                    //Case found the NOT_VALID son so NOT node is VALID and timer needs to be started (if not already started)
                    init_time(&(r->timer), &(r->counter), current_packet_time);
                }
                if (result == VALID) {
                    //son of NOT is valid so NOT node is NOT_VALID
                    curr_r->valid = VALID;
                    r->valid = NOT_VALID;
                    return NOT_VALID;
                } else if (result == NOT_VALID || result == NOT_YET) {
                    //son of NOT is NOT_VALID so NOT node can still be VALID (if timeout is reached with the son always remaining NOT_VALID)
                    //now need to check next noeud and if next noeud is not valid then leave as it is
                    //but if next branch is valid then should set NOT noeud to VALID
                    curr_r_NOT = curr_r;
                    if (r->list_of_sons->next != NULL) {
                        curr_r = r->list_of_sons->next;
                    } else {
                        //EDMO!
                        curr_r = r->list_of_sons->father;
                        while(curr_r != NULL && curr_r->next == NULL){
                            curr_r = curr_r->father;
                        }
                        if(curr_r != NULL && curr_r->next != NULL){
                            curr_r = curr_r->next;
                            curr_r->father = r;
                            result = verify( pkt, leftleft, situation, curr_root, list_of_tuples, reference, cause, curr_r, current_packet_time );
                            if (result == VALID) {
                                //Found valid so NOT is valid also
                                curr_r->valid = VALID;
                                r->valid = VALID;
                                curr_r_NOT->valid = VALID;
                                return VALID;
                            }
                        }
                        curr_r->valid = NOT_YET;
                        r->valid = NOT_YET;
                        return NOT_YET;
                    }
                }
            }
            (void)fprintf(stderr, "Error 38: Encoutered incorrect sequence of events.\n");
            break;
        case REPEAT: //same as AND but do it several repeat_times, couting them in repeat_times_found
            // TODO
            break;
        case XFUNCT:
        case XAND:
        case XOR:
        case NEQ:
        case EQ:
        case GT:
        case GTE:
        case LT:
        case LTE:
        case XC:
        case XCE:
        case XD:
        case XDE:
        case XE:
        case XIN:
        case ADD:
        case SUB:
        case MUL:
        case DIV:
            temp_rule = r;
            result = verify_segment( pkt, NO, list_of_tuples, temp_rule, curr_root );
            if (result == VALID) {
                if (temp_rule->description != NULL) {
                    strncpy(cause, temp_rule->description, SIZE_CAUSE);
                    cause[SIZE_CAUSE]='\0';
                }
                store_tuples( pkt, context, curr_root, r->root, temp_rule->event_id, cause );
            }
            return result;
            break;
        default:
            (void)fprintf(stderr, "Error 39: Should be a event. XML properties file: %s might be incorrect.\n", op->RuleFileName);
            break;
    }//end of switch THEN/OR/AND/NOT/REPEAT
    (void)fprintf(stderr, "Error 40: Possible error in the XML properties file: %s.\n", op->RuleFileName);
    return NOT_VALID;
}

int analyse_incoming_packet(const ipacket_t * ipacket, void* arg)
{
    if (p_meta == 0) {
        p_meta = get_protocol_id_by_name("META");
        a_utime = get_attribute_id_by_protocol_id_and_attribute_name(p_meta, "UTIME");
    }
    packet_count++;
    op = (OPTIONS_struct *) arg;
    OutputFile = op->OutputFile;
    if (OutputFile == NULL)OutputFile = stderr;
    short result = 0;
    rule *curr_rule = top_rule;
    rule *curr_rule_instance = NULL;
    rule *temp = NULL;
    rule *root_inst = NULL;
    struct timeval current_packet_time;
    short reference = 0;
    char *cause = xmalloc(SIZE_CAUSE+1);

    current_packet_time.tv_sec = get_seconds( ipacket );
    current_packet_time.tv_usec = get_useconds( ipacket );
    curr_rule = top_rule;
    int skip = NO;
    short if_valid_and_no_instance_satisfied_then_generate_not_satisfied = NOT_VALID;
    while (curr_rule != NULL) {
        curr_rule_instance = curr_rule->list_of_instances;
        //first verify existing instances
        skip = NO;
        if(curr_rule->delay_min < 0){
          strncpy(cause,"C1 satisfied but C2 not found in property: 'if C1 THEN BEFORE we should have C2'", SIZE_CAUSE);
          cause[SIZE_CAUSE]='\0';
          if_valid_and_no_instance_satisfied_then_generate_not_satisfied = verify_left(ipacket, cause, curr_rule, curr_rule);
          *cause = '\0';
        }
        while (curr_rule_instance != NULL) {
            result = verify(ipacket, NO, SAME, curr_rule, curr_rule_instance->list_of_tuples, &reference, cause, curr_rule_instance, current_packet_time);
            if (result == SKIP2) {
                (void)fprintf(stderr, "Error 41: Problem in packet number: %lld\n", packet_count);
                continue;
            }
            temp = curr_rule_instance->next;
            //if instance is VALID or NOT_VALID then eliminate it
            if (result != NOT_YET) {
                if (result == COUNT_NOT_SATISFIED || result == COUNT_NOT_SATISFIED_ELIMINATE) {
                    rule_is_satisfied_or_not( ipacket, op->Print, curr_rule, curr_rule_instance, cause, NOT_SATISFIED, NO );
                    (curr_rule->nb_not_satisfied)++;
                } else if (result == COUNT_SATISFIED || result == COUNT_SATISFIED_ELIMINATE) {
                    rule_is_satisfied_or_not( ipacket, op->Print, curr_rule, curr_rule_instance, cause, SATISFIED, NO );
                    (curr_rule->nb_satisfied)++;
                    //skip = YES; //Case root says that if property is satisfied thanks to current packet
                                //then do not create new instance using the current packet
                                //If new instance is wanted, this is managed by keep_state
                    if_valid_and_no_instance_satisfied_then_generate_not_satisfied = NOT_VALID;//so that right branch of BEFORE tree is not counted as
                                                                                               //NOT_SATISFIED
                }
                if (result == COUNT_NOT_SATISFIED_ELIMINATE || result == ELIMINATE || result == COUNT_SATISFIED_ELIMINATE ||
                        result == NOT_VALID || result == VALID || result == NOT_YET) {
                    copy_instance(&root_inst, curr_rule, NULL, curr_rule_instance);
                    eliminate_instance(&curr_rule, &curr_rule_instance, "instance");
                } else {
                    (void)fprintf(stderr, "Should not be here\n");
                    exit(1);
                    //keep_context_only(&curr_rule, &curr_rule_instance, "instance", SAME);
                }
            } else {
                //case NOT_YET: event satisfied
            }
            curr_rule_instance = temp;
        }
        if(if_valid_and_no_instance_satisfied_then_generate_not_satisfied == VALID){
          // TODO: works only if left branch is one event
          if_valid_and_no_instance_satisfied_then_generate_not_satisfied = NOT_VALID;
          strncpy(cause,"C1 satisfied but C2 not found in property: 'if C1 THEN BEFORE we should have C2'", SIZE_CAUSE);
          cause[SIZE_CAUSE]='\0';
          rule_is_satisfied_or_not( ipacket, op->Print, curr_rule, curr_rule, cause, NOT_SATISFIED, YES );
          *cause = '\0';
          (curr_rule->nb_not_satisfied)++;
        }
        //then verify a brand new one
        temp = curr_rule->next;
        if (skip == NO) {
            curr_rule_instance = create_instance(&root_inst, curr_rule, NULL);
            result = verify(ipacket, YES, SAME, curr_rule, curr_rule_instance->list_of_tuples, &reference, cause, curr_rule_instance, current_packet_time);
            //if instance is VALID or NOT_VALID then eliminate it
            if (result != NOT_YET) {
                if (result == COUNT_NOT_SATISFIED || result == COUNT_NOT_SATISFIED_ELIMINATE) {
                    rule_is_satisfied_or_not( ipacket, op->Print, curr_rule, curr_rule_instance, cause, NOT_SATISFIED, NO );
                    (curr_rule->nb_not_satisfied)++;
                } else if (result == COUNT_SATISFIED || result == COUNT_SATISFIED_ELIMINATE) {
                    rule_is_satisfied_or_not( ipacket, op->Print, curr_rule, curr_rule_instance, cause, SATISFIED, NO );
                    (curr_rule->nb_satisfied)++;
                }
                if (result == COUNT_NOT_SATISFIED_ELIMINATE || result == ELIMINATE || result == COUNT_SATISFIED_ELIMINATE || result == NOT_VALID) {
                    eliminate_instance(&curr_rule, &curr_rule_instance, "instance");
                } else {
                    (void)fprintf(stderr, "Should not be here2\n");
                    exit(1);
                }
            }
        }
        curr_rule = temp;
    }
    xfree(cause);
    return 0;
}

void init_options( mmt_handler_t *mmt )
{
    int ret;

    if (p_meta == 0) {
        p_meta = get_protocol_id_by_name("META");
        a_utime = get_attribute_id_by_protocol_id_and_attribute_name(p_meta, "UTIME");
        token2 = xmalloc(30);
        token3 = xmalloc(30);
    }
    read_rules( mmt );

    //we now have registered extraction attributes
    // The next function is to be called with the right parameters
    //    analyse_incoming_packet(top_attribute);
    ret = register_packet_handler( mmt, 1, analyse_incoming_packet, (u_char *) op );
    if (ret <= 0) {
        (void)fprintf(stderr, "Error 42: in registering packet handler function.\n");
        exit(-1);
    }
    //register_packet_handler(mmt, 2, debug_extracted_attributes_printout_handler, NULL);

}

void print_summary()
{
    rule *temp = top_rule;
    while (temp != NULL) {
        (void)fprintf(stderr, "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - --\n");
        (void)print_message(temp->type_rule, BOTH, NEITHER, temp->property_id, temp->description);
        if (temp->type_rule == ATTACK) {
            (void)fprintf(stderr, "    ATTACKS DETECTED                      : %6ld times,\n", temp->nb_satisfied);
            (void)fprintf(stderr, "    OCCURRENCES DETECTED FREE from attack : %6ld times.\n", temp->nb_not_satisfied);
        } else if (temp->type_rule == EVASION) {
            (void)fprintf(stderr, "    EVASION DETECTED                      : %6ld times,\n", temp->nb_satisfied);
            (void)fprintf(stderr, "    OCCURRENCES DETECTED FREE from evasion : %6ld times.\n", temp->nb_not_satisfied);
        } else if (temp->type_rule == SECURITY_RULE || temp->type_rule == TEST) {
            (void)fprintf(stderr, "    RESPECTED : %6ld times,\n", temp->nb_satisfied);
            (void)fprintf(stderr, "    VIOLATED  : %6ld times.\n", temp->nb_not_satisfied);
        }
        temp = temp->next;
    }
}

char * xml_summary()
{
    //if used in the main.c needs to be freed
    int sp = 0;
    int spb = 0;
    rule *temp = top_rule;
    char *xml_string = xmalloc(10000);
    strcpy(xml_string, "</detail>\n");
    (void)strcat(xml_string, "<summary>\n");
    char tmp[1000];
    if (corr_mess != 0) {
        spb = 1;
        (void)strcat(xml_string, "  <spb>\n");
        (void)sprintf(tmp, "   <id>0</id>\n");
        (void)strcat(xml_string, tmp);
        (void)sprintf(tmp, "   <description>ATTACK: Corrupted messages: due to an attack, evasion or error.</description>\n");
        (void)strcat(xml_string, tmp);
        (void)sprintf(tmp, "   <detected>%lld</detected>\n", corr_mess);
        (void)strcat(xml_string, tmp);
        (void)sprintf(tmp, "   <not_detected>N&#47;A</not_detected>\n");
        (void)strcat(xml_string, tmp);
        (void)strcat(xml_string, "  </spb>\n");
    }
    while (temp != NULL) {
        if (temp->type_rule == ATTACK) {
            spb = 1;
            (void)strcat(xml_string, "  <spb>\n");
            (void)sprintf(tmp, "   <id>%d</id>\n", temp->property_id);
            (void)strcat(xml_string, tmp);
            (void)sprintf(tmp, "   <description>ATTACK: %s</description>\n", temp->description);
            (void)strcat(xml_string, tmp);
            (void)sprintf(tmp, "   <detected>%ld</detected>\n", temp->nb_satisfied);
            (void)strcat(xml_string, tmp);
            (void)sprintf(tmp, "   <not_detected>%ld</not_detected>\n", temp->nb_not_satisfied);
            (void)strcat(xml_string, tmp);
            (void)strcat(xml_string, "  </spb>\n");
        }else if (temp->type_rule == EVASION) {
            spb = 1;
            (void)strcat(xml_string, "  <spb>\n");
            (void)sprintf(tmp, "   <id>%d</id>\n", temp->property_id);
            (void)strcat(xml_string, tmp);
            (void)sprintf(tmp, "   <description>EVASION: %s</description>\n", temp->description);
            (void)strcat(xml_string, tmp);
            (void)sprintf(tmp, "   <detected>%ld</detected>\n", temp->nb_satisfied);
            (void)strcat(xml_string, tmp);
            (void)sprintf(tmp, "   <not_detected>%ld</not_detected>\n", temp->nb_not_satisfied);
            (void)strcat(xml_string, tmp);
            (void)strcat(xml_string, "  </spb>\n");
        } else if (temp->type_rule == SECURITY_RULE || temp->type_rule == TEST) {
            sp = 1;
            (void)strcat(xml_string, "  <sp>\n");
            (void)sprintf(tmp, "   <id>%d</id>\n", temp->property_id);
            (void)strcat(xml_string, tmp);
            if (temp->type_rule == SECURITY_RULE) (void)sprintf(tmp, "   <description>SECURITY RULE: %s</description>\n", temp->description);
            else (void)sprintf(tmp, "   <description>%s</description>\n", temp->description);
            (void)strcat(xml_string, tmp);
            (void)sprintf(tmp, "   <respected>%ld</respected>\n", temp->nb_satisfied);
            (void)strcat(xml_string, tmp);
            (void)sprintf(tmp, "   <violated>%ld</violated>\n", temp->nb_not_satisfied);
            (void)strcat(xml_string, tmp);
            (void)strcat(xml_string, "  </sp>\n");
        }
        temp = temp->next;
    }
    if (sp == 0) {
        (void)strcat(xml_string, "  <sp>\n");
        (void)strcat(xml_string, "   <id></id>\n");
        (void)strcat(xml_string, "   <description>none</description>\n");
        (void)strcat(xml_string, "  </sp>\n");
    }
    if (spb == 0) {
        (void)strcat(xml_string, "  <spb>\n");
        (void)strcat(xml_string, "   <id></id>\n");
        (void)strcat(xml_string, "   <description>none</description>\n");
        (void)strcat(xml_string, "  </spb>\n");
    }
    (void)strcat(xml_string, "</summary>\n");
    (void)strcat(xml_string, "</results>\n");
    return xml_string;
}

void init_sec_lib( mmt_handler_t *mmt, char * property_file,
        short option_satisfied, short option_not_satisfied, result_callback cont_funct,
        result_callback db_create_funct, result_callback db_insert_funct, void * user_args)
{
    op = (OPTIONS_struct *)xcalloc(1, sizeof (OPTIONS_struct));
    op->StartTime = time(NULL);
    op->Print = BOTH;
    op->user_args = (void *)user_args;
    if (option_satisfied == 1 && option_not_satisfied == 0) op->Print = SATISFIED;
    if (option_satisfied == 0 && option_not_satisfied == 1) op->Print = NOT_SATISFIED;
    op->RuleFileName = strdup(property_file);
    op->callback_funct = cont_funct;
    op->RuleFile = open_file(op->RuleFileName, "r");
    op->user_args = (void *)user_args;
    if (op->RuleFile == NULL) {
        (void)fprintf(stderr, "Error 104: Input rule file not found or incorrect file name: %s.\n", op->TraceFileName);
        exit(1);
    }
    init_options( mmt );
}
