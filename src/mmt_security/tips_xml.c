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
 *       Filename:  tips_xml.c
 *    Description:  Open Source prototype version of the MMT_Security library
 *                  that allows analysing network traffic
 *                  to detect normal or abnormal behaviour.
 *
 *    Responsibility: XML loading — parses the XML properties file
 *    (libxml2 reader walk in processNode/read_rules), builds the
 *    rule/attribute tree and the boolean-expression subtrees.
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

    static rule *bot_rule = NULL;
    static rule *root_rule;

    static father *top_father = NULL;
    static father *bot_father = NULL;

rule * create_rule()
{
    rule * a_rule = (rule *) xmalloc(sizeof (rule));
    if(a_rule == NULL) return NULL;
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

void create_father(rule *a_rule, short depth, enum_clean clean)
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
        if(top_father == NULL) return;
        top_father->node = a_rule;
        top_father->depth = depth;
        top_father->next = NULL;
        top_father->prev = NULL;
        bot_father = top_father;
    } else {
        temp = (father *) xmalloc(sizeof (father));
        if (temp == NULL)
            return;
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
    temp->next = NULL;
    xfree(bot_father);
    bot_father = temp;
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
    /* Callers hand buffers of at least 18 bytes (buff1[100] in get_my_data,
     * temp_MAC[22] in store_history); the bound is enforced anyway so the
     * write can never overflow a smaller destination. A MAC string is
     * "xx:xx:xx:xx:xx:xx" = 17 chars + NUL. */
    if(pbyMacAddressInBytes != NULL)
        (void)snprintf(*pszMACAddress, 18, "%02x%c%02x%c%02x%c%02x%c%02x%c%02x", pbyMacAddressInBytes[0] & 0xff,
            cSep, pbyMacAddressInBytes[1]& 0xff,
            cSep, pbyMacAddressInBytes[2]& 0xff,
            cSep, pbyMacAddressInBytes[3]& 0xff,
            cSep, pbyMacAddressInBytes[4]& 0xff,
            cSep, pbyMacAddressInBytes[5]& 0xff);
    else
        (void)snprintf(*pszMACAddress, 18, "00:00:00:00:00");
}

void *get_xdata(long type, int size, void *str, short is_string_data)
{
    /* Only used when reading constant values from the XML file.
     * `str` has two possible shapes: a quoted 'value' constant arrives as an
     * mmt_string_data_t (is_string_data == YES, the text sits at str + 4),
     * while a bare numeric token arrives as a plain NUL-terminated char*
     * (is_string_data == NO). */
    unsigned char c = 0;
    unsigned short s = 0;
    unsigned long l = 0;
    unsigned long long ll = 0L;
    /* enum_yes is {YES=0, NO=1}: compare explicitly, never test truthily */
    const char *txt = (is_string_data == YES) ? (const char *) str + sizeof(uint32_t) : (const char *) str;
    void * data = NULL;
    /* a negative declared size would become a huge size_t in the memcpy
     * calls below — refuse it up-front */
    if (size < 0) return NULL;
    data = (void *) xmalloc(size > 0 ? size : 1);
    if(data == NULL) return NULL;
    unsigned char *temp_MAC = NULL;
    mmt_string_data_t *tmp = NULL;
    switch (type) {
        case MMT_DATA_MAC_ADDR:
            temp_MAC = xmalloc(22);
            if (temp_MAC == NULL)
            {
                xfree(data);
                return NULL;
            }

            convert_mac_string_to_byte(txt, &temp_MAC);
            memcpy(data, (void *) temp_MAC, size);
            if (temp_MAC != NULL) xfree(temp_MAC);
            return (void *) data;
            break;
        case MMT_U16_DATA:
            s = (unsigned short) atoi(txt);
            memcpy(data, (void *) (&s), size);
            return (void *) data;
            break;
        case MMT_U32_DATA:
            l = (unsigned long) atol(txt);
            memcpy(data, (void *) (&l), size);
            return (void *) data;
            break;
        case MMT_U64_DATA:
            ll = (unsigned long long) atoll(txt);
            memcpy(data, (void *) (&ll), size);
            return (void *) data;
            break;
        case MMT_U8_DATA:
        case MMT_DATA_CHAR:
            c = (unsigned char) atoi(txt);
            memcpy(data, (void *) (&c), size);
            return (void *) data;
            break;
        case MMT_DATA_IP_ADDR:
            /* dotted-quad string, e.g. "10.0.0.1" or '10.0.0.1' */
            if (inet_pton(AF_INET, txt, data) != 1) {
                xfree(data);
                return NULL;
            }
            return (void *) data;
            break;
        case MMT_DATA_IP6_ADDR:
            /* textual IPv6, e.g. '2001:db8::1' */
            if (inet_pton(AF_INET6, txt, data) != 1) {
                xfree(data);
                return NULL;
            }
            return (void *) data;
            break;
        case MMT_DATA_FLOAT: {
            float f = (float) atof(txt);
            memcpy(data, (void *) (&f), (size < (int) sizeof (float)) ? (size_t) size : sizeof (float));
            return (void *) data;
            break;
        }
        case MMT_STRING_DATA_POINTER: {
            /* the attribute data is a char* — keep a private copy of the
             * constant so the tuple owns its memory like every other case */
            char *copy = (char *) xmalloc(strlen(txt) + 1);
            if (copy == NULL) {
                xfree(data);
                return NULL;
            }
            (void)strcpy(copy, txt);
            memcpy(data, (void *) (&copy), (size < (int) sizeof (char *)) ? (size_t) size : sizeof (char *));
            return (void *) data;
            break;
        }
        case MMT_STRING_DATA:
        case MMT_DATA_PATH:
        case MMT_STRING_LONG_DATA:
        case MMT_BINARY_VAR_DATA:
        case MMT_BINARY_DATA:
            if (is_string_data == YES) {
                /* copy the whole mmt_string_data_t record (len + payload) */
                memcpy(data, (void *) str, size);
            } else {
                /* a bare token is only a few valid bytes on the caller's
                 * stack — never copy `size` bytes from it */
                size_t n = strlen(txt) + 1;
                if (n > (size_t) size) n = (size_t) size;
                memcpy(data, (void *) txt, n);
            }
            return (void *) data;
            break;
        case MMT_HEADER_LINE: {
        	xfree (data);
        	//str is an instance of mmt_string_data_t when the value is quoted
        	tmp = str;
        	/* the struct must be large enough to hold ptr+len no matter what
        	 * the caller-passed size is */
        	if (size < (int)sizeof(mmt_header_line_t)) size = sizeof(mmt_header_line_t);
        	mmt_header_line_t *hl = (mmt_header_line_t *) xmalloc( size );
            if(hl == NULL){
                return NULL;
            }
            /* the declared length is bounded by the source record so a bogus
             * value cannot over-read the source or underflow hl->len - 1 */
            uint32_t hl_len = (is_string_data == YES) ? tmp->len : (uint32_t) strlen(txt) + 1;
            if (hl_len == 0) hl_len = 1;
            if (hl_len > STRING_DATA_LEN) hl_len = STRING_DATA_LEN;
        	hl->len = (uint16_t) hl_len;
        	char *hlp = xmalloc( hl->len);
            if(hlp == NULL){
                xfree(hl);
                return NULL;
            }
        	memcpy(hlp, (is_string_data == YES) ? (const void *)tmp->data : (const void *)txt, hl->len);
        	hlp[ hl->len - 1 ] = '\0';
        	hl->ptr = hlp;
        	return hl;
            break;
        }
        /* Types with no defined record representation cannot appear as
         * constants either — returning NULL marks the leaf as unusable,
         * which is the intended "unsupported" outcome (#326). */
        case MMT_DATA_TIMEVAL:
        case MMT_DATA_PORT:
        case MMT_DATA_PORT_RANGE:
        case MMT_DATA_DATE:
        case MMT_DATA_TIMEARG:
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
        case MMT_UNDEFINED_TYPE:
             return NULL;
             break;
        default:
            (void)fprintf(stderr, "Error 2: Type [%ld], size [%d] not implemented yet, data type unknown.\n [%s]\n", type, size, (char *)data);
            exit(-1);
    }//end of switch
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
    /* F-BUG-103 (#209): every token buffer is 30 bytes — stop at 29 and skip
     * the rest of the identifier so parsing stays in sync. */
    while ((isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) && i < (short)(sizeof(token_tmp) - 1)) {
        (*ltoken2)[i] = *temp2;
        i++;
        temp2++;
    }
    (*ltoken2)[i] = '\0';
    while (isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) temp2++;
    if (*temp2 != '.') {
        (void)fprintf(stderr, "Error 3b: Incorrect name in PROTO.FIELD.EVENT: %s", temp);
        exit(-1);
    }
    temp2++; //skip the point
    i = 0;
    while ((isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) && i < (short)(sizeof(token_tmp) - 1)) {
        (*ltoken3)[i] = *temp2;
        temp2++;
        i++;
    }
    (*ltoken3)[i] = '\0';
    while (isalpha(*temp2) || *temp2 == '_' || isdigit(*temp2)) temp2++;
    if (*temp2 == '.') {//we have a reference to an event (event_id)
        temp2++;
        i = 0;
        while (isdigit(*temp2) && i < (short)(sizeof(token_tmp) - 1)) {
            token_tmp[i] = *temp2;
            temp2++;
            i++;
        }
        token_tmp[i] = '\0';
        while (isdigit(*temp2)) temp2++;
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
        if(b_tuple == NULL) return;
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
    if(output == NULL) return NULL;
    strncpy(output, start, end - start);
    output[end - start] = '\0';
    //caller needs to free return value
    return output;
}

int funct_get_return_type_and_size(int *size, char *lib_name, char *funct_name)
{
    void * lib_pointer;
    void *(*embedded_function)();
    int type = 0;
    lib_pointer = dlopen(lib_name, RTLD_LAZY);
    if (lib_pointer != NULL) {
        *(void **) (&embedded_function) = dlsym(lib_pointer, "get_data_type_of_funct_return_value");
        int * temph = (int*) embedded_function(funct_name, size);
        type = *temph;
        xfree(temph);
    }
    return type;
}

char * funct_get_info_param( mmt_handler_t *mmt, enum_yes reg_tuple, char * input, tuple *a_tuple)
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
        a_tuple->data_type_id = mmt_attribute_get_data_type_typed(a_tuple->protocol_id, a_tuple->field_id);
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
        if(a_tuple->data == NULL){
            return NULL;
        }
        strncpy(a_tuple->data, start, end - start);
        ((char *) a_tuple->data)[end - start] = '\0';
        if (*end == ',') {
            end++;
            return end;
        }
        return NULL;
    }

    if (*end == ')')
        /* ')' closes the parameter list: nothing more to parse, so the
         * caller stops iterating — returning NULL is intentional. */
        return NULL;

    return NULL;
}

void create_boolean_expression(mmt_handler_t *mmt, enum_yes first_time, rule *a_rule, char *expression)
{
    //parse expression and create sub-tree, a_rule->value = top operator
    //((ARP.OPCODE == 2)&&(ARP.SRC_PROTO == ARP.SRC_PROTO.1))
    //OR, AND, NEQ, EQ, GT, GTE, LT, LTE, THEN, COMPUTE, XC, XCE, XD, XDE, XE, ADD, SUB, MUL, DIV
    //DE, DNE
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
            if(new_rule == NULL) return;
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
    } else if (*temp == 'D' && *(temp + 1) == 'E' && (*(temp + 2) == ' ' || *(temp + 2) == ')')) {
        // DE (Does Exitst)
        temp2 = temp + 3;
        a_rule->father->value = DE;
        create_boolean_expression(mmt, NO, a_rule->father, temp2);
    } else if (*temp == 'D' && *(temp + 1) == 'N' && *(temp + 2) == 'E' && (*(temp + 3) == ' ' || *(temp + 3) == ')')) {
        // DE (Does Not  Exitst)
        temp2 = temp + 4;
        a_rule->father->value = DNE;
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
        new_rule->t.data = (void *) get_xdata(new_rule->t.data_type_id, new_rule->t.data_size, (void *) (&s), YES);
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
        new_rule->t.data_type_id = mmt_attribute_get_data_type_typed(new_rule->t.protocol_id, new_rule->t.field_id);
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
            if(a_tuple == NULL) {
                xfree(new_rule);
                return;
            }
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
        if(top_tuple == NULL) {
            xfree(new_rule);
            return ;
        }
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
        enum_yes reg_tuple = YES;

        command2 = funct_get_info_param( mmt, reg_tuple, command2, a_tuple );
        while( command2 ) {
            new_tuple = (tuple *)xmalloc(sizeof (tuple));
            if(new_tuple == NULL){
                return;
            }
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
        /* F-BUG-103 (#209): a digit run longer than the 30-byte token buffer
         * is rejected instead of overflowing it (same convention as the
         * over-long quoted string above). */
        if (i >= (int)sizeof(token)) {
            (void)fprintf(stderr, "Error 3c: Number too long in boolean expression: %s", expression);
            exit(-1);
        }
        strncpy(token, temp, i);
        token[i] = '\0';

        // create new_rule
        new_rule = create_rule();
        if(new_rule == NULL) return;
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
        new_rule->t.data = (void *) get_xdata(new_rule->t.data_type_id, new_rule->t.data_size, (void *) token, NO);
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
    short depth = 0;
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
            if(a_rule == NULL){
                return 0;
            }
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
            if (a_rule == NULL)
            {
                return 0;
            }
            a_rule->type = SON;
            state = SON;
        } else if (xmlStrcmp(name, (const xmlChar*)"event") == 0) {
            a_rule = create_rule();
            if (a_rule == NULL)
            {
                return 0;
            }
            a_rule->type = SON;
            state = EVENT;
        }
    }
    int i;
    int count;
    count = xmlTextReaderAttributeCount(reader);
    if (count > 100) count = 100;
    for (i = 0; i < count; i++) {
        attribute_value[i] = xmlTextReaderGetAttributeNo(reader, i);
    }
    for (i = 0; i < count && i < 100; i++) {
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
    for (i = 0; i < count && i < 100; i++) {
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
        if(los!=NULL){
            if (los->list_of_sons == NULL)
            {
                los->list_of_sons = a_rule;
                a_rule->father = los;
            }
            else
            {
                a_temp = los->list_of_sons;
                while (a_temp->next != NULL)
                    a_temp = a_temp->next;
                a_temp->next = a_rule;
                a_rule->father = los;
                a_rule->prev = a_temp;
            }
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
        if (a_tuple == NULL)
        {
            return;
        }
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
