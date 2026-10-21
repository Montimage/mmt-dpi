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

    /* The node whose boolean_expression create_boolean_expression() is
     * compiling: the parser may climb back to it but never above it (#512). */
    static rule *expr_root = NULL;
    static const char *expr_text = NULL;

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
    a_rule->funct = NULL; //Only if XFUNCT leaf node: funct_name resolved at load
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

int create_father(rule *a_rule, short depth, enum_clean clean)
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
        if(top_father == NULL) return -1;
        top_father->node = a_rule;
        top_father->depth = depth;
        top_father->next = NULL;
        top_father->prev = NULL;
        bot_father = top_father;
    } else {
        temp = (father *) xmalloc(sizeof (father));
        if (temp == NULL)
            return -1;
        temp->node = a_rule;
        temp->depth = depth;
        temp->next = NULL;
        temp->prev = bot_father;
        bot_father->next = temp;
        bot_father = temp;
    }
    return 0;
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
    uint32_t l = 0;
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
            /* a 4-byte attribute: never an LP64 unsigned long (#511) */
            l = (uint32_t) atol(txt);
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
            /* the caller rejects the rule (#512) */
            (void)fprintf(stderr, "Error 2: Type [%ld], size [%d] not implemented yet, data type unknown.\n", type, size);
            xfree(data);
            return NULL;
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
        (void)fprintf(stderr, "Error 3b: Incorrect name in PROTO.FIELD.EVENT: %s\n", temp);
        return NULL;
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

int register_tuple(mmt_handler_t *mmt, tuple * a_tuple)
{
    int ret = 1;
    if (is_registered_attribute(mmt, a_tuple->protocol_id, a_tuple->field_id) == 0) {
        ret = register_extraction_attribute(mmt, a_tuple->protocol_id, a_tuple->field_id);
    }
    if (ret <= 0) {
        (void)fprintf(stderr, "Error 9b: in register_extraction_attribute proto=%ld, field=%ld. Value not available.\n", a_tuple->protocol_id, a_tuple->field_id);
        return -1;
    }
    return 0;
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
    while (*end != '(' && *end != ' ' && *end != '\0')end++;
    if (end == start || *end == '\0') {
        /* no name, or no parameter list: never scan past the string (#512) */
        (void)fprintf(stderr, "Error 3d: Incorrect function call: %s\n", input);
        return NULL;
    }
    output = xmalloc(end - start + 1);
    if(output == NULL) return NULL;
    strncpy(output, start, end - start);
    output[end - start] = '\0';
    //caller needs to free return value
    return output;
}

/* Number of parameters of the call "name(p1, ..., pn)": 0 for "name()",
 * -1 without a '(' ... ')' list. Parameters never contain ',' or ')'. */
int funct_count_params( const char *call )
{
    const char *p = strchr(call, '(');
    int n = 1;
    if (p == NULL || strchr(p, ')') == NULL) return -1;
    p++;
    while (*p == ' ') p++;
    if (*p == ')') return 0;
    for (; *p != ')'; p++) {
        if (*p == ',') n++;
    }
    return n;
}

/* Type of the value funct_name returns, as the library's
 * get_data_type_of_funct_return_value() reports it; -1 when the library or
 * that symbol is missing or it returns nothing (#511). */
static int funct_get_return_type_and_size(int *size, char *funct_name)
{
    int *(*type_of)(char *, int *);
    int type;
    embedded_funct_t f = embedded_funct_resolve("get_data_type_of_funct_return_value");
    if (f == NULL) return -1;
    type_of = (int *(*)(char *, int *)) f;
    int * temph = type_of(funct_name, size);
    if (temph == NULL) {
        (void)fprintf(stderr, "Error 3h: No return type for embedded function %s\n", funct_name);
        return -1;
    }
    type = *temph;
    xfree(temph);
    return type;
}

/* Embedded #function(...) call, checked once at load (#511): the call has
 * a parameter list of at most EMBEDDED_FUNCT_MAX_PARAMS entries and the
 * library exports the function. Returns it, or NULL with the reason on
 * stderr. Used for expression leaves and for #function reactions. */
static embedded_funct_t funct_check_call(const char *call, const char *funct_name)
{
    int n = funct_count_params(call);
    if (n < 0) {
        (void)fprintf(stderr, "Error 3d: Incorrect function call: %s\n", call);
        return NULL;
    }
    if (n > EMBEDDED_FUNCT_MAX_PARAMS) {
        (void)fprintf(stderr, "Error 3e: Embedded function %s takes %d parameters, at most %d are supported\n",
                funct_name, n, EMBEDDED_FUNCT_MAX_PARAMS);
        return NULL;
    }
    return embedded_funct_resolve(funct_name);
}

int funct_get_info_param( mmt_handler_t *mmt, enum_yes reg_tuple, char * input, tuple *a_tuple, char **next)
{
    //input: param1,...) or param1) or )
    //*next: NULL if no params left, else the text after the ','
    //returns 0, or -1 when the parameter cannot be parsed (#512) — the old
    //NULL return also stood for "last parameter", so errors were invisible
    short ref = 0;
    char *start = input;
    char *end = NULL;
    *next = NULL;
    while (*start == ' ')start++;
    end = strpbrk(start, ",)");
    if (end == NULL) {
        (void)fprintf(stderr, "Error 3f: Unterminated parameter list: %s\n", input);
        return -1;
    }
    if (isalpha(*start)) {
        //PROTO.FIELD or PROTO.FIELD.EVENT
        ref = 0;
        if (tokenize(start, &token2, &token3, &ref) == NULL) return -1;
        a_tuple->protocol_id = get_protocol_id_by_name(token2);
        a_tuple->field_id = get_attribute_id_by_protocol_id_and_attribute_name(a_tuple->protocol_id, token3);
        if (a_tuple->protocol_id <= 0 || a_tuple->field_id <= 0) {
            (void)fprintf(stderr, "Error 9a: Unknown attribute %s.%s\n", token2, token3);
            return -1;
        }
        a_tuple->data_type_id = mmt_attribute_get_data_type_typed(a_tuple->protocol_id, a_tuple->field_id);
        a_tuple->data_size = get_data_size_by_proto_and_field_ids(a_tuple->protocol_id, a_tuple->field_id);
        a_tuple->event_id = ref;
        if (ref > 0 || reg_tuple == YES) {
            if (register_tuple( mmt, a_tuple ) != 0) return -1;
            add_tuple_to_list_of_tuples(a_tuple);
        }
    } else if (isdigit(*start)) {
        a_tuple->data = xmalloc(end - start + 1);
        if(a_tuple->data == NULL){
            return -1;
        }
        strncpy(a_tuple->data, start, end - start);
        ((char *) a_tuple->data)[end - start] = '\0';
    } else if (start == end && *end == ')') {
        /* ')' closes an empty parameter list: nothing to parse */
        return 0;
    } else {
        (void)fprintf(stderr, "Error 3f: Unsupported function parameter: %s\n", input);
        return -1;
    }
    //not NULL: a next param exists
    if (*end == ',') {
        const char *after = end + 1;
        while (*after == ' ') after++;
        if (*after == ')' || *after == ',') {
            (void)fprintf(stderr, "Error 3f: Empty parameter in function call: %s\n", input);
            return -1;
        }
        *next = end + 1;
    }
    return 0;
}

static void append_son(rule *a_rule, rule *new_rule)
{
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
}

static tuple *new_param_tuple(void)
{
    tuple *t = (tuple *) xmalloc(sizeof (tuple));
    if (t == NULL) return NULL;
    t->protocol_id = -1;
    t->field_id = -1;
    t->data_type_id = -1;
    t->data_size = -1;
    t->event_id = -1;
    t->valid = NOT_YET; //not used in this context
    t->data = NULL;
    t->next = NULL;
    return t;
}

static int create_boolean_expression(mmt_handler_t *mmt, enum_yes first_time, rule *a_rule, char *expression);

/* An operator applies to the node holding its left operand's father: climb
 * one level — never above the node the expression belongs to (#512: a
 * leading operator or a surplus ')' used to dereference a NULL father or
 * rewrite the enclosing operator). value < 0 climbs without setting. */
static int climb_with_operator(mmt_handler_t *mmt, rule *a_rule, short value, char *rest)
{
    if (a_rule == expr_root || a_rule->father == NULL) {
        (void)fprintf(stderr, "Error 37b: Unbalanced boolean expression: %s\n", expr_text);
        return -1;
    }
    if (value >= 0) a_rule->father->value = value;
    return create_boolean_expression(mmt, NO, a_rule->father, rest);
}

/* Returns 0, or -1 with the reason on stderr (#512: no more process exits).
 * Each node is linked into the tree as soon as it is created, so the caller
 * frees a failed expression by freeing the tree it belongs to. */
static int create_boolean_expression(mmt_handler_t *mmt, enum_yes first_time, rule *a_rule, char *expression)
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
            return create_boolean_expression(mmt, NO, a_rule, temp2);
        }
        //create new_rule
        new_rule = create_rule();
        if(new_rule == NULL) return -1;
        new_rule->type = SON;
        new_rule->value = NOP;
        append_son(a_rule, new_rule);
        return create_boolean_expression(mmt, NO, new_rule, temp2);
    } else if (*temp == ')') {
        //go up one; a surplus ')' that ends the expression is tolerated, as
        //it always was (the old parser stopped on the empty rest)
        if (a_rule == expr_root || a_rule->father == NULL) {
            char *rest = temp + 1;
            while (isspace(*rest)) rest++;
            if (*rest == '\0') return 0;
        }
        return climb_with_operator(mmt, a_rule, -1, temp + 1);
    } else if (*temp == '\0') {
        //do nothing
        return 0;
    } else if (*temp == 'X' && *(temp + 1) == 'E' && *(temp + 2) == ' ') {
        //XE (identical to a string)
        return climb_with_operator(mmt, a_rule, XE, temp + 2);
    } else if (*temp == 'X' && *(temp + 1) == 'C' && *(temp + 2) == ' ') {
        return climb_with_operator(mmt, a_rule, XC, temp + 2);
    } else if (*temp == 'X' && *(temp + 1) == 'D' && *(temp + 2) == ' ') {
        return climb_with_operator(mmt, a_rule, XD, temp + 2);
    } else if (*temp == 'X' && *(temp + 1) == 'C' && *(temp + 2) == 'E' && *(temp + 3) == ' ') {
        return climb_with_operator(mmt, a_rule, XCE, temp + 3);
    } else if (*temp == 'X' && *(temp + 1) == 'D' && *(temp + 2) == 'E' && *(temp + 3) == ' ') {
        return climb_with_operator(mmt, a_rule, XDE, temp + 3);
    } else if (*temp == 'I' && *(temp + 1) == 'N' && *(temp + 2) == ' ') {
        //IN+blank
        return climb_with_operator(mmt, a_rule, XIN, temp + 3);
    } else if (*temp == 'D' && *(temp + 1) == 'E' && (*(temp + 2) == ' ' || *(temp + 2) == ')')) {
        // DE (Does Exitst)
        return climb_with_operator(mmt, a_rule, DE, temp + 3);
    } else if (*temp == 'D' && *(temp + 1) == 'N' && *(temp + 2) == 'E' && (*(temp + 3) == ' ' || *(temp + 3) == ')')) {
        // DE (Does Not  Exitst)
        return climb_with_operator(mmt, a_rule, DNE, temp + 4);
    } else if (*temp == '\'') {
        // 'string'
        temp++;
        temp2 = temp;
        i = 0;
        while (*temp2 != '\'' && *temp2 != '\0' && i < 1000) {
            temp2++;
            i++;
        }
        if (i > 999 || *temp2 != '\'') {
            (void)fprintf(stderr, "Error 3a: Incorrect string in boolean expression: %s\n", expression);
            return -1;
        }
        i = temp2 - temp;
        mmt_string_data_t s;
        strncpy((char*)s.data, temp, i);
        s.data[i] = '\0';
        temp2++; //skip the last '\''
        s.len = i + 1;
        //create new_rule
        new_rule = create_rule();
        if (new_rule == NULL) return -1;
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
        append_son(a_rule, new_rule);
        new_rule->t.data = (void *) get_xdata(new_rule->t.data_type_id, new_rule->t.data_size, (void *) (&s), YES);
        if (new_rule->t.data == NULL) {
            (void)fprintf(stderr, "Error 3g: Constant '%s' cannot be read as the type of its operand in: %s\n", (char *)s.data, expression);
            return -1;
        }
        return create_boolean_expression(mmt, NO, new_rule, temp2);
    } else if (isalpha(*temp) || *temp == '_') {
        //PROTO.FIELD.EVENT
        temp2 = tokenize(temp, &token2, &token3, &ref);
        if (temp2 == NULL) return -1;
        //create new_rule
        new_rule = create_rule();
        if (new_rule == NULL) return -1;
        new_rule->type = LEAF;
        new_rule->value = XVAR;
        new_rule->t.protocol_id = get_protocol_id_by_name(token2);
        new_rule->t.field_id = get_attribute_id_by_protocol_id_and_attribute_name(new_rule->t.protocol_id, token3);
        append_son(a_rule, new_rule);
        if (new_rule->t.protocol_id <= 0 || new_rule->t.field_id <= 0) {
            (void)fprintf(stderr, "Error 9a: Unknown attribute %s.%s in boolean expression: %s\n", token2, token3, expression);
            return -1;
        }
        new_rule->t.data_type_id = mmt_attribute_get_data_type_typed(new_rule->t.protocol_id, new_rule->t.field_id);
        int ret = 1;
        if (is_registered_attribute(mmt, new_rule->t.protocol_id, new_rule->t.field_id) == 0) {
            ret = register_extraction_attribute(mmt, new_rule->t.protocol_id, new_rule->t.field_id);
        }
        if (ret <= 0) {
            (void)fprintf(stderr, "Error 9: in register_extraction_attribute proto=%ld, field=%ld.Value not available.\n", new_rule->t.protocol_id, new_rule->t.field_id);
            return -1;
        }
        if (ref > 0) {
            new_rule->t.event_id = ref;
            tuple * a_tuple = (tuple *) xmalloc(sizeof (tuple));
            if(a_tuple == NULL) {
                return -1;
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
        return create_boolean_expression(mmt, NO, new_rule, temp2);
    } else if (*temp == '#') {
        //Embedded function: #function_name(param1,param2,...) where param is a numeric constant or of the form PROTO.FIELD.EVENT_ID
        char *what_to_do = temp;
        char * funct_name = funct_extract_name(what_to_do);
        //funct_name is a malloc that contains the name
        int data_size = 0;
        if (funct_name == NULL) return -1;

        //create new_rule
        //new_rule->t contains info on return value and new_rule->t.next... contains info on parameters
        new_rule = create_rule();
        if (new_rule == NULL) {
            xfree(funct_name);
            return -1;
        }
        new_rule->type = LEAF;
        new_rule->value = XFUNCT;
        new_rule->funct_name = funct_name; //do not free funct_name
        append_son(a_rule, new_rule);

        //#511: resolve the symbol and bound the arity once, here, instead
        //of an unchecked dlsym() and an unbounded data[] on every packet
        new_rule->funct = funct_check_call(what_to_do, funct_name);
        if (new_rule->funct == NULL) return -1;
        int return_type = funct_get_return_type_and_size(&data_size, funct_name);
        if (return_type < 0) return -1;
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

        //t.next lists one tuple per parameter; an empty list leaves it
        //NULL so the function is called without arguments
        char * command2 = command;
        tuple ** link = &new_rule->t.next;
        enum_yes reg_tuple = YES;
        while (*command2 != ')') {
            tuple * new_tuple = new_param_tuple();
            if (new_tuple == NULL) return -1;
            *link = new_tuple;
            link = &new_tuple->next;
            if (funct_get_info_param( mmt, reg_tuple, command2, new_tuple, &command2 ) != 0) return -1;
            if (new_tuple->protocol_id == -1 && new_tuple->data == NULL) {
                (void)fprintf(stderr, "Error 3f: Empty parameter in function call: %s\n", what_to_do);
                return -1;
            }
            if (command2 == NULL) break;
        }
        return create_boolean_expression(mmt, NO, new_rule, strchr(command, ')') + 1);
    } else if (isdigit(*temp)) {
        // 1.0
        temp2 = temp;
        while (isxdigit(*temp2) || *temp2 == '.')temp2++;
        i = temp2 - temp;
        /* F-BUG-103 (#209): a digit run longer than the 30-byte token buffer
         * is rejected instead of overflowing it (same convention as the
         * over-long quoted string above). */
        if (i >= (int)sizeof(token)) {
            (void)fprintf(stderr, "Error 3c: Number too long in boolean expression: %s\n", expression);
            return -1;
        }
        strncpy(token, temp, i);
        token[i] = '\0';

        // create new_rule
        new_rule = create_rule();
        if(new_rule == NULL) return -1;
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
        append_son(a_rule, new_rule);
        new_rule->t.data = (void *) get_xdata(new_rule->t.data_type_id, new_rule->t.data_size, (void *) token, NO);
        if (new_rule->t.data == NULL) {
            (void)fprintf(stderr, "Error 3g: Constant %s cannot be read as the type of its operand in: %s\n", token, expression);
            return -1;
        }
        return create_boolean_expression(mmt, NO, new_rule, temp2);
    } else if (*temp == '=' && *(temp + 1) == '=') {
        // ==
        return climb_with_operator(mmt, a_rule, EQ, temp + 2);
    } else if (*temp == '|' && *(temp + 1) == '|') {
        // ||
        return climb_with_operator(mmt, a_rule, XOR, temp + 2);
    } else if (*temp == '!' && *(temp + 1) == '=') {
        // !=
        return climb_with_operator(mmt, a_rule, NEQ, temp + 2);
    } else if (*temp == '>' && *(temp + 1) != '=') {
        // >
        return climb_with_operator(mmt, a_rule, GT, temp + 1);
    } else if (*temp == '>' && *(temp + 1) == '=') {
        // >=
        return climb_with_operator(mmt, a_rule, GTE, temp + 2);
    } else if (*temp == '<' && *(temp + 1) != '=') {
        // <
        return climb_with_operator(mmt, a_rule, LT, temp + 1);
    } else if (*temp == '<' && *(temp + 1) == '=') {
        // <=
        return climb_with_operator(mmt, a_rule, LTE, temp + 2);
    } else if (*temp == '&' && *(temp + 1) == '&') {
        // &&
        return climb_with_operator(mmt, a_rule, XAND, temp + 2);
    } else if (*temp == '+') {
        return climb_with_operator(mmt, a_rule, ADD, temp + 1);
    } else if (*temp == '-') {
        return climb_with_operator(mmt, a_rule, SUB, temp + 1);
    } else if (*temp == '*') {
        return climb_with_operator(mmt, a_rule, MUL, temp + 1);
    } else if (*temp == '/') {
        return climb_with_operator(mmt, a_rule, DIV, temp + 1);
    }
    (void)fprintf(stderr, "Error 37: Illegal character found in boolean expression: %c%c.\n", *temp, *(temp + 1));
    return -1;
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

static void free_tuple_list(tuple *t)
{
    while (t != NULL) {
        tuple *n = t->next;
        xfree(t->data);
        xfree(t);
        t = n;
    }
}

/* Frees a rule tree the loader built (#512: a failed load releases what it
 * built). Rule instances are not trees of this kind — they share t.next and
 * delay_units with their template — so this never runs on one. */
static void free_rule_tree(rule *r)
{
    rule *s, *n;
    if (r == NULL) return;
    for (s = r->list_of_sons; s != NULL; s = n) {
        n = s->next;
        free_rule_tree(s);
    }
    if (r->value == XCON && r->t.data != NULL) {
        /* get_xdata() constants that own a second allocation */
        if (r->t.data_type_id == MMT_HEADER_LINE)
            xfree((void *) ((mmt_header_line_t *) r->t.data)->ptr);
        else if (r->t.data_type_id == MMT_STRING_DATA_POINTER && r->t.data_size >= (int) sizeof (char *))
            xfree(*(char **) r->t.data);
    }
    xfree(r->t.data);
    free_tuple_list(r->t.next);
    free_tuple_list(r->list_of_tuples);
    free_tuple_list(r->list_of_tuples_to_print);
    xfree(r->description);
    xfree(r->funct_name);
    xfree(r->if_satisfied);
    xfree(r->if_not_satisfied);
    xfree(r->delay_units);
    xfree(r->keep_state);
    xfree(r->json_history);
    xfree(r);
}

void free_rules( void )
{
    rule *r = top_rule, *n;
    while (r != NULL) {
        n = r->next;
        free_rule_tree(r);
        r = n;
    }
    top_rule = NULL;
    bot_rule = NULL;
    root_rule = NULL;
    while (bot_father != NULL) eliminate_bot_father();
    expr_root = NULL;
    expr_text = NULL;
}

/* A #function(...) reaction is checked at load like an expression leaf
 * (#511): a missing function or too many parameters reject the rule. */
static int check_reaction(const char *what_to_do)
{
    char *funct_name;
    embedded_funct_t f;
    if (what_to_do == NULL) return -1; /* strdup() failed */
    if (strchr(what_to_do, '#') == NULL) return 0;
    funct_name = funct_extract_name(strchr(what_to_do, '#'));
    if (funct_name == NULL) return -1;
    f = funct_check_call(what_to_do, funct_name);
    xfree(funct_name);
    return (f == NULL) ? -1 : 0;
}

/* delay_min/delay_max: "<num>", "<num>-" or "<num>+" — never empty (#512:
 * the suffix test read index -1 of an empty value) */
static int read_delay(rule *a_rule, const xmlChar *value, const char *name, char suffix, short *not_equal, double *delay)
{
    int len = xmlStrlen(value);
    if (len == 0) {
        (void)fprintf(stderr, "Error 12b: Empty %s attribute.\n", name);
        return -1;
    }
    if (value[len - 1] == (xmlChar) suffix) {
        *not_equal = YES;
    }
    long long ll = atoll((const char*)value);
    if (ll == 0) *delay = 0;
    else *delay = get_double_in_sec (a_rule->delay_units, ll);
    return 0;
}

/* Applies one XML attribute to a_rule. Returns 0, or -1 with the reason on
 * stderr. */
static int apply_attribute(mmt_handler_t *mmt, rule *a_rule, const xmlChar *attribute_name, const xmlChar *v)
{
    if (xmlStrcmp(attribute_name, (const xmlChar*)"value") == 0) {
        if (xmlStrcmp(v, (const xmlChar*)"THEN") == 0) a_rule->value = THEN;
        else if (xmlStrcmp(v, (const xmlChar*)"COMPUTE") == 0) a_rule->value = COMPUTE;
        else if (xmlStrcmp(v, (const xmlChar*)"OR") == 0) a_rule->value = OR;
        else if (xmlStrcmp(v, (const xmlChar*)"AND") == 0) a_rule->value = AND;
        else if (xmlStrcmp(v, (const xmlChar*)"NOT") == 0) a_rule->value = NOT;
        else if (xmlStrcmp(v, (const xmlChar*)"REPEAT") == 0) a_rule->value = REPEAT;
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"event_id") == 0) {
        a_rule->event_id = atol((const char*)v);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"keep_state") == 0) {
        a_rule->keep_state = strdup((const char*)v);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"boolean_expression") == 0) {
        expr_root = a_rule;
        expr_text = (const char *) v;
        return create_boolean_expression(mmt, YES, a_rule, (char *) v);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"delay_units") == 0) {
        a_rule->delay_units = strdup((const char*)v); //Y,M,D,H,m,s(default),ms,mms
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"delay_max") == 0) {
        //<num>,<num>-
        return read_delay(a_rule, v, "delay_max", '-', &a_rule->not_equal_max, &a_rule->delay_max);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"description") == 0) {
        a_rule->description = strdup((const char*)v);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"property_id") == 0) {
        a_rule->property_id = atoi((const char*)v);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"if_not_satisfied") == 0) {
        a_rule->if_not_satisfied = strdup((const char*)v);
        return check_reaction(a_rule->if_not_satisfied);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"if_satisfied") == 0) {
        a_rule->if_satisfied = strdup((const char*)v);
        return check_reaction(a_rule->if_satisfied);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"type_property") == 0) {
        if (xmlStrncmp(v, (const xmlChar*)"ATTACK", 3) == 0) a_rule->type_rule = ATTACK;
        else if (xmlStrncmp(v, (const xmlChar*)"EVASION", 3) == 0) a_rule->type_rule = EVASION;
        else if (xmlStrncmp(v, (const xmlChar*)"SECURITY_RULE", 3) == 0) a_rule->type_rule = SECURITY_RULE;
        else if (xmlStrncmp(v, (const xmlChar*)"TEST", 3) == 0) a_rule->type_rule = TEST;
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"delay_min") == 0) {
        //<num>,<num>+
        return read_delay(a_rule, v, "delay_min", '+', &a_rule->not_equal_min, &a_rule->delay_min);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"counter_max") == 0) {
        a_rule->counter_max = atoi((const char*)v);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"counter_min") == 0) {
        a_rule->counter_min = atoi((const char*)v);
    } else if (xmlStrcmp(attribute_name, (const xmlChar*)"repeat_times") == 0) {
        a_rule->repeat_times = atoi((const char*)v);
    }
    return 0;
}

/* Attaches an <operator>/<event> node to its parent on the father stack.
 * Returns -1 when the tree has no parent for it (#512: an element outside
 * a <property>, or at its property's depth, underflowed the stack). */
static int attach_to_father(rule *a_rule, short depth)
{
    rule *los = NULL;
    if (bot_father == NULL) {
        los = NULL;
    } else if (bot_father->depth < depth) {
        los = bot_father->node;
        if (create_father(a_rule, depth, DONT_CLEAN) != 0) return -1;
    } else if (bot_father->depth == depth) {
        if (bot_father->prev != NULL) {
            los = bot_father->prev->node;
            bot_father->node = a_rule;
        }
    } else if (bot_father->prev != NULL && bot_father->prev->prev != NULL) {
        los = bot_father->prev->prev->node;
        bot_father->prev->node = a_rule;
        eliminate_bot_father();
    }
    if (los == NULL) {
        (void)fprintf(stderr, "Error 12c: <operator>/<event> outside a <property> branch.\n");
        return -1;
    }
    append_son(los, a_rule);
    return 0;
}

/* Returns 0, or -1 when the node makes the rule file invalid (#512: the
 * loader used to trust any well-formed XML and end the process on the rest). */
static int processNode( mmt_handler_t *mmt, xmlTextReaderPtr reader)
{
    const xmlChar *name, *attribute_value[100], *attribute_name;
    rule *a_rule = NULL;
    int state = 0;
    int ret;
    int err = 0;
    short depth = 0;
    attribute_name = NULL;
    for (ret = 0; ret < 100; ret++)attribute_value[ret] = NULL;
    name = xmlTextReaderConstName(reader);
    if (name == NULL || name[0] == '#') return 0;
    ret = xmlTextReaderNodeType(reader);
    depth = xmlTextReaderDepth(reader);
    if (ret == XML_READER_TYPE_END_ELEMENT) {
        while (bot_father != NULL && bot_father->depth >= depth) eliminate_bot_father();
        return 0;
    }
    if (ret != XML_READER_TYPE_ELEMENT) return 0;
    if (xmlStrcmp(name, (const xmlChar*)"beginning") == 0) {
        return 0;
    } else if (xmlStrcmp(name, (const xmlChar*)"property") == 0) {
        a_rule = create_rule();
        if(a_rule == NULL){
            return -1;
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
        if (create_father(a_rule, depth, CLEAN) != 0) return -1;
    } else if (xmlStrcmp(name, (const xmlChar*)"operator") == 0) {
        a_rule = create_rule();
        if (a_rule == NULL)
        {
            return -1;
        }
        a_rule->type = SON;
        state = SON;
    } else if (xmlStrcmp(name, (const xmlChar*)"event") == 0) {
        a_rule = create_rule();
        if (a_rule == NULL)
        {
            return -1;
        }
        a_rule->type = SON;
        state = EVENT;
    } else {
        (void)fprintf(stderr, "Error 12a: Unknown element <%s>.\n", (const char *) name);
        return -1;
    }
    if (state != ROOT && root_rule == NULL) {
        /* expressions file their event references in root_rule */
        (void)fprintf(stderr, "Error 12c: <%s> outside a <property>.\n", (const char *) name);
        free_rule_tree(a_rule);
        return -1;
    }
    int i;
    int count;
    count = xmlTextReaderAttributeCount(reader);
    if (count > 100) count = 100;
    for (i = 0; i < count; i++) {
        attribute_value[i] = xmlTextReaderGetAttributeNo(reader, i);
    }
    for (i = 0; i < count && err == 0; i++) {
        xmlTextReaderMoveToAttributeNo(reader, i);
        attribute_name = xmlTextReaderConstName(reader);
        if (attribute_name == NULL || attribute_value[i] == NULL) continue;
        err = apply_attribute(mmt, a_rule, attribute_name, attribute_value[i]);
    }
    expr_root = NULL;
    expr_text = NULL;
    for (i = 0; i < count && i < 100; i++) {
        if (attribute_value[i] != NULL) {
            xfree((char *) attribute_value[i]);
            attribute_value[i] = NULL;
        }
    }
    if (state == ROOT) {
        /* already on the rule list: free_rules() releases it */
        return err;
    }
    if (err == 0) err = attach_to_father(a_rule, depth);
    if (err != 0) free_rule_tree(a_rule);
    return err;
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

/* THEN needs both branches, AND two sons, OR/REPEAT one, NOT exactly one:
 * verify() dereferences them unchecked (#512). Expression nodes (the
 * comparison/arithmetic operators and their leaves) are not checked. */
static int validate_rule_tree(const rule *r, int property_id)
{
    const rule *s;
    int n = 0;
    for (s = r->list_of_sons; s != NULL; s = s->next) n++;
    if ((r->value == THEN && n != 2) || (r->value == AND && n < 2) ||
            ((r->value == OR || r->value == REPEAT) && n < 1) || (r->value == NOT && n != 1)) {
        (void)fprintf(stderr, "Error 12d: %s node with %d branch(es) in property %d.\n",
                r->value == THEN ? "THEN" : r->value == AND ? "AND" : r->value == OR ? "OR" :
                r->value == NOT ? "NOT" : "REPEAT", n, property_id);
        return -1;
    }
    if (r->value == THEN || r->value == AND || r->value == OR || r->value == NOT || r->value == REPEAT) {
        for (s = r->list_of_sons; s != NULL; s = s->next)
            if (validate_rule_tree(s, property_id) != 0) return -1;
    }
    return 0;
}

/* Returns 0, or -1 with the reason on stderr after freeing every rule the
 * failed load built (#512). */
int read_rules( mmt_handler_t *mmt )
{
    LIBXML_TEST_VERSION
    xmlTextReaderPtr reader;
    int ret;
    int invalid = 0;
    rule * temp;

    op->timestamp_proto_id = p_meta;
    op->timestamp_field_id = a_utime;

    /* every verdict is stamped from META.UTIME — registered on this handler
     * (it used to be registered once per process, from the first
     * expression, through a function-static flag) */
    if (is_registered_attribute(mmt, p_meta, a_utime) != 1 &&
            register_extraction_attribute(mmt, p_meta, a_utime) <= 0) {
        (void)fprintf(stderr, "Error 8: in register_extraction_attribute proto=META, field=UTIME. Timestamp not available.\n");
        return -1;
    }

    reader = xmlReaderForFile(op->RuleFileName, NULL, 0);
    if (reader == NULL) {
        (void)fprintf(stderr, "Error 14: Unable to open the XML properties file: %s.\n", op->RuleFileName);
        return -1;
    }
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
        if (processNode( mmt, reader ) != 0) {
            invalid = 1;
            break;
        }
        ret = xmlTextReaderRead(reader);
    }
    xmlFreeTextReader(reader);
    if (invalid) {
        (void)fprintf(stderr, "Error 13b: in XML properties file: %s. Invalid rule.\n", op->RuleFileName);
        free_rules();
        return -1;
    }
    if (ret != 0) {
        (void)fprintf(stderr, "Error 13: in XML properties file: %s. Parsing failed.\n", op->RuleFileName);
        free_rules();
        return -1;
    }
    for (temp = top_rule; temp != NULL; temp = temp->next) {
        if (validate_rule_tree(temp, temp->property_id) != 0) {
            (void)fprintf(stderr, "Error 13b: in XML properties file: %s. Invalid rule.\n", op->RuleFileName);
            free_rules();
            return -1;
        }
    }
    //Need to recuperate what attributes will need to be printed out (<proto_id, field_id, data_type_id>)
    temp = top_rule;
    while (temp) {
        recuperate_attributes(temp, temp);
        temp = temp->next;
    }
    return 0;
}
