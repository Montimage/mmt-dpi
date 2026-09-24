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
 *       Filename:  tips_report.c
 *    Description:  Open Source prototype version of the MMT_Security library
 *                  that allows analysing network traffic
 *                  to detect normal or abnormal behaviour.
 *
 *    Responsibility: reporting — verdict formatting, JSON history
 *    accumulation (store_history/store_tuples), the user callback
 *    dispatch (rule_is_satisfied_or_not/detected_corrupted_message),
 *    reaction command generation and the end-of-run summaries.
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

    static long long corr_mess = 0;

/* F-BUG-092 (#209): control bytes escape as \u + 4 hex digits — up to 6
 * output bytes per
 * input byte — so the destination is size*6+1, non-positive sizes are
 * rejected, and the loop tracks the remaining capacity. */
char * convert_string_to_json_compatible (char * p, int size){
    char * result = NULL;
    char *c = NULL;
    char *r = NULL;
    int pos = 0;
    size_t remaining;
    if (p == NULL || size <= 0) return NULL;
    if ((size_t) size > (SIZE_MAX - 1) / 6) return NULL;
    c = p;
    result = xmalloc ((size_t) size * 6 + 1);
    r = result;
    if(r == NULL) return NULL;
    *r = '\0';
    remaining = (size_t) size * 6; /* keep the last byte for the terminator */
    for (pos=0; pos<size && remaining > 0; pos++){
        const char *esc = NULL;
        switch (*c) {
            case  '"': esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\b': esc = "\\b"; break;
            case '\f': esc = "\\f"; break;
            case '\n': esc = "\\n"; break;
            case '\r': esc = "\\r"; break;
            case '\t': esc = "\\t"; break;
            default:
                if ((unsigned char) *c <= '\x1f') {
                    if (remaining < 6) { c++; goto done; }
                    snprintf(r, 7, "\\u%04x", (int)(unsigned char)(*c));
                    r += 6;
                    remaining -= 6;
            	} else {
                    *r = *c; r++;
                    remaining--;
            	}
                break;
        } //end of switch
        if (esc != NULL) {
            if (remaining < 2) { c++; goto done; }
            memcpy(r, esc, 2); r += 2;
            remaining -= 2;
        }
        //end string
        *r = '\0';
        c++;
    } //end of for
done:
    *r = '\0';
    return result;
}

static void json_grow_append(char **buf, size_t *cap, const char *src) {
    if (!buf || !cap || !src) return;
    size_t cur = strlen(*buf);
    size_t add = strlen(src);
    if (cur + add + 1 > *cap) {
        size_t newcap = *cap * 2;
        while (newcap < cur + add + 1) newcap *= 2;
        char *nb = xmalloc(newcap);
        if (!nb) return;
        memcpy(nb, *buf, cur + 1);
        xfree(*buf);
        *buf = nb;
        *cap = newcap;
    }
    memcpy(*buf + cur, src, add + 1);
}

void store_history( verify_ctx_t *ctx, enum_operation_type context, rule *curr_rule, char *cause, short event_id )
{
    unsigned long L1=0,L2=0,L3=0,L4=0;
    //store data on packet so that they can be printed if rule is satisfied
    void * data1 = NULL;
    void * data2 = NULL;
    long type = 0;
    char * buff =NULL;
    mmt_binary_data_t *db1;
    int data_size = 0, j = 0, data_pointer_size = 0;
    char * data_pointer = NULL;
    char * new_data_pointer = NULL;
    struct timeval tvp;
    size_t json_cap = 65536, json_cap1 = 8192;
    char *json_buff=xcalloc(json_cap,1);
    if(json_buff == NULL) return;
    char *json_buff1=xcalloc(json_cap1,1);
    if (json_buff1 == NULL) {
        xfree(json_buff);
        return;
    }
    char *temp_MAC;
    //mmt_header_line_t *hl;
    void *data_ptr;

    tvp.tv_sec=0;
    tvp.tv_usec=0;
    {
        void *utime = get_attribute_extracted_data(ctx->pkt, PROTO_META, META_UTIME);
        if (utime != NULL) tvp = *(struct timeval *) utime;
    }

    snprintf(json_buff, json_cap, "\"timestamp\":%lu.%06lu", tvp.tv_sec, (long) tvp.tv_usec);

    int having_ip_src = 0, having_ip_dst = 0, having_mac_src = 0, having_mac_dst = 0;
    const char *proto_name, *att_name;

    if (cause != NULL && *cause != '\0') {
        snprintf(json_buff1, json_cap1, ",\"description\":\"%s\"", cause);
        json_grow_append(&json_buff, &json_cap, json_buff1);
        json_grow_append(&json_buff, &json_cap, ",\"attributes\":[");

        int num_attr = 0;
        unsigned long tmp_lu=0;
        //printout all the attributes
        tuple * temp = ctx->curr_root->list_of_tuples_to_print;
        while (temp) {
            if(temp->protocol_id<1||temp->field_id<1){
              temp=temp->next;
              continue;
            }
            data1 = get_attribute_extracted_data(ctx->pkt, temp->protocol_id, temp->field_id);
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
                case MMT_DATA_IP6_ADDR: {
                    char ip6_str[INET6_ADDRSTRLEN];
                    if (inet_ntop(AF_INET6, data1, ip6_str, sizeof(ip6_str)) != NULL) {
                        snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%s\"},", proto_name, att_name, ip6_str);
                        json_grow_append(&json_buff, &json_cap, json_buff1);
                    }
                    break;
                }
                case MMT_DATA_FLOAT:
                    snprintf(json_buff1, json_cap1, "{\"%s.%s\":%f},", proto_name,
                            att_name, (double) *(float*) (data1));
                    json_grow_append(&json_buff, &json_cap, json_buff1);
                    break;
                case MMT_DATA_MAC_ADDR:
                    temp_MAC = xmalloc(22);
                    if (temp_MAC == NULL) goto cleanup; /* F-BUG-096: one exit frees both JSON buffers */
                    convert_mac_bytes_to_string(&temp_MAC, (unsigned char *) data1);
                    snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%s\"},", proto_name, att_name, temp_MAC);
                    json_grow_append(&json_buff, &json_cap, json_buff1);
                    xfree(temp_MAC);
                    break;
                case MMT_DATA_TIMEVAL: {
                    struct timeval tv = *(struct timeval *) (data1);
                    snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%lu.%06lu\"},", proto_name,
                            att_name, tv.tv_sec, (long) tv.tv_usec);
                    json_grow_append(&json_buff, &json_cap, json_buff1);
                    break;
                }
                case MMT_DATA_IP_ADDR:
                    if(proto_name!=NULL && att_name!=NULL && *((char*)data1)!=0){
                       L1 = (*(unsigned long*)(data1)&0x000000ff);
                       L2 = (*(unsigned long*)(data1)&0x0000ff00)>>8;
                       L3 = (*(unsigned long*)(data1)&0x00ff0000)>>16;
                       L4 = (*(unsigned long*)(data1)&0xff000000)>>24;
                       snprintf(json_buff1, json_cap1,"{\"%s.%s\":\"%lu.%lu.%lu.%lu\"},", proto_name, att_name, L1, L2, L3, L4);
                    }else
                       snprintf(json_buff1, json_cap1,"{\"x.x\":\"0.0.0.0\"},");
                    json_grow_append(&json_buff, &json_cap, json_buff1);
                    break;
                case MMT_U16_DATA:
                    snprintf(json_buff1, json_cap1, "{\"%s.%s\":%u},", proto_name,
                            att_name, *(unsigned short*) (data1));
                    json_grow_append(&json_buff, &json_cap, json_buff1);
                    break;
                case MMT_U32_DATA:
                    tmp_lu=*(uint32_t*) data1;
                    snprintf(json_buff1, json_cap1, "{\"%s.%s\":%lu},", proto_name,
                            att_name, tmp_lu);
                    json_grow_append(&json_buff, &json_cap, json_buff1);
                    break;
                case MMT_U64_DATA:
                case MMT_DATA_POINT:
                    snprintf(json_buff1, json_cap1, "{\"%s.%s\":%"PRIu64"},", proto_name,
                            att_name, *(uint64_t*) (data1));
                    json_grow_append(&json_buff, &json_cap, json_buff1);
                    break;
                case MMT_U8_DATA:
                case MMT_DATA_CHAR:
                    snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%u\"},", proto_name,
                            att_name, *(unsigned char*) (data1));
                    json_grow_append(&json_buff, &json_cap, json_buff1);
                    break;
                case MMT_HEADER_LINE: {
                	//parse_mmt_header_line( &data1, & data_size );
                    int hl_len = ((mmt_header_line_t *)data1)->len;
                    if (hl_len < 0) hl_len = 0;
                    if (hl_len > 512) hl_len = 512;
                    buff = xmalloc (hl_len + 1);
                    if(buff == NULL){
                        /* F-BUG-096 (#209): the old `break` only left the
                         * switch — the loop kept appending into the freed
                         * json_buff and both buffers were freed again at the
                         * bottom (use-after-free + double free). Every failure
                         * path now reaches the single cleanup exit. */
                        goto cleanup;
                    }
                    memcpy(buff, ((mmt_header_line_t *)data1)->ptr, hl_len);
                    buff[hl_len] ='\0';
					snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%s\"},", proto_name,
							att_name, (char *)buff);
                    xfree(buff);
					json_grow_append(&json_buff, &json_cap, json_buff1);
					break;
                }
                case MMT_DATA_PATH:
                case MMT_STRING_LONG_DATA:
                case MMT_STRING_DATA: {
                    /* declared prefix is packet-controlled: bound it by the
                     * record size and by the stack buffer (F-BUG-091, #209) */
                    int slen = *(int*)(data1);
                    if (slen > data_size - (int)sizeof(int)) slen = data_size - (int)sizeof(int);
                    if (slen > 512) slen = 512;
                    if (slen < 0) slen = 0;
                    char tmp_str[513];
                    memcpy(tmp_str, (char*)(data1 + sizeof(int)), slen);
                    tmp_str[slen]='\0';
                    snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%s\"},", proto_name, att_name, tmp_str);
                    json_grow_append(&json_buff, &json_cap, json_buff1);
                    break;
                }
                case MMT_BINARY_DATA:
                case MMT_BINARY_VAR_DATA:
                    db1 = (mmt_binary_data_t *) (data1);
                    /* db1->len is a packet-controlled record prefix — bound it
                     * by the inline array the record actually carries, same
                     * family as the int-prefix clamps above (F-BUG-091, #209) */
                    data_size = db1->len;
                    if (data_size > (int)(type == MMT_BINARY_VAR_DATA ? BINARY_1024DATA_LEN : BINARY_64DATA_LEN))
                        data_size = (int)(type == MMT_BINARY_VAR_DATA ? BINARY_1024DATA_LEN : BINARY_64DATA_LEN);
                    if (data_size < 0) data_size = 0;
                    data2 = db1->data;
                    if (data_size == 4) {
                        L1 = (*(unsigned long*)(data2)&0x000000ff);
                        L2 = (*(unsigned long*)(data2)&0x0000ff00)>>8;
                        L3 = (*(unsigned long*)(data2)&0x00ff0000)>>16;
                        L4 = (*(unsigned long*)(data2)&0xff000000)>>24;
                        snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%lu.%lu.%lu.%lu\"},", proto_name, att_name, L1, L2, L3, L4);
                        json_grow_append(&json_buff, &json_cap, json_buff1);
                    } else if (data_size == 6) {
                        int close_tag=NO;
                        for (j = 0; j < data_size; j++) {
                            if (j == 0) {
                                snprintf(json_buff1, json_cap1, "{\"%s.%s\":%2.2X", proto_name,
                                        att_name, *((unsigned char*) data2 + j));
                                close_tag=YES;
                            } else {
                                snprintf(json_buff1, json_cap1, ":%2.2X", *((unsigned char*) data2 + j));
                            }
                            json_grow_append(&json_buff, &json_cap, json_buff1);
                        }
                        if(close_tag==YES)
                          json_grow_append(&json_buff, &json_cap, "},");
                    } else {
                        int close_tag=NO;
                        for (j = 0; j < data_size; j++) {
                            if (j == 0) {
                                snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%02X", proto_name,
                                        att_name, *((unsigned char*) data2 + j));
                                close_tag=YES;
                            } else {
                                snprintf(json_buff1, json_cap1, ":%02X", *((unsigned char*) data2 + j));
                            }
                            json_grow_append(&json_buff, &json_cap, json_buff1);
                        }
                        //end attribute
                        if(close_tag==YES)
                          json_grow_append(&json_buff, &json_cap, "\"},");
                    }
                    break;
                case MMT_DATA_POINTER:
                    /* only tcp.p_payload (354.4098) has a printable form —
                     * a generic pointer value is meaningless in a verdict. */
               	 //check only if we are verifying tcp.p_payload
               	 if( temp->protocol_id == 354  && temp->field_id == 4098 ){
							  data_ptr = get_attribute_extracted_data_by_name(ctx->pkt, "tcp","payload_len");
							  if( data_ptr != NULL ){
								  data_pointer_size = *(int *) data_ptr;
								  data_pointer = get_attribute_extracted_data_by_name(ctx->pkt, "tcp","p_payload");
								  if( data_pointer != NULL ){
									  new_data_pointer = convert_string_to_json_compatible (data_pointer, data_pointer_size);
									  /* NULL on non-positive size or OOM — a NULL %s
									   * argument is undefined; skip the attribute */
									  if (new_data_pointer != NULL) {
										  snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%s\"},", proto_name, att_name, (char*) (new_data_pointer));
										  json_grow_append(&json_buff, &json_cap, json_buff1);
										  xfree (new_data_pointer);
									  }
								  }
							  }
               	  }
                    break;
                case MMT_STRING_DATA_POINTER:
                    /* pointer-typed attribute: data1 is the string itself —
                     * bound the scan by the string-record capacity */
                    if ((char *) data1 != NULL) {
                        char *esc = convert_string_to_json_compatible((char *) data1,
                                (int) strnlen((char *) data1, STRING_DATA_LEN));
                        if (esc != NULL) {
                            snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%s\"},", proto_name, att_name, esc);
                            json_grow_append(&json_buff, &json_cap, json_buff1);
                            xfree(esc);
                        }
                    }
                    break;
                case MMT_GENERIC_HEADER_LINE: {
                    /* RFC2822 header line: NUL-terminated field and value */
                    mmt_generic_header_line_t *ghl = (mmt_generic_header_line_t *) (data1);
                    if (ghl->hfield != NULL || ghl->hvalue != NULL) {
                        char *esc = convert_string_to_json_compatible(
                                ghl->hfield != NULL ? (char *) ghl->hfield : "",
                                (int) (ghl->hfield != NULL ? strlen(ghl->hfield) : 0));
                        char *esc2 = convert_string_to_json_compatible(
                                ghl->hvalue != NULL ? (char *) ghl->hvalue : "",
                                (int) (ghl->hvalue != NULL ? strlen(ghl->hvalue) : 0));
                        snprintf(json_buff1, json_cap1, "{\"%s.%s\":\"%s: %s\"},", proto_name, att_name,
                                esc != NULL ? esc : "", esc2 != NULL ? esc2 : "");
                        json_grow_append(&json_buff, &json_cap, json_buff1);
                        if (esc != NULL) xfree(esc);
                        if (esc2 != NULL) xfree(esc2);
                    }
                    break;
                }
                /* Types with no defined record representation — none is
                 * emitted by extraction, so omitting the attribute is the
                 * intended result (#326). */
                case MMT_DATA_PORT:
                case MMT_DATA_PORT_RANGE:
                case MMT_DATA_DATE:
                case MMT_DATA_LAYERID:
                case MMT_DATA_TIMEARG:
                case MMT_DATA_IP_NET:
                case MMT_DATA_FILTER_STATE:
                case MMT_UNDEFINED_TYPE:
                case MMT_DATA_BUFFER:
                case MMT_DATA_STRING_INDEX:
                case MMT_DATA_PARENT:
                case MMT_STATS:
                    break;

                default:
                    (void)fprintf(stderr, "Error 15.2: Type not implemented yet. Data type unknown.\n");
                    exit(-1);
            }//end of switch
            temp = temp->next;
            data1 = NULL;
        }
        //ensure IP or MAC of src and dst are included in attribute
        if( having_ip_src == 0){
            data1 = NULL;
        	data1 = get_attribute_extracted_data(ctx->pkt, 178, 12);
            if(data1!= NULL && *((char*)data1)!=0){
                L1 = (*(unsigned long*)(data1)&0x000000ff);
                L2 = (*(unsigned long*)(data1)&0x0000ff00)>>8;
                L3 = (*(unsigned long*)(data1)&0x00ff0000)>>16;
                L4 = (*(unsigned long*)(data1)&0xff000000)>>24;
        		snprintf(json_buff1, json_cap1,"{\"ip.src\":\"%lu.%lu.%lu.%lu\"},", L1, L2, L3, L4);
        	    json_grow_append(&json_buff, &json_cap, json_buff1);
       	   }else if( having_mac_src == 0 ){
        		data1 = get_attribute_extracted_data(ctx->pkt, 99, 3);
        		temp_MAC = xmalloc(22);
        		if (temp_MAC == NULL) goto cleanup;
				convert_mac_bytes_to_string(&temp_MAC, (unsigned char *) data1);
        		snprintf(json_buff1, json_cap1,"{\"eth.src\":\"%s\"},", temp_MAC );
        		json_grow_append(&json_buff, &json_cap, json_buff1);
        		xfree( temp_MAC );
        	}
        	num_attr ++;
            data1 = NULL;
        }

        if( having_ip_dst == 0){
            data1 = NULL;
            data1 = get_attribute_extracted_data(ctx->pkt, 178, 13);
            if(data1!=NULL && *((char*)data1)!=0){
                L1 = (*(unsigned long*)(data1)&0x000000ff);
                L2 = (*(unsigned long*)(data1)&0x0000ff00)>>8;
                L3 = (*(unsigned long*)(data1)&0x00ff0000)>>16;
                L4 = (*(unsigned long*)(data1)&0xff000000)>>24;
				snprintf(json_buff1, json_cap1,"{\"ip.dst\":\"%lu.%lu.%lu.%lu\"},", L1, L2, L3, L4);
			    json_grow_append(&json_buff, &json_cap, json_buff1);
		    }else if( having_mac_dst == 0 ){
				data1 = get_attribute_extracted_data(ctx->pkt, 99, 2);
				temp_MAC = xmalloc(22);
				if (temp_MAC == NULL) goto cleanup;
				convert_mac_bytes_to_string(&temp_MAC, (unsigned char *) data1);
				snprintf(json_buff1, json_cap1,"{\"eth.dst\":\"%s\"},", temp_MAC);
				json_grow_append(&json_buff, &json_cap, json_buff1);
				xfree( temp_MAC );
			}
			num_attr ++;
            data1 = NULL;
		}

        if( num_attr > 0 ){
        	//remove the last comma in "event: [{...},...,{..},"
        	size_t _jlen = strlen(json_buff);
        	if (_jlen > 0 && json_buff[_jlen - 1] == ',')
        	    json_buff[_jlen - 1] = '\0';
        }
        json_grow_append(&json_buff, &json_cap, "]");
        {
            size_t ev_len = strlen(json_buff) + 64;
            char *ev_buf = xmalloc(ev_len);
            if (ev_buf) {
                snprintf(ev_buf, ev_len, "\"event_%d\":{%s},", event_id, json_buff );
                size_t _l = strlen(ev_buf);
                if (_l + 1 > json_cap) { char *nb = realloc(json_buff, _l+1); if (nb) { json_buff=nb; json_cap=_l+1; } }
                if (_l + 1 <= json_cap) memcpy(json_buff, ev_buf, _l + 1);
                xfree(ev_buf);
            }
        }

        short c = 0;
        if (context == BEFORE || context == AFTER || context == SAME) c = 1;
        /* size_t: the history grows one event per satisfied condition — an int
         * could wrap on a long-running probe (F-BUG-096, #209) */
        size_t json_buff_size = strlen(json_buff) + 1 + (size_t) c;
        if (curr_rule->json_history != NULL) {
            json_buff_size = json_buff_size + strlen(curr_rule->json_history);
            char *tmp = realloc(curr_rule->json_history, json_buff_size);
            if(tmp!=NULL){
                curr_rule->json_history = tmp;
            }else{
                goto cleanup;
            }
        } else {
            curr_rule->json_history = xcalloc(1, json_buff_size);
            if (curr_rule->json_history == NULL){
                goto cleanup;
            }
        }

        {
            /* bounded append: json_buff_size was sized for exactly this */
            size_t _off = strlen(curr_rule->json_history);
            size_t _n = strlen(json_buff) + 1;
            if (_off + _n <= json_buff_size)
                memcpy(curr_rule->json_history + _off, json_buff, _n);
        }
    }
cleanup:
    xfree(json_buff);
    xfree(json_buff1);
}

void store_tuples( verify_ctx_t *ctx, enum_operation_type context, rule *curr_rule, short event_id, char *cause )
{
    tuple * temp_tuple = NULL;
    if(curr_rule != NULL) temp_tuple = curr_rule->list_of_tuples;
    void *data = NULL;
    while (temp_tuple != NULL) {
        if (event_id != temp_tuple->event_id) {
            temp_tuple = temp_tuple->next;
            continue;
        }
        data = get_attribute_extracted_data( ctx->pkt, temp_tuple->protocol_id, temp_tuple->field_id );
        if (data == NULL) {
            (void)printf("Error 16: in stored reference tuples. Data is not available. packet_id=%"PRIu64", protocol_id=%ld, field_id=%ld\n",
            		ctx->pkt->packet_id,
                    temp_tuple->protocol_id, temp_tuple->field_id);
            //exit(-1);
        } else {
            temp_tuple->data_size = get_data_size_by_proto_and_field_ids(temp_tuple->protocol_id, temp_tuple->field_id);
            temp_tuple->valid = FOUND;
            temp_tuple->data = (void *) xmalloc(temp_tuple->data_size);
            if (temp_tuple->data == NULL) {
                return;
            }
            /* a pointer-typed attribute's datum is the pointer itself —
             * store the pointer value so references can compare the
             * pointed-to string (#326) */
            if (temp_tuple->data_type_id == MMT_STRING_DATA_POINTER)
                memcpy(temp_tuple->data, &data, temp_tuple->data_size);
            else
                memcpy(temp_tuple->data, data, temp_tuple->data_size);
        }
        temp_tuple = temp_tuple->next;
    }
    store_history(ctx, context, curr_rule, cause, event_id);
}

void get_verdict( enum_type_rule_node t, enum_print po, enum_print state, char **str_verdict, char **str_type ){
	char verdict[100];
	char type[100];
    memset(verdict,0,100);
    memset(type, 0, 100);
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
				/* inconclusive at the start or the end of input: the
				 * property could not be decided either way */
				(void)strcpy(verdict, "unknown");
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
				/* inconclusive at the start or the end of input */
				(void)strcpy(verdict, "unknown");
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

void detected_corrupted_message( verify_ctx_t *ctx, rule *r, char *cause, enum_print state )
{
    rule *temp = r;
    char *history = NULL;
    char *str = NULL;

    if(op->callback_funct != NULL){
    	char *verdict = NULL, *type = NULL;
    	get_verdict( ATTACK, op->Print, state, &verdict, &type );

        //char * xml_string = xml_message(ATTACK, op->Print, state, 0, cause);
      	if ( verdict == NULL) {
            if (type != NULL)
                free(type);
            return;
          }

      	if (temp != NULL && temp->json_history == NULL)
    	  temp = temp->root;
      	if (temp != NULL && temp->json_history != NULL)
      		history = temp->json_history;

      	corr_mess++;

        if(history != NULL){
      	  //remove the last comma — an empty history has no last char (F-BUG-103)
		  size_t hlen = strlen( history );
		  if( hlen > 0 && history[hlen - 1] == ',')
			history[hlen - 1] = '\0';

            str = xmalloc( strlen( history ) + 3 );
            if(str == NULL){
                xfree(verdict);
                xfree(type);
                return;
            }
      	  snprintf( str, strlen( history ) + 3, "{%s}", history );
      	  ((op->callback_funct))( 0, verdict, type, cause, str, ctx->pkt->p_hdr->ts,(void *) op->user_args);
          xfree( str );
        }
      	xfree( verdict );
      	xfree( type );
    }
    return;
}

int print_message(enum_type_rule_node type, enum_print po, enum_print state, int num, char *desc)
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

void print_nothing(enum_print print_option, rule *curr_root, rule *r, char *cause, enum_print state) {
    //(void)fprintf(stderr, "nothing\n");
}

static long counter_detection = 0;

/*
 * SECURITY FIX F-BUG-207 (#136): Strict whitelist quoting for packet-derived
 * attribute values interpolated into reaction commands.
 *
 * Previously generate_command() substituted PROTO.FIELD values obtained via
 * get_value() (packet-derived, attacker-controlled) directly into a shell
 * string passed to the shell via system. Any shell metacharacter in the
 * attribute ( ; & | $ ` \ " ' * ? ~ < > ( ) { } etc.) would be interpreted
 * by /bin/sh.
 *
 * Mechanism: every packet-derived substitution is now wrapped in single quotes
 * with embedded single quotes escaped as '\'' (POSIX sh: close quote, escaped
 * quote, open quote). The resulting argument is a single shell word whose
 * content is taken literally — no metacharacter inside can trigger command
 * separation, expansion, or redirection. Constants (digits) are left unquoted
 * as they originate from the rule file, not the packet. The single caller
 * rule_is_satisfied_or_not is audited below; it receives only escaped values
 * from this function. Alternative (argv/environment/file without shell) was
 * considered and would be equivalent; quoting was chosen to keep the existing
 * system API while eliminating injection. Verified by the metacharacter-
 * attribute reaction test in tests/rule_engine (task 1.1 ENABLESEC suite).
 */
static char *escape_shell_arg(const char *arg) {
    if (arg == NULL) return NULL;
    size_t len = strlen(arg);
    // worst: each ' -> '\'' (4 chars) + 2 surrounding quotes + NUL
    char *out = xmalloc(len * 4 + 3);
    if (out == NULL) return NULL;
    char *p = out;
    *p++ = '\'';
    for (size_t i = 0; i < len; i++) {
        if (arg[i] == '\'') {
            *p++ = '\'';
            *p++ = '\\';
            *p++ = '\'';
            *p++ = '\'';
        } else {
            *p++ = arg[i];
        }
    }
    *p++ = '\'';
    *p++ = '\0';
    return out;
}

/* F-BUG-102 (#209): the command buffer used to be sized from the parameter
 * names in `input` while the escaped substitutions can add hundreds of bytes
 * each. The output is now grown on demand, and every error path funnels to
 * one exit that releases it (the four early `return NULL`s used to leak it). */
static int gc_append(char **buf, size_t *cap, size_t *len, const char *src, size_t n) {
    if (*len + n + 1 > *cap) {
        size_t nc = *cap ? *cap : 256;
        while (nc < *len + n + 1) nc *= 2;
        char *nb = xmalloc(nc);
        if (nb == NULL) return -1;
        if (*len > 0) memcpy(nb, *buf, *len);
        nb[*len] = '\0';
        xfree(*buf);
        *buf = nb;
        *cap = nc;
    }
    memcpy(*buf + *len, src, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

char *generate_command( const ipacket_t *pkt, rule *r, char * input )
{
    //input: "name_of_script parameters" where parameters can be constants or variables (e.g., script(1,META.PROTO.3) )
    //output: idem but replacing variables with the value (e.g., script 1 801)
    char * output = NULL;
    char * tempi = NULL;
    char numbuf[40];
    size_t out_cap = 0, out_len = 0;
    int oom = 0;
    tuple *list_of_tuples = r->list_of_tuples;

    // Start with expansion room for quoting; the buffer grows further on
    // demand so escaped substitutions can never overrun it.
    out_cap = strlen(input) * 4 + 4096;
    output = xmalloc(out_cap);

    if (output == NULL) {
        (void)fprintf(stderr, "Error 22x: Out of memory\n");
        return NULL;
    }
    output[0] = '\0';

    //Copy input to output, replacing the variables with the values recovered below
    // if a value is not available then print an error and return NULL!

    oom |= gc_append(&output, &out_cap, &out_len, "/opt/mmt/probe/conf/./", 22);

    tempi = input;
    while (*tempi == ' ') tempi++;
    while (*tempi != '(' && *tempi != '\0') { // && *tempi != ' ') {
        oom |= gc_append(&output, &out_cap, &out_len, tempi, 1);
        tempi++;
    }
    if (*tempi == '\0') {
        (void)fprintf(stderr, "Error 22x: missing '(' in: %s\n", input);
        goto fail;
    }
    while (*tempi == ' ') tempi++;
    if (*tempi != '(') {
        (void)fprintf(stderr, "Error 22x: missing '(' in: %s\n", input);
        goto fail;
    }
    tempi++; //skip '('
    oom |= gc_append(&output, &out_cap, &out_len, " ", 1);
    //we have: "script_name "
    counter_detection++;
    snprintf(numbuf, sizeof(numbuf), "%ld ", counter_detection);
    oom |= gc_append(&output, &out_cap, &out_len, numbuf, strlen(numbuf));

    while (*tempi == ' ') tempi++;

    int closed = 0;
    while (isalpha(*tempi) || *tempi == '_' || isdigit(*tempi) || *tempi == ')') {
        if (oom) goto fail;
        if (isdigit(*tempi)) {
            //we have a constant that ends with ')' or ' ' or ',' or '\0'
            while (*tempi != ',' && *tempi != ')' && *tempi != ' ' && *tempi != '\0') {
                oom |= gc_append(&output, &out_cap, &out_len, tempi, 1);
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
            // SECURITY: packet-derived data must never be interpolated raw.
            // Apply strict single-quote escaping so shell metachars are literal.
            char *escaped = escape_shell_arg(data ? data : "");
            if (escaped != NULL) {
                oom |= gc_append(&output, &out_cap, &out_len, escaped, strlen(escaped));
                xfree(escaped);
            }
            xfree(data);
        }
        while (*tempi == ' ') tempi++;
        if (*tempi == ',') {
            tempi++;
            while (*tempi == ' ') tempi++;
            oom |= gc_append(&output, &out_cap, &out_len, " ", 1);
            if (isalpha(*tempi) || *tempi == '_' || isdigit(*tempi)) continue;
            else {
                (void)fprintf(stderr, "Error 22x: missing parameter\n");
                goto fail;
            }
        }
        if (*tempi == ')') {
            output[out_len] = '\0';
            closed = 1;
            break;
        }
        if (*tempi == '\0') {
            (void)fprintf(stderr, "Error 22x: missing ')' in: %s\n", input);
            goto fail;
        }
    }
    if (oom || !closed) {
        if (!closed) (void)fprintf(stderr, "Error 22x: missing ')' in: %s\n", input);
        goto fail;
    }
    //Put data in file with name: detection_<counter_detection>.data
    //Will be used by python script
    FILE * pythonDataFile;
    char pythonDataFileName[50];
    rule * rr = NULL;
    snprintf(pythonDataFileName, 50, "/opt/mmt/probe/conf/detection_%ld.data", counter_detection);
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
fail:
    xfree(output);
    return NULL;
}

char *my_strstr(char *texte, char* pattern, enum_yes reverse){
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

void get_time_value(char * history, char *a_time, enum_yes reverse, enum_yes direct)
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
            while(*pt_i != '\0' && *pt_i != '=') pt_i++;
            if (*pt_i != '='){
              (void)fprintf(stderr, "Error 22yyy: '=' not found: %s\n", pt_i);
              return;
            }
            pt_i++;
            pt_j = pt_i;
            while(*pt_j != '\0' && *pt_j != '<') pt_j++;
            if (*pt_j == '\0') {
              (void)fprintf(stderr, "Error 22yyy: '<' not found: %s\n", pt_i);
              return;
            }
            len = pt_j - pt_i;
            if (len<1 || len>99){
              (void)fprintf(stderr, "Error 22yyy1: length out of bounds in: %s\n", pt_i);
              return;
            }
            strncpy(a_time, pt_i, len);
            a_time[len]='\0';
        }
}

void rule_is_satisfied_or_not( verify_ctx_t *ctx, rule *r, enum_print state ) {
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
		int prop_id = ctx->curr_root->property_id;
		char *des   = r->description;

		get_verdict( ctx->curr_root->type_rule, op->Print, state, &verdict, &type );
		if( verdict == NULL) {
            if(type!=NULL) free(type);
            return;
        }
		if (r->json_history != NULL){
            history = r->json_history;
            //remove the last comma — an empty history has no last char (F-BUG-103)
            size_t hlen = strlen(history);
            if (hlen > 0 && history[hlen - 1] == ',')
                history[hlen - 1] = '\0';

            char *temp = xmalloc(strlen(history) + 3);
            if(temp != NULL){
                snprintf(temp, strlen(history) + 3, "{%s}", history);
                ((op->callback_funct))(prop_id, verdict, type, des, temp, ctx->pkt->p_hdr->ts, (void *)op->user_args);
                xfree(temp);
            }
           
        }
		xfree( verdict );
		xfree( type );
    }

    /* Reaction scripts are resolved from the folder generate_command
     * prepends (/opt/mmt/probe/conf/) and run in the current working
     * directory of the engine process. */
    void *data = NULL;
    short do_it = 0;
    char * what_to_do = NULL;
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
                // AUDITED CALL SITE (F-BUG-207 / #136):
                // The system call below receives ONLY the string produced by
                // generate_command, which applies escape_shell_arg to every
                // packet-derived PROTO.FIELD substitution (see generate_command
                // header comment). No raw attribute value reaches the shell;
                // metachars are neutralised inside single quotes. Grep for
                // system + open paren in src/mmt_security/tips.c should show
                // this as the sole call site and this comment as its audit.
                // The metacharacter-attribute test in tests/rule_engine
                // proves no injection occurs.
                command = generate_command( ctx->pkt, r, what_to_do );
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
                if(top_tuple == NULL){
                    xfree(funct_name);
                    return;
                }
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

                command2 = funct_get_info_param( ctx->pkt->mmt_handler, NOT_USED, command, a_tuple);
                while( command2 ) {
                    new_tuple = (tuple *)xmalloc(sizeof (tuple));
                    if(new_tuple == NULL){
                        xfree(top_tuple);
                        xfree(funct_name);
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
                    if(a_tuple != NULL){
                        a_tuple->next = new_tuple;
                        a_tuple = new_tuple;
                        command2 = funct_get_info_param(ctx->pkt->mmt_handler, NOT_USED, command2, a_tuple);
                    }
                }
                enum_found found = NOT_FOUND; //not used in this context
                data = funct_get_params_and_execute( ctx, funct_name, data_size, top_tuple, r->list_of_tuples, &found);
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

/* F-BUG-103 (#209): xml_summary wrote into a fixed 10000-byte buffer with a
 * 1000-byte scratch — attacker-controlled descriptions could overflow both.
 * Grow-on-demand formatted append instead; returns -1 on allocation failure. */
static int xml_appendf(char **buf, size_t *cap, const char *fmt, ...) {
    va_list ap, ap2;
    int need;
    size_t cur;
    if (buf == NULL || cap == NULL || fmt == NULL) return -1;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) { va_end(ap2); return -1; }
    cur = (*buf != NULL) ? strlen(*buf) : 0;
    if (cur + (size_t) need + 1 > *cap) {
        size_t nc = (*cap != 0) ? *cap : 1024;
        char *nb;
        while (nc < cur + (size_t) need + 1) nc *= 2;
        nb = xmalloc(nc);
        if (nb == NULL) { va_end(ap2); return -1; }
        if (*buf != NULL) memcpy(nb, *buf, cur + 1);
        else nb[0] = '\0';
        xfree(*buf);
        *buf = nb;
        *cap = nc;
    }
    vsnprintf(*buf + cur, *cap - cur, fmt, ap2);
    va_end(ap2);
    return 0;
}

char * xml_summary()
{
    //if used in the main.c needs to be freed
    int sp = 0;
    int spb = 0;
    rule *temp = top_rule;
    size_t xml_cap = 1024;
    char *xml_string = xcalloc(1, xml_cap);
    if(xml_string == NULL) return NULL;
    xml_appendf(&xml_string, &xml_cap, "</detail>\n");
    xml_appendf(&xml_string, &xml_cap, "<summary>\n");
    if (corr_mess != 0) {
        spb = 1;
        xml_appendf(&xml_string, &xml_cap,
                "  <spb>\n"
                "   <id>0</id>\n"
                "   <description>ATTACK: Corrupted messages: due to an attack, evasion or error.</description>\n"
                "   <detected>%lld</detected>\n"
                "   <not_detected>N&#47;A</not_detected>\n"
                "  </spb>\n", corr_mess);
    }
    while (temp != NULL) {
        const char *descr = temp->description ? temp->description : "";
        if (temp->type_rule == ATTACK) {
            spb = 1;
            xml_appendf(&xml_string, &xml_cap,
                    "  <spb>\n"
                    "   <id>%d</id>\n"
                    "   <description>ATTACK: %s</description>\n"
                    "   <detected>%ld</detected>\n"
                    "   <not_detected>%ld</not_detected>\n"
                    "  </spb>\n",
                    temp->property_id, descr, temp->nb_satisfied, temp->nb_not_satisfied);
        }else if (temp->type_rule == EVASION) {
            spb = 1;
            xml_appendf(&xml_string, &xml_cap,
                    "  <spb>\n"
                    "   <id>%d</id>\n"
                    "   <description>EVASION: %s</description>\n"
                    "   <detected>%ld</detected>\n"
                    "   <not_detected>%ld</not_detected>\n"
                    "  </spb>\n",
                    temp->property_id, descr, temp->nb_satisfied, temp->nb_not_satisfied);
        } else if (temp->type_rule == SECURITY_RULE || temp->type_rule == TEST) {
            sp = 1;
            xml_appendf(&xml_string, &xml_cap,
                    "  <sp>\n"
                    "   <id>%d</id>\n"
                    "   <description>%s%s</description>\n"
                    "   <respected>%ld</respected>\n"
                    "   <violated>%ld</violated>\n"
                    "  </sp>\n",
                    temp->property_id,
                    (temp->type_rule == SECURITY_RULE) ? "SECURITY RULE: " : "",
                    descr, temp->nb_satisfied, temp->nb_not_satisfied);
        }
        temp = temp->next;
    }
    if (sp == 0) {
        xml_appendf(&xml_string, &xml_cap,
                "  <sp>\n"
                "   <id></id>\n"
                "   <description>none</description>\n"
                "  </sp>\n");
    }
    if (spb == 0) {
        xml_appendf(&xml_string, &xml_cap,
                "  <spb>\n"
                "   <id></id>\n"
                "   <description>none</description>\n"
                "  </spb>\n");
    }
    xml_appendf(&xml_string, &xml_cap, "</summary>\n");
    xml_appendf(&xml_string, &xml_cap, "</results>\n");
    return xml_string;
}
