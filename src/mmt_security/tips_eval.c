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
 *       Filename:  tips_eval.c
 *    Description:  Open Source prototype version of the MMT_Security library
 *                  that allows analysing network traffic
 *                  to detect normal or abnormal behaviour.
 *
 *    Responsibility: rule evaluation — rule-instance lifecycle
 *    (create/copy/eliminate_instance), the verify() dispatcher and
 *    its per-node-type handlers, temporal control (check_time family)
 *    and the action() verdict table.
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
            if(a_tuple == NULL){
                xfree(a_rule);
                return NULL;
            }
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
            if (a_rule->t.data==NULL){
                xfree(a_rule);
                return NULL;
            }
            memcpy(a_rule->t.data, (void *)(r->t.data), a_rule->t.data_size);
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
            if (temp_tuple->data == NULL)
            {
                return;
            }
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
  char *buff = xmalloc(10);
  if (buff == NULL)
  {
      return NULL;
  }
  rule *new_rule = create_instance(root_inst, r, father);
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
       /* buff is 10 bytes and buff_ids holds 100 ids — clamp both */
       size_t tok_len = (size_t)(pt2 - pt);
       if (tok_len > 9) tok_len = 9;
       memcpy(buff,pt,tok_len);
       buff[tok_len]='\0';
       if (i < 100) buff_ids[i++]=atoi(buff);
    }
    if(*pt2=='\0')break;
    pt=pt2+1;
  }

  if(new_rule != NULL){
    if(orig_rule->json_history != NULL){
      char * json_history = strdup(orig_rule->json_history);
      if(json_history == NULL){
          xfree(buff);
          return NULL;
      }
      pt = strstr(json_history,"event");
      while (pt != NULL){
        pt2 = strstr(pt,"description");
        if(pt2 != NULL){
          pt2 = pt2 + 18;
          pt3 = strchr(pt2,':');
          if (pt3 != NULL){
            size_t tok_len = (size_t)(pt3 - pt2);
            if (tok_len > 9) tok_len = 9;
            memcpy(buff,pt2,tok_len);
            buff[tok_len]='\0';
            if(event_found(buff_ids, atoi(buff)) == NO){
              pt2 = eliminate_from(pt);
            }
          }
        }
        /* a malformed history without a "description" after an "event" leaves
         * pt2 NULL — stop instead of strstr(NULL, ...) (F-BUG-103, #209) */
        pt = (pt2 != NULL) ? strstr(pt2,"event") : NULL;
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
          if(temp_lot->data == NULL){
              xfree(new_rule);
              xfree(buff);
              return NULL;
          }
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

static int temptemp = 0;

int verify_segment( verify_ctx_t *ctx, rule *c )
{
    short result = 0;
    void *result_value = NULL;
    rule *temp1, *temp2;
    switch (c->value) {
        case XOR:
            //Need to analyse the sons
            temp1 = c->list_of_sons;
            while (temp1 != NULL) {
                result = verify_segment( ctx, temp1 );
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
                result = verify_segment( ctx, temp1 );
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
                result = verify_segment( ctx, temp1 );
                if (result != VALID) {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
            }
            if (temp2->type != LEAF && temp2->t.valid == NOT_YET) {
                result = verify_segment( ctx, temp2 );
                if (result != VALID) {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
            }
            //Need to compare all the sons even if more than two (i.e. A > B > C)
            while (temp2) {
                uint64_t tmp=0;
                void *not_used = &tmp;
                result = get_data_from_pcap( ctx, COMPARE, &not_used, c->value, temp1, temp2 );
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
                result = verify_segment( ctx, temp1 );
                if (result != VALID) {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
            }
            if (temp2->type != LEAF && temp2->t.valid == NOT_YET) {
                result = verify_segment( ctx, temp2 );
                if (result != VALID) {
                    c->valid = NOT_VALID;
                    return NOT_VALID;
                }
            }
            temptemp++;
            result = get_data_from_pcap( ctx, COMPUTE, &result_value, c->value, temp1, temp2 );
            if (result_value == NULL) {
                //changed so that considered as a violated property (corrupted message):
                c->valid = NOT_VALID;
                store_history(ctx, SAME, c, NULL, 0);
                detected_corrupted_message(ctx, c, "Corrupted message: due to an attack or error.", SATISFIED);
                return NOT_VALID;
            }
            //Need to use result_value
            c->t.protocol_id = temp1->t.protocol_id;
            c->t.field_id = temp1->t.field_id;
            c->t.data_type_id = MMT_U64_DATA;//temp1->t.data_type_id;
            c->t.data_size = sizeof(uint64_t);//temp1->t.data_size;
            c->t.valid = VALID;
            c->t.data = xmalloc(c->t.data_size);
            if(c->t.data == NULL){
                xfree(result_value);
                return NOT_VALID;
            }
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
        case DNE:
        case DE:
            temp1 = c->list_of_sons;
            result = exists_or_not (ctx->pkt, c->value, temp1);
            if (result != VALID) {
                c->valid = NOT_VALID;
                return NOT_VALID;
            }
            c->valid = VALID;
            return VALID;
            break;
        default:
            (void)fprintf(stderr, "Error 20a: Should be an event_operator or a condition.\n");
    }//end of switch
    (void)fprintf(stderr, "Error 21: Problem verifying condition.\n");

    return NOT_VALID;
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
    // TODO(#326): increment counter
    int ret = 0;
    // ret = COUNTIN;
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

short action(enum_operation_type situation, enum_yes leftleft, rule *r)
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

int verify_left( verify_ctx_t *ctx, rule *r )
{
    short result = 0;
    rule *temp_rule = NULL;
    switch (r->value) {
        case THEN:
                if (r->list_of_sons != NULL) {
                    result = verify_left( ctx, r->list_of_sons );
                    return result;
                } else {
                    (void)fprintf(stderr, "Error 26: Encoutered incorrect sequence of events.\n");
                }
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
            result = verify_segment( ctx, temp_rule );
            if(result == VALID){
              if(ctx->curr_root->json_history != NULL){
                xfree (ctx->curr_root->json_history);
                ctx->curr_root->json_history = NULL;
              }
              store_history(ctx, SAME, ctx->curr_root, ctx->cause, ctx->curr_root->list_of_sons->event_id);
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

//Tail shared by every verify() arm that fell through its checks — the
//malformed-tree diagnostic plus the NOT_VALID verdict the switch produced.
static int verify_malformed_rule( void )
{
    (void)fprintf(stderr, "Error 40: Possible error in the XML properties file: %s.\n", op->RuleFileName);
    return NOT_VALID;
}

//THEN node, SAME packet: verify the left son then, when it validated, the
//right son — a right son that fails is stamped NOT_VALID. A missing left
//son takes the malformed-tree tail.
static int verify_then_same( verify_ctx_t *ctx, rule *r )
{
    short result = 0;
    if (r->list_of_sons != NULL) {
        r->list_of_sons->father = r;
        result = verify( ctx, SAME, r->list_of_sons );
        if (result == VALID) {
            r->list_of_sons->next->father = r;
            result = verify( ctx, SAME, r->list_of_sons->next );
            if (result == NOT_VALID)r->list_of_sons->next->valid = NOT_VALID;
        }
        return action(SAME, ctx->leftleft, r);
    }
    (void)fprintf(stderr, "Error 26: Encoutered incorrect sequence of events.\n");
    return verify_malformed_rule();
}

//THEN/AFTER, left son still pending: verify it for this packet — when it
//validates, arm the node timer and, unless a delay_min gate applies, verify
//the right son on the same packet with leftleft dropped to NO.
static int verify_then_after_pending( verify_ctx_t *ctx, rule *r )
{
    short result = 0;
    const enum_yes leftleft = ctx->leftleft;
    //Need to verify left branch
    r->list_of_sons->father = r;
    result = verify( ctx, AFTER, r->list_of_sons );
    if (result == VALID) {
        //Left branch was found valid so need to start timer
        result = init_time(&(r->timer), &(r->counter), ctx->current_packet_time);
        if (r->delay_min == 0 && r->not_equal_min == NO) {
            //Since there is no delay_min set we need to verify, for the same packet, the right branch
            r->list_of_sons->next->father = r;
            ctx->leftleft = NO;
            result = verify( ctx, AFTER, r->list_of_sons->next );
            ctx->leftleft = leftleft;
        }
    }
    return action(AFTER, leftleft, r);
}

//THEN/AFTER, left son already valid: control the node timeout — TIMEIN is
//still pending, a NOT right son turns expiry into validity, anything else
//fails the node — otherwise verify the right son for this packet.
static int verify_then_after_valid( verify_ctx_t *ctx, rule *r )
{
    //Left branch already valid so need to check for timeout
    short result = check_time(r, ctx->current_packet_time); //returns SKIP2/TIMEOUT/TIMEIN/COUNTOUT/COUNTIN
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
    result = verify( ctx, AFTER, r->list_of_sons->next );
    return action(AFTER, ctx->leftleft, r);
}

//THEN node, AFTER situation (counter_max or delay_max armed): dispatch on
//the left son's state — pending, already valid (timeout control), or dead.
static int verify_then_after( verify_ctx_t *ctx, rule *r )
{
    if (r->list_of_sons != NULL) {
        if (r->list_of_sons->valid == NOT_YET) {
            return verify_then_after_pending( ctx, r );
        }
        if (r->list_of_sons->valid == VALID) {
            return verify_then_after_valid( ctx, r );
        }
        if (r->list_of_sons->valid == NOT_VALID) {
            return action(AFTER, ctx->leftleft, r);
        }
        (void)fprintf(stderr, "Error 27: Encoutered incorrect sequence of events.\n");
    }
    (void)fprintf(stderr, "Error 30: Encoutered incorrect sequence of events.\n");
    return verify_malformed_rule();
}

//THEN/BEFORE, right son still pending: verify it for this packet — when it
//validates, arm the node timer and, unless a delay_max gate applies, verify
//the left son on the same packet.
static int verify_then_before_pending( verify_ctx_t *ctx, rule *r )
{
    short result = 0;
    //Need to verify right branch
    r->list_of_sons->next->father = r;
    result = verify( ctx, BEFORE, r->list_of_sons->next );
    r->list_of_sons->next->valid = result;
    if (result == VALID) {
        //Right branch was found valid so need to start timer
        result = init_time(&(r->timer), &(r->counter), ctx->current_packet_time);
        if (r->delay_max == 0 && r->not_equal_max == NO) {
            //Since there is no delay_max set we need to verify, for the same packet, the left branch
            r->list_of_sons->father = r;
            result = verify( ctx, BEFORE, r->list_of_sons );
        }
    }
    return action(BEFORE, ctx->leftleft, r);
}

//THEN/BEFORE, right son already valid: control the node timeout — a NOT
//left son turns expiry into validity, anything else eliminates the node —
//otherwise verify the left son for this packet.
static int verify_then_before_valid( verify_ctx_t *ctx, rule *r )
{
    //Right branch already valid so need to check for timeout
    short result = check_time(r, ctx->current_packet_time); //returns SKIP2/TIMEOUT/TIMEIN/COUNTOUT/COUNTIN
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
    result = verify( ctx, BEFORE, r->list_of_sons );
    return action(BEFORE, ctx->leftleft, r);
}

//THEN node, BEFORE situation (negative counter_min or delay_min): dispatch
//on the right son's state — pending, already valid (timeout control), or
//the left son dead.
static int verify_then_before( verify_ctx_t *ctx, rule *r )
{
    if (r->list_of_sons != NULL) {
        if (r->list_of_sons->next->valid == NOT_YET) {
            return verify_then_before_pending( ctx, r );
        }
        if (r->list_of_sons->next->valid == VALID) {
            return verify_then_before_valid( ctx, r );
        }
        if (r->list_of_sons->valid == NOT_VALID) {
            return action(BEFORE, ctx->leftleft, r);
        }
        (void)fprintf(stderr, "Error 35: Encoutered incorrect sequence of events.\n");
    }
    return verify_malformed_rule();
}

//THEN node: pick the temporal situation — counter_max/delay_max mean
//AFTER, a negative counter_min/delay_min mean BEFORE, otherwise both sons
//are tested on the SAME packet — report inconsistent son states, then run
//the per-situation walk.
static int verify_then( verify_ctx_t *ctx, rule *r )
{
    //Determine if we are in the situation AFTER or BEFORE and report errors in state of sons
    //  (e.g., if "A then AFTER B" and "A not_yet" and "B valid" => error because B can not be valid before A in this situation)
    if (r->counter_max > 0 || r->delay_max > 0) {
        if (r->list_of_sons != NULL && r->list_of_sons->valid == NOT_YET &&
                r->list_of_sons->next != NULL && r->list_of_sons->next->valid == VALID) {
            (void)fprintf(stderr, "Error 24.5: Encoutered incorrect sequence of events.\n");
        }
        return verify_then_after( ctx, r );
    }
    if (r->counter_min < 0 || r->delay_min < 0) {
        if (r->list_of_sons != NULL && r->list_of_sons->valid == VALID &&
                r->list_of_sons->next != NULL && r->list_of_sons->next->valid == NOT_YET) {
            (void)fprintf(stderr, "Error 25: Encoutered incorrect sequence of events.\n");
        }
        return verify_then_before( ctx, r );
    }
    return verify_then_same( ctx, r );
}

//OR node: no timer — verify each son in order until one validates; the
//first VALID son validates the node, otherwise every son and the node are
//stamped NOT_VALID. Sons are verified in the BEFORE situation (the
//uninitialised-then-0 context verify() always passed here).
static int verify_or( verify_ctx_t *ctx, rule *r )
{
    short result = 0;
    rule *curr_r = NULL;
    //No timer needed
    if (r->list_of_sons != NULL) {
        curr_r = r->list_of_sons;
        //assume none are valid
        while (curr_r != NULL) {
            curr_r->father = r;
            result = verify( ctx, BEFORE, curr_r );
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
    return verify_malformed_rule();
}

//AND node with the timer already armed (a son validated earlier): control
//the node timeout — a satisfied son opposite a NOT sibling keeps the node
//VALID, anything else fails it. SKIP2 means the window is still open.
static int verify_and_timeout( verify_ctx_t *ctx, rule *r )
{
    short result = check_time(r, ctx->current_packet_time); //returns SKIP2/TIMEOUT/TIMEIN/COUNTOUT/COUNTIN
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
    return SKIP2;
}

//AND node, one not-yet-valid son: verify it, arm the node timer on the
//first VALID son, and fold the verdict into the node flags.
static void verify_and_son( verify_ctx_t *ctx, rule *r, rule *curr_r, int *one_already_valid, int *all_valid )
{
    short result = 0;
    curr_r->father = r;
    result = verify( ctx, BEFORE, curr_r );
    if (*one_already_valid == 0) {
        if (result == VALID) {
            //Case found the first VALID son so timer needs to be started
            init_time(&(r->timer), &(r->counter), ctx->current_packet_time);
            *one_already_valid = 1;
        }
    }
    if (result == VALID) {
        *one_already_valid = 1;
        curr_r->valid = VALID;
    } else if (result == NOT_VALID) {
        curr_r->valid = NOT_YET;
        *all_valid = 0;
    } else if (result == NOT_YET) {
        curr_r->valid = NOT_YET;
        *all_valid = 0;
    }
}

//AND node: with a son already valid, control the armed timer first; then
//verify each pending son — all VALID means the node validates, none ever
//valid fails it, otherwise it stays pending.
static int verify_and( verify_ctx_t *ctx, rule *r )
{
    short result = 0;
    rule *curr_r = NULL;
    int one_already_valid = 0;
    int all_valid = 1;
    //Timer needed
    if (r->list_of_sons == NULL) {
        (void)fprintf(stderr, "Error 37: Encoutered incorrect sequence of events.\n");
        return verify_malformed_rule();
    }
    curr_r = r->list_of_sons;
    while (curr_r != NULL) {
        if (curr_r->valid == VALID) {
            one_already_valid = 1;
            break;
        }
        curr_r = curr_r->next;
    }
    if (one_already_valid == 1) {
        //Case timer already started so need to control timeout
        result = verify_and_timeout( ctx, r );
        if (result != SKIP2) {
            return result;
        }
    }
    curr_r = r->list_of_sons;
    while (curr_r != NULL) {
        if (curr_r->valid != VALID) {
            verify_and_son( ctx, r, curr_r, &one_already_valid, &all_valid );
        }
        curr_r = curr_r->next;
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

//NOT node whose son stayed NOT_VALID/NOT_YET and has no right sibling: the
//verdict depends on the enclosing sequence — climb to the nearest ancestor
//having a next sibling and verify it; its VALID lifts the NOT node too.
static int verify_not_backtrack( verify_ctx_t *ctx, rule *r, rule *curr_r )
{
    short result = 0;
    rule *curr_r_NOT = curr_r;
    //EDMO!
    curr_r = r->list_of_sons->father;
    while(curr_r != NULL && curr_r->next == NULL){
        curr_r = curr_r->father;
    }
    if(curr_r != NULL && curr_r->next != NULL){
        curr_r = curr_r->next;
        curr_r->father = r;
        result = verify( ctx, BEFORE, curr_r );
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

//NOT node: with the timer already armed, a timeout means the son never
//validated so the node is VALID; otherwise verify the son — a VALID son
//fails the node, a still-failing son arms the timer once and may still
//validate through the enclosing sequence.
static int verify_not( verify_ctx_t *ctx, rule *r )
{
    short result = 0;
    rule *curr_r = NULL;
    //Timer needed
    if (r->list_of_sons == NULL) {
        (void)fprintf(stderr, "Error 38: Encoutered incorrect sequence of events.\n");
        return verify_malformed_rule();
    }
    curr_r = r->list_of_sons;
    if (r->timer.tv_usec != 0 || r->timer.tv_sec != 0) {
        //Case timer already started so need to control timeout
        result = check_time(r, ctx->current_packet_time); //returns SKIP2/TIMEOUT/TIMEIN/COUNTOUT/COUNTIN
        if (result != SKIP2) {
            //Son never found VALID so the NOT node is VALID
            r->valid = VALID;
            return VALID;
        }
    }
    curr_r->father = r;
    result = verify( ctx, BEFORE, curr_r );
    if (result == NOT_VALID && r->timer.tv_usec == 0 && r->timer.tv_sec == 0) {
        //Case found the NOT_VALID son so NOT node is VALID and timer needs to be started (if not already started)
        init_time(&(r->timer), &(r->counter), ctx->current_packet_time);
    }
    if (result == VALID) {
        //son of NOT is valid so NOT node is NOT_VALID
        curr_r->valid = VALID;
        r->valid = NOT_VALID;
        return NOT_VALID;
    }
    if (result == NOT_VALID || result == NOT_YET) {
        //son of NOT is NOT_VALID so NOT node can still be VALID (if timeout is reached with the son always remaining NOT_VALID)
        //now need to check next noeud and if next noeud is not valid then leave as it is
        //but if next branch is valid then should set NOT noeud to VALID
        if (r->list_of_sons->next == NULL) {
            return verify_not_backtrack( ctx, r, curr_r );
        }
    }
    (void)fprintf(stderr, "Error 38: Encoutered incorrect sequence of events.\n");
    return verify_malformed_rule();
}

//Leaf node (event expression or arithmetic): evaluate the condition
//against the instance tuples; a VALID leaf copies its description into the
//diagnostic buffer and stores the event tuples.
static int verify_leaf( verify_ctx_t *ctx, enum_operation_type context, rule *r )
{
    short result = verify_segment( ctx, r );
    if (result == VALID) {
        if (r->description != NULL) {
            strncpy(ctx->cause, r->description, SIZE_CAUSE);
            ctx->cause[SIZE_CAUSE]='\0';
        }
        store_tuples( ctx, context, r->root, r->event_id, ctx->cause );
    }
    return result;
}

int verify( verify_ctx_t *ctx, enum_operation_type context, rule *r )
{
    *ctx->cause = '\0';
    switch (r->value) {
        case THEN:
            return verify_then( ctx, r );
        case OR:
            return verify_or( ctx, r );
        case AND:
            return verify_and( ctx, r );
        case NOT:
            return verify_not( ctx, r );
        case REPEAT: //same as AND but do it several repeat_times, couting them in repeat_times_found
            // TODO(#326)
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
            return verify_leaf( ctx, context, r );
        default:
            (void)fprintf(stderr, "Error 39: Should be a event. XML properties file: %s might be incorrect.\n", op->RuleFileName);
            break;
    }//end of switch THEN/OR/AND/NOT/REPEAT
    return verify_malformed_rule();
}
