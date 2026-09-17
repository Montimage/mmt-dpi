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
 *       Filename:  tips.c
 *    Description:  Open Source prototype version of the MMT_Security library
 *                  that allows analysing network traffic
 *                  to detect normal or abnormal behaviour.
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

//*************************************************************************************
//*   Not included: repetition, negation, keep_state
//*************************************************************************************

    static FILE *OutputFile = NULL;
    long long packet_count = 0;
    short p_meta = 0;
    short a_utime = 0;
    char *token2;
    char *token3;

    OPTIONS_struct *op;
    rule *top_rule = NULL;

FILE *open_file(char *name, char *mode)
{
    if(name == NULL) return NULL;
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
    if(cause == NULL){
        return 0;
    }
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
            verify_ctx_t vctx = { ipacket, curr_rule, curr_rule_instance->list_of_tuples, &reference, cause, current_packet_time, NO };
            result = verify(&vctx, SAME, curr_rule_instance);
            if (result == NOT_VALID) {
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
          // TODO(#326): works only if left branch is one event
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
            if(curr_rule_instance == NULL){
                xfree(cause);
                return 0;
            }
            verify_ctx_t vctx = { ipacket, curr_rule, curr_rule_instance->list_of_tuples, &reference, cause, current_packet_time, YES };
            result = verify(&vctx, SAME, curr_rule_instance);
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

void init_sec_lib( mmt_handler_t *mmt, char * property_file,
        short option_satisfied, short option_not_satisfied, result_callback cont_funct,
        result_callback db_create_funct, result_callback db_insert_funct, void * user_args)
{
    op = (OPTIONS_struct *)xcalloc(1, sizeof (OPTIONS_struct));
    if(op == NULL) return ;
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
        (void)fprintf(stderr, "Error 104: Input rule file not found or incorrect file name: %s.\n", op->RuleFileName);
        exit(1);
    }
    init_options( mmt );
}
