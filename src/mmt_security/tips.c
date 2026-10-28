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
#include <pthread.h>

#include <libxml2/libxml/xmlreader.h>
#include "tips_internal.h"
#include "struct_defs.h"
#include "public_defs.h"
#include "data_defs.h"
#include "extraction_lib.h"
#include "mmt_core.h"
#include "packet_processing.h"
#include "plugin_defs.h"
#include "types_defs.h"
#define _STDC_FORMAT_MARCROS
#include <inttypes.h>

//*************************************************************************************
//*   Not included: repetition, negation, keep_state
//*************************************************************************************

/* Issue #551: the engine state lives in mmt_sec_engine_t (tips_internal.h).
 * sec_unbound is what sec_cur points to outside every engine entry point —
 * zeroed like the globals it replaces and never registered. */
static mmt_sec_engine_t sec_unbound;
__thread mmt_sec_engine_t *sec_cur = &sec_unbound;

mmt_sec_engine_t *sec_bind( mmt_sec_engine_t *e )
{
    mmt_sec_engine_t *prev = sec_cur;
    sec_cur = (e != NULL) ? e : &sec_unbound;
    return prev;
}

/* The live engines, one per handler (#551; #512 allowed one per process).
 * The mutex guards the list only: an engine's state belongs to the thread
 * that feeds its handler. Newest first, so the head is the most recently
 * loaded engine — the one the argument-less summaries report. */
static pthread_mutex_t sec_engines_lock = PTHREAD_MUTEX_INITIALIZER;
static mmt_sec_engine_t *sec_engines = NULL;

FILE *open_file(char *name, char *mode)
{
    if(name == NULL) return NULL;
    FILE *file = NULL;
    errno = 0;
    file = fopen(name, mode);
    int saveerrno = errno;
    if (file == NULL) {
        /* the caller handles the failure (#512: this used to exit) */
        (void)fprintf(stderr, "Error 100: Can't open file \"%s\" using mode \"%s\" gives error: %s\n", name, mode, strerror(saveerrno));
    }
    return file;
}
void close_file(FILE *file) {
    int ret=0;
    errno = 0;
    ret = fclose(file);
    int saveerrno = errno;
    if (ret != 0) {
        (void)fprintf(stderr, "Error 100b: Can't close file, returns: %d, gives error: %s\n", ret, strerror(saveerrno));
    }
}

/* process-wide allocation statistic, shared by every engine (atomic, #551) */
static unsigned int xallocated_memory_size;
void * xcalloc(unsigned long num, unsigned long size){
   void * retval = calloc(num, size);
   if (retval != NULL) {
       __atomic_fetch_add(&xallocated_memory_size, (unsigned int) size, __ATOMIC_RELAXED);
   }
   return retval;
}

void * xmalloc(unsigned long size) {
   void * retval = malloc(size);
   if (retval != NULL) {
       __atomic_fetch_add(&xallocated_memory_size, (unsigned int) size, __ATOMIC_RELAXED);
   }
   return retval;
}
void xfree(void *freeable) {
   if(freeable != NULL) free(freeable);
}

static int analyse_packet(const ipacket_t * ipacket);

/* The registered packet handler: arg is the engine init_sec_lib() loaded on
 * this handler (#551), bound to this thread for the packet. */
int analyse_incoming_packet(const ipacket_t * ipacket, void* arg)
{
    mmt_sec_engine_t *prev = sec_bind((mmt_sec_engine_t *) arg);
    int ret = analyse_packet(ipacket);
    (void) sec_bind(prev);
    return ret;
}

static int analyse_packet(const ipacket_t * ipacket)
{
    sec_cur->packet_count++;
    short result = 0;
    rule *curr_rule = sec_cur->top_rule;
    rule *curr_rule_instance = NULL;
    rule *temp = NULL;
    rule *root_inst = NULL;
    struct timeval current_packet_time;
    char *cause = xmalloc(SIZE_CAUSE+1);
    if(cause == NULL){
        return 0;
    }
    current_packet_time.tv_sec = get_seconds( ipacket );
    current_packet_time.tv_usec = get_useconds( ipacket );
    curr_rule = sec_cur->top_rule;
    int skip = NO;
    short if_valid_and_no_instance_satisfied_then_generate_not_satisfied = NOT_VALID;
    while (curr_rule != NULL) {
        curr_rule_instance = curr_rule->list_of_instances;
        //first verify existing instances
        skip = NO;
        if(curr_rule->delay_min < 0){
          strncpy(cause,"C1 satisfied but C2 not found in property: 'if C1 THEN BEFORE we should have C2'", SIZE_CAUSE);
          cause[SIZE_CAUSE]='\0';
          {
            //Left-branch probe: .EVENT references stay symbolic (skip_refs = YES)
            //and the rule's own tuple store is used, not an instance's.
            verify_ctx_t lctx = { ipacket, curr_rule, curr_rule->list_of_tuples, cause, current_packet_time, NO, YES };
            if_valid_and_no_instance_satisfied_then_generate_not_satisfied = verify_left(&lctx, curr_rule);
          }
          *cause = '\0';
        }
        while (curr_rule_instance != NULL) {
            verify_ctx_t vctx = { ipacket, curr_rule, curr_rule_instance->list_of_tuples, cause, current_packet_time, NO, NO };
            result = verify(&vctx, SAME, curr_rule_instance);
            if (result == NOT_VALID) {
                /* reported, then eliminated below like any other final
                 * result — the `continue` here re-verified the same
                 * instance forever (#511) */
                (void)fprintf(stderr, "Error 41: Problem in packet number: %lld\n", sec_cur->packet_count);
            }
            temp = curr_rule_instance->next;
            //if instance is VALID or NOT_VALID then eliminate it
            if (result != NOT_YET) {
                if (result == COUNT_NOT_SATISFIED || result == COUNT_NOT_SATISFIED_ELIMINATE) {
                    rule_is_satisfied_or_not( &vctx, curr_rule_instance, NOT_SATISFIED );
                    (curr_rule->nb_not_satisfied)++;
                } else if (result == COUNT_SATISFIED || result == COUNT_SATISFIED_ELIMINATE) {
                    rule_is_satisfied_or_not( &vctx, curr_rule_instance, SATISFIED );
                    (curr_rule->nb_satisfied)++;
                    //skip = YES; //Case root says that if property is satisfied thanks to current packet
                                //then do not create new instance using the current packet
                                //If new instance is wanted, this is managed by keep_state
                    if_valid_and_no_instance_satisfied_then_generate_not_satisfied = NOT_VALID;//so that right branch of BEFORE tree is not counted as
                                                                                               //NOT_SATISFIED
                }
                if (result == COUNT_NOT_SATISFIED_ELIMINATE || result == ELIMINATE || result == COUNT_SATISFIED_ELIMINATE ||
                        result == NOT_VALID || result == VALID || result == NOT_YET) {
                    /* keep_state keeps the state of a satisfied instance;
                     * an expired or failed one is not re-created — its copy
                     * expired again on every later packet (#510 follow-up) */
                    if (result == COUNT_SATISFIED_ELIMINATE)
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
          /* Known limitation: the BEFORE left-branch probe (verify_left)
           * evaluates a single event — a composite left branch is not
           * supported (#326). */
          if_valid_and_no_instance_satisfied_then_generate_not_satisfied = NOT_VALID;
          strncpy(cause,"C1 satisfied but C2 not found in property: 'if C1 THEN BEFORE we should have C2'", SIZE_CAUSE);
          cause[SIZE_CAUSE]='\0';
          {
            verify_ctx_t nctx = { ipacket, curr_rule, curr_rule->list_of_tuples, cause, current_packet_time, NO, NO };
            rule_is_satisfied_or_not( &nctx, curr_rule, NOT_SATISFIED );
          }
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
            verify_ctx_t vctx = { ipacket, curr_rule, curr_rule_instance->list_of_tuples, cause, current_packet_time, YES, NO };
            result = verify(&vctx, SAME, curr_rule_instance);
            //if instance is VALID or NOT_VALID then eliminate it
            if (result != NOT_YET) {
                if (result == COUNT_NOT_SATISFIED || result == COUNT_NOT_SATISFIED_ELIMINATE) {
                    rule_is_satisfied_or_not( &vctx, curr_rule_instance, NOT_SATISFIED );
                    (curr_rule->nb_not_satisfied)++;
                } else if (result == COUNT_SATISFIED || result == COUNT_SATISFIED_ELIMINATE) {
                    rule_is_satisfied_or_not( &vctx, curr_rule_instance, SATISFIED );
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

/* Runs with e bound to this thread (init_sec_lib). */
static int init_options( mmt_sec_engine_t *e, mmt_handler_t *mmt )
{
    int ret;

    /* packet handler 1 is the engine's: register_packet_handler() reports
     * success for an id already taken without registering, which would leave
     * the engine unfed (#551) */
    if (is_registered_packet_handler(mmt, 1)) {
        (void)fprintf(stderr, "Error 42: in registering packet handler function: id 1 is already registered on this handler.\n");
        return -1;
    }
    e->p_meta = get_protocol_id_by_name("META");
    e->a_utime = get_attribute_id_by_protocol_id_and_attribute_name(e->p_meta, "UTIME");
    e->token2 = xmalloc(30);
    e->token3 = xmalloc(30);
    if (e->token2 == NULL || e->token3 == NULL) return -1;
    if (read_rules( mmt ) != 0) return -1;

    //we now have registered extraction attributes
    // The next function is to be called with the right parameters
    //    analyse_incoming_packet(top_attribute);
    ret = register_packet_handler( mmt, 1, analyse_incoming_packet, (u_char *) e );
    if (ret <= 0) {
        (void)fprintf(stderr, "Error 42: in registering packet handler function.\n");
        free_rules();
        return -1;
    }
    //register_packet_handler(mmt, 2, debug_extracted_attributes_printout_handler, NULL);
    return 0;
}

/* Frees what an engine owns; e is bound to this thread. Live rule instances
 * hang off each ROOT's list_of_instances and are not part of the rule trees
 * free_rules() releases. */
static void free_engine( mmt_sec_engine_t *e )
{
    rule *r, *inst;
    for (r = e->top_rule; r != NULL; r = r->next) {
        while ((inst = r->list_of_instances) != NULL) {
            rule *root = r, *head = inst;
            eliminate_instance(&root, &inst, "instance");
            if (r->list_of_instances == head) break; /* not unlinked: never loop */
        }
    }
    free_rules();
    xfree(e->token2);
    xfree(e->token3);
    if (e->op != NULL) xfree(e->op->RuleFileName);
    xfree(e->op);
    xfree(e);
}

/* Whether e's packet handler is registered on the live handler mmt. */
static int engine_is_registered( const mmt_handler_t *mmt, const mmt_sec_engine_t *e )
{
    uint32_t i;
    for (i = 0; i < mmt->packet_handlers_len; i++) {
        const packet_handler_t *ph = &mmt->packet_handlers[i];
        if (ph->packet_handler_id == 1)
            return ph->function == analyse_incoming_packet && ph->args == (u_char *) e;
    }
    return 0;
}

static void unlink_engine_locked( mmt_sec_engine_t *e )
{
    mmt_sec_engine_t **pp;
    for (pp = &sec_engines; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == e) { *pp = e->next; e->next = NULL; return; }
    }
}

/* The registry entry for the live handler mmt — loading or loaded — or
 * NULL. The registry is keyed by the handler's address, and a handler
 * closed without close_sec_lib() leaves its engine behind: a loaded entry
 * whose packet handler is not registered on mmt belongs to that closed
 * handler, whose address mmt reuses, and is freed here (it touches only
 * the engine's own memory, never the dead handler). */
static mmt_sec_engine_t *find_engine_locked( const mmt_handler_t *mmt )
{
    mmt_sec_engine_t *e;
    for (e = sec_engines; e != NULL; e = e->next)
        if (e->mmt == mmt) break;
    if (e != NULL && e->loaded && !engine_is_registered(mmt, e)) {
        mmt_sec_engine_t *prev = sec_bind(e);
        unlink_engine_locked(e);
        free_engine(e);
        (void) sec_bind(prev);
        e = NULL;
    }
    return e;
}

mmt_sec_engine_t *mmt_sec_engine_of( const mmt_handler_t *mmt )
{
    mmt_sec_engine_t *e;
    pthread_mutex_lock(&sec_engines_lock);
    e = find_engine_locked(mmt);
    if (e != NULL && !e->loaded) e = NULL;
    pthread_mutex_unlock(&sec_engines_lock);
    return e;
}

int init_sec_lib( mmt_handler_t *mmt, char * property_file,
        enum_print print_option, result_callback cont_funct, void * user_args)
{
    mmt_sec_engine_t *e, *prev;
    OPTIONS_struct *op;
    if (mmt == NULL || property_file == NULL) {
        (void)fprintf(stderr, "Error 104: init_sec_lib() needs a handler and a rule file.\n");
        return -1;
    }
    e = (mmt_sec_engine_t *)xcalloc(1, sizeof (mmt_sec_engine_t));
    if (e == NULL) return -1;
    e->mmt = mmt;
    /* One engine per handler: the handler is claimed under the registry
     * lock, so of two concurrent calls on one handler exactly one loads. */
    pthread_mutex_lock(&sec_engines_lock);
    if (find_engine_locked(mmt) != NULL) {
        pthread_mutex_unlock(&sec_engines_lock);
        xfree(e);
        (void)fprintf(stderr, "Error 105: init_sec_lib() called again: this handler already runs a security engine.\n");
        return -1;
    }
    e->next = sec_engines;
    sec_engines = e;
    pthread_mutex_unlock(&sec_engines_lock);

    prev = sec_bind(e);
    op = e->op = (OPTIONS_struct *)xcalloc(1, sizeof (OPTIONS_struct));
    if(op == NULL) goto fail;
    op->StartTime = time(NULL);
    op->Print = print_option;
    op->user_args = (void *)user_args;
    op->RuleFileName = strdup(property_file);
    op->callback_funct = cont_funct;
    if (op->RuleFileName == NULL) goto fail;
    op->RuleFile = open_file(op->RuleFileName, "r");
    if (op->RuleFile == NULL) {
        (void)fprintf(stderr, "Error 104: Input rule file not found or incorrect file name: %s.\n", op->RuleFileName);
        goto fail;
    }
    /* only proves the file can be read: libxml2 opens it by name */
    close_file(op->RuleFile);
    op->RuleFile = NULL;
    if (init_options( e, mmt ) != 0) goto fail;
    pthread_mutex_lock(&sec_engines_lock);
    e->loaded = 1;
    pthread_mutex_unlock(&sec_engines_lock);
    (void) sec_bind(prev);
    return 0;
fail:
    /* nothing of a failed load survives: a later call may try again */
    pthread_mutex_lock(&sec_engines_lock);
    unlink_engine_locked(e);
    pthread_mutex_unlock(&sec_engines_lock);
    free_engine(e);
    (void) sec_bind(prev);
    return -1;
}

int close_sec_lib( mmt_handler_t *mmt )
{
    mmt_sec_engine_t *e, *prev;
    pthread_mutex_lock(&sec_engines_lock);
    e = find_engine_locked(mmt);
    if (e != NULL && !e->loaded) e = NULL;   /* still loading: not closable */
    /* not from the engine's own result callback: its packet is still being
     * analysed over the rule list this would free */
    if (e != NULL && e == sec_cur) e = NULL;
    if (e != NULL) unlink_engine_locked(e);
    pthread_mutex_unlock(&sec_engines_lock);
    if (e == NULL) return -1;
    /* find_engine_locked() proved packet handler 1 is this engine's */
    (void) unregister_packet_handler(mmt, 1);
    prev = sec_bind(e);
    free_engine(e);
    (void) sec_bind(prev);
    return 0;
}

/* The summaries take no engine argument (public_defs.h): they report the
 * engine bound on this thread — a result callback calling them — or else
 * the most recently loaded live engine, as the one engine #512 allowed (an
 * engine still loading is skipped). The registry lock keeps that engine
 * from being closed meanwhile. */
static void with_summary_engine( void (*fn)(void *), void *arg )
{
    mmt_sec_engine_t *prev, *e;
    if (sec_cur != &sec_unbound) { fn(arg); return; }
    pthread_mutex_lock(&sec_engines_lock);
    for (e = sec_engines; e != NULL && !e->loaded; e = e->next) ;
    prev = sec_bind(e);
    fn(arg);
    (void) sec_bind(prev);
    pthread_mutex_unlock(&sec_engines_lock);
}

static void print_summary_cb( void *arg ) { (void) arg; print_engine_summary(); }
static void xml_summary_cb( void *arg ) { *(char **) arg = xml_engine_summary(); }

void print_summary()
{
    with_summary_engine(print_summary_cb, NULL);
}

char * xml_summary()
{
    char *xml = NULL;
    with_summary_engine(xml_summary_cb, &xml);
    return xml;
}
