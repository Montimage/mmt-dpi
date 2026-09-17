/*
 * File:   tips_internal.h
 * Author: montimage
 *
 * Internal cross-unit declarations for the MMT_Security rule engine.
 *
 * tips.c was split along its four responsibilities (issue #235,
 * F-CLEAN-003):
 *   - tips.c         driver/runtime: engine state, memory and file
 *                    helpers, init_sec_lib/init_options and the
 *                    analyse_incoming_packet entry point;
 *   - tips_xml.c     XML loading of the properties file into rule trees;
 *   - tips_extract.c pcap extraction and leaf-expression evaluation;
 *   - tips_eval.c    rule-instance lifecycle and the verify() traversal;
 *   - tips_report.c  verdict reporting, JSON history and reactions.
 *
 * The entry points and state below keep external linkage so the five
 * units can call each other; they are not part of the public SDK ABI
 * (this header is not installed). No `extern` lines appear in the .c
 * files — every cross-boundary symbol is declared here.
 */

#ifndef TIPS_INTERNAL_H
#define TIPS_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/time.h>

#include "struct_defs.h"
#include "public_defs.h"
#include "data_defs.h"

#define LIB_NAME "libembedded_functions.so"
#define SIZE_CAUSE 1000

/* ===== Engine state =======================================================
 * One definition site each — all in tips.c. The writer set spans every
 * unit, so file-local `static` is not an option: op is set by
 * init_sec_lib() (tips.c) and read by loaders, evaluators and reporters;
 * top_rule is the rule list the XML loader builds and the driver and the
 * reporters walk; token2/token3 are the scratch token buffers init_options
 * allocates for the XML-side parsers; packet_count/p_meta/a_utime are the
 * packet clock state. bot_rule/root_rule and the father stack are written
 * and read only inside tips_xml.c, so they stay file-local there; the same
 * applies to corr_mess (tips_report.c), temptemp (tips_eval.c) and
 * counter_detection (tips_report.c). */

extern OPTIONS_struct *op;
extern rule *top_rule;
extern long long packet_count;
extern short p_meta;
extern short a_utime;
extern char *token2;
extern char *token3;

/* ===== tips.c — helpers and the packet entry point =======================*/

void * xcalloc(unsigned long num, unsigned long size);
void * xmalloc(unsigned long size);
void xfree(void *freeable);
void close_file(FILE *file);

/* ===== tips_xml.c — XML loading, called by tips.c and the others =========*/

void read_rules( mmt_handler_t *mmt );
rule * create_rule();
void convert_mac_bytes_to_string(char **pszMACAddress, unsigned char *pbyMacAddressInBytes);
char * funct_extract_name(char * input);
char * funct_get_info_param( mmt_handler_t *mmt, short reg_tuple, char * input, tuple *a_tuple);

/* ===== tips_extract.c — pcap extraction and leaf evaluation ==============*/

long get_seconds( const ipacket_t *pkt );
long get_useconds( const ipacket_t *pkt );
char * get_value( const ipacket_t *pkt, char *input, short *jump, short *size, tuple *list_of_tuples );
void * funct_get_params_and_execute( const ipacket_t *pkt, short skip_refs, char *lib_name, char *funct_name, int data_size, tuple *tt, tuple *list_of_tuples, short *found );
int exists_or_not (const ipacket_t *pkt, short operator, rule *r);
int get_data_from_pcap( const ipacket_t *pkt, short skip_refs, short action, void** result_value, tuple *list_of_tuples, short operator, rule *r1, rule *r2);

/* ===== tips_eval.c — instance lifecycle and the verify() traversal =======*/

rule *create_instance(rule **root_inst, rule *r, rule* father);
rule *copy_instance(rule **root_inst, rule *r, rule* father, rule *orig_rule);
int eliminate_instance(rule **r, rule **i, char *type);
int verify_left(const ipacket_t *pkt, char *cause, rule *r, rule *root);

//Invariant arguments threaded through one verify() traversal: the packet
//under test, the rule the instance belongs to, the instance's tuple list,
//the caller's verdict scratch flag, the diagnostic buffer and the packet's
//arrival time. leftleft rides along because it is constant for the whole
//traversal except the single point where a THEN node drops to its right
//branch; the recursion is the only writer and it restores the flag before
//returning, so callers always observe the value they set.
typedef struct {
    const ipacket_t *pkt;
    rule *curr_root;
    tuple *list_of_tuples;
    short *reference;
    char *cause;
    struct timeval current_packet_time;
    short leftleft;
} verify_ctx_t;

int verify( verify_ctx_t *ctx, short context, rule *r );

/* ===== tips_report.c — verdicts, history, reactions, summaries ===========*/

void store_history(const ipacket_t *pkt, short context, rule *curr_root, rule *curr_rule, char *cause, short event_id);
void store_tuples( const ipacket_t *pkt, short context, rule *curr_root, rule *curr_rule, short event_id, char *cause );
void detected_corrupted_message(short print_option, rule *r, char *cause, short state, struct timeval packet_time_stamp);
void rule_is_satisfied_or_not(const ipacket_t *pkt, short print_option, rule *curr_root, rule *r, char *cause, short state, short use_cause);

#ifdef __cplusplus
}
#endif

#endif /* TIPS_INTERNAL_H */
