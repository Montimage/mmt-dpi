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

/* An embedded #function(...) takes at most this many parameters: the call
 * goes through one exact per-arity signature, void *f(void *, ...) with
 * 0..4 void * parameters (#511). */
#define EMBEDDED_FUNCT_MAX_PARAMS 4
typedef void *(*embedded_funct_t)(void);

/* Default directory of the reaction scripts and their detection_<n>.data
 * files: $(MMT_BASE)/probe/conf, baked in by rules/common.mk; the
 * MMT_SEC_REACTION_DIR environment variable (an absolute path) overrides it
 * at run time (#512). */
#ifndef MMT_SEC_REACTION_DIR_OPT
#define MMT_SEC_REACTION_DIR_OPT "/opt/mmt/probe/conf"
#endif

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

//Invariant arguments threaded through one verify() traversal: the packet
//under test, the rule the instance belongs to, the instance's tuple list,
//the diagnostic buffer and the packet's arrival time. leftleft rides along
//because it is constant for the whole traversal except the single point
//where a THEN node drops to its right branch; the recursion is the only
//writer and it restores the flag before returning, so callers always
//observe the value they set. skip_refs tells the pcap extraction whether
//.EVENT tuple references resolve (NO) or stay symbolic (YES — used by
//verify_left's left-branch probe); it used to be passed alongside pkt and
//list_of_tuples through verify_segment, get_data_from_pcap and
//funct_get_params_and_execute — that bundle, and the one reporting helpers
//re-received, now rides on this struct (issue #236, F-CLEAN-003).
typedef struct {
    const ipacket_t *pkt;
    rule *curr_root;
    tuple *list_of_tuples;
    char *cause;
    struct timeval current_packet_time;
    enum_yes leftleft;
    enum_yes skip_refs;
} verify_ctx_t;

/* ===== tips.c — helpers and the packet entry point =======================*/

void * xcalloc(unsigned long num, unsigned long size);
void * xmalloc(unsigned long size);
void xfree(void *freeable);
void close_file(FILE *file);
/* Loads the rule file and registers the packet handler on mmt. Returns 0, or
 * -1 with the reason on stderr — a malformed rule file, a missing embedded
 * function, a failed registration, or a second call: the engine state is
 * process-global, so a process runs at most one engine (docs/THREADING.md).
 * A failed load frees what it built and leaves the engine uninitialised. */
int init_sec_lib( mmt_handler_t *mmt, char *property_file, enum_print print_option, result_callback cont_funct, void *user_args );

/* ===== tips_xml.c — XML loading, called by tips.c and the others =========*/

int read_rules( mmt_handler_t *mmt );
void free_rules( void );
rule * create_rule();
void convert_mac_bytes_to_string(char **pszMACAddress, unsigned char *pbyMacAddressInBytes);
char * funct_extract_name(char * input);
int funct_get_info_param( mmt_handler_t *mmt, enum_yes reg_tuple, char * input, tuple *a_tuple, char **next);
int funct_count_params( const char *call );

/* ===== tips_extract.c — pcap extraction and leaf evaluation ==============*/

long get_seconds( const ipacket_t *pkt );
long get_useconds( const ipacket_t *pkt );
char * get_value( const ipacket_t *pkt, char *input, short *jump, short *size, tuple *list_of_tuples );
embedded_funct_t embedded_funct_resolve( const char *funct_name );
void * funct_get_params_and_execute( verify_ctx_t *ctx, embedded_funct_t funct, int data_size, tuple *tt, tuple *list_of_tuples, enum_found *found );
int exists_or_not (const ipacket_t *pkt, enum_operation operator, rule *r);
int get_data_from_pcap( verify_ctx_t *ctx, enum_operation action, void** result_value, enum_operation operator, rule *r1, rule *r2);

/* ===== tips_eval.c — instance lifecycle and the verify() traversal =======*/

rule *create_instance(rule **root_inst, rule *r, rule* father);
rule *copy_instance(rule **root_inst, rule *r, rule* father, rule *orig_rule);
int eliminate_instance(rule **r, rule **i, char *type);
int verify_left( verify_ctx_t *ctx, rule *r );
int verify( verify_ctx_t *ctx, enum_operation_type context, rule *r );

/* ===== tips_report.c — verdicts, history, reactions, summaries ===========*/

void store_history( verify_ctx_t *ctx, enum_operation_type context, rule *curr_rule, char *cause, short event_id );
void store_tuples( verify_ctx_t *ctx, enum_operation_type context, rule *curr_rule, short event_id, char *cause );
void detected_corrupted_message( verify_ctx_t *ctx, rule *r, char *cause, enum_print state );
void rule_is_satisfied_or_not( verify_ctx_t *ctx, rule *r, enum_print state );

#ifdef __cplusplus
}
#endif

#endif /* TIPS_INTERNAL_H */
