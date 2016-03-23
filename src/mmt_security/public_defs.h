/* 
 * File:   public_defs.h
 * Author: montimage
 *
 * Created on 8 mars 2011, 15:26
 */

#ifndef PUBLIC_DEFS_H
#define	PUBLIC_DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap/pcap.h>

typedef void (*result_callback) (int prop_id, char *verdict, char *type, char *cause, char *history, struct timeval packet_timestamp,void *user_args);

//--------------------------------- Command options ----------------------------------------------------
typedef struct {
  char Options[100] ;
  char * TraceFileName;
  char * TraceInterfaceName;
  FILE * TraceFile;
  char * RuleFileName;
  FILE * RuleFile;
  char * OutputFileName;
  FILE * OutputFile;
  short Print;
  short TypeInput;
  time_t StartTime;
  time_t EndTime ;
  long timestamp_proto_id;
  long timestamp_field_id;
  result_callback callback_funct_db_create;
  result_callback callback_funct;
  result_callback callback_funct_db_insert;
  int property_table[100];
  int event_table[1000];
  void * user_args;
  pcap_t *pcap; //TODO: check if we need this! Normally the library should not depend on pcap! I think this should be deleted
  struct pcap_pkthdr p_pkthdr;  //TODO: same as previous comment, this should be removed, in all cases we should use our own packet
                                //header structure defined in MMT extract lib
} OPTIONS_struct ;      //Structure containing command options
//--------------------------------- End of command options ----------------------------------------------------

enum {
  SATISFIED, NOT_SATISFIED, BOTH, NEITHER
}enum_print;

enum {
  PCAP, TDMA 
}enum_type_input;

#define MTU_BIG               (16*1024)

void init_options ();
void print_summary ();
FILE *open_file (char *name, char *mode);

#ifdef	__cplusplus
}
#endif

#endif	/* PUBLIC_DEFS_H */

