/*
 * File:   struct_defs.h
 * Author: montimage
 *
 * Created on 8 mars 2011, 15:26
 */

#ifndef STRUCT_DEFS_H
#define	STRUCT_DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

enum {
  ROOT, SON, LEAF, ROOT_INSTANCE, EVENT
}enum_type_node;

enum {
  VALID, NOT_VALID, NOT_YET, TIMEOUT, TIMEIN, COUNTOUT, COUNTIN, ELIMINATE, CONTINUE, COUNT_SATISFIED,
  COUNT_SATISFIED_ELIMINATE, COUNT_NOT_SATISFIED, COUNT_NOT_SATISFIED_ELIMINATE, SKIP2
}enum_result;

enum {
  OR, AND, NOT, REPEAT, NEQ, EQ, GT, GTE, LT, LTE,
  THEN, COMPUTE, COMPARE, XC, XCE, XD, XDE, XE, ADD, SUB,
  MUL, DIV, XVAR, XCON, NOP, XAND, XOR, XIN, XFUNCT
//NEQ =  not equal to
//GT  =  grater than
//E   =  ... or equal to
//LT  =  less than
//XC  =  contains     (for text)
//XD  =  contained in (for text)
//XE  =  identical to (for text)
//ADD =  add (numeric operator)
//SUB =  subtract (numeric operator)
//MUL =  multiply (numeric operator)
//DIV =  divide (numeric operator)
//XIN =  in the table (numeric operator)
}enum_operation;

enum {
  ATTACK, SECURITY_RULE, TEST
}enum_type_rule_node;

enum {
  YES, NO, NOT_USED
}enum_yes;

enum {
  NOT_OK, OK
}enum_ok;

enum {
  DONT_CLEAN, CLEAN
}enum_clean;

enum {
  FOUND, NOT_FOUND, SKIP
}enum_found;

#define FORMAT_IP(ip)  ((ip)&0x000000ff),((ip)&0x0000ff00)>>8,((ip)&0x00ff0000)>>16,(ip)>>24

#define FIRST_EVENT_NUMBER 100

enum {
  BEFORE, AFTER, SAME
}enum_operation_type;

typedef struct ATTRIBUTE_struct{
  long protocol_id;//Number that identifies protocol (using those defined in protodef.h)
  long field_id;   //Number that identifies attribute (using those defined in protodef.h)
  void *data;      //Binary that needs to be casted using data_type given by protocol_id and field_id (NULL if in given rule)
  struct ATTRIBUTE_struct *next; //Pointer to the next event element. NULL if this is the last event element.
}packet_attribute;

//END_OF_PUBLIC

typedef struct TUPLE_struct{ //used by list_of_tuples to store values in a rule
  long protocol_id;
  long field_id;
  long data_type_id;
  int data_size;
  short event_id;
  int valid; //VALID/NOT_YET indicates if the values are valid or not yet set
  void *data;                //binary that needs to be casted using data_type
  struct TUPLE_struct *next; //next tuple used only in ROOT_INSTANCE to store a list of values
}tuple;

typedef struct RULE_struct{
  short type;		//ROOT/SON/LEAF/ROOT_INSTANCE/EVENT
  short value;		//THEN/OR/AND/NOT/REPEAT/COMPUTE/event_number
  short already_satisfied; //indicates that the rule has already been satisfied so that a timeout will not be treated as a violation
  tuple t;              //Only used by a LEAF in a EVENT or (t.valid, t.data) to store result from compute
  char * description;   //Only used by a ROOT or a ROOT_INSTANCE node. Printed when a conclusion for the rule is reached so that the user can identify it.
  char * funct_name;    //Used by XFUNCT nodes to hold function_name
  struct RULE_struct *root; //Only used by non-ROOT and non-ROOT_INSTANCE
  int property_id;      //Only used by a ROOT node. Printed when a conclusion for the rule is reached so that the user can identify it.
  char* if_satisfied; //Only used by a ROOT node. Function call done  when a conclusion for the rule is reached.
  char* if_not_satisfied; //Only used by a ROOT node. Function call done  when a conclusion for the rule is reached.
  int type_rule;        //Only used by a ROOT node. Determines how the rule will be printed.
  //char * history;       //Only used by a ROOT_INSTANCE node. Printed when a conclusion for the rule is reached so that the user can identify the causes.
  char * json_history;       //Only used by a ROOT_INSTANCE node. Printed when a conclusion for the rule is reached so that the user can identify the causes.
  long nb_satisfied;    //Only used by ROOT to keep statistics per rule
  long nb_not_satisfied;//Only used by ROOT to keep statistics per rule
  short valid;		//VALID/NOT_VALID/NOT_YET
  char *delay_units;	//default is seconds; other possible values: "Y","M","D","H","m","s","ms","mms"
  double delay_max;	//default is 0, if value is < 0 then event needs to be satisfied before, if = 0 then in same packet, if > 0 then after
  double delay_min;	//idem
  short not_equal_max;  //default is NO (delay <= delay_max), if YES (delay < delay_max)
  short not_equal_min;  //default is NO (delay >= delay_min), if YES (delay > delay_min)
  int counter_max;	//idem, note that either delay or counter needs to be used not both
  int counter_min;	//idem
  short always_create_new;//YES/NO default is YES (optional), can be used at root level (use packet that satisfied a rule to create a new instance or not),
                          //                        and can be used at the event level (use packet that satisfied event to create a new instance or not)
  int repeat_times;	        //used only for REPEAT node (optional)
  int repeat_times_found;	//couter of times detected
  struct timeval timer; //receives current packet time when need to start calculating for a timeout
  int counter;          //set to 1 when need to start calculating number of packets

  char * boolean_expression; //Only used in an event node for writing it to the db
  short event_id;         //Only used when it is an operator node in a event
  char * keep_state;       //used at ROOT_INSTANCE node to indicate that the rule should be kept and that the state of the listed event ids should be
                          //preserved or eliminated. This is so that, for instance, a rule with T(E1, E2) will give two SATISFIED if we get E1,E2,E2
                          //(until the timeout for the rule)

  struct TUPLE_struct *list_of_tuples_to_print;  //Only used by a ROOT to list <protocol_id, field_id, data_type_id>
                                                 //to printout when the rule is satisfied or not.

  struct TUPLE_struct *list_of_tuples;           //Used by a ROOT_INSTANCE to store all the values with a reference attribute in a EVENT.
                                                 //and by FUNCT to store information on return value and parameters
  struct RULE_struct  *list_of_sons;             //For all, creates hierarchy
  struct RULE_struct  *list_of_instances;        //Only if ROOT node
  //struct RULE_struct  *attached_rule;            //Only used in BEFORE nodes
  //short skip_control;                            //Only used in BEFORE nodes in attached rules to determine if left hand is valid but the context not
  struct RULE_struct  *prev;
  struct RULE_struct  *next;
  struct RULE_struct  *father; //used only when creating computation tree or for backtracking in case of NOT node
}rule;

typedef struct FATHER_struct{
  short depth;          //node tree depth (rule/event is 1)
  struct RULE_struct *node;
  struct FATHER_struct *prev;
  struct FATHER_struct *next;
}father;

typedef struct REFERENCE_NAME_struct{
  char * name;
  short  value;
  struct REFERENCE_NAME_struct *next;
}reference_name;

static rule *top_rule = NULL;
static rule *bot_rule = NULL;
static father *top_father = NULL;
static father *bot_father = NULL;
static rule *root_rule;

#define MTU_BIG               (16*1024)


/*
    //List of events to verify for a given rule or provided by an event notification

    typedef struct EVENT_struct {
        int event_id;
        long protocol_id;
        long field_id;
        int operation; //The comparaison operator. This can be OR, AND, EQ, GT, GTE, LT or LTE given by enum_operation
        void *data; //Binary that needs to be casted using data_type given by protocol_id and field_id
        struct EVENT_struct *next;
    } event;

    //List of given events for a given rule

    typedef struct GIVEN_EVENT_struct {
        int event_id; ////1..number of events
        struct EVENT_struct *list_of_events;
        struct ATTRIBUTE_struct *list_of_attributes;
        struct GIVEN_EVENT_struct *next_event;
    } given_event;

    //List of given rules

    typedef struct GIVEN_RULE_struct {
        int rule_id; //1..number of rules
        struct GIVEN_EVENT_struct *list_of_given_events;
        struct GIVEN_RULE_struct *next_rule;
    } given_rule;

    //Structure used to provide the information on an event that has occurred.
    //An event can be the reception of a message containing specific data
    //(i.e. reception of an HTTP message with OK response code)

    typedef struct EVENT_NOTIFICATION_struct { //list of events observed for one packet
        long rule_id;
        long event_id;
        struct timeval timestamp;

        struct EVENT_struct *list_of_events;
        struct ATTRIBUTE_struct *list_of_attributes;
    } event_notification;
*/
#ifdef	__cplusplus
}
#endif

#endif	/* STRUCT_DEFS_H */

