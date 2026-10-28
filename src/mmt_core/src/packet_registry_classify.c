/*
 * packet_registry_classify.c — per-protocol callback registration: the
 * classification chain, the session-data analysis chain and the session
 * callbacks a plugin attaches to its protocol_t. Split out of
 * packet_registry.c (issue #549); the protocol table itself stays there.
 */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include "packet_processing.h"
#include "mmt_core.h"
#include "memory.h"
#include "plugins_engine.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <pthread.h>

/**
 * Register classificaiton function internal - insert this function into right position: for example: classify FTP after HTTP -> HTTP 10, FTP 50
 * @param  proto              Protocol ID
 * @param  classification_fct classify function
 * @param  weight             weight of this function
 * @return                    0 failed
 *                            1 successful
 */
int register_classification_function_internal(protocol_t * proto, generic_classification_function classification_fct, int weight) {
    if (weight < 0) weight = 0;
    if (weight > 100) weight = 100;
    mmt_classify_proto_t * temp = (mmt_classify_proto_t *) mmt_malloc(sizeof (mmt_classify_proto_t));
    if (temp == NULL) {
        return 0;
    }
    memset(temp, 0, sizeof (mmt_classify_proto_t));
    temp->weight = weight;
    temp->next = NULL;
    temp->previous = NULL;
    temp->classify_me = classification_fct;

    mmt_classify_proto_t * temp_list = proto->classify_next.classify_protos;
    if (temp_list == NULL) {
        proto->classify_next.classify_protos = temp;
        temp->next = NULL;
        temp->previous = NULL;
    } else {
        if (temp->weight < temp_list->weight) {
            //The new element should be inserted at the head of the list
            temp->next = temp_list;
            temp->previous = NULL;
            temp_list->previous = temp;
            proto->classify_next.classify_protos = temp;
        } else {
            while (temp_list->next != NULL) {
                if (temp_list->next->weight > temp->weight) {
                    //Get out of the while loop
                    break;
                }
                temp_list = temp_list->next;
            }
            //Now we point to the element where we will insert the new elemnt
            temp->next = temp_list->next;
            temp->previous = temp_list;
            if (temp_list->next != NULL) {
                //temp_list is not the last element
                temp_list->next->previous = temp;
            }
            temp_list->next = temp;
        }
    }

    return 1;
}

/**
 * Register classification function with parent protocol
 * For examples: register mmt_check_ftp for protocol FTP with parent protocol is TCP
 * @param  proto_id           protocol id (FTP)
 * @param  classification_fct classify function
 * @param  weight             weight of this function
 * @return                    0 if there is no classification function
 *                            call to register_classification_function_internal
 */
bool register_classification_function_with_parent_protocol(uint32_t proto_id, generic_classification_function classification_fct, int weight) {
    if (classification_fct != NULL) {
        protocol_t * proto = get_protocol_struct_by_protocol_id(proto_id);
        if (proto) {
            if (weight < 0) weight = 0;
            if (weight > 100) weight = 100;
            // if ((weight > 10) && (weight < 90)) weight = 90;// LN: Dont know why we do that????
            return register_classification_function_internal(proto, classification_fct, weight);
        }
    }
    return 0;
}
/**
 * Register classification function without parent protocol
 * @param  proto              protocol
 * @param  classification_fct classification function
 * @return                    0 if failed
 *                            go to #register_classification_function_internal
 */
/* Default weight for callbacks registered without an explicit one: the middle
 * of the 10..80 range register_classification_function_full() documents. */
#define MMT_DEFAULT_CALLBACK_WEIGHT 50

bool register_classification_function(protocol_t *proto, generic_classification_function classification_fct) {
    if (classification_fct != NULL) {
        return register_classification_function_internal(proto, classification_fct, MMT_DEFAULT_CALLBACK_WEIGHT);
    }
    return 0;
}

bool register_pre_post_classification_functions(protocol_t *proto,
        generic_classification_function pre_classification,
        generic_classification_function post_classification) {

    proto->classify_next.pre_classify = pre_classification;
    proto->classify_next.post_classify = post_classification;

    return 1;

}

bool register_classification_function_full(protocol_t *proto, generic_classification_function classification_fct, int weight,
        generic_classification_function pre_classification, generic_classification_function post_classification) {
    if (weight < 10) weight = 10;
    if (weight > 90) weight = 90;

    int retval = 1;
    if (classification_fct != NULL) {
        retval = register_classification_function_internal(proto, classification_fct, weight);
    }
    if (retval > 0) {
        proto->classify_next.pre_classify = pre_classification;
        proto->classify_next.post_classify = post_classification;
    }
    return retval;
}

void register_sessionizer_function(protocol_t *proto, generic_sessionizer_function sessionizer_fct,
                                   generic_session_context_cleanup_function session_context_cleanup_fct, generic_comparison_fct session_keys_comparison_fct) {
    proto->sessionize = sessionizer_fct;
    proto->session_context_cleanup = session_context_cleanup_fct;
    proto->has_session = HAS_SESSION_CONTEXT;
    proto->session_key_compare = session_keys_comparison_fct;
}

void register_session_hash_function(protocol_t *proto, generic_hash_fct session_key_hash_fct) {
    proto->session_key_hash = session_key_hash_fct;
}

void register_session_equal_function(protocol_t *proto, generic_equal_fct session_key_equal_fct) {
    proto->session_key_equal = session_key_equal_fct;
}

void register_proto_context_init_cleanup_function(protocol_t *proto, generic_proto_context_init_function context_init_fct,
        generic_proto_context_cleanup_function context_cleanup_fct, void * args) {
    proto->protocol_context_init = context_init_fct;
    proto->protocol_context_cleanup = context_cleanup_fct;
    proto->protocol_context_args = args;
}

void register_session_data_initialization_function(protocol_t *proto, generic_session_data_initialization_function session_data_init_fct) {
    proto->session_data_init = session_data_init_fct;
}

void register_session_data_cleanup_function(protocol_t *proto, generic_session_data_cleanup_function session_data_cleanup_fct) {
    proto->session_data_cleanup = session_data_cleanup_fct;
}

int register_data_analysis_function_internal(protocol_t * proto, generic_session_data_analysis_function analysis_fct, int weight) {
    if (weight < 0) weight = 0;
    if (weight > 100) weight = 100;
    mmt_analyse_me_t * temp = (mmt_analyse_me_t *) mmt_malloc(sizeof (mmt_analyse_me_t));
    if (temp == NULL) {
        return 0;
    }
    memset(temp, 0, sizeof (mmt_analyse_me_t));
    temp->weight = weight;
    temp->next = NULL;
    temp->previous = NULL;
    temp->analyse_me = analysis_fct;

    mmt_analyse_me_t * temp_list = proto->data_analyser.analyse;
    if (temp_list == NULL) {
        proto->data_analyser.analyse = temp;
        temp->next = NULL;
        temp->previous = NULL;
    } else {
        if (temp->weight < temp_list->weight) {
            //The new element should be inserted at the head of the list
            temp->next = temp_list;
            temp->previous = NULL;
            temp_list->previous = temp;
            proto->data_analyser.analyse = temp;
        } else {
            while (temp_list->next != NULL) {
                if (temp_list->next->weight > temp->weight) {
                    //Get out of the while loop
                    break;
                }
                temp_list = temp_list->next;
            }
            //Now we point to the element where we will insert the new elemnt
            temp->next = temp_list->next;
            temp->previous = temp_list;
            if (temp_list->next != NULL) {
                //temp_list is not the last element
                temp_list->next->previous = temp;
            }
            temp_list->next = temp;
        }
    }

    return 1;
}

bool register_session_data_analysis_function_with_protocol(uint32_t proto_id,
        generic_session_data_analysis_function session_data_analysis_fct, int weight) {
    if (session_data_analysis_fct != NULL) {
        protocol_t * proto = get_protocol_struct_by_protocol_id(proto_id);
        if (proto) {
            if (weight < 0) weight = 0;
            if (weight > 100) weight = 100;
            if ((weight > 10) && (weight < 90)) weight = 90;
            return register_data_analysis_function_internal(proto, session_data_analysis_fct, weight);
        }
    }
    return 0;
}

bool register_session_data_analysis_function(protocol_t *proto,
        generic_session_data_analysis_function session_data_analysis_fct) {
    if (session_data_analysis_fct != NULL) {
        return register_data_analysis_function_internal(proto, session_data_analysis_fct, MMT_DEFAULT_CALLBACK_WEIGHT);
    }
    return 0;
}

bool register_pre_post_analysis_functions(protocol_t *proto,
        generic_session_data_analysis_function pre_analysis,
        generic_session_data_analysis_function post_analysis) {

    proto->data_analyser.pre_analyse  = pre_analysis;
    proto->data_analyser.post_analyse = post_analysis;

    return 1;
}

bool register_session_data_analysis_function_full(protocol_t *proto,
        generic_session_data_analysis_function session_data_analysis_fct,
        int weight,
        generic_session_data_analysis_function pre_analysis,
        generic_session_data_analysis_function post_analysis) {
    if (weight < 10) weight = 10;
    if (weight > 90) weight = 90;

    int retval = 1;
    if (session_data_analysis_fct != NULL) {
        retval = register_data_analysis_function_internal(proto, session_data_analysis_fct, weight);
    }
    if (retval > 0) {
        proto->data_analyser.pre_analyse = pre_analysis;
        proto->data_analyser.post_analyse = post_analysis;
    }
    return retval;
}
