/*
 * File:   hash_utils.h
 * Author: montimage
 *
 * Created on 25 juillet 2011, 15:34
 */

#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include "types_defs.h"
#include "data_defs.h"
#include "packet_processing.h"
#include "mmt_core.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: add documentation
//  API for session management
void *get_session_from_protocol_context_by_session_key(void *protocol_context, void *key);
int insert_session_into_protocol_context(void *protocol_context, void *key, void *value);
int delete_session_from_protocol_context(void *protocol_context, void *key);
void clear_sessions_from_protocol_context(void *protocol_context);
void protocol_sessions_iteration_callback(void *protocol_context, generic_mapspace_iteration_callback fct, void *args);
// End of API for session management

void *init_map_space(generic_comparison_fct comp_fct);
void *init_int_map_space(generic_int_comparison_fct comp_fct);

int insert_key_value(void *maplist, void *key, void *value);
int insert_int_key_value(void *maplist, uint32_t key, void *value);
int update_key_value(void *maplist, void *key, void *new_value);
void *find_key_value(void *maplist, void *key);
void *find_int_key_value(void *maplist, uint32_t key);
int delete_key_value(void *maplist, void *key);
int delete_int_key_value(void *maplist, uint32_t key);
void clear_map_space(void *maplist);
void clear_int_map_space(void *maplist);
void delete_map_space(void *maplist);
void delete_int_map_space(void *maplist);
void mapspace_iteration_callback(void *maplist, generic_mapspace_iteration_callback fct, void *args);
void int_mapspace_iteration_callback(void *maplist, generic_mapspace_iteration_callback fct, void *args);

int insert_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout, mmt_session_t *session);
int update_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t new_timeout, uint32_t old_timeout,
									 mmt_session_t *session);
mmt_session_t *get_timed_out_session_list(mmt_handler_t *mmt_handler, uint32_t timeout);
int delete_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout);
void clear_timeout_milestones(mmt_handler_t *mmt_handler);
int force_session_timeout(mmt_handler_t *mmt_handler, mmt_session_t *session);
void timeout_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct);
void session_timer_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct);
int insert_protocol_stack_into_map(uint32_t key, void *value);
void *get_protocol_stack_from_map(uint32_t key);
int delete_protocol_stack_from_map(uint32_t key);
void clear_protocol_stack_map();

#ifdef __cplusplus
}
#endif

#endif /* HASH_UTILS_H */
