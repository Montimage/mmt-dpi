/*
 * File:   smb.h
 * Author: montimage
 *
 * Created on 07 decembre 2018
 */

#ifndef MMT_SMB_H
#define MMT_SMB_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

typedef struct smb_session_struct smb_session_t;

struct smb_session_struct {
  uint64_t session_id;
  uint8_t nt_create_request;
  uint8_t write_request;
  struct smb_session_struct * next;
  struct smb_session_struct * prev;
};

smb_session_t * smb_session_new();
void * smb_session_free();

int smb_insert_session(smb_session_t * root, smb_session_t * new_session);

smb_session_t * smb_find_session_by_id(smb_session_t * root, uint64_t session_id);

smb_session_t * smb_remove_session_by_id(smb_session_t * root, uint64_t session_id);

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_SMB_H */