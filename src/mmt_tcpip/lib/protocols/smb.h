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

#define SMB_VERSION_1 0xff
#define SMB_VERSION_2 0xfe
#define SMB_VERSION_3 0xfd

#define SMB1_CMD_CLOSE 0x04
#define SMB1_CMD_READ 0x2e
#define SMB1_CMD_WRITE 0x2f
#define SMB1_CMD_NT_TRANS 0xa0
#define SMB1_CMD_NT_CREATE 0xa2
#define SMB1_CMD_TRANS2 0x32

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

typedef struct smb_session_struct smb_session_t;

typedef struct smb_file_struct smb_file_t;

struct smb_file_struct {
  uint16_t file_id;
  uint32_t current_len;
  uint32_t current_seg_len;
  mmt_header_line_t * file_path;
  smb_file_t * next;
};

struct smb_session_struct {
  uint64_t session_id;
  // command
  uint8_t smb1_cmd_write; // 0x2f
  uint8_t smb1_cmd_nt_create; // 0xa2
  uint8_t smb1_cmd_read; // 0x2e
  uint8_t smb1_cmd_trans2;// 0x32
  uint8_t smb1_cmd_nt_trans; // 0xa0
  uint8_t smb1_cmd_close; // 0x04
  // For files
  uint8_t sm1_file_transferring;
  uint16_t last_cmd;
  smb_file_t * files;
  smb_file_t * current_file;
  uint16_t current_file_id;
  // For linked-list
  struct smb_session_struct * next;
  struct smb_session_struct * prev;
};

smb_session_t * smb_session_new(uint64_t session_id);
void smb_session_free(smb_session_t * node);

int smb_insert_session(smb_session_t * root, smb_session_t * new_session);

smb_session_t * smb_find_session_by_id(smb_session_t * root, uint64_t session_id);

smb_session_t * smb_remove_session_by_id(smb_session_t * root, uint64_t session_id);

smb_file_t * smb_file_new(void);
void smb_file_free(smb_file_t * file);
int smb_session_insert_file(smb_session_t * smb_ss, smb_file_t * file);
smb_file_t * smb_session_find_file_by_id(smb_session_t * smb_ss, uint16_t file_id);

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_SMB_H */