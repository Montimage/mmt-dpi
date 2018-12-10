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

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_SMB_H */