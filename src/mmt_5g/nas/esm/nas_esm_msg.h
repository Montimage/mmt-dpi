/*
 * nas_esm_msg.h
 *
 *  Created on: Dec 10, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_ESM_NAS_ESM_MSG_H_
#define SRC_MMT_5G_NAS_ESM_NAS_ESM_MSG_H_

#include <stdlib.h>
#include <stdint.h>

#include "nas_esm_msg_header.h"
#include "nas_esm_activate_default_eps_bearer_context_request.h"
typedef union{
	nas_esm_msg_header_t                                  header;
	nas_esm_activate_default_eps_bearer_context_request_t active_default_esp_bearer_context_request;
}nas_esm_msg_t;

int nas_esm_decode_msg( nas_esm_msg_t *msg, const uint8_t *buffer, uint32_t len );
#endif /* SRC_MMT_5G_NAS_ESM_NAS_ESM_MSG_H_ */
