/*
 * nas_esm_msg.c
 *
 *  Created on: Dec 10, 2018
 *          by: Huu-Nghia
 */

#include "../util/decoder.h"
#include "nas_esm_msg.h"

int nas_esm_decode_msg( nas_esm_msg_t *msg, const uint8_t *buffer, uint32_t len ){
	switch( msg->header.message_type ){
	case NAS_ESM_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST:
		return nas_esm_decode_activate_default_eps_bearer_context_request(& msg->active_default_esp_bearer_context_request, buffer, len );
		break;
	}
	return 0;
}
