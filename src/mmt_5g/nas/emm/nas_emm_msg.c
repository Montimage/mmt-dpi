/*
 * emm_msg.c
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */


#include "nas_emm_msg.h"
int nas_emm_decode_msg(nas_emm_msg_t *msg, const uint8_t *buffer, uint32_t len){
	switch( msg->header.message_type ){
	case NAS_EMM_ATTACH_REQUEST:
		return nas_emm_decode_attach_request( msg->attach_request, buffer, len );
	case NAS_EMM_ATTACH_ACCEPT:
		return nas_emm_decode_attach_accept( msg->attach_accept, buffer, len );
	}
	return DECODE_VALUE_DOESNT_MATCH;
}
