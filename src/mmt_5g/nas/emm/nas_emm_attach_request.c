/*
 * attach_request.c
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../util/TLVEncoder.h"
#include "../util/TLVDecoder.h"
#include "nas_emm_attach_request.h"

int nas_decode_emm_attach_request(nas_emm_attach_request_msg_t *msg, const uint8_t *buffer, uint32_t len){

	uint32_t decoded = 0;
	uint32_t ret = 0;
	if( len < sizeof( nas_emm_attach_request_msg_t ))
		return 0;

	ret = nas_decode_msg_header( &msg->header, &buffer[0], len );
	if( ret == 0 )
		return 0;
	decoded += ret;

	ret = nas_decode_emm_msg_type( &msg->message_type, &buffer[decoded], len - decoded );

	if( ret == 0 )
		return 0;
	if( msg->message_type != ATTACH_REQUEST )
		return 0;

	decoded += ret;

	msg->eps_attach_type = *( uint8_t *) &buffer[decoded];

	if( (msg->eps_attach_type & EPS_ATTACH_TYPE_IMSI) == 0)
		return 0;

	decoded += 1;

	return nas_decode_eps_mobile_identity(&msg->old_guti_or_imsi, 0, buffer + decoded, len - decoded) ;
}
