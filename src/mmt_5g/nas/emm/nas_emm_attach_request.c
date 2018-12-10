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

#include "nas_emm_attach_request.h"
#include "../util/decoder.h"

int nas_emm_decode_attach_request(nas_emm_attach_request_t *msg, const uint8_t *buffer, uint32_t len){

	uint32_t decoded = 0;
	uint32_t ret = 0;

	DECODE_U8(buffer+decoded, &msg->eps_attach_type, decoded );

	if( msg->eps_attach_type & EPS_ATTACH_TYPE_IMSI )
		decoded += nas_decode_eps_mobile_identity(&msg->old_guti_or_imsi, 0, buffer+decoded, len-decoded) ;


	return decoded;
}
