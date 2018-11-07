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
#include "attach_request.h"

int decode_attach_request(attach_request_msg *msg, const uint8_t *buffer, uint32_t len){

	if( len < sizeof( attach_request_msg ))
		return 0;

	msg = (attach_request_msg *)buffer;

	if( msg->eps_attach_type != EPS_ATTACH_TYPE_IMSI )
		return 0;

	uint32_t decoded = 3;
	return decode_eps_mobile_identity(&msg->old_guti_or_imsi, 0, buffer + decoded, len - decoded) ;
}
