/*
 * nas_msg.c
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */


#include "nas_msg_header.h"

int nas_decode_msg_header( nas_msg_header_t *msg, const uint8_t * buffer, int len ){
	if( len < sizeof( nas_msg_header_t ))
		return 0;
	*msg = *(nas_msg_header_t *) buffer;

	switch( msg->protocol_discriminator ){
	case EPS_MOBILITY_MANAGEMENT_MESSAGE:
	case EPS_SESSION_MANAGEMENT_MESSAGE:
		break;
	default:
		//NAS for EPC has only the 2 above types
		//otherwise, buffer is not a NAS
		return 0;
	}
	return sizeof( nas_msg_header_t );
}
