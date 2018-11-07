/*
 * emm_msg.c
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */


#include "emm_msg.h"
int emm_msg_decode(emm_msg *msg, const uint8_t *buffer, uint32_t len){
	if( len < sizeof( emm_msg ))
		return 0;
	msg = (emm_msg *) buffer;
	if( msg->header.protocol_discriminator != EPS_MOBILITY_MANAGEMENT_MESSAGE )
		return 0;
	switch( msg->header.message_type ){
	case ATTACH_REQUEST:
		return decode_attach_request( &msg->attach_request, buffer, len );
	}
	return 0;
}
