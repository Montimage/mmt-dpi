/*
 * nas_msg.c
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */


#include "nas_msg.h"

int nas_msg_decode( nas_msg_t *msg, const uint8_t * buffer, int len, void *security){
	if( len < sizeof( nas_msg_t ))
		return 0;
	msg = (nas_msg_t *) buffer;
	switch( msg->header.protocol_discriminator ){
	case EPS_MOBILITY_MANAGEMENT_MESSAGE:
		return emm_msg_decode( &msg->emm_msg, buffer, len );
	}
	return 0;
}
