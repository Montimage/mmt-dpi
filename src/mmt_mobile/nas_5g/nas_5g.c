/*
 * nas_5g_msg.c
 *
 *  Created on: Dec 18, 2020
 *      Author: nhnghia
 */

#include "string.h"
#include "nas_5g.h"

bool nas_5g_decode( nas_5g_msg_t *nas_msg, const uint8_t *buffer, uint32_t length ){
	//not enougth room
	if( length < sizeof( nas_5g_msg_t ))
		return false;
	memset( nas_msg, 0, sizeof( nas_5g_msg_t ));
	nas_5g_msg_t *msg = (nas_5g_msg_t *) buffer;
	//copy result to nas_msg
	nas_msg->protocol_discriminator = msg->protocol_discriminator;
	nas_msg->mmm = msg->mmm;
	nas_msg->smm = msg->smm;
	return true;
}
