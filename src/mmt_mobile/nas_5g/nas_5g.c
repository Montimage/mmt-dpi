/*
 * nas_5g_msg.c
 *
 *  Created on: Dec 18, 2020
 *      Author: nhnghia
 */

#include "string.h"
#include "nas_5g.h"

bool nas_5g_decode( nas_5g_msg_t *msg, const uint8_t *buffer, uint32_t length ){
	if( length < sizeof( nas_5g_msg_t ))
		return false;
	memset( msg, 0, sizeof( nas_5g_msg_t ));
	msg = (nas_5g_msg_t *) buffer;
	return true;
}
