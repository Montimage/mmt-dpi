/*
 * nas_5g_msg.c
 *
 *  Created on: Dec 18, 2020
 *      Author: nhnghia
 */

#include "string.h"
#include "nas_5g.h"

bool nas_5g_decode( nas_5g_msg_t *nas_msg, const uint8_t *buffer, uint32_t length ){
	if( nas_msg == NULL || buffer == NULL )
		return false;
	//not enougth room
	if( length < sizeof( nas_5g_msg_t ))
		return false;
	/* F-BUG-120: never reinterpret the wire buffer as the packed-bitfield
	 * union — copy the captured bytes, then let the union members read them. */
	memcpy( nas_msg, buffer, sizeof( nas_5g_msg_t ));
	return true;
}
