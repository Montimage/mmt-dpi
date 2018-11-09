/*
 * emm_msg.c
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */


#include "nas_emm_msg_type_t.h"
int nas_decode_emm_msg_type(nas_emm_msg_type_t *msg, const uint8_t *buffer, uint32_t len){
	if( len < sizeof( nas_emm_msg_type_t ))
		return 0;

	*msg = *(nas_emm_msg_type_t *) buffer;
	return sizeof( nas_emm_msg_type_t );
}
