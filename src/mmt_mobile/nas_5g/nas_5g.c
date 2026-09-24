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
	/* Issue #427: the plain 5GMM header is 3 octets (TS 24.501 §9.1.1) and
	 * only the 5GSM header is 4, so requiring sizeof(nas_5g_msg_t) (the 4-octet
	 * union) rejected minimal 5GMM messages such as the Authentication
	 * Response. Require the header of the discriminated message type. */
	if( length == 0 )
		return false;
	const size_t header_len = ( buffer[0] == NAS5G_SESSION_MANAGEMENT_MESSAGE )
			? sizeof( nas_5g_smm_msg_header_t )
			: sizeof( nas_5g_mmm_msg_header_t );
	if( length < header_len )
		return false;
	/* F-BUG-120: never reinterpret the wire buffer as the packed-bitfield
	 * union — copy the captured bytes, then let the union members read them.
	 * Union octets the buffer does not cover are zeroed, never over-read. */
	memset( nas_msg, 0, sizeof( nas_5g_msg_t ));
	memcpy( nas_msg, buffer,
			length < sizeof( nas_5g_msg_t ) ? length : sizeof( nas_5g_msg_t ));
	return true;
}
