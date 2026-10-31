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

/* TS 24.501 §9.1.1, §9.3.1: a security protected 5GMM message carries its
 * security header type in bits 1-4 of octet 2, then the MAC (octets 3-6)
 * and the sequence number (octet 7); the protected NAS message follows.
 * Types 1 and 3 are integrity protected but not ciphered, so that inner
 * message is plain text (issue #573: type 1 was reported as 0); types 2 and
 * 4 are ciphered and report 0. The type is read from the octet, not from
 * the header bitfield, whose nibble order is compiler-dependent. */
bool nas_5g_message_type( const uint8_t *buffer, uint32_t length, uint8_t *message_type ){
	nas_5g_msg_t msg;
	if( message_type == NULL || !nas_5g_decode( &msg, buffer, length ))
		return false;
	if( msg.protocol_discriminator == NAS5G_SESSION_MANAGEMENT_MESSAGE ){
		*message_type = msg.smm.message_type;
		return true;
	}
	switch( buffer[1] & 0x0F ){
	case NAS5G_SECURITY_HEADER_PLAIN:
		*message_type = msg.mmm.message_type;
		return true;
	case NAS5G_SECURITY_HEADER_INTEGRITY_PROTECTED:
	case NAS5G_SECURITY_HEADER_INTEGRITY_PROTECTED_NEW_CONTEXT:
		/* F-BUG-085: length - 7 must not wrap when length < 7 */
		if( length <= NAS5G_SECURITY_PROTECTED_HEADER_LENGTH
				|| !nas_5g_decode( &msg, buffer + NAS5G_SECURITY_PROTECTED_HEADER_LENGTH,
						length - NAS5G_SECURITY_PROTECTED_HEADER_LENGTH ))
			return false;
		*message_type = msg.mmm.message_type;
		return true;
	default:
		//otherwise the message is encrypted
		*message_type = 0;
		return true;
	}
}
