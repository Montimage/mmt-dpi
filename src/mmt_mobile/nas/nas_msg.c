/*
 * nas_msg.c
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */


#include "nas_msg.h"
#include "util/decoder.h"


static inline int _nas_msg_plain_decode(
		const uint8_t                   *buffer,
		nas_msg_plain_t                 *msg,
		int                             length)
{
	int size = 0, byte = 0;

	/* F-BUG-081: validate the length before reading the first header byte —
	 * a minimum-size security-protected PDU reaches here with length == 0. */
	CHECK_PDU_POINTER_AND_LENGTH_DECODER( buffer, 1, length );

	DECODE_U8( buffer, *(uint8_t *)& msg->emm.header, size );

	switch ( msg->emm.header.protocol_discriminator ){
	case NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE:
		/* EMM header: one more byte for the message type. buffer is already
		 * proven non-NULL above — only the length leg is still needed. */
		CHECK_LENGTH_DECODER( length, size + 1 );
		DECODE_U8( buffer+size, msg->emm.header.message_type, size );

		/* Decode EPS Mobility Management L3 message */
		byte = nas_emm_decode_msg(&msg->emm, buffer + size, length - size);
		break;
	case NAS_EPS_SESSION_MANAGEMENT_MESSAGE:

		/* ESM header: procedure transaction identity + message type */
		CHECK_PDU_POINTER_AND_LENGTH_DECODER( buffer, size + 2, length );
		DECODE_U8( buffer+size, msg->esm.header.procedure_transaction_identity, size );
		DECODE_U8( buffer+size, msg->esm.header.message_type, size );

		/* Decode EPS Session Management L3 message */
		byte = nas_esm_decode_msg(&msg->esm, buffer+size, length - size);
		break;
	default:
		LOG("Unknown protocol discriminator %d", msg->emm.header.protocol_discriminator );
		return DECODE_PROTOCOL_NOT_SUPPORTED;
	}

	if( byte < 0 )
		return byte;
	return (size + byte );
}

/**
 * Decrypt security-protected NAS message
 *
 * The SDK holds no NAS security context (K_NASenc, NAS COUNT), so nothing is
 * ever decrypted (issue #452, docs/DECISIONS.md). A ciphered payload is
 * passed through unchanged only when it may be plain text: the ciphering
 * algorithm is EEA0 (null ciphering) or unknown. When the algorithm is known
 * to be non-null, NULL is returned and the payload is not decoded.
 */
static inline const uint8_t* _nas_msg_decrypt(
		const uint8_t      *src,
		uint8_t             security_header_type,
		int                 ciphering_algorithm
)
{
	switch (security_header_type) {
	case NAS_SECURITY_HEADER_TYPE_NOT_PROTECTED:
	case NAS_SECURITY_HEADER_TYPE_SERVICE_REQUEST:
	case NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED:
	case NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_NEW:
		return src;

	case NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED:
	case NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED_NEW:
		if( ciphering_algorithm == NAS_CIPHERING_ALGORITHM_EEA0
				|| ciphering_algorithm == NAS_CIPHERING_ALGORITHM_UNKNOWN )
			return src;
		/* EEA1-EEA3 (or a reserved value): the payload is ciphertext */
		return NULL;
	default:
		LOG("Unknown security header type %u", security_header_type);
		return NULL;
	};
}

/**
 * Issue #452: with an unknown ciphering algorithm, a ciphered payload may be
 * ciphertext. The message inside a security-protected NAS message is a plain
 * NAS message (TS 24.301 §9.1): octet 1 is 0x07 for EMM (protocol
 * discriminator 7, security header type 0) or has protocol discriminator 2
 * for ESM (upper nibble: EPS bearer identity). Any other first octet cannot
 * be plain text, so it is not decoded.
 */
static inline bool _nas_msg_is_plausible_plain( const uint8_t *buffer, int length ){
	if( length < 1 )
		return false;
	return buffer[0] == NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE
		|| (buffer[0] & 0x0F) == NAS_EPS_SESSION_MANAGEMENT_MESSAGE;
}

/**
 * Decode security-protected NAS message.
 *
 * @inputs:
 *
 * @outputs:
 * - msg: Decoded NAS message
 *
 * @return:
 * - A positive number of bytes in the buffer if the data have been successfully decoded
 * - A negative number representing error code, otherwise.
 */
static inline int _nas_msg_protected_decode(
		const uint8_t                 *buffer,
		nas_msg_security_protected_t  *msg,
		int                            length,
		int                            ciphering_algorithm
)
{
	//ensure buffer is big enough to contain nas_msg_security_header_t
	CHECK_PDU_POINTER_AND_LENGTH_DECODER( buffer, NAS_MESSAGE_SECURITY_HEADER_SIZE, length );

	int size = 0;
	int bytes = DECODE_BUFFER_TOO_SHORT;

	//decode security-protected header
	nas_msg_security_header_t *header = &msg->header;
	/* Decode the first octet of the header (security header type or EPS bearer
	 * identity, and protocol discriminator) */
	DECODE_U8(buffer, *(uint8_t*)(header), size);
	 /* Decode the message authentication code */
	DECODE_U32(buffer+size, header->message_authentication_code, size);
	/* Decode the sequence number */
	DECODE_U8(buffer+size, header->sequence_number, size);


	/* Decrypt the security protected NAS message */
	 const uint8_t* plain_msg = _nas_msg_decrypt(
					buffer + size,
					header->security_header_type,
					ciphering_algorithm );

	 /* NULL: ciphered with a non-null algorithm, or a reserved security
	  * header type (not a ciphered payload) */
	 if( unlikely( plain_msg == NULL ))
		 return nas_is_ciphered_security_header( header->security_header_type )
			 ? DECODE_CIPHERED_PAYLOAD : DECODE_MAC_MISMATCH;

	 /* ciphered with an unknown algorithm: decode only a plausible plain
	  * NAS message (issue #452) */
	 if( ciphering_algorithm == NAS_CIPHERING_ALGORITHM_UNKNOWN
			 && nas_is_ciphered_security_header( header->security_header_type )
			 && !_nas_msg_is_plausible_plain( plain_msg, length - size ))
		 return DECODE_CIPHERED_PAYLOAD;

	/* Decode the decrypted message as plain NAS message */
	bytes = _nas_msg_plain_decode(plain_msg, &msg->msg, length - size);

	//in case of error
	if (bytes < 0)
		return (bytes);

	return (size + bytes);
}

int nas_decode( nas_msg_t *msg, const uint8_t *buffer, int length ){
	return nas_decode_ciphered( msg, buffer, length, NAS_CIPHERING_ALGORITHM_UNKNOWN );
}

int nas_decode_ciphered( nas_msg_t *msg, const uint8_t *buffer, int length,
		int ciphering_algorithm ){
	/* Decode the header */

	CHECK_PDU_POINTER_AND_LENGTH_DECODER( buffer, 3, length );

	//1. if the message is security-protected?
	nas_msg_header_t *header = &msg->header;

	/* Decode the first octet of the header (security header type or EPS bearer
	 * identity, and protocol discriminator) */
	*(uint8_t*)(header) = *buffer;

	/*
	 * EMM Service Request message is an exception that breaks the normal rules
	 * since it has been tweaked to fit into a single initial RRC message
	 * and hence optimizing the performance of the system.
	 */

	if( header->security_header_type == NAS_SECURITY_HEADER_TYPE_SERVICE_REQUEST ){
		return 0;
	}
	else if ( nas_is_security_protected_msg( msg )){
		//we are going to decode security-protected NAS message
		return _nas_msg_protected_decode(buffer,
				&msg->protected_msg,
				length,
				ciphering_algorithm );
	}
	else{

		/* Decode plain NAS message */
		return _nas_msg_plain_decode(buffer,
				&msg->plain_msg,
				length);
	}
}

int nas_get_security_mode_command_ciphering( const uint8_t *buffer, int length ){
	/* security header (6) + EMM header (2) + selected NAS security algorithms */
	if( buffer == NULL || length < NAS_MESSAGE_SECURITY_HEADER_SIZE + 3 )
		return NAS_CIPHERING_ALGORITHM_UNKNOWN;
	/* octet 1: EMM, integrity protected (TS 24.301 §5.4.3.2: the Security
	 * Mode Command is integrity protected but not ciphered) */
	if( (buffer[0] & 0x0F) != NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE )
		return NAS_CIPHERING_ALGORITHM_UNKNOWN;
	switch( buffer[0] >> 4 ){
	case NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED:
	case NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_NEW:
		break;
	default:
		return NAS_CIPHERING_ALGORITHM_UNKNOWN;
	}
	const uint8_t *plain = buffer + NAS_MESSAGE_SECURITY_HEADER_SIZE;
	if( plain[0] != NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE
			|| plain[1] != NAS_EMM_SECURITY_MODE_COMMAND )
		return NAS_CIPHERING_ALGORITHM_UNKNOWN;
	/* Selected NAS security algorithms (TS 24.301 §9.9.3.23): bits 7-5 of
	 * the octet are the type of ciphering algorithm, 0 = EEA0 */
	return (plain[2] >> 4) & 0x07;
}
