/*
 * octet_string.c
 *
 *  Created on: Dec 10, 2018
 *          by: Huu-Nghia
 */

#include "decoder.h"
#include "octet_string.h"

int nas_decode_octet_string( nas_octet_string_t *msg, const uint8_t *buffer, uint16_t len ){
	int decoded = 0;

	CHECK_PDU_POINTER_AND_LENGTH_DECODER( buffer, NAS_OCTET_STRING_SIZE, len );

	DECODE_LENGTH_U16(buffer + decoded, &msg->len, decoded);

	CHECK_LENGTH_DECODER(len - decoded, msg->len);

	msg->data = buffer + decoded;

	return (decoded + msg->len);
}
