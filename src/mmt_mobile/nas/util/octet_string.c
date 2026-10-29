/*
 * octet_string.c
 *
 *  Created on: Dec 10, 2018
 *          by: Huu-Nghia
 */

#include "decoder.h"
#include "octet_string.h"

int nas_decode_octet_string( nas_octet_string_t *msg, uint8_t length_byte_size, const uint8_t *buffer, uint16_t len ){
	int decoded = 0;
	int rc;

	rc = nas_check_pdu(buffer, NAS_OCTET_STRING_MINIMUM_LENGTH, len);
	if (unlikely(rc < 0)) {
		NAS_LOG_PDU_CHECK(rc, NAS_OCTET_STRING_MINIMUM_LENGTH, len);
		return rc;
	}

	switch( length_byte_size ){
	case 1:
		DECODE_U8(buffer + decoded, msg->len, decoded);
		break;
	case 2:
		DECODE_LENGTH_U16(buffer + decoded, msg->len, decoded);
		break;
	}

	rc = nas_check_length(len - decoded, msg->len);
	if (unlikely(rc < 0))
		return rc;

	msg->data = buffer + decoded;

	return (decoded + msg->len);
}
