/*
 * octet_string.h
 *
 *  Created on: Dec 10, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_UTIL_OCTET_STRING_H_
#define SRC_MMT_5G_NAS_UTIL_OCTET_STRING_H_

#include <stdlib.h>
#include <stdint.h>

#define NAS_OCTET_STRING_MINIMUM_LENGTH     2
#define NAS_OCTET_STRING_MAXIMUM_LENGTH 65367

typedef struct{
	uint16_t len;
	const uint8_t *data;
}nas_octet_string_t;

int nas_decode_octet_string( nas_octet_string_t *msg, uint8_t length_byte_size, const uint8_t *buffer, uint16_t len );
#endif /* SRC_MMT_5G_NAS_UTIL_OCTET_STRING_H_ */
