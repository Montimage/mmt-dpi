#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "octet_string.h"

#ifndef ESM_MESSAGE_CONTAINER_H_
#define ESM_MESSAGE_CONTAINER_H_

#define ESM_MESSAGE_CONTAINER_MINIMUM_LENGTH     2 // [length]+[length]
#define ESM_MESSAGE_CONTAINER_MAXIMUM_LENGTH 65538 // [IEI]+[length]+[length]+[ESM msg]

typedef nas_octet_string_t esm_message_container_t;

int nas_decode_esm_message_container(esm_message_container_t *msg, uint8_t iei, const uint8_t *buffer, uint32_t len);

#endif /* ESM MESSAGE CONTAINER_H_ */

