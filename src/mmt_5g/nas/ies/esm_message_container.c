#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "esm_message_container.h"
#include "../util/decoder.h"

//#define NAS_DEBUG 1

int nas_decode_esm_message_container(esm_message_container_t *msg, uint8_t iei,  const uint8_t *buffer, uint32_t len)
{
  int decoded = 0;

  if (iei > 0) {
    CHECK_IEI_DECODER(iei, *buffer);
    decoded++;
  }

  int byte = nas_decode_octet_string( msg, buffer + decoded, len-decoded);

  RETURN( byte, decoded );
}
