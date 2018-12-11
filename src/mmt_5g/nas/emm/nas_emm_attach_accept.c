/*
 * nas_emm_attach_accept.c
 *
 *  Created on: Nov 12, 2018
 *          by: Huu-Nghia
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include "nas_emm_attach_accept.h"
#include "../util/decoder.h"

int nas_emm_decode_attach_accept(nas_emm_attach_accept_t *attach_accept, const uint8_t *buffer, uint32_t len){
  uint32_t decoded = 0;
  int ret = 0;

  // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
  CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, NAS_EMM_ATTACH_ACCEPT_MIN_LEN, len);

  /* Decoding mandatory fields */
  DECODE_U8( buffer, attach_accept->eps_attach_result, decoded );
  DECODE_U8( buffer, attach_accept->t3412value, decoded );

  ret = nas_decode_tracking_area_identity_list(&attach_accept->tailist, 0, buffer + decoded, len - decoded);
  CHECK_RESULT_DECODER( ret, decoded );

  ret = nas_decode_octet_string(&attach_accept->esm_message_container, 2, buffer + decoded, len - decoded);
  CHECK_RESULT_DECODER( ret, decoded );

  return decoded;
}
