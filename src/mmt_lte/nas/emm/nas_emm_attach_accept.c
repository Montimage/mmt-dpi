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


typedef enum attach_accept_iei_tag {
  ATTACH_ACCEPT_GUTI_IEI                          = 0x50, /* 0x50 = 80 */
  ATTACH_ACCEPT_LOCATION_AREA_IDENTIFICATION_IEI  = 0x13, /* 0x13 = 19 */
  ATTACH_ACCEPT_MS_IDENTITY_IEI                   = 0x23, /* 0x23 = 35 */
  ATTACH_ACCEPT_EMM_CAUSE_IEI                     = 0x53, /* 0x53 = 83 */
  ATTACH_ACCEPT_T3402_VALUE_IEI                   = 0x17, /* 0x17 = 23 */
  ATTACH_ACCEPT_T3423_VALUE_IEI                   = 0x59, /* 0x59 = 89 */
  ATTACH_ACCEPT_EQUIVALENT_PLMNS_IEI              = 0x4A, /* 0x4A = 74 */
  ATTACH_ACCEPT_EMERGENCY_NUMBER_LIST_IEI         = 0x34, /* 0x34 = 52 */
  ATTACH_ACCEPT_EPS_NETWORK_FEATURE_SUPPORT_IEI   = 0x64, /* 0x64 = 100 */
  ATTACH_ACCEPT_ADDITIONAL_UPDATE_RESULT_IEI      = 0xF0, /* 0xF0 = 240 */
} attach_accept_iei;


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

  /* Decoding optional fields */
  while(((int32_t)len - (int32_t)decoded) > 0) {
	  uint8_t ieiDecoded = *(buffer + decoded);

	  /* Type | value iei are below 0x80 so just return the first 4 bits */
	  if (ieiDecoded >= 0x80)
		  ieiDecoded = ieiDecoded & 0xf0;

	  switch(ieiDecoded) {
	  case ATTACH_ACCEPT_GUTI_IEI:
		  ret = nas_decode_eps_mobile_identity(&attach_accept->guti, ATTACH_ACCEPT_GUTI_IEI,
				  buffer + decoded, len - decoded);
		  CHECK_RESULT_DECODER( ret, decoded );

		  return decoded;
		  break;
	  default:
		  //TODO: need to extract full message
		  //as we are interested only in ATTACH_ACCEPT_GUTI_IEI
		  //increasing decoded will examine all buffer
		  decoded ++;
		  break;
	  }
  }
  return decoded;
}
