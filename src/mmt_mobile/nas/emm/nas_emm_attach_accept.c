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
  ATTACH_ACCEPT_T3412_EXTENDED_VALUE_IEI          = 0x5E, /* 0x5E = 94 */
} attach_accept_iei;

/* Record a TLV value view once (TS 24.301 §7.6.3: first occurrence wins) */
static inline void _set_octets(nas_emm_attach_accept_t *acc, uint32_t bit,
		nas_octet_string_t *dst, const uint8_t *value, uint32_t value_len){
	if( acc->present & bit )
		return;
	dst->data = value;
	dst->len  = (uint16_t) value_len;
	acc->present |= bit;
}

/* Count a skipped IE; saturates instead of wrapping */
static inline void _count_unknown(nas_emm_attach_accept_t *acc){
	if( acc->unknown_ies < UINT8_MAX )
		acc->unknown_ies ++;
}

static inline void _set_u8(nas_emm_attach_accept_t *acc, uint32_t bit,
		uint8_t *dst, uint8_t value){
	if( acc->present & bit )
		return;
	*dst = value;
	acc->present |= bit;
}

/*
 * Decode one optional IE at buffer[0..len). Its format follows the IEI
 * (TS 24.007 §11.2.4, TS 24.301 §8.2.1): IEI >= 0x80 is a one-octet type-1
 * TV, 0x13/0x17/0x53/0x59 are fixed-length TV, 0x7X is TLV-E and every
 * other IEI is TLV. Returns the IE size, or DECODE_BUFFER_TOO_SHORT when it
 * would overrun len.
 */
static int _decode_optional_ie(nas_emm_attach_accept_t *acc, const uint8_t *buffer, uint32_t len){
	const uint8_t iei = buffer[0];
	uint32_t hdr, value_len;

	if( iei >= 0x80 ){
		if( (iei & 0xF0) == ATTACH_ACCEPT_ADDITIONAL_UPDATE_RESULT_IEI )
			_set_u8( acc, NAS_EMM_ATTACH_ACCEPT_HAS_ADDITIONAL_UPDATE_RESULT,
					&acc->additional_update_result, iei & 0x0F );
		else
			_count_unknown( acc );
		return 1;
	}

	switch( iei ){
	case ATTACH_ACCEPT_LOCATION_AREA_IDENTIFICATION_IEI:
		CHECK_LENGTH_DECODER( len, 6 );
		_set_octets( acc, NAS_EMM_ATTACH_ACCEPT_HAS_LAI, &acc->lai, buffer + 1, 5 );
		return 6;
	case ATTACH_ACCEPT_EMM_CAUSE_IEI:
	case ATTACH_ACCEPT_T3402_VALUE_IEI:
	case ATTACH_ACCEPT_T3423_VALUE_IEI:
		CHECK_LENGTH_DECODER( len, 2 );
		if( iei == ATTACH_ACCEPT_EMM_CAUSE_IEI )
			_set_u8( acc, NAS_EMM_ATTACH_ACCEPT_HAS_EMM_CAUSE, &acc->emm_cause, buffer[1] );
		else if( iei == ATTACH_ACCEPT_T3402_VALUE_IEI )
			_set_u8( acc, NAS_EMM_ATTACH_ACCEPT_HAS_T3402_VALUE, &acc->t3402value, buffer[1] );
		else
			_set_u8( acc, NAS_EMM_ATTACH_ACCEPT_HAS_T3423_VALUE, &acc->t3423value, buffer[1] );
		return 2;
	}

	/* TLV (1-octet length) or TLV-E (2-octet length) */
	if( (iei & 0xF0) == 0x70 ){
		CHECK_LENGTH_DECODER( len, 3 );
		hdr       = 3;
		value_len = ((uint32_t) buffer[1] << 8) | buffer[2];
	}else{
		CHECK_LENGTH_DECODER( len, 2 );
		hdr       = 2;
		value_len = buffer[1];
	}
	CHECK_LENGTH_DECODER( len - hdr, value_len );

	switch( iei ){
	case ATTACH_ACCEPT_GUTI_IEI:
		if( acc->present & NAS_EMM_ATTACH_ACCEPT_HAS_GUTI )
			break;
		if( nas_decode_eps_mobile_identity( &acc->guti, ATTACH_ACCEPT_GUTI_IEI,
				buffer, hdr + value_len ) > 0 )
			acc->present |= NAS_EMM_ATTACH_ACCEPT_HAS_GUTI;
		else /* a malformed GUTI must not leave a half-filled identity;
		      * the first well-formed GUTI is the one kept */
			memset( &acc->guti, 0, sizeof( acc->guti ));
		break;
	case ATTACH_ACCEPT_MS_IDENTITY_IEI:
		_set_octets( acc, NAS_EMM_ATTACH_ACCEPT_HAS_MS_IDENTITY,
				&acc->ms_identity, buffer + hdr, value_len );
		break;
	case ATTACH_ACCEPT_EQUIVALENT_PLMNS_IEI:
		_set_octets( acc, NAS_EMM_ATTACH_ACCEPT_HAS_EQUIVALENT_PLMNS,
				&acc->equivalent_plmns, buffer + hdr, value_len );
		break;
	case ATTACH_ACCEPT_EMERGENCY_NUMBER_LIST_IEI:
		_set_octets( acc, NAS_EMM_ATTACH_ACCEPT_HAS_EMERGENCY_NUMBER_LIST,
				&acc->emergency_number_list, buffer + hdr, value_len );
		break;
	case ATTACH_ACCEPT_EPS_NETWORK_FEATURE_SUPPORT_IEI:
		_set_octets( acc, NAS_EMM_ATTACH_ACCEPT_HAS_EPS_NETWORK_FEATURE_SUPPORT,
				&acc->eps_network_feature_support, buffer + hdr, value_len );
		break;
	case ATTACH_ACCEPT_T3412_EXTENDED_VALUE_IEI:
		_set_octets( acc, NAS_EMM_ATTACH_ACCEPT_HAS_T3412_EXTENDED_VALUE,
				&acc->t3412_extended_value, buffer + hdr, value_len );
		break;
	default:
		_count_unknown( acc );
		break;
	}
	return (int)(hdr + value_len);
}



int nas_emm_decode_attach_accept(nas_emm_attach_accept_t *attach_accept, const uint8_t *buffer, uint32_t len){
  int decoded = 0;
  int ret = 0;

  // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
  CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, NAS_EMM_ATTACH_ACCEPT_MIN_LEN, len);

  /* Decoding mandatory fields */
  // F-BUG-214: pass buffer+decoded for t3412value (misreported attribute)
  // F-BUG-215: capture negative errors in signed and early-return before uint32 wrap
  DECODE_U8( buffer + decoded, attach_accept->eps_attach_result, decoded );
  DECODE_U8( buffer + decoded, attach_accept->t3412value, decoded );

  ret = nas_decode_tracking_area_identity_list(&attach_accept->tailist, 0, buffer + decoded, len - decoded);
  CHECK_RESULT_DECODER( ret, decoded );

  ret = nas_decode_octet_string(&attach_accept->esm_message_container, 2, buffer + decoded, len - decoded);
  CHECK_RESULT_DECODER( ret, decoded );

  /* Decoding optional fields: issue #335 — walk every IE by its format
   * instead of scanning byte by byte for the GUTI IEI. An IE that overruns
   * the message stops the walk; the fields decoded so far stay valid. */
  attach_accept->present     = 0;
  attach_accept->unknown_ies = 0;
  while( decoded < (int32_t)len ){
	  ret = _decode_optional_ie( attach_accept, buffer + decoded, len - decoded );
	  if( ret <= 0 ){
		  attach_accept->present |= NAS_EMM_ATTACH_ACCEPT_TRUNCATED;
		  break;
	  }
	  decoded += ret;
  }
  return decoded;
}
