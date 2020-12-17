/*
 * ngap.c
 *
 *  Created on: Dec 14, 2020
 *      Author: nhnghia
 */
#include "ngap.h"

bool try_decode_ngap( const uint8_t * buffer, const uint32_t length ){
	NGAP_NGAP_PDU_t *pdu_p = NULL;
	asn_dec_rval_t dec_ret;
	if( length == 0 )
		return false;
	dec_ret = aper_decode( NULL, &asn_DEF_NGAP_NGAP_PDU, (void **)&pdu_p,
			buffer,
			length,
			0,
			0);
	if( dec_ret.code != RC_OK ){
		return false;
	}
	ASN_STRUCT_FREE( asn_DEF_NGAP_NGAP_PDU, pdu_p );
	return true;
}

bool decode_ngap( ngap_message_t *msg, const uint8_t * buffer, const uint32_t length ){
	if( msg == NULL )
		return false;

	NGAP_NGAP_PDU_t *pdu_p = NULL;
	asn_dec_rval_t dec_ret;
	if( length == 0 )
		return false;
	dec_ret = aper_decode( NULL, &asn_DEF_NGAP_NGAP_PDU, (void **)&pdu_p,
			buffer,
			length,
			0,
			0);
	if( dec_ret.code != RC_OK )
		return false;
	msg->pdu_present = pdu_p->present;
	bool ret = false;
	switch( pdu_p->present ){
	case NGAP_NGAP_PDU_PR_initiatingMessage:
		msg->procedure_code = pdu_p->choice.initiatingMessage->procedureCode;
		break;
	case NGAP_NGAP_PDU_PR_successfulOutcome:
		msg->procedure_code = pdu_p->choice.successfulOutcome->procedureCode;
		break;
	case NGAP_NGAP_PDU_PR_unsuccessfulOutcome:
		msg->procedure_code = pdu_p->choice.unsuccessfulOutcome->procedureCode;
		break;
	case NGAP_NGAP_PDU_PR_NOTHING:
		break;
	}
	ASN_STRUCT_FREE( asn_DEF_NGAP_NGAP_PDU, pdu_p );
	return ret;
}
