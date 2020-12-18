/*
 * ngap.c
 *
 *  Created on: Dec 14, 2020
 *      Author: nhnghia
 */
#include "ngap.h"
#include "NGAP_ProtocolIE-Field.h"

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

static inline bool _decode_NGAP_InitialUEMessage_t(ngap_message_t *msg, NGAP_InitialUEMessage_t *data){
	int i, decoded = 0;
	for( i=0; i<data->protocolIEs.list.count; i++){
		NGAP_InitialUEMessage_IEs_t *ie_p = data->protocolIEs.list.array[i];
		switch( ie_p->value.present ){
		case NGAP_InitialUEMessage_IEs__value_PR_NAS_PDU:
			msg->nas_pdu.data = ie_p->value.choice.NAS_PDU.buf;
			msg->nas_pdu.size = ie_p->value.choice.NAS_PDU.size;
			break;
		default:
			break;
		}
	}
	return true;
}

static inline bool _decode_NGAP_DownlinkNASTransport(ngap_message_t *msg, NGAP_DownlinkNASTransport_t *data){
	int i, decoded = 0;
	for( i=0; i<data->protocolIEs.list.count; i++){
		NGAP_DownlinkNASTransport_IEs_t *ie_p = data->protocolIEs.list.array[i];
		switch( ie_p->value.present ){
		case NGAP_DownlinkNASTransport_IEs__value_PR_NAS_PDU:
			msg->nas_pdu.data = ie_p->value.choice.NAS_PDU.buf;
			msg->nas_pdu.size = ie_p->value.choice.NAS_PDU.size;
			break;
		default:
			break;
		}
	}
	return true;
}

static inline bool _decode_NGAP_UplinkNASTransport(ngap_message_t *msg, NGAP_UplinkNASTransport_t *data){
	int i, decoded = 0;
	for( i=0; i<data->protocolIEs.list.count; i++){
		NGAP_UplinkNASTransport_IEs_t *ie_p = data->protocolIEs.list.array[i];
		switch( ie_p->value.present ){
		case NGAP_UplinkNASTransport_IEs__value_PR_NAS_PDU:
			msg->nas_pdu.data = ie_p->value.choice.NAS_PDU.buf;
			msg->nas_pdu.size = ie_p->value.choice.NAS_PDU.size;
			break;
		default:
			break;
		}
	}
	return true;
}

static inline bool _decode_initiatingMessage( ngap_message_t *msg, NGAP_InitiatingMessage_t *data ){
	switch( data->value.present ){
	case NGAP_InitiatingMessage__value_PR_InitialUEMessage:
		return _decode_NGAP_InitialUEMessage_t(msg, &data->value.choice.InitialUEMessage);
	case NGAP_InitiatingMessage__value_PR_DownlinkNASTransport:
		return _decode_NGAP_DownlinkNASTransport(msg, &data->value.choice.DownlinkNASTransport);
	case NGAP_InitiatingMessage__value_PR_UplinkNASTransport:
		return _decode_NGAP_UplinkNASTransport(msg, &data->value.choice.UplinkNASTransport);
	default:
		break;
	}
	return true;
}

static bool _decode_successfulOutcome( ngap_message_t *msg, NGAP_SuccessfulOutcome_t *data ){
	return true;
}

static bool _decode_unsuccessfulOutcome( ngap_message_t *msg, NGAP_UnsuccessfulOutcome_t *data ){
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
	//reset msg
	memset(msg, 0, sizeof( ngap_message_t));
	msg->pdu_present = pdu_p->present;
	bool ret = false;
	switch( pdu_p->present ){
	case NGAP_NGAP_PDU_PR_initiatingMessage:
		msg->procedure_code = pdu_p->choice.initiatingMessage->procedureCode;
		ret = _decode_initiatingMessage(msg, pdu_p->choice.initiatingMessage);
		break;
	case NGAP_NGAP_PDU_PR_successfulOutcome:
		msg->procedure_code = pdu_p->choice.successfulOutcome->procedureCode;
		ret = _decode_successfulOutcome( msg, pdu_p->choice.successfulOutcome);
		break;
	case NGAP_NGAP_PDU_PR_unsuccessfulOutcome:
		msg->procedure_code = pdu_p->choice.unsuccessfulOutcome->procedureCode;
		ret = _decode_unsuccessfulOutcome( msg, pdu_p->choice.unsuccessfulOutcome);
		break;
	case NGAP_NGAP_PDU_PR_NOTHING:
		break;
	}
	ASN_STRUCT_FREE( asn_DEF_NGAP_NGAP_PDU, pdu_p );
	return ret;
}
