/*
 * ngap.c
 *
 *  Created on: Dec 14, 2020
 *      Author: nhnghia
 */
#include "ngap.h"
#include "NGAP_ProtocolIE-Field.h"

#include "nas_msg.h"

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

static inline uint64_t _get_amf_ue_ngap_id( const NGAP_AMF_UE_NGAP_ID_t * id ){
	uint64_t value = 0;
	unsigned long *l = &value;
	asn_INTEGER2ulong(id, l);
	return value;
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
		case NGAP_InitialUEMessage_IEs__value_PR_RAN_UE_NGAP_ID:
			msg->ran_ue_id = ie_p->value.choice.RAN_UE_NGAP_ID;
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
		case NGAP_DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID:
			msg->amf_ue_id = _get_amf_ue_ngap_id( & ie_p->value.choice.AMF_UE_NGAP_ID );
			break;
		case NGAP_DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID:
			msg->ran_ue_id = ie_p->value.choice.RAN_UE_NGAP_ID;
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
		case NGAP_UplinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID:
			msg->amf_ue_id = _get_amf_ue_ngap_id( & ie_p->value.choice.AMF_UE_NGAP_ID );
			break;
		case NGAP_UplinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID:
			msg->ran_ue_id = ie_p->value.choice.RAN_UE_NGAP_ID;
			break;
		default:
			break;
		}
	}
	return true;
}

static inline bool _decode_NGAP_HandoverRequired(ngap_message_t *msg, NGAP_HandoverRequired_t *data){
	int i, decoded = 0;
	for( i=0; i<data->protocolIEs.list.count; i++){
		NGAP_HandoverRequiredIEs_t *ie_p = data->protocolIEs.list.array[i];
		switch( ie_p->value.present ){
		case NGAP_HandoverRequiredIEs__value_PR_AMF_UE_NGAP_ID:
			msg->amf_ue_id = _get_amf_ue_ngap_id( & ie_p->value.choice.AMF_UE_NGAP_ID );
			break;
		case NGAP_HandoverRequiredIEs__value_PR_RAN_UE_NGAP_ID:
			msg->ran_ue_id = ie_p->value.choice.RAN_UE_NGAP_ID;
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
	case NGAP_InitiatingMessage__value_PR_HandoverRequired:
		return _decode_NGAP_HandoverRequired(msg, &data->value.choice.HandoverRequired);
	default:
		break;
	}
	return true;
}

static inline bool _decode_NGAP_UEContextReleaseComplete( ngap_message_t *msg, NGAP_UEContextReleaseComplete_t *data ){
	int i, decoded = 0;
	for( i=0; i<data->protocolIEs.list.count; i++){
		NGAP_UEContextReleaseComplete_IEs_t *ie_p = data->protocolIEs.list.array[i];
		switch( ie_p->value.present ){
		case NGAP_UEContextReleaseComplete_IEs__value_PR_AMF_UE_NGAP_ID:
			msg->amf_ue_id = _get_amf_ue_ngap_id( & ie_p->value.choice.AMF_UE_NGAP_ID );
			break;
		case NGAP_UEContextReleaseComplete_IEs__value_PR_RAN_UE_NGAP_ID:
			msg->ran_ue_id = ie_p->value.choice.RAN_UE_NGAP_ID;
			break;
		default:
			break;
		}
	}
	return true;
}

static bool _decode_successfulOutcome( ngap_message_t *msg, NGAP_SuccessfulOutcome_t *data ){
	switch( data->value.present ){
	case NGAP_SuccessfulOutcome__value_PR_UEContextReleaseComplete:
		return _decode_NGAP_UEContextReleaseComplete( msg, &data->value.choice.UEContextReleaseComplete );
	default:
		break;
	}
	return true;
}


static inline bool _decode_NGAP_UEContextModificationFailure( ngap_message_t *msg, NGAP_UEContextModificationFailure_t *data ){
	int i, decoded = 0;
	for( i=0; i<data->protocolIEs.list.count; i++){
		NGAP_UEContextModificationFailureIEs_t *ie_p = data->protocolIEs.list.array[i];
		switch( ie_p->value.present ){
		case NGAP_UEContextModificationFailureIEs__value_PR_AMF_UE_NGAP_ID:
			msg->amf_ue_id = _get_amf_ue_ngap_id( & ie_p->value.choice.AMF_UE_NGAP_ID );
			break;
		case NGAP_UEContextModificationFailureIEs__value_PR_RAN_UE_NGAP_ID:
			msg->ran_ue_id = ie_p->value.choice.RAN_UE_NGAP_ID;
			break;
		default:
			break;
		}
	}
	return true;
}

static bool _decode_unsuccessfulOutcome( ngap_message_t *msg, NGAP_UnsuccessfulOutcome_t *data ){
	switch( data->value.present ){
	case NGAP_UnsuccessfulOutcome__value_PR_UEContextModificationFailure:
		return _decode_NGAP_UEContextModificationFailure( msg, &data->value.choice.UEContextModificationFailure );
	default:
		break;
	}
	return true;
}

bool decode_ngap( ngap_message_t *msg, const uint8_t * buffer, const uint32_t length ){
	if( msg == NULL )
		return false;

	NGAP_NGAP_PDU_t *pdu_p = NULL;
	asn_dec_rval_t dec_ret;
	void *p;
	if( length == 0 || buffer == NULL)
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


uint32_t get_nas_pdu( void *data, uint32_t data_size, const uint8_t *buffer, uint32_t length ){
	ngap_message_t message, *msg = &message;
	if( data == NULL || data_size == 0 )
		return 0;

	NGAP_NGAP_PDU_t *pdu_p = NULL;
	asn_dec_rval_t dec_ret;
	void *p;
	if( length == 0 || buffer == NULL )
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

	if( ! ret ){
		ASN_STRUCT_FREE( asn_DEF_NGAP_NGAP_PDU, pdu_p );
		return 0;
	}

	if( msg->nas_pdu.size > 0 ){
		//copy data used by NAS_PDU
		if( data_size > msg->nas_pdu.size )
			data_size = msg->nas_pdu.size;
		memcpy(data, msg->nas_pdu.data, data_size);
	}


	ASN_STRUCT_FREE( asn_DEF_NGAP_NGAP_PDU, pdu_p );
	return data_size;
}
