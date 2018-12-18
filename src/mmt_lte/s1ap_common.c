/*
 * s1ap_common.c
 *
 *  Created on: Nov 6, 2018
 *      Author: nhnghia
 */

#include <stdlib.h>
#include "s1ap_common.h"
#include "nas/nas_msg.h"

static inline uint32_t _octet_string_to_uint32_t( const OCTET_STRING_t *t){
	if( t->size != 4 )
		return 0;
	uint32_t val = *(uint32_t*) t->buf;
	return val;
}

static inline uint32_t _bit_string_to_uint32_t( const BIT_STRING_t *t){
	if( t->size != 4 )
		return 0;
	uint32_t val = *(uint32_t*) t->buf;
	return val;
}


static inline int _decode_mme_enb_ue_id(
		s1ap_message_t *message,
		S1ap_IE_t *ie_p) {
	int i, decoded = 0;
	int tempDecoded = 0;
	switch(ie_p->id) {
			case S1ap_ProtocolIE_ID_id_MME_UE_S1AP_ID:
			{
				S1ap_MME_UE_S1AP_ID_t *s1apMMEUES1APID_p = NULL;
				tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_MME_UE_S1AP_ID, (void**)&s1apMMEUES1APID_p);
				if (tempDecoded < 0 || s1apMMEUES1APID_p == NULL) {
					S1AP_ERROR("Decoding of IE mme_ue_s1ap_id failed\n");
					if (s1apMMEUES1APID_p)
						ASN_STRUCT_FREE(asn_DEF_S1ap_MME_UE_S1AP_ID, s1apMMEUES1APID_p);
					return -1;
				}

				//HN:
				message->mme_ue_id = *s1apMMEUES1APID_p;

				decoded += tempDecoded;
				XER_FPRINT(&asn_DEF_S1ap_MME_UE_S1AP_ID, s1apMMEUES1APID_p);
				ASN_STRUCT_FREE( asn_DEF_S1ap_MME_UE_S1AP_ID, s1apMMEUES1APID_p);
			}
			break;
			case S1ap_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			{
				S1ap_ENB_UE_S1AP_ID_t *s1apENBUES1APID_p = NULL;
				tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_ENB_UE_S1AP_ID, (void**)&s1apENBUES1APID_p);
				if (tempDecoded < 0 || s1apENBUES1APID_p == NULL) {
					S1AP_ERROR("Decoding of IE eNB_UE_S1AP_ID failed\n");
					if (s1apENBUES1APID_p)
						ASN_STRUCT_FREE(asn_DEF_S1ap_ENB_UE_S1AP_ID, s1apENBUES1APID_p);
					return -1;
				}

				//HN:
				message->enb_ue_id = *s1apENBUES1APID_p;

				decoded += tempDecoded;
				XER_FPRINT(&asn_DEF_S1ap_ENB_UE_S1AP_ID, s1apENBUES1APID_p);
				ASN_STRUCT_FREE(asn_DEF_S1ap_ENB_UE_S1AP_ID, s1apENBUES1APID_p);
			}
			break;
	}
	return decoded;
}


static inline int _decode_s1ap_e_rabsetuplistctxtsures(
		s1ap_message_t *message,
		S1ap_E_RABSetupListCtxtSURes_t *s1ap_E_RABSetupListCtxtSURes) {

	int i, decoded = 0;
	int tempDecoded = 0;

	assert(s1ap_E_RABSetupListCtxtSURes != NULL);

	for (i = 0; i < s1ap_E_RABSetupListCtxtSURes->list.count; i++) {
		S1ap_IE_t *ie_p = s1ap_E_RABSetupListCtxtSURes->list.array[i];
		switch (ie_p->id) {
		case S1ap_ProtocolIE_ID_id_E_RABSetupItemCtxtSURes:
		{
			S1ap_E_RABSetupItemCtxtSURes_t *s1apERABSetupItemCtxtSURes_p = NULL;
			tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_E_RABSetupItemCtxtSURes, (void**)&s1apERABSetupItemCtxtSURes_p);
			if (tempDecoded < 0 || s1apERABSetupItemCtxtSURes_p == NULL) {
				S1AP_ERROR("Decoding of IE e_RABSetupItemCtxtSURes for message S1ap_E_RABSetupListCtxtSURes failed\n");
				if (s1apERABSetupItemCtxtSURes_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABSetupItemCtxtSURes, s1apERABSetupItemCtxtSURes_p);
				return -1;
			}

			//HN: here we can get gtp teid
			message->gtp_teid = _octet_string_to_uint32_t( & s1apERABSetupItemCtxtSURes_p->gTP_TEID );

			//HN: here we can get ENB IP
			message->enb_ipv4 = _bit_string_to_uint32_t( & s1apERABSetupItemCtxtSURes_p->transportLayerAddress );

			decoded += tempDecoded;
			XER_FPRINT( &asn_DEF_S1ap_E_RABSetupItemCtxtSURes, s1apERABSetupItemCtxtSURes_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABSetupItemCtxtSURes, s1apERABSetupItemCtxtSURes_p);
			return decoded;
		}
		break;
		default:
			S1AP_ERROR("Unknown protocol IE id (%d) for message s1ap_uplinkueassociatedlppatransport_ies\n", (int)ie_p->id);
			return -1;
		}
	}
	return decoded;
}

static inline int _s1ap_decode_e_rabtobesetuplistctxtsureq(
		s1ap_message_t *message,
		S1ap_E_RABToBeSetupListCtxtSUReq_t *s1ap_E_RABToBeSetupListCtxtSUReq) {

	int i, decoded = 0;
	int tempDecoded = 0;

	assert(s1ap_E_RABToBeSetupListCtxtSUReq != NULL);

	for (i = 0; i < s1ap_E_RABToBeSetupListCtxtSUReq->list.count; i++) {
		S1ap_IE_t *ie_p = s1ap_E_RABToBeSetupListCtxtSUReq->list.array[i];
		switch (ie_p->id) {
		case S1ap_ProtocolIE_ID_id_E_RABToBeSetupItemCtxtSUReq:
		{
			S1ap_E_RABToBeSetupItemCtxtSUReq_t *s1apERABToBeSetupItemCtxtSUReq_p = NULL;
			tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, (void**)&s1apERABToBeSetupItemCtxtSUReq_p);
			if (tempDecoded < 0 || s1apERABToBeSetupItemCtxtSUReq_p == NULL) {
				S1AP_ERROR("Decoding of IE e_RABToBeSetupItemCtxtSUReq for message S1ap_E_RABToBeSetupListCtxtSUReq failed\n");
				if (s1apERABToBeSetupItemCtxtSUReq_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, s1apERABToBeSetupItemCtxtSUReq_p);
				return -1;
			}

			//HN:here we can get gtp teid
			message->gtp_teid = _octet_string_to_uint32_t( & s1apERABToBeSetupItemCtxtSUReq_p->gTP_TEID );

			//HN: here we can get IP of mme
			message->mme_ipv4 =  _bit_string_to_uint32_t( & s1apERABToBeSetupItemCtxtSUReq_p->transportLayerAddress );

			//HN: extract UE IP from NAS PDU
			//s1apERABToBeSetupItemCtxtSUReq_p->nAS_PDU;
			S1ap_NAS_PDU_t *nas_pdu = s1apERABToBeSetupItemCtxtSUReq_p->nAS_PDU;
			if( nas_pdu != NULL ){
				nas_msg_t  m;
				memset( &m, 0, sizeof( m ) );
				//HN: get UE IP here
				if( nas_decode( &m, nas_pdu->buf, nas_pdu->size ) > 0
						&& nas_is_security_protected_msg( &m )
						&& m.protected_msg.header.protocol_discriminator == NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE
						&& m.protected_msg.msg.emm.header.message_type   == NAS_EMM_ATTACH_ACCEPT
						){
					const nas_octet_string_t *octet = & m.protected_msg.msg.emm.attach_accept.esm_message_container;
					if( octet->len > 0 ){
						nas_msg_t  mm;
						memset( &mm, 0, sizeof( mm ) );
						if( nas_decode( &mm, octet->data, octet->len) > 0 ){
							//need to check
							nas_pdn_address_t *pdn = &mm.plain_msg.esm.active_default_esp_bearer_context_request.pdn_address;
							if( pdn && pdn->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV4 ){
								message->ue_ipv4 = *(uint32_t *) pdn->pdn_address_information.data;
							}
						}
					}
				}
			}

			decoded += tempDecoded;
			XER_FPRINT( &asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, s1apERABToBeSetupItemCtxtSUReq_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, s1apERABToBeSetupItemCtxtSUReq_p);

			return decoded;
		} break;
		default:
			S1AP_ERROR("Unknown protocol IE id (%d) for message s1ap_uplinkueassociatedlppatransport_ies\n", (int)ie_p->id);
			return -1;
		}
	}
	return decoded;
}

static inline int _decode_s1ap_initialContextSetupRequest(
		s1ap_message_t *message,
		ANY_t *any_p) {
	S1ap_InitialContextSetupRequest_t *s1ap_InitialContextSetupRequest_p = NULL;
	int i, decoded = 0;
	int tempDecoded = 0;
	assert(any_p != NULL);

	S1AP_DEBUG("Decoding message S1ap_InitialContextSetupRequestIEs (%s:%d)\n", __FILE__, __LINE__);

	ANY_to_type_aper(any_p, &asn_DEF_S1ap_InitialContextSetupRequest, (void**)&s1ap_InitialContextSetupRequest_p);

	for (i = 0; i < s1ap_InitialContextSetupRequest_p->s1ap_InitialContextSetupRequest_ies.list.count; i++) {
		S1ap_IE_t *ie_p;
		ie_p = s1ap_InitialContextSetupRequest_p->s1ap_InitialContextSetupRequest_ies.list.array[i];

		tempDecoded = _decode_mme_enb_ue_id( message, ie_p );
		if( tempDecoded != 0 ){
			decoded += tempDecoded;
			continue;
		}

		switch(ie_p->id) {
		case S1ap_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq:
		{
			S1ap_E_RABToBeSetupListCtxtSUReq_t *s1apERABToBeSetupListCtxtSUReq_p = NULL;
			tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, (void**)&s1apERABToBeSetupListCtxtSUReq_p);
			if (tempDecoded < 0 || s1apERABToBeSetupListCtxtSUReq_p == NULL) {
				S1AP_ERROR("Decoding of IE e_RABToBeSetupListCtxtSUReq failed\n");
				if (s1apERABToBeSetupListCtxtSUReq_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, s1apERABToBeSetupListCtxtSUReq_p);

				decoded = -1;
				goto _finish;
			}
			if (_s1ap_decode_e_rabtobesetuplistctxtsureq(message, s1apERABToBeSetupListCtxtSUReq_p) < 0) {
				S1AP_ERROR("Decoding of encapsulated IE s1apERABToBeSetupListCtxtSUReq failed\n");
			}

			decoded += tempDecoded;
			XER_FPRINT(&asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, s1apERABToBeSetupListCtxtSUReq_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, s1apERABToBeSetupListCtxtSUReq_p);

			goto _finish;
		}
		break;

		}
	}

	_finish:
	ASN_STRUCT_FREE(asn_DEF_S1ap_InitialContextSetupRequest, s1ap_InitialContextSetupRequest_p);
	return decoded;
}




static inline int _decode_s1ap_initialContextSetupResponse(
		s1ap_message_t *message,
		ANY_t *any_p) {

	S1ap_InitialContextSetupResponse_t *s1ap_InitialContextSetupResponse_p = NULL;
	int i, decoded = 0;
	int tempDecoded = 0;
	assert(any_p != NULL);

	S1AP_DEBUG("Decoding message S1ap_InitialContextSetupResponseIEs (%s:%d)\n", __FILE__, __LINE__);

	ANY_to_type_aper(any_p, &asn_DEF_S1ap_InitialContextSetupResponse, (void**)&s1ap_InitialContextSetupResponse_p);

	for (i = 0; i < s1ap_InitialContextSetupResponse_p->s1ap_InitialContextSetupResponse_ies.list.count; i++) {
		S1ap_IE_t *ie_p;
		ie_p = s1ap_InitialContextSetupResponse_p->s1ap_InitialContextSetupResponse_ies.list.array[i];

		tempDecoded = _decode_mme_enb_ue_id( message, ie_p );
		if( tempDecoded != 0 ){
			decoded += tempDecoded;
			continue;
		}

		switch(ie_p->id) {
		case S1ap_ProtocolIE_ID_id_E_RABSetupListCtxtSURes:
		{
			S1ap_E_RABSetupListCtxtSURes_t *s1apERABSetupListCtxtSURes_p = NULL;
			tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_E_RABSetupListCtxtSURes, (void**)&s1apERABSetupListCtxtSURes_p);
			if (tempDecoded < 0 || s1apERABSetupListCtxtSURes_p == NULL) {
				S1AP_ERROR("Decoding of IE e_RABSetupListCtxtSURes failed\n");
				if (s1apERABSetupListCtxtSURes_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABSetupListCtxtSURes, s1apERABSetupListCtxtSURes_p);
				return -1;
			}

			if (_decode_s1ap_e_rabsetuplistctxtsures( message, s1apERABSetupListCtxtSURes_p) < 0) {
				S1AP_ERROR("Decoding of encapsulated IE s1apERABSetupListCtxtSURes failed\n");
			}

			decoded += tempDecoded;
			XER_FPRINT( &asn_DEF_S1ap_E_RABSetupListCtxtSURes, s1apERABSetupListCtxtSURes_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABSetupListCtxtSURes, s1apERABSetupListCtxtSURes_p);
		}
		break;
		}
	}

	ASN_STRUCT_FREE(asn_DEF_S1ap_InitialContextSetupResponse, s1ap_InitialContextSetupResponse_p);
	return decoded;
}

static inline int _decode_s1ap_initialuemessageies(
		s1ap_message_t *message,
		ANY_t *any_p) {

	S1ap_InitialUEMessage_t *s1ap_InitialUEMessage_p = NULL;
	int i, decoded = 0;
	int tempDecoded = 0;
	assert(any_p != NULL);

	S1AP_DEBUG("Decoding message S1ap_InitialUEMessageIEs (%s:%d)\n", __FILE__, __LINE__);

	ANY_to_type_aper(any_p, &asn_DEF_S1ap_InitialUEMessage, (void**)&s1ap_InitialUEMessage_p);

	for (i = 0; i < s1ap_InitialUEMessage_p->s1ap_InitialUEMessage_ies.list.count; i++) {
		S1ap_IE_t *ie_p;
		ie_p = s1ap_InitialUEMessage_p->s1ap_InitialUEMessage_ies.list.array[i];

		tempDecoded = _decode_mme_enb_ue_id( message, ie_p );
		if( tempDecoded != 0 ){
			decoded += tempDecoded;
			continue;
		}

		switch(ie_p->id) {
		case S1ap_ProtocolIE_ID_id_NAS_PDU:
		{
			S1ap_NAS_PDU_t *s1apNASPDU_p = NULL;
			tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_NAS_PDU, (void**)&s1apNASPDU_p);
			if (tempDecoded < 0 || s1apNASPDU_p == NULL) {
				S1AP_ERROR("Decoding of IE nas_pdu failed\n");
				if (s1apNASPDU_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_NAS_PDU, s1apNASPDU_p);

				decoded = -1;
				goto _finish;
			}
			decoded += tempDecoded;

			nas_msg_t  m;
			memset( &m, 0, sizeof( m ) );
			//we can get IMSI
			if( nas_decode( &m, s1apNASPDU_p->buf, s1apNASPDU_p->size ) > 0 ){
				if( m.header.protocol_discriminator == NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE
						&& m.plain_msg.emm.header.message_type == NAS_EMM_ATTACH_REQUEST
				){
					const nas_imsi_eps_mobile_identity_t *imsi = &m.plain_msg.emm.attach_request.old_guti_or_imsi.imsi;
					//imsi.digitX are numbers
					//=> we convert them to char, e.g., 7 => '7'
					message->imsi[0] = '0' + imsi->digit1;
					message->imsi[1] = '0' + imsi->digit2;
					message->imsi[2] = '0' + imsi->digit3;
					message->imsi[3] = '0' + imsi->digit4;
					message->imsi[4] = '0' + imsi->digit5;
					message->imsi[5] = '0' + imsi->digit6;
					message->imsi[6] = '0' + imsi->digit7;
					message->imsi[7] = '0' + imsi->digit8;
					message->imsi[8] = '0' + imsi->digit9;
					message->imsi[9] = '0' + imsi->digit10;
					message->imsi[10] ='0' + imsi->digit11;
					message->imsi[11] ='0' + imsi->digit12;
					message->imsi[12] ='0' + imsi->digit13;
					message->imsi[13] ='0' + imsi->digit14;
					message->imsi[14] ='0' + imsi->digit15;
					//printf("Got IMSI: %.*s\n", 15, message->imsi );
				}
			}

			XER_FPRINT(&asn_DEF_S1ap_NAS_PDU, s1apNASPDU_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_NAS_PDU, s1apNASPDU_p);
			goto _finish;
		}
		break;
		}
	}

	_finish:
	ASN_STRUCT_FREE( asn_DEF_S1ap_InitialUEMessage, s1ap_InitialUEMessage_p );
	return decoded;
}


static inline int _decode_s1ap_S1SetupRequest(
		s1ap_message_t *message,
		ANY_t *any_p) {

	S1ap_S1SetupRequest_t *s1ap_S1SetupRequest_p = NULL;
	int i, decoded = 0;
	int tempDecoded = 0;

	assert(any_p != NULL);

	S1AP_DEBUG("Decoding message S1ap_S1SetupRequestIEs (%s:%d)\n", __FILE__, __LINE__);

	ANY_to_type_aper(any_p, &asn_DEF_S1ap_S1SetupRequest, (void**)&s1ap_S1SetupRequest_p);

	for (i = 0; i < s1ap_S1SetupRequest_p->s1ap_S1SetupRequest_ies.list.count; i++) {
		S1ap_IE_t *ie_p;
		ie_p = s1ap_S1SetupRequest_p->s1ap_S1SetupRequest_ies.list.array[i];

		tempDecoded = _decode_mme_enb_ue_id( message, ie_p );
		if( tempDecoded != 0 ){
			decoded += tempDecoded;
			continue;
		}

		switch(ie_p->id) {
		case S1ap_ProtocolIE_ID_id_eNBname:
		{
			S1ap_ENBname_t *s1apENBname_p = NULL;

			tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_ENBname, (void**)&s1apENBname_p);
			if (tempDecoded < 0 || s1apENBname_p == NULL) {
				S1AP_ERROR("Decoding of IE eNBname failed\n");
				if (s1apENBname_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_ENBname, s1apENBname_p);

				decoded = -1;
				goto _finish;
			}

			//HN: here we got eNodeB's name
			int len = sizeof( message->enb_name ) - 1; //one byte for '\0'
			if( len > s1apENBname_p->size )
				len = s1apENBname_p->size;
			memcpy( message->enb_name,  s1apENBname_p->buf, len );
			message->enb_name[len] = '\0';

			S1AP_DEBUG("ENB name: %.*s\n", s1apENBname_p->size, message->enb_name.ptr );

			decoded += tempDecoded;

			XER_FPRINT( &asn_DEF_S1ap_ENBname, s1apENBname_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_ENBname, s1apENBname_p);

			goto _finish;
		} break;
		}
	}

	_finish:
	ASN_STRUCT_FREE( asn_DEF_S1ap_S1SetupRequest, s1ap_S1SetupRequest_p);
	return decoded;
}

static inline int _decode_s1ap_S1SetupResponse(
		s1ap_message_t *message,
		ANY_t *any_p) {
	S1ap_S1SetupResponse_t *s1ap_S1SetupResponse_p = NULL;
	int i, decoded = 0;
	int tempDecoded = 0;
	assert(any_p != NULL);

	S1AP_DEBUG("Decoding message S1ap_S1SetupResponseIEs (%s:%d)\n", __FILE__, __LINE__);

	ANY_to_type_aper(any_p, &asn_DEF_S1ap_S1SetupResponse, (void**)&s1ap_S1SetupResponse_p);

	for (i = 0; i < s1ap_S1SetupResponse_p->s1ap_S1SetupResponse_ies.list.count; i++) {
		S1ap_IE_t *ie_p;
		ie_p = s1ap_S1SetupResponse_p->s1ap_S1SetupResponse_ies.list.array[i];

		tempDecoded = _decode_mme_enb_ue_id( message, ie_p );
		if( tempDecoded != 0 ){
			decoded += tempDecoded;
			continue;
		}

		switch(ie_p->id) {
		/* Optional field */
		case S1ap_ProtocolIE_ID_id_MMEname:
		{
			S1ap_MMEname_t *s1apMMEname_p = NULL;

			tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_MMEname, (void**)&s1apMMEname_p);
			if (tempDecoded < 0 || s1apMMEname_p == NULL) {
				S1AP_ERROR("Decoding of IE mmEname failed\n");
				if (s1apMMEname_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_MMEname, s1apMMEname_p);

				decoded = -1;
				goto _finish;
			}
			decoded += tempDecoded;

			//HN: Here we can get MME's name
			int len = sizeof( message->mme_name ) - 1; //one byte for '\0'
			if( len > s1apMMEname_p->size )
				len = s1apMMEname_p->size;
			memcpy( message->mme_name,  s1apMMEname_p->buf, len );
			message->mme_name[len] = '\0';

			XER_FPRINT(&asn_DEF_S1ap_MMEname, s1apMMEname_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_MMEname, s1apMMEname_p);
			goto _finish;
		}
		break;
		}
	}

	_finish:
	ASN_STRUCT_FREE( asn_DEF_S1ap_S1SetupResponse, s1ap_S1SetupResponse_p);
	return decoded;
}

static int _decode_s1ap_initiatingMessage(s1ap_message_t *message,
		S1ap_InitiatingMessage_t *initiating_p){
	int ret = 0;

	switch(initiating_p->procedureCode) {
	case S1ap_ProcedureCode_id_initialUEMessage:
		return _decode_s1ap_initialuemessageies( message, &initiating_p->value );
		break;
	case S1ap_ProcedureCode_id_InitialContextSetup:
		return _decode_s1ap_initialContextSetupRequest( message, &initiating_p->value );
		break;
	case S1ap_ProcedureCode_id_S1Setup:
		return _decode_s1ap_S1SetupRequest( message, &initiating_p->value);
		break;
	}

	return ret;
}


static int _decode_s1ap_successfulOutcomeMessage(s1ap_message_t *message,
		S1ap_SuccessfulOutcome_t *initiating_p){
	int ret = 0;

	switch(initiating_p->procedureCode) {
	case S1ap_ProcedureCode_id_InitialContextSetup:
		return _decode_s1ap_initialContextSetupResponse( message, &initiating_p->value );
		break;
	case S1ap_ProcedureCode_id_S1Setup:
		return _decode_s1ap_S1SetupResponse( message, &initiating_p->value);
		break;
	}

	return ret;
}
/**
 * This function tries to fill information to all field of s1ap_message_t from S1AP packets
 *
 * - enb_name: S1SetupRequest/initiatingMessage/id-eNBname/value/ENBname
 * - imsi    : InitialUEMessage/id-NAS-PDU/(NAS)PDU/EPS mobile identity/IMSI
 * - gtp_teid: InitialContextSetupREquest/initiatingMessage/value/InitialContextSetupRequest/protocolIEs/
 *                 E-RABToBeSetupItemCtxtSUReq/gTP-TEID
 * - IP      : In the same packet of GTP_TEID; same path/(NAS)PDU/EMS message container/PDN address
 */
int s1ap_decode(s1ap_message_t *message, const uint8_t * const buffer,
		const uint32_t length)
{
	S1AP_PDU_t *pdu_p = NULL;
	asn_dec_rval_t dec_ret;

	assert(message != NULL);

	if( length == 0 )
		return 0;

	dec_ret = aper_decode(NULL,
			&asn_DEF_S1AP_PDU,
			(void **)&pdu_p,
			buffer,
			length,
			0,
			0);

	if (dec_ret.code != RC_OK) {
		fprintf(stderr, "[S1AP] Failed to decode S1AP, code %d, consumed: %zu\n", dec_ret.code, dec_ret.consumed);
		return -1;
	}

	int ret = 0;
	switch(pdu_p->present) {
	case S1AP_PDU_PR_initiatingMessage:
		message->procedure_code = pdu_p->choice.initiatingMessage.procedureCode;
		ret = _decode_s1ap_initiatingMessage(message,
				&pdu_p->choice.initiatingMessage);
		break;
	case S1AP_PDU_PR_successfulOutcome:
		message->procedure_code = pdu_p->choice.successfulOutcome.procedureCode;
		ret = _decode_s1ap_successfulOutcomeMessage(message,
				&pdu_p->choice.successfulOutcome);
		break;
	case S1AP_PDU_PR_unsuccessfulOutcome:
		message->procedure_code = pdu_p->choice.unsuccessfulOutcome.procedureCode;
		break;
	default:
		fprintf(stderr, "[S1AP] Unknown S1AP presence (%d)\n", (int)pdu_p->present);
		break;
	}

	ASN_STRUCT_FREE( asn_DEF_S1AP_PDU, pdu_p );

	return ret;
}

/*
int main(){
	s1ap_message_t msg;
	const uint8_t *buffer[] = {
			"\x00\x09\x00\x80\xd9\x00\x00\x06\x00\x00\x00\x02\x00\x03\x00\x08" \
			"\x00\x04\x80\x06\x69\x2d\x00\x42\x00\x08\x10\x01\x86\xa0\x40\x01" \
			"\x86\xa0\x00\x18\x00\x80\x8a\x00\x00\x34\x00\x80\x84\x45\x00\x09" \
			"\x3c\x0f\x80\xac\x10\x00\x01\x00\x00\x00\x01\x75\x27\x2e\xb9\xda" \
			"\xae\x01\x07\x42\x02\x49\x06\x00\x42\xf4\x99\x31\x32\x00\x48\x52" \
			"\x03\xc1\x01\x09\x1c\x08\x69\x6e\x74\x65\x72\x6e\x65\x74\x06\x6d" \
			"\x6e\x63\x30\x39\x39\x06\x6d\x63\x63\x32\x34\x34\x04\x67\x70\x72" \
			"\x73\x05\x01\x0a\x00\x00\x01\x27\x1e\x80\x80\x21\x0a\x03\x00\x00" \
			"\x0a\x81\x06\x08\x08\x08\x08\x00\x0d\x04\x08\x08\x08\x08\x00\x05" \
			"\x01\x02\x00\x10\x02\x05\xa0\x50\x0b\xf6\x42\xf4\x99\x80\x04\x03" \
			"\x00\x00\x04\x57\x13\x42\xf4\x99\x31\x32\x23\x05\xf4\x00\x00\x68" \
			"\x61\x00\x6b\x00\x05\x1a\x00\x0d\x00\x00\x00\x49\x00\x20\x43\xfa" \
			"\x55\x1d\x17\xf2\xdc\x7d\x37\x01\x71\x78\x5a\xc4\x68\xcc\x8d\xa4" \
			"\x7b\x65\x3b\x58\xce\xcd\x9b\xf0\x19\xfb\x63\x66\x74\xe9",

			"\x00\x0c\x00\x80\x8a\x00\x00\x05\x00\x08\x00\x04\x80\x06\x69\x2d" \
			"\x00\x1a\x00\x60\x5f\x07\x41\x72\x08\x29\x44\x99\x00\x00\x00\x00" \
			"\x20\x05\xe0\x60\xc0\x40\x19\x00\x23\x02\x03\xd0\x11\x27\x1d\x80" \
			"\x80\x21\x10\x01\x00\x00\x10\x81\x06\x00\x00\x00\x00\x83\x06\x00" \
			"\x00\x00\x00\x00\x0d\x00\x00\x0a\x00\x00\x10\x00\x5c\x0a\x00\x31" \
			"\x03\xe5\xe0\x2e\x90\x11\x03\x57\x58\xa6\x20\x0a\x60\x14\x04\x62" \
			"\x91\x81\x00\x12\x1e\x00\x40\x08\x04\x02\x60\x04\x00\x02\x1f\x00" \
			"\x5d\x01\x00\xc1\x00\x43\x00\x06\x00\x42\xf4\x99\x31\x32\x00\x64" \
			"\x40\x08\x00\x42\xf4\x99\x00\xe0\x00\x00\x00\x86\x40\x01\x30"

	};
	uint32_t len[] = {222, 143};
	int i;
	for( i=0; i<2; i++ ){
		printf("%d buffer len : %d\n", i, len[i] );
		s1ap_decode( &msg, buffer[i], len[i] );
		printf( "gtp_teid: %d\n", msg.gtp_teid );
	}
}
*/
