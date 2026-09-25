/*
 * s1ap_common.c
 *
 *  Created on: Nov 6, 2018
 *      Author: nhnghia
 */

#include <stdlib.h>
#include <string.h>
#include "s1ap_common.h"
#include "nas/nas_msg.h"
#include "proto_s1ap.h"

static inline const asn_codec_ctx_t * _aper_codec_ctx( void );

/*
 * ANY_to_type_aper() decodes with a NULL codec context, i.e. with the
 * default stack guard that always trips under ASan (see _aper_codec_ctx()).
 * Once the open types decode (issue #427), every IE value goes through this
 * path, so decode them with the same context as the outer S1AP-PDU.
 */
static int _any_to_type_aper(ANY_t *st, asn_TYPE_descriptor_t *td, void **struct_ptr){
	asn_dec_rval_t rval;
	void *newst = NULL;

	if( st == NULL || td == NULL || struct_ptr == NULL )
		return -1;
	if( st->buf == NULL ){
		/* nothing to convert */
		*struct_ptr = NULL;
		return 0;
	}
	rval = aper_decode( _aper_codec_ctx(), td, &newst, st->buf, st->size, 0, 0 );
	if( rval.code == RC_OK ){
		*struct_ptr = newst;
		return 0;
	}
	/* remove the partially decoded data */
	ASN_STRUCT_FREE( *td, newst );
	return -1;
}

static inline uint32_t _octet_string_to_uint32_t( const OCTET_STRING_t *t){
	if( t->size != 4 || t->buf == NULL )
		return 0;
	uint32_t val;
	memcpy( &val, t->buf, sizeof( val ));
	return val;
}

static inline uint32_t _bit_string_to_uint32_t( const BIT_STRING_t *t){
	if( t->size != 4 || t->buf == NULL )
		return 0;
	uint32_t val;
	memcpy( &val, t->buf, sizeof( val ));
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
				tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_MME_UE_S1AP_ID, (void**)&s1apMMEUES1APID_p);
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
				tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_ENB_UE_S1AP_ID, (void**)&s1apENBUES1APID_p);
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

	/* F-SEC-011 (issue #214): decoded-message pointers are validated
	 * unconditionally — the shipped build defines NDEBUG, so an assert()
	 * here would compile out and a NULL would dereference below. */
	if (s1ap_E_RABSetupListCtxtSURes == NULL) {
		S1AP_ERROR("NULL E_RABSetupListCtxtSURes\n");
		return -1;
	}

	for (i = 0; i < s1ap_E_RABSetupListCtxtSURes->list.count; i++) {
		S1ap_IE_t *ie_p = s1ap_E_RABSetupListCtxtSURes->list.array[i];
		switch (ie_p->id) {
		case S1ap_ProtocolIE_ID_id_E_RABSetupItemCtxtSURes:
		{
			S1ap_E_RABSetupItemCtxtSURes_t *s1apERABSetupItemCtxtSURes_p = NULL;
			tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_E_RABSetupItemCtxtSURes, (void**)&s1apERABSetupItemCtxtSURes_p);
			if (tempDecoded < 0 || s1apERABSetupItemCtxtSURes_p == NULL) {
				S1AP_ERROR("Decoding of IE e_RABSetupItemCtxtSURes for message S1ap_E_RABSetupListCtxtSURes failed\n");
				if (s1apERABSetupItemCtxtSURes_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABSetupItemCtxtSURes, s1apERABSetupItemCtxtSURes_p);
				return -1;
			}

			//HN: here we can get gtp teid
			message->gtp_teid = _octet_string_to_uint32_t( & s1apERABSetupItemCtxtSURes_p->gTP_TEID );
			message->gtp_teid = ntohl( message->gtp_teid );

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

	if (s1ap_E_RABToBeSetupListCtxtSUReq == NULL) {
		S1AP_ERROR("NULL E_RABToBeSetupListCtxtSUReq\n");
		return -1;
	}

	for (i = 0; i < s1ap_E_RABToBeSetupListCtxtSUReq->list.count; i++) {
		S1ap_IE_t *ie_p = s1ap_E_RABToBeSetupListCtxtSUReq->list.array[i];
		switch (ie_p->id) {
		case S1ap_ProtocolIE_ID_id_E_RABToBeSetupItemCtxtSUReq:
		{
			S1ap_E_RABToBeSetupItemCtxtSUReq_t *s1apERABToBeSetupItemCtxtSUReq_p = NULL;
			tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, (void**)&s1apERABToBeSetupItemCtxtSUReq_p);
			if (tempDecoded < 0 || s1apERABToBeSetupItemCtxtSUReq_p == NULL) {
				S1AP_ERROR("Decoding of IE e_RABToBeSetupItemCtxtSUReq for message S1ap_E_RABToBeSetupListCtxtSUReq failed\n");
				if (s1apERABToBeSetupItemCtxtSUReq_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, s1apERABToBeSetupItemCtxtSUReq_p);
				return -1;
			}

			//HN: extract qci, priority level
			const S1ap_E_RABLevelQoSParameters_t *qos = &s1apERABToBeSetupItemCtxtSUReq_p->e_RABlevelQoSParameters;
			message->qos_qci = qos->qCI;
			message->qos_priority_level = qos->allocationRetentionPriority.priorityLevel;

			//HN:here we can get gtp teid
			message->gtp_teid = _octet_string_to_uint32_t( & s1apERABToBeSetupItemCtxtSUReq_p->gTP_TEID );
			message->gtp_teid = ntohl( message->gtp_teid );

			//HN: here we can get IP of gw
			message->gw_ipv4 =  _bit_string_to_uint32_t( & s1apERABToBeSetupItemCtxtSUReq_p->transportLayerAddress );

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

					//parser ESM message container to get UE's IP
					const nas_octet_string_t *octet = & m.protected_msg.msg.emm.attach_accept.esm_message_container;
					if( octet->len > 0 ){
						nas_msg_t  mm;
						memset( &mm, 0, sizeof( mm ) );
						/* issue #427 review: only read the ESM view of an
						 * Activate Default EPS Bearer Context Request — any other
						 * layout aliases unrelated union bytes as the PDN address.
						 * nas_decode() routes every ESM PDU to the plain decoder;
						 * octet 1's upper nibble is the EPS bearer identity, not a
						 * security header type, so nas_is_plain_msg() must not gate */
						if( nas_decode( &mm, octet->data, octet->len) > 0
								&& mm.plain_msg.header.protocol_discriminator == NAS_EPS_SESSION_MANAGEMENT_MESSAGE
								&& mm.plain_msg.esm.header.message_type == NAS_ESM_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST ){
							// F-BUG-202: bound UE-IP read by pdn_type-implied minimum
							nas_pdn_address_t *pdn = &mm.plain_msg.esm.active_default_esp_bearer_context_request.pdn_address;
							if( pdn && pdn->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV4
									&& pdn->pdn_address_information.data != NULL
									&& pdn->pdn_address_information.len >= 4 ){
								memcpy( &message->ue_ipv4, pdn->pdn_address_information.data,
										sizeof( message->ue_ipv4 ));
							}
						}
					}
					//parse EPS mobile identity to get m_tmsi
					if( (m.protected_msg.msg.emm.attach_accept.present & NAS_EMM_ATTACH_ACCEPT_HAS_GUTI)
							&& m.protected_msg.msg.emm.attach_accept.guti.guti.typeofidentity == EPS_MOBILE_IDENTITY_GUTI ){
						message->m_tmsi = m.protected_msg.msg.emm.attach_accept.guti.guti.mtmsi;
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
	if (any_p == NULL) {
		S1AP_ERROR("NULL ANY_t value\n");
		return -1;
	}

	S1AP_DEBUG("Decoding message S1ap_InitialContextSetupRequestIEs (%s:%d)\n", __FILE__, __LINE__);

	tempDecoded = _any_to_type_aper(any_p, &asn_DEF_S1ap_InitialContextSetupRequest, (void**)&s1ap_InitialContextSetupRequest_p);
	if (tempDecoded < 0 || s1ap_InitialContextSetupRequest_p == NULL) {
		S1AP_ERROR("Decoding of S1ap_InitialContextSetupRequest failed\n");
		if (s1ap_InitialContextSetupRequest_p)
			ASN_STRUCT_FREE(asn_DEF_S1ap_InitialContextSetupRequest, s1ap_InitialContextSetupRequest_p);
		return -1;
	}

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
			tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, (void**)&s1apERABToBeSetupListCtxtSUReq_p);
			if (tempDecoded < 0 || s1apERABToBeSetupListCtxtSUReq_p == NULL) {
				S1AP_ERROR("Decoding of IE e_RABToBeSetupListCtxtSUReq failed\n");
				if (s1apERABToBeSetupListCtxtSUReq_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, s1apERABToBeSetupListCtxtSUReq_p);

				decoded = -1;
				goto _finish;
			}
			if (_s1ap_decode_e_rabtobesetuplistctxtsureq(message, s1apERABToBeSetupListCtxtSUReq_p) < 0) {
				S1AP_ERROR("Decoding of encapsulated IE s1apERABToBeSetupListCtxtSUReq failed\n");
				if (s1apERABToBeSetupListCtxtSUReq_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, s1apERABToBeSetupListCtxtSUReq_p);
				decoded = -1;
				goto _finish;
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
	if (any_p == NULL) {
		S1AP_ERROR("NULL ANY_t value\n");
		return -1;
	}

	S1AP_DEBUG("Decoding message S1ap_InitialContextSetupResponseIEs (%s:%d)\n", __FILE__, __LINE__);

	tempDecoded = _any_to_type_aper(any_p, &asn_DEF_S1ap_InitialContextSetupResponse, (void**)&s1ap_InitialContextSetupResponse_p);
	if (tempDecoded < 0 || s1ap_InitialContextSetupResponse_p == NULL) {
		S1AP_ERROR("Decoding of S1ap_InitialContextSetupResponse failed\n");
		if (s1ap_InitialContextSetupResponse_p)
			ASN_STRUCT_FREE(asn_DEF_S1ap_InitialContextSetupResponse, s1ap_InitialContextSetupResponse_p);
		return -1;
	}

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
			tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_E_RABSetupListCtxtSURes, (void**)&s1apERABSetupListCtxtSURes_p);
			if (tempDecoded < 0 || s1apERABSetupListCtxtSURes_p == NULL) {
				S1AP_ERROR("Decoding of IE e_RABSetupListCtxtSURes failed\n");
				if (s1apERABSetupListCtxtSURes_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABSetupListCtxtSURes, s1apERABSetupListCtxtSURes_p);
				/* must go through _finish to free the outer decoded tree
				 * (F-BUG-087) */
				decoded = -1;
				goto _finish;
			}

			if (_decode_s1ap_e_rabsetuplistctxtsures( message, s1apERABSetupListCtxtSURes_p) < 0) {
				S1AP_ERROR("Decoding of encapsulated IE s1apERABSetupListCtxtSURes failed\n");
				decoded = -1;
			} else
				decoded += tempDecoded;

			XER_FPRINT( &asn_DEF_S1ap_E_RABSetupListCtxtSURes, s1apERABSetupListCtxtSURes_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABSetupListCtxtSURes, s1apERABSetupListCtxtSURes_p);

			goto _finish;
		}
		break;
		}
	}

	_finish:
	ASN_STRUCT_FREE(asn_DEF_S1ap_InitialContextSetupResponse, s1ap_InitialContextSetupResponse_p);
	return decoded;
}

static inline int _decode_s1ap_initialuemessageies(
		s1ap_message_t *message,
		ANY_t *any_p) {

	S1ap_InitialUEMessage_t *s1ap_InitialUEMessage_p = NULL;
	int i, decoded = 0;
	int tempDecoded = 0;
	if (any_p == NULL) {
		S1AP_ERROR("NULL ANY_t value\n");
		return -1;
	}

	S1AP_DEBUG("Decoding message S1ap_InitialUEMessageIEs (%s:%d)\n", __FILE__, __LINE__);

	tempDecoded = _any_to_type_aper(any_p, &asn_DEF_S1ap_InitialUEMessage, (void**)&s1ap_InitialUEMessage_p);
	if (tempDecoded < 0 || s1ap_InitialUEMessage_p == NULL) {
		S1AP_ERROR("Decoding of S1ap_InitialUEMessage failed\n");
		if (s1ap_InitialUEMessage_p)
			ASN_STRUCT_FREE(asn_DEF_S1ap_InitialUEMessage, s1ap_InitialUEMessage_p);
		return -1;
	}

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
			tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_NAS_PDU, (void**)&s1apNASPDU_p);
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
				nas_msg_plain_t *plain_msg = nas_get_plain_msg( &m );

				if( plain_msg->header.protocol_discriminator == NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE
						&& plain_msg->emm.header.message_type == NAS_EMM_ATTACH_REQUEST ){

					nas_eps_mobile_identity_t *eps_id = & plain_msg->emm.attach_request.old_guti_or_imsi;
					switch( eps_id->guti.typeofidentity ){
					case EPS_MOBILE_IDENTITY_IMSI: {
						const nas_imsi_eps_mobile_identity_t *imsi = & eps_id->imsi;
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
						message->imsi[15] = '\0';
						/* an even digit count ends with the 0xF filler
						 * (TS 24.301 §9.9.3.12): 14 digits, not a '?' */
						if( imsi->oddeven == EPS_MOBILE_IDENTITY_EVEN )
							message->imsi[14] = '\0';
						message->has_imsi = 1;
						//printf("Got IMSI: %.*s\n", 15, message->imsi );
						break;
					}
					case EPS_MOBILE_IDENTITY_GUTI: {
						message->m_tmsi = eps_id->guti.mtmsi;
						break;
					}
					}
				}
			}

			XER_FPRINT(&asn_DEF_S1ap_NAS_PDU, s1apNASPDU_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_NAS_PDU, s1apNASPDU_p);
		}
		break;

		case S1ap_ProtocolIE_ID_id_S_TMSI: {
            S1ap_S_TMSI_t *s1apSTMSI_p = NULL;
            tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_S_TMSI, (void**)&s1apSTMSI_p);
            if (tempDecoded < 0 || s1apSTMSI_p == NULL) {
                S1AP_ERROR("Decoding of IE s_tmsi failed\n");
                if (s1apSTMSI_p)
                    ASN_STRUCT_FREE(asn_DEF_S1ap_S_TMSI, s1apSTMSI_p);
                decoded = -1;
				goto _finish;
            }
            decoded += tempDecoded;


            message->m_tmsi = _octet_string_to_uint32_t( &s1apSTMSI_p->m_TMSI );
            message->m_tmsi = ntohl( message->m_tmsi );

            XER_FPRINT( &asn_DEF_S1ap_S_TMSI, s1apSTMSI_p);
            ASN_STRUCT_FREE(asn_DEF_S1ap_S_TMSI, s1apSTMSI_p);
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

	if (any_p == NULL) {
		S1AP_ERROR("NULL ANY_t value\n");
		return -1;
	}

	S1AP_DEBUG("Decoding message S1ap_S1SetupRequestIEs (%s:%d)\n", __FILE__, __LINE__);

	tempDecoded = _any_to_type_aper(any_p, &asn_DEF_S1ap_S1SetupRequest, (void**)&s1ap_S1SetupRequest_p);
	if (tempDecoded < 0 || s1ap_S1SetupRequest_p == NULL) {
		S1AP_ERROR("Decoding of S1ap_S1SetupRequest failed\n");
		if (s1ap_S1SetupRequest_p)
			ASN_STRUCT_FREE(asn_DEF_S1ap_S1SetupRequest, s1ap_S1SetupRequest_p);
		return -1;
	}

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

			tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_ENBname, (void**)&s1apENBname_p);
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
			if( len > 0 )
				message->has_enb_name = 1;

			S1AP_DEBUG("ENB name: %.*s\n", s1apENBname_p->size, message->enb_name );

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
	if (any_p == NULL) {
		S1AP_ERROR("NULL ANY_t value\n");
		return -1;
	}

	S1AP_DEBUG("Decoding message S1ap_S1SetupResponseIEs (%s:%d)\n", __FILE__, __LINE__);

	tempDecoded = _any_to_type_aper(any_p, &asn_DEF_S1ap_S1SetupResponse, (void**)&s1ap_S1SetupResponse_p);
	if (tempDecoded < 0 || s1ap_S1SetupResponse_p == NULL) {
		S1AP_ERROR("Decoding of S1ap_S1SetupResponse failed\n");
		if (s1ap_S1SetupResponse_p)
			ASN_STRUCT_FREE(asn_DEF_S1ap_S1SetupResponse, s1ap_S1SetupResponse_p);
		return -1;
	}

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

			tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_MMEname, (void**)&s1apMMEname_p);
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
			if( len > 0 )
				message->has_mme_name = 1;

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


/**
 * Set status of UE depending the cause it was released
 */
static inline int _decode_s1ap_cause(
		s1ap_message_t *message,
		S1ap_IE_t *ie_p){

	int decoded = 0;
	S1ap_Cause_t *s1apCause_p = NULL;
	decoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_Cause, (void**)&s1apCause_p);
	if (decoded < 0 || s1apCause_p == NULL) {
		S1AP_ERROR("Decoding of IE cause failed\n");
		if (s1apCause_p)
			ASN_STRUCT_FREE(asn_DEF_S1ap_Cause, s1apCause_p);
		return -1;
	}

	switch( s1apCause_p->present ){
	case S1ap_Cause_PR_NOTHING:
		break;
	case S1ap_Cause_PR_transport:
		break;
	case S1ap_Cause_PR_radioNetwork: {
		switch( s1apCause_p->choice.radioNetwork ){
		case S1ap_CauseRadioNetwork_radio_connection_with_ue_lost:
			message->ue_status = S1AP_ENTITY_STATUS_LOST_SIGNAL;
			break;
		default:
			break;
		}
	}
	break;

	case S1ap_Cause_PR_nas:{
		switch( s1apCause_p->choice.nas ){
		case S1ap_CauseNas_detach:
			message->ue_status = S1AP_ENTITY_STATUS_DETACHED;
			break;
		}
	}
	break;

	case S1ap_Cause_PR_protocol:
		break;
	case S1ap_Cause_PR_misc:
		break;
	}

	XER_FPRINT(&asn_DEF_S1ap_Cause, s1apCause_p);
	ASN_STRUCT_FREE(asn_DEF_S1ap_Cause, s1apCause_p);
	return decoded;
}

static inline int _decode_s1ap_uecontextrelease(
		s1ap_message_t *message,
		ANY_t *any_p) {

    S1ap_UEContextReleaseCommand_t *s1ap_UEContextReleaseCommand_p = NULL;
    int i, decoded = 0;
    int tempDecoded = 0;
    if (any_p == NULL) {
        S1AP_ERROR("NULL ANY_t value\n");
        return -1;
    }

    S1AP_DEBUG("Decoding message S1ap_UEContextReleaseCommandIEs (%s:%d)\n", __FILE__, __LINE__);

    tempDecoded = _any_to_type_aper(any_p, &asn_DEF_S1ap_UEContextReleaseCommand, (void**)&s1ap_UEContextReleaseCommand_p);
    if (tempDecoded < 0 || s1ap_UEContextReleaseCommand_p == NULL) {
        S1AP_ERROR("Decoding of S1ap_UEContextReleaseCommand failed\n");
        if (s1ap_UEContextReleaseCommand_p)
            ASN_STRUCT_FREE(asn_DEF_S1ap_UEContextReleaseCommand, s1ap_UEContextReleaseCommand_p);
        return -1;
    }

    for (i = 0; i < s1ap_UEContextReleaseCommand_p->s1ap_UEContextReleaseCommand_ies.list.count; i++) {
        S1ap_IE_t *ie_p;
        ie_p = s1ap_UEContextReleaseCommand_p->s1ap_UEContextReleaseCommand_ies.list.array[i];
        switch(ie_p->id) {
            case S1ap_ProtocolIE_ID_id_UE_S1AP_IDs: {

                S1ap_UE_S1AP_IDs_t *s1apUES1APIDs_p = NULL;
                tempDecoded = _any_to_type_aper(&ie_p->value, &asn_DEF_S1ap_UE_S1AP_IDs, (void**)&s1apUES1APIDs_p);
                if (tempDecoded < 0 || s1apUES1APIDs_p == NULL) {
                    S1AP_ERROR("Decoding of IE uE_S1AP_IDs failed\n");
                    if (s1apUES1APIDs_p)
                        ASN_STRUCT_FREE(asn_DEF_S1ap_UE_S1AP_IDs, s1apUES1APIDs_p);
                    decoded = -1;
                    goto _finish;
                }

                //HN: here we cant get either only mme_ue_id or (mme_ue_id, pair enb_ue_id)
                switch( s1apUES1APIDs_p->present ){
                case S1ap_UE_S1AP_IDs_PR_mME_UE_S1AP_ID:
                	message->mme_ue_id = s1apUES1APIDs_p->choice.mME_UE_S1AP_ID;
                	break;
                case S1ap_UE_S1AP_IDs_PR_uE_S1AP_ID_pair:
                	message->mme_ue_id = s1apUES1APIDs_p->choice.uE_S1AP_ID_pair.mME_UE_S1AP_ID;
                	message->enb_ue_id = s1apUES1APIDs_p->choice.uE_S1AP_ID_pair.eNB_UE_S1AP_ID;
                	break;
                case S1ap_UE_S1AP_IDs_PR_NOTHING:
                	break;
                }

                decoded += tempDecoded;
                XER_FPRINT( &asn_DEF_S1ap_UE_S1AP_IDs, s1apUES1APIDs_p);
                ASN_STRUCT_FREE( asn_DEF_S1ap_UE_S1AP_IDs, s1apUES1APIDs_p);
            }
			break;
            case S1ap_ProtocolIE_ID_id_Cause:
            	tempDecoded = _decode_s1ap_cause( message, ie_p );
            	if (tempDecoded < 0 ) {
            		decoded = -1;
            		goto _finish;
            		return -1;
            	}
            	decoded += tempDecoded;
            	break;
            default:
                S1AP_ERROR("Unknown protocol IE id (%d) for message s1ap_uecontextreleasecommandies\n", (int)ie_p->id);
                decoded = -1;
                goto _finish;
        }
    }

    _finish:
	ASN_STRUCT_FREE( asn_DEF_S1ap_UEContextReleaseCommand, s1ap_UEContextReleaseCommand_p);
    return decoded;
}

static inline int _decode_s1ap_UEContextReleaseRequest(
		s1ap_message_t *message,
		ANY_t *any_p) {

	S1ap_UEContextReleaseRequest_t *s1ap_UEContextReleaseRequest_p =  NULL;
	int i, decoded = 0;
	int tempDecoded = 0;
	if (any_p == NULL) {
		S1AP_ERROR("NULL ANY_t value\n");
		return -1;
	}

	S1AP_DEBUG("Decoding message S1ap_UEContextReleaseRequestIEs (%s:%d)\n", __FILE__, __LINE__);

	tempDecoded = _any_to_type_aper(any_p, &asn_DEF_S1ap_UEContextReleaseRequest, (void**)&s1ap_UEContextReleaseRequest_p);
	if (tempDecoded < 0 || s1ap_UEContextReleaseRequest_p == NULL) {
		S1AP_ERROR("Decoding of S1ap_UEContextReleaseRequest failed\n");
		if (s1ap_UEContextReleaseRequest_p)
			ASN_STRUCT_FREE(asn_DEF_S1ap_UEContextReleaseRequest, s1ap_UEContextReleaseRequest_p);
		return -1;
	}

	for (i = 0; i < s1ap_UEContextReleaseRequest_p->s1ap_UEContextReleaseRequest_ies.list.count; i++) {

		S1ap_IE_t *ie_p;
		ie_p = s1ap_UEContextReleaseRequest_p->s1ap_UEContextReleaseRequest_ies.list.array[i];

		tempDecoded = _decode_mme_enb_ue_id( message, ie_p );
		if( tempDecoded != 0 ){
			decoded += tempDecoded;
			continue;
		}

		switch(ie_p->id) {
		case S1ap_ProtocolIE_ID_id_MME_UE_S1AP_ID:
		case S1ap_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			break;
		case S1ap_ProtocolIE_ID_id_Cause:
			tempDecoded = _decode_s1ap_cause( message, ie_p );
			if (tempDecoded < 0 ) {
				decoded = -1;
				goto _finish;
				return -1;
			}
			decoded += tempDecoded;
			break;
			/* Optional field */
		case S1ap_ProtocolIE_ID_id_GWContextReleaseIndication:
			break;
		default:
			S1AP_ERROR("Unknown protocol IE id (%d) for message s1ap_uecontextreleaserequesties\n", (int)ie_p->id);
			decoded = -1;
			goto _finish;
		}
	}

	_finish:
	ASN_STRUCT_FREE( asn_DEF_S1ap_UEContextReleaseRequest, s1ap_UEContextReleaseRequest_p);
	return decoded;
}

static int _decode_s1ap_initiatingMessage(s1ap_message_t *message,
		S1ap_InitiatingMessage_t *initiating_p){
	int ret = 0;

	switch(initiating_p->procedureCode) {
	case S1ap_ProcedureCode_id_initialUEMessage:
		message->ue_status = S1AP_ENTITY_STATUS_ATTACHING;
		return _decode_s1ap_initialuemessageies( message, &initiating_p->value );
		break;
	case S1ap_ProcedureCode_id_InitialContextSetup:
		return _decode_s1ap_initialContextSetupRequest( message, &initiating_p->value );
		break;
	case S1ap_ProcedureCode_id_S1Setup:
		message->enb_status = S1AP_ENTITY_STATUS_ATTACHING;
		message->mme_status = S1AP_ENTITY_STATUS_ATTACHING;
		return _decode_s1ap_S1SetupRequest( message, &initiating_p->value);
		break;
	case S1ap_ProcedureCode_id_UEContextRelease:
		return _decode_s1ap_uecontextrelease( message, &initiating_p->value);
		break;
	case S1ap_ProcedureCode_id_UEContextReleaseRequest:
		return _decode_s1ap_UEContextReleaseRequest( message, &initiating_p->value);
		break;
	}

	return ret;
}


static int _decode_s1ap_successfulOutcomeMessage(s1ap_message_t *message,
		S1ap_SuccessfulOutcome_t *initiating_p){
	int ret = 0;

	switch(initiating_p->procedureCode) {
	case S1ap_ProcedureCode_id_InitialContextSetup:
		message->ue_status = S1AP_ENTITY_STATUS_ATTACHED;
		return _decode_s1ap_initialContextSetupResponse( message, &initiating_p->value );
		break;
	case S1ap_ProcedureCode_id_S1Setup:
		message->enb_status = S1AP_ENTITY_STATUS_ATTACHED;
		message->mme_status = S1AP_ENTITY_STATUS_ATTACHED;
		return _decode_s1ap_S1SetupResponse( message, &initiating_p->value);
		break;
	}

	return ret;
}

/*
 * Issue #427: every S1AP open type (S1AP-PDU value, ProtocolIE value) is
 * generated as an ANY, and the vendored ANY_decode_aper() asks
 * aper_get_length() for its length determinant with ebits = 0
 * (src/mmt_mobile/asn1c/common/ANY.c). That returns per_get_few_bits(pd, 0)
 * == 0 without reading the octet-aligned X.691 §11.2 length, so each ANY
 * decodes as empty and consumes nothing: the message handlers then fail on
 * the empty IE container ("Decoding of S1ap_InitialUEMessage failed") and no
 * s1ap.* attribute is ever extracted. The generated tree must not be edited,
 * so the corrected decoder below (the same body with ebits = -1, i.e. read
 * the general length determinant) is installed into the shared asn_OP_ANY
 * operation table once, when the library is loaded — before any thread can
 * decode — so the table is never written concurrently with a read.
 */
#undef RETURN
#define RETURN(_code)                       \
	do {                                    \
		asn_dec_rval_t tmprval;             \
		tmprval.code = _code;               \
		tmprval.consumed = consumed_myself; \
		return tmprval;                     \
	} while(0)

static asn_dec_rval_t _any_decode_aper_open_type(
		const asn_codec_ctx_t *opt_codec_ctx,
		const asn_TYPE_descriptor_t *td,
		const asn_per_constraints_t *constraints, void **sptr,
		asn_per_data_t *pd) {
	const asn_OCTET_STRING_specifics_t *specs =
		td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
		              : &asn_SPC_ANY_specs;
	size_t consumed_myself = 0;
	int repeat;
	ANY_t *st = (ANY_t *)*sptr;

	(void)opt_codec_ctx;
	(void)constraints;

	if(!st) {
		st = (ANY_t *)(*sptr = CALLOC(1, specs->struct_size));
		if(!st) RETURN(RC_FAIL);
	}

	st->size = 0;
	do {
		ssize_t raw_len;
		void *p;

		/* unconstrained, octet-aligned length determinant (X.691 §11.9) */
		raw_len = aper_get_length(pd, -1, -1, &repeat);
		if(raw_len < 0) RETURN(RC_WMORE);
		if(raw_len == 0 && st->buf) break;

		p = REALLOC(st->buf, st->size + (size_t)raw_len + 1);
		if(!p) RETURN(RC_FAIL);
		st->buf = (uint8_t *)p;

		if(per_get_many_bits(pd, &st->buf[st->size], 0, raw_len * 8) < 0)
			RETURN(RC_WMORE);
		consumed_myself += raw_len * 8;
		st->size += raw_len;
	} while(repeat);
	st->buf[st->size] = 0; /* nul-terminate */

	RETURN(RC_OK);
}
#undef RETURN

__attribute__((constructor))
static void _install_any_aper_decoder( void ){
	asn_OP_ANY.aper_decoder = _any_decode_aper_open_type;
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
/*
 * asn1c's stack-overflow guard measures nesting depth by the distance
 * between the codec context and its own frame (&ctx). AddressSanitizer
 * relocates instrumented locals onto its fake stack, so that distance
 * always exceeds ASN__DEFAULT_STACK_MAX and every PER decode fails with
 * RC_WMORE ("Stack limit 30000 reached"). The generated trees under
 * src/mmt_mobile/asn1c/ must not be edited, so the limit is disabled
 * here (and in ngap.c) only for ASan builds: release keeps the guard
 * because MMT_BUILD_ASAN is defined solely by BUILD=asan.
 */
static const asn_codec_ctx_t _aper_codec_ctx_storage = { 0 };

static inline const asn_codec_ctx_t * _aper_codec_ctx( void ){
#if defined(MMT_BUILD_ASAN)
	return &_aper_codec_ctx_storage;
#else
	return NULL;
#endif
}

int s1ap_decode(s1ap_message_t *message, const uint8_t * const buffer,
		const uint32_t length)
{
	S1AP_PDU_t *pdu_p = NULL;
	asn_dec_rval_t dec_ret;

	if (message == NULL) {
		fprintf(stderr, "[S1AP] NULL output message pointer\n");
		return -1;
	}

	if( length == 0 )
		return 0;

	/* F-SEC-011 (issue #214): a NULL buffer with a nonzero length is
	 * rejected unconditionally — aper_decode() would dereference it. */
	if (buffer == NULL) {
		fprintf(stderr, "[S1AP] NULL input buffer\n");
		return -1;
	}

	dec_ret = aper_decode(_aper_codec_ctx(),
			&asn_DEF_S1AP_PDU,
			(void **)&pdu_p,
			buffer,
			length,
			0,
			0);

	if (dec_ret.code != RC_OK) {
		fprintf(stderr, "[S1AP] Failed to decode S1AP, code %d, consumed: %zu\n", dec_ret.code, dec_ret.consumed);
		/* aper_decode leaves the partially-decoded tree in pdu_p — free it
		 * here or every malformed S1AP packet leaks it (F-BUG-078).
		 * ASN_STRUCT_FREE is NULL-safe. */
		ASN_STRUCT_FREE( asn_DEF_S1AP_PDU, pdu_p );
		return -1;
	}

	message->pdu_present = pdu_p->present;
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
