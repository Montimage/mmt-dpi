/*
 * s1ap_common.c
 *
 *  Created on: Nov 6, 2018
 *      Author: nhnghia
 */

#include <stdlib.h>
#include "mmt_core.h"
#include "s1ap_common.h"
#include "nas/emm/nas_emm_attach_request.h"

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


			//TODO extract IP from NAS PDU
			//s1apERABToBeSetupItemCtxtSUReq_p->nAS_PDU;

			decoded += tempDecoded;
			XER_FPRINT( &asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, s1apERABToBeSetupItemCtxtSUReq_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, s1apERABToBeSetupItemCtxtSUReq_p);
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
	S1ap_InitialContextSetupRequest_t  s1ap_InitialContextSetupRequest;
	S1ap_InitialContextSetupRequest_t *s1ap_InitialContextSetupRequest_p = &s1ap_InitialContextSetupRequest;
	int i, decoded = 0;
	int tempDecoded = 0;
	assert(any_p != NULL);

	S1AP_DEBUG("Decoding message S1ap_InitialContextSetupRequestIEs (%s:%d)\n", __FILE__, __LINE__);

	ANY_to_type_aper(any_p, &asn_DEF_S1ap_InitialContextSetupRequest, (void**)&s1ap_InitialContextSetupRequest_p);

	for (i = 0; i < s1ap_InitialContextSetupRequest_p->s1ap_InitialContextSetupRequest_ies.list.count; i++) {
		S1ap_IE_t *ie_p;
		ie_p = s1ap_InitialContextSetupRequest_p->s1ap_InitialContextSetupRequest_ies.list.array[i];
		switch(ie_p->id) {
		case S1ap_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq:
		{
			S1ap_E_RABToBeSetupListCtxtSUReq_t *s1apERABToBeSetupListCtxtSUReq_p = NULL;
			tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, (void**)&s1apERABToBeSetupListCtxtSUReq_p);
			if (tempDecoded < 0 || s1apERABToBeSetupListCtxtSUReq_p == NULL) {
				S1AP_ERROR("Decoding of IE e_RABToBeSetupListCtxtSUReq failed\n");
				if (s1apERABToBeSetupListCtxtSUReq_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, s1apERABToBeSetupListCtxtSUReq_p);
				return -1;
			}
			if (_s1ap_decode_e_rabtobesetuplistctxtsureq(message, s1apERABToBeSetupListCtxtSUReq_p) < 0) {
				S1AP_ERROR("Decoding of encapsulated IE s1apERABToBeSetupListCtxtSUReq failed\n");
			}

			decoded += tempDecoded;
			XER_FPRINT(&asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, s1apERABToBeSetupListCtxtSUReq_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, s1apERABToBeSetupListCtxtSUReq_p);
		}
		break;

		}
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
            }
            break;
            default:
                S1AP_ERROR("Unknown protocol IE id (%d) for message s1ap_uplinkueassociatedlppatransport_ies\n", (int)ie_p->id);
                return -1;
        }
    }
    return decoded;
}


static inline int _decode_s1ap_initialContextSetupResponse(
		s1ap_message_t *message,
		ANY_t *any_p) {

    S1ap_InitialContextSetupResponse_t  s1ap_InitialContextSetupResponse;
    S1ap_InitialContextSetupResponse_t *s1ap_InitialContextSetupResponse_p = &s1ap_InitialContextSetupResponse;
    int i, decoded = 0;
    int tempDecoded = 0;
    assert(any_p != NULL);

    S1AP_DEBUG("Decoding message S1ap_InitialContextSetupResponseIEs (%s:%d)\n", __FILE__, __LINE__);

    ANY_to_type_aper(any_p, &asn_DEF_S1ap_InitialContextSetupResponse, (void**)&s1ap_InitialContextSetupResponse_p);

    for (i = 0; i < s1ap_InitialContextSetupResponse_p->s1ap_InitialContextSetupResponse_ies.list.count; i++) {
        S1ap_IE_t *ie_p;
        ie_p = s1ap_InitialContextSetupResponse_p->s1ap_InitialContextSetupResponse_ies.list.array[i];
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
    return decoded;
}

static inline int _decode_s1ap_initialuemessageies(
		s1ap_message_t *message,
		ANY_t *any_p) {

	S1ap_InitialUEMessage_t  s1ap_InitialUEMessage;
	S1ap_InitialUEMessage_t *s1ap_InitialUEMessage_p = &s1ap_InitialUEMessage;
	int i, decoded = 0;
	int tempDecoded = 0;
	assert(any_p != NULL);

	S1AP_DEBUG("Decoding message S1ap_InitialUEMessageIEs (%s:%d)\n", __FILE__, __LINE__);

	ANY_to_type_aper(any_p, &asn_DEF_S1ap_InitialUEMessage, (void**)&s1ap_InitialUEMessage_p);

	for (i = 0; i < s1ap_InitialUEMessage_p->s1ap_InitialUEMessage_ies.list.count; i++) {
		S1ap_IE_t *ie_p;
		ie_p = s1ap_InitialUEMessage_p->s1ap_InitialUEMessage_ies.list.array[i];
		switch(ie_p->id) {
		case S1ap_ProtocolIE_ID_id_NAS_PDU:
		{
			S1ap_NAS_PDU_t *s1apNASPDU_p = NULL;
			tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_NAS_PDU, (void**)&s1apNASPDU_p);
			if (tempDecoded < 0 || s1apNASPDU_p == NULL) {
				S1AP_ERROR("Decoding of IE nas_pdu failed\n");
				if (s1apNASPDU_p)
					ASN_STRUCT_FREE(asn_DEF_S1ap_NAS_PDU, s1apNASPDU_p);
				return -1;
			}
			decoded += tempDecoded;

			nas_emm_attach_request_msg_t  m;
			memset( &m, 0, sizeof( m ) );
			//we can get IMSI
			if( nas_decode_emm_attach_request( &m, s1apNASPDU_p->buf, s1apNASPDU_p->size ) > 0 ){

				//imsi.digitX are numbers
				//=> we convert them to char, e.g., 7 => '7'
				message->imsi[0] = '0' + m.old_guti_or_imsi.imsi.digit1;
				message->imsi[1] = '0' + m.old_guti_or_imsi.imsi.digit2;
				message->imsi[2] = '0' + m.old_guti_or_imsi.imsi.digit3;
				message->imsi[3] = '0' + m.old_guti_or_imsi.imsi.digit4;
				message->imsi[4] = '0' + m.old_guti_or_imsi.imsi.digit5;
				message->imsi[5] = '0' + m.old_guti_or_imsi.imsi.digit6;
				message->imsi[6] = '0' + m.old_guti_or_imsi.imsi.digit7;
				message->imsi[7] = '0' + m.old_guti_or_imsi.imsi.digit8;
				message->imsi[8] = '0' + m.old_guti_or_imsi.imsi.digit9;
				message->imsi[9] = '0' + m.old_guti_or_imsi.imsi.digit10;
				message->imsi[10] ='0' + m.old_guti_or_imsi.imsi.digit11;
				message->imsi[11] ='0' + m.old_guti_or_imsi.imsi.digit12;
				message->imsi[12] ='0' + m.old_guti_or_imsi.imsi.digit13;
				message->imsi[13] ='0' + m.old_guti_or_imsi.imsi.digit14;
				message->imsi[14] ='0' + m.old_guti_or_imsi.imsi.digit15;
				//printf("Got IMSI: %.*s\n", 15, message->imsi );

			}

			XER_FPRINT(&asn_DEF_S1ap_NAS_PDU, s1apNASPDU_p);
			ASN_STRUCT_FREE(asn_DEF_S1ap_NAS_PDU, s1apNASPDU_p);
		}
		break;
		}
	}
	return decoded;
}


static inline int _decode_s1ap_S1SetupRequest(
    s1ap_message_t *message,
    ANY_t *any_p) {

    S1ap_S1SetupRequest_t  s1ap_S1SetupRequest;
    S1ap_S1SetupRequest_t *s1ap_S1SetupRequest_p = &s1ap_S1SetupRequest;
    int i, decoded = 0;
    int tempDecoded = 0;

    assert(any_p != NULL);

    S1AP_DEBUG("Decoding message S1ap_S1SetupRequestIEs (%s:%d)\n", __FILE__, __LINE__);

    ANY_to_type_aper(any_p, &asn_DEF_S1ap_S1SetupRequest, (void**)&s1ap_S1SetupRequest_p);

    for (i = 0; i < s1ap_S1SetupRequest_p->s1ap_S1SetupRequest_ies.list.count; i++) {
        S1ap_IE_t *ie_p;
        ie_p = s1ap_S1SetupRequest_p->s1ap_S1SetupRequest_ies.list.array[i];
        switch(ie_p->id) {
            case S1ap_ProtocolIE_ID_id_eNBname:
            {
                S1ap_ENBname_t *s1apENBname_p = NULL;

                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_S1ap_ENBname, (void**)&s1apENBname_p);
                if (tempDecoded < 0 || s1apENBname_p == NULL) {
                    S1AP_ERROR("Decoding of IE eNBname failed\n");
                    if (s1apENBname_p)
                        ASN_STRUCT_FREE(asn_DEF_S1ap_ENBname, s1apENBname_p);
                    return -1;
                }

                //HN: here we got eNodeB's name
                message->enb_name.len = s1apENBname_p->size;
                message->enb_name.ptr = (char *)s1apENBname_p->buf;

                S1AP_DEBUG("ENB name: %.*s\n", s1apENBname_p->size, message->enb_name.ptr );

                decoded += tempDecoded;

                XER_FPRINT( &asn_DEF_S1ap_ENBname, s1apENBname_p);
				ASN_STRUCT_FREE(asn_DEF_S1ap_ENBname, s1apENBname_p);
            } break;
        }
    }
    return decoded;
}

static inline int _decode_s1ap_S1SetupResponse(
    s1ap_message_t *message,
    ANY_t *any_p) {
	 S1ap_S1SetupResponse_t  s1ap_S1SetupResponse;
	    S1ap_S1SetupResponse_t *s1ap_S1SetupResponse_p = &s1ap_S1SetupResponse;
	    int i, decoded = 0;
	    int tempDecoded = 0;
	    assert(any_p != NULL);

	    S1AP_DEBUG("Decoding message S1ap_S1SetupResponseIEs (%s:%d)\n", __FILE__, __LINE__);

	    ANY_to_type_aper(any_p, &asn_DEF_S1ap_S1SetupResponse, (void**)&s1ap_S1SetupResponse_p);

	    for (i = 0; i < s1ap_S1SetupResponse_p->s1ap_S1SetupResponse_ies.list.count; i++) {
	        S1ap_IE_t *ie_p;
	        ie_p = s1ap_S1SetupResponse_p->s1ap_S1SetupResponse_ies.list.array[i];
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
	                    return -1;
	                }
	                decoded += tempDecoded;
	                XER_FPRINT(&asn_DEF_S1ap_MMEname, s1apMMEname_p);

	                //HN: Here we can get MME's name
	                message->mme_name.len = s1apMMEname_p->size;
	                message->mme_name.ptr = (char *)s1apMMEname_p->buf;

	                if (s1apMMEname_p)
	                	ASN_STRUCT_FREE(asn_DEF_S1ap_MMEname, s1apMMEname_p);
	            }
	            break;
	        }
	    }
	    return decoded;
}

static int _decode_s1ap_initiatingMessage(s1ap_message_t *message,
		S1ap_InitiatingMessage_t *initiating_p){
	int ret = -1;

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
	int ret = -1;

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
	S1AP_PDU_t  pdu;
	S1AP_PDU_t *pdu_p = &pdu;
	asn_dec_rval_t dec_ret;

	assert(message != NULL);

	memset((void *)message, 0, sizeof(s1ap_message_t));

	memset((void *)pdu_p, 0, sizeof(S1AP_PDU_t));


	dec_ret = aper_decode(NULL,
			&asn_DEF_S1AP_PDU,
			(void **)&pdu_p,
			buffer,
			length,
			0,
			0);

	if (dec_ret.code != RC_OK) {
		log_err("Failed to decode pdu");
		return -1;
	}

	return 0;


	switch(pdu_p->present) {
	case S1AP_PDU_PR_initiatingMessage:
		return _decode_s1ap_initiatingMessage(message,
				&pdu_p->choice.initiatingMessage);
	case S1AP_PDU_PR_successfulOutcome:
		return _decode_s1ap_successfulOutcomeMessage(message,
						&pdu_p->choice.successfulOutcome);
	case S1AP_PDU_PR_unsuccessfulOutcome:
		break;
	default:
		debug("Unknown presence (%d) or not implemented", (int)pdu_p->present);
		break;
	}

	return 0;
}
