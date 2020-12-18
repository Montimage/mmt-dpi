/*
 * proto_ngap.h
 *
 *  Created on: Dec 11, 2020
 *      Author: nhnghia
 */

#ifndef SRC_MMT_MOBILE_INCLUDE_PROTO_NGAP_H_
#define SRC_MMT_MOBILE_INCLUDE_PROTO_NGAP_H_

enum {
	NGAP_ATT_PROCEDURE_CODE = 1,
	NGAP_ATT_PDU_PRESENT,
	NGAP_ATT_AMF_UE_ID,
	NGAP_ATT_RAN_UE_ID,
};

#define NGAP_PROCEDURE_CODE_ALIAS "procedure_code"
#define NGAP_PDU_PRESENT_ALIAS    "pdu_present"
#define NGAP_AMF_UE_ID_ALIAS      "amf_ue_id"
#define NGAP_RAN_UE_ID_ALIAS      "ran_ue_id"

#endif /* SRC_MMT_MOBILE_INCLUDE_PROTO_NGAP_H_ */
