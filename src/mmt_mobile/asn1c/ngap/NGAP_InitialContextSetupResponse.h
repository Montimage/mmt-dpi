/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-PDU-Contents"
 * 	found in "./support/ngap-r15.2.0/PDU-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_InitialContextSetupResponse_H_
#define	_NGAP_InitialContextSetupResponse_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_ProtocolIE-Container.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NGAP_InitialContextSetupResponse */
typedef struct NGAP_InitialContextSetupResponse {
	NGAP_ProtocolIE_Container_124P12_t	 protocolIEs;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_InitialContextSetupResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_InitialContextSetupResponse;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_InitialContextSetupResponse_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_InitialContextSetupResponse_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_InitialContextSetupResponse_H_ */
#include <asn_internal.h>
