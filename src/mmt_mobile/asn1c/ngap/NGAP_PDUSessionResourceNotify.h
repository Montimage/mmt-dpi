/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-PDU-Contents"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_PDUSessionResourceNotify_H_
#define	_NGAP_PDUSessionResourceNotify_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_ProtocolIE-Container.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NGAP_PDUSessionResourceNotify */
typedef struct NGAP_PDUSessionResourceNotify {
	NGAP_ProtocolIE_Container_6976P6_t	 protocolIEs;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_PDUSessionResourceNotify_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_PDUSessionResourceNotify;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_PDUSessionResourceNotify_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_PDUSessionResourceNotify_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_PDUSessionResourceNotify_H_ */
#include <asn_internal.h>
