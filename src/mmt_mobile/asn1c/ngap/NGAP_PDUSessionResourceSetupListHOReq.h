/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_PDUSessionResourceSetupListHOReq_H_
#define	_NGAP_PDUSessionResourceSetupListHOReq_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_PDUSessionResourceSetupItemHOReq;

/* NGAP_PDUSessionResourceSetupListHOReq */
typedef struct NGAP_PDUSessionResourceSetupListHOReq {
	A_SEQUENCE_OF(struct NGAP_PDUSessionResourceSetupItemHOReq) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_PDUSessionResourceSetupListHOReq_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_PDUSessionResourceSetupListHOReq;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NGAP_PDUSessionResourceSetupItemHOReq.h"

#endif	/* _NGAP_PDUSessionResourceSetupListHOReq_H_ */
#include <asn_internal.h>
