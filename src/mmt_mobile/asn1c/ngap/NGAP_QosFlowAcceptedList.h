/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_QosFlowAcceptedList_H_
#define	_NGAP_QosFlowAcceptedList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_QosFlowAcceptedItem;

/* NGAP_QosFlowAcceptedList */
typedef struct NGAP_QosFlowAcceptedList {
	A_SEQUENCE_OF(struct NGAP_QosFlowAcceptedItem) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_QosFlowAcceptedList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_QosFlowAcceptedList;
extern asn_SET_OF_specifics_t asn_SPC_NGAP_QosFlowAcceptedList_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_QosFlowAcceptedList_1[1];
extern asn_per_constraints_t asn_PER_type_NGAP_QosFlowAcceptedList_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NGAP_QosFlowAcceptedItem.h"

#endif	/* _NGAP_QosFlowAcceptedList_H_ */
#include <asn_internal.h>
