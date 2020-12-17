/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "./support/s1ap-r10.5.0/S1AP-IEs.asn"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -fno-include-deps -no-gen-example`
 */

#ifndef	_S1ap_ServedGUMMEIsItem_H_
#define	_S1ap_ServedGUMMEIsItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include "S1ap-ServedPLMNs.h"
#include "S1ap-ServedGroupIDs.h"
#include "S1ap-ServedMMECs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct S1ap_IE_Extensions;

/* S1ap-ServedGUMMEIsItem */
typedef struct S1ap_ServedGUMMEIsItem {
	S1ap_ServedPLMNs_t	 servedPLMNs;
	S1ap_ServedGroupIDs_t	 servedGroupIDs;
	S1ap_ServedMMECs_t	 servedMMECs;
	struct S1ap_IE_Extensions	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} S1ap_ServedGUMMEIsItem_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_S1ap_ServedGUMMEIsItem;
extern asn_SEQUENCE_specifics_t asn_SPC_S1ap_ServedGUMMEIsItem_specs_1;
extern asn_TYPE_member_t asn_MBR_S1ap_ServedGUMMEIsItem_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _S1ap_ServedGUMMEIsItem_H_ */
#include <asn_internal.h>
