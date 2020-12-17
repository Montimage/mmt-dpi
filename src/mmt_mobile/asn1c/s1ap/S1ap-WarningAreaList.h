/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "./support/s1ap-r10.5.0/S1AP-IEs.asn"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -fno-include-deps -no-gen-example`
 */

#ifndef	_S1ap_WarningAreaList_H_
#define	_S1ap_WarningAreaList_H_


#include <asn_application.h>

/* Including external dependencies */
#include "S1ap-ECGIList.h"
#include "S1ap-TAIListforWarning.h"
#include "S1ap-EmergencyAreaIDList.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum S1ap_WarningAreaList_PR {
	S1ap_WarningAreaList_PR_NOTHING,	/* No components present */
	S1ap_WarningAreaList_PR_cellIDList,
	S1ap_WarningAreaList_PR_trackingAreaListforWarning,
	S1ap_WarningAreaList_PR_emergencyAreaIDList
	/* Extensions may appear below */
	
} S1ap_WarningAreaList_PR;

/* S1ap-WarningAreaList */
typedef struct S1ap_WarningAreaList {
	S1ap_WarningAreaList_PR present;
	union S1ap_WarningAreaList_u {
		S1ap_ECGIList_t	 cellIDList;
		S1ap_TAIListforWarning_t	 trackingAreaListforWarning;
		S1ap_EmergencyAreaIDList_t	 emergencyAreaIDList;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} S1ap_WarningAreaList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_S1ap_WarningAreaList;

#ifdef __cplusplus
}
#endif

#endif	/* _S1ap_WarningAreaList_H_ */
#include <asn_internal.h>
