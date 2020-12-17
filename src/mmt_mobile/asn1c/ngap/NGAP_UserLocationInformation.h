/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_UserLocationInformation_H_
#define	_NGAP_UserLocationInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_UserLocationInformation_PR {
	NGAP_UserLocationInformation_PR_NOTHING,	/* No components present */
	NGAP_UserLocationInformation_PR_userLocationInformationEUTRA,
	NGAP_UserLocationInformation_PR_userLocationInformationNR,
	NGAP_UserLocationInformation_PR_userLocationInformationN3IWF,
	NGAP_UserLocationInformation_PR_choice_Extensions
} NGAP_UserLocationInformation_PR;

/* Forward declarations */
struct NGAP_UserLocationInformationEUTRA;
struct NGAP_UserLocationInformationNR;
struct NGAP_UserLocationInformationN3IWF;
struct NGAP_ProtocolIE_SingleContainer;

/* NGAP_UserLocationInformation */
typedef struct NGAP_UserLocationInformation {
	NGAP_UserLocationInformation_PR present;
	union NGAP_UserLocationInformation_u {
		struct NGAP_UserLocationInformationEUTRA	*userLocationInformationEUTRA;
		struct NGAP_UserLocationInformationNR	*userLocationInformationNR;
		struct NGAP_UserLocationInformationN3IWF	*userLocationInformationN3IWF;
		struct NGAP_ProtocolIE_SingleContainer	*choice_Extensions;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_UserLocationInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_UserLocationInformation;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NGAP_UserLocationInformationEUTRA.h"
#include "NGAP_UserLocationInformationNR.h"
#include "NGAP_UserLocationInformationN3IWF.h"
#include "NGAP_ProtocolIE-SingleContainer.h"

#endif	/* _NGAP_UserLocationInformation_H_ */
#include <asn_internal.h>
