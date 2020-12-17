/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_LastVisitedCellInformation_H_
#define	_NGAP_LastVisitedCellInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_LastVisitedEUTRANCellInformation.h"
#include "NGAP_LastVisitedUTRANCellInformation.h"
#include "NGAP_LastVisitedGERANCellInformation.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_LastVisitedCellInformation_PR {
	NGAP_LastVisitedCellInformation_PR_NOTHING,	/* No components present */
	NGAP_LastVisitedCellInformation_PR_nGRANCell,
	NGAP_LastVisitedCellInformation_PR_eUTRANCell,
	NGAP_LastVisitedCellInformation_PR_uTRANCell,
	NGAP_LastVisitedCellInformation_PR_gERANCell,
	NGAP_LastVisitedCellInformation_PR_choice_Extensions
} NGAP_LastVisitedCellInformation_PR;

/* Forward declarations */
struct NGAP_LastVisitedNGRANCellInformation;
struct NGAP_ProtocolIE_SingleContainer;

/* NGAP_LastVisitedCellInformation */
typedef struct NGAP_LastVisitedCellInformation {
	NGAP_LastVisitedCellInformation_PR present;
	union NGAP_LastVisitedCellInformation_u {
		struct NGAP_LastVisitedNGRANCellInformation	*nGRANCell;
		NGAP_LastVisitedEUTRANCellInformation_t	 eUTRANCell;
		NGAP_LastVisitedUTRANCellInformation_t	 uTRANCell;
		NGAP_LastVisitedGERANCellInformation_t	 gERANCell;
		struct NGAP_ProtocolIE_SingleContainer	*choice_Extensions;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_LastVisitedCellInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_LastVisitedCellInformation;
extern asn_CHOICE_specifics_t asn_SPC_NGAP_LastVisitedCellInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_LastVisitedCellInformation_1[5];
extern asn_per_constraints_t asn_PER_type_NGAP_LastVisitedCellInformation_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NGAP_LastVisitedNGRANCellInformation.h"
#include "NGAP_ProtocolIE-SingleContainer.h"

#endif	/* _NGAP_LastVisitedCellInformation_H_ */
#include <asn_internal.h>
