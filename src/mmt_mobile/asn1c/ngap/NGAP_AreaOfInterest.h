/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_AreaOfInterest_H_
#define	_NGAP_AreaOfInterest_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_AreaOfInterestTAIList;
struct NGAP_AreaOfInterestCellList;
struct NGAP_AreaOfInterestRANNodeList;
struct NGAP_ProtocolExtensionContainer;

/* NGAP_AreaOfInterest */
typedef struct NGAP_AreaOfInterest {
	struct NGAP_AreaOfInterestTAIList	*areaOfInterestTAIList;	/* OPTIONAL */
	struct NGAP_AreaOfInterestCellList	*areaOfInterestCellList;	/* OPTIONAL */
	struct NGAP_AreaOfInterestRANNodeList	*areaOfInterestRANNodeList;	/* OPTIONAL */
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_AreaOfInterest_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_AreaOfInterest;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_AreaOfInterest_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_AreaOfInterest_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_AreaOfInterest_H_ */
#include <asn_internal.h>
