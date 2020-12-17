/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_EPS_TAI_H_
#define	_NGAP_EPS_TAI_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_PLMNIdentity.h"
#include "NGAP_EPS-TAC.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_EPS-TAI */
typedef struct NGAP_EPS_TAI {
	NGAP_PLMNIdentity_t	 pLMNIdentity;
	NGAP_EPS_TAC_t	 ePS_TAC;
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_EPS_TAI_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_EPS_TAI;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_EPS_TAI_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_EPS_TAI_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_EPS_TAI_H_ */
#include <asn_internal.h>
