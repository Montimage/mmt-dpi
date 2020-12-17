/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_PagingAttemptInformation_H_
#define	_NGAP_PagingAttemptInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_PagingAttemptCount.h"
#include "NGAP_IntendedNumberOfPagingAttempts.h"
#include "NGAP_NextPagingAreaScope.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_PagingAttemptInformation */
typedef struct NGAP_PagingAttemptInformation {
	NGAP_PagingAttemptCount_t	 pagingAttemptCount;
	NGAP_IntendedNumberOfPagingAttempts_t	 intendedNumberOfPagingAttempts;
	NGAP_NextPagingAreaScope_t	*nextPagingAreaScope;	/* OPTIONAL */
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_PagingAttemptInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_PagingAttemptInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_PagingAttemptInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_PagingAttemptInformation_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_PagingAttemptInformation_H_ */
#include <asn_internal.h>
