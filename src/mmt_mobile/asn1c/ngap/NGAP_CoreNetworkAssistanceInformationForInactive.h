/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_CoreNetworkAssistanceInformationForInactive_H_
#define	_NGAP_CoreNetworkAssistanceInformationForInactive_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_UEIdentityIndexValue.h"
#include "NGAP_PagingDRX.h"
#include "NGAP_PeriodicRegistrationUpdateTimer.h"
#include "NGAP_MICOModeIndication.h"
#include "NGAP_TAIListForInactive.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ExpectedUEBehaviour;
struct NGAP_ProtocolExtensionContainer;

/* NGAP_CoreNetworkAssistanceInformationForInactive */
typedef struct NGAP_CoreNetworkAssistanceInformationForInactive {
	NGAP_UEIdentityIndexValue_t	 uEIdentityIndexValue;
	NGAP_PagingDRX_t	*uESpecificDRX;	/* OPTIONAL */
	NGAP_PeriodicRegistrationUpdateTimer_t	 periodicRegistrationUpdateTimer;
	NGAP_MICOModeIndication_t	*mICOModeIndication;	/* OPTIONAL */
	NGAP_TAIListForInactive_t	 tAIListForInactive;
	struct NGAP_ExpectedUEBehaviour	*expectedUEBehaviour;	/* OPTIONAL */
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_CoreNetworkAssistanceInformationForInactive_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_CoreNetworkAssistanceInformationForInactive;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NGAP_ExpectedUEBehaviour.h"
#include "NGAP_ProtocolExtensionContainer.h"

#endif	/* _NGAP_CoreNetworkAssistanceInformationForInactive_H_ */
#include <asn_internal.h>
