/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_SecondaryRATDataUsageReportTransfer_H_
#define	_NGAP_SecondaryRATDataUsageReportTransfer_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_SecondaryRATUsageInformation;
struct NGAP_ProtocolExtensionContainer;

/* NGAP_SecondaryRATDataUsageReportTransfer */
typedef struct NGAP_SecondaryRATDataUsageReportTransfer {
	struct NGAP_SecondaryRATUsageInformation	*secondaryRATUsageInformation;	/* OPTIONAL */
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_SecondaryRATDataUsageReportTransfer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_SecondaryRATDataUsageReportTransfer;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NGAP_SecondaryRATUsageInformation.h"
#include "NGAP_ProtocolExtensionContainer.h"

#endif	/* _NGAP_SecondaryRATDataUsageReportTransfer_H_ */
#include <asn_internal.h>
