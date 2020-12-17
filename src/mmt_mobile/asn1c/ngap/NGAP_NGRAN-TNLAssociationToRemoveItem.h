/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_NGRAN_TNLAssociationToRemoveItem_H_
#define	_NGAP_NGRAN_TNLAssociationToRemoveItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_CPTransportLayerInformation.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_CPTransportLayerInformation;
struct NGAP_ProtocolExtensionContainer;

/* NGAP_NGRAN-TNLAssociationToRemoveItem */
typedef struct NGAP_NGRAN_TNLAssociationToRemoveItem {
	NGAP_CPTransportLayerInformation_t	 tNLAssociationTransportLayerAddress;
	struct NGAP_CPTransportLayerInformation	*tNLAssociationTransportLayerAddressAMF;	/* OPTIONAL */
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_NGRAN_TNLAssociationToRemoveItem_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_NGRAN_TNLAssociationToRemoveItem;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_NGRAN_TNLAssociationToRemoveItem_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_NGRAN_TNLAssociationToRemoveItem_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NGAP_CPTransportLayerInformation.h"
#include "NGAP_ProtocolExtensionContainer.h"

#endif	/* _NGAP_NGRAN_TNLAssociationToRemoveItem_H_ */
#include <asn_internal.h>
