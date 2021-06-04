/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_AdditionalQosFlowInformation_H_
#define	_NGAP_AdditionalQosFlowInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_AdditionalQosFlowInformation {
	NGAP_AdditionalQosFlowInformation_more_likely	= 0
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_AdditionalQosFlowInformation;

/* NGAP_AdditionalQosFlowInformation */
typedef long	 NGAP_AdditionalQosFlowInformation_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_AdditionalQosFlowInformation_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_AdditionalQosFlowInformation;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_AdditionalQosFlowInformation_specs_1;
asn_struct_free_f NGAP_AdditionalQosFlowInformation_free;
asn_struct_print_f NGAP_AdditionalQosFlowInformation_print;
asn_constr_check_f NGAP_AdditionalQosFlowInformation_constraint;
ber_type_decoder_f NGAP_AdditionalQosFlowInformation_decode_ber;
der_type_encoder_f NGAP_AdditionalQosFlowInformation_encode_der;
xer_type_decoder_f NGAP_AdditionalQosFlowInformation_decode_xer;
xer_type_encoder_f NGAP_AdditionalQosFlowInformation_encode_xer;
oer_type_decoder_f NGAP_AdditionalQosFlowInformation_decode_oer;
oer_type_encoder_f NGAP_AdditionalQosFlowInformation_encode_oer;
per_type_decoder_f NGAP_AdditionalQosFlowInformation_decode_uper;
per_type_encoder_f NGAP_AdditionalQosFlowInformation_encode_uper;
per_type_decoder_f NGAP_AdditionalQosFlowInformation_decode_aper;
per_type_encoder_f NGAP_AdditionalQosFlowInformation_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_AdditionalQosFlowInformation_H_ */
#include <asn_internal.h>