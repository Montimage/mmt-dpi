/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_EmergencyServiceTargetCN_H_
#define	_NGAP_EmergencyServiceTargetCN_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_EmergencyServiceTargetCN {
	NGAP_EmergencyServiceTargetCN_fiveGC	= 0,
	NGAP_EmergencyServiceTargetCN_epc	= 1
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_EmergencyServiceTargetCN;

/* NGAP_EmergencyServiceTargetCN */
typedef long	 NGAP_EmergencyServiceTargetCN_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_EmergencyServiceTargetCN_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_EmergencyServiceTargetCN;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_EmergencyServiceTargetCN_specs_1;
asn_struct_free_f NGAP_EmergencyServiceTargetCN_free;
asn_struct_print_f NGAP_EmergencyServiceTargetCN_print;
asn_constr_check_f NGAP_EmergencyServiceTargetCN_constraint;
ber_type_decoder_f NGAP_EmergencyServiceTargetCN_decode_ber;
der_type_encoder_f NGAP_EmergencyServiceTargetCN_encode_der;
xer_type_decoder_f NGAP_EmergencyServiceTargetCN_decode_xer;
xer_type_encoder_f NGAP_EmergencyServiceTargetCN_encode_xer;
oer_type_decoder_f NGAP_EmergencyServiceTargetCN_decode_oer;
oer_type_encoder_f NGAP_EmergencyServiceTargetCN_encode_oer;
per_type_decoder_f NGAP_EmergencyServiceTargetCN_decode_uper;
per_type_encoder_f NGAP_EmergencyServiceTargetCN_encode_uper;
per_type_decoder_f NGAP_EmergencyServiceTargetCN_decode_aper;
per_type_encoder_f NGAP_EmergencyServiceTargetCN_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_EmergencyServiceTargetCN_H_ */
#include <asn_internal.h>
