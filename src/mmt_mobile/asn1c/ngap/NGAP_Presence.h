/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-CommonDataTypes"
 * 	found in "./support/ngap-r15.2.0/Common-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_Presence_H_
#define	_NGAP_Presence_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_Presence {
	NGAP_Presence_optional	= 0,
	NGAP_Presence_conditional	= 1,
	NGAP_Presence_mandatory	= 2
} e_NGAP_Presence;

/* NGAP_Presence */
typedef long	 NGAP_Presence_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_Presence_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_Presence;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_Presence_specs_1;
asn_struct_free_f NGAP_Presence_free;
asn_struct_print_f NGAP_Presence_print;
asn_constr_check_f NGAP_Presence_constraint;
ber_type_decoder_f NGAP_Presence_decode_ber;
der_type_encoder_f NGAP_Presence_encode_der;
xer_type_decoder_f NGAP_Presence_decode_xer;
xer_type_encoder_f NGAP_Presence_encode_xer;
oer_type_decoder_f NGAP_Presence_decode_oer;
oer_type_encoder_f NGAP_Presence_encode_oer;
per_type_decoder_f NGAP_Presence_decode_uper;
per_type_encoder_f NGAP_Presence_encode_uper;
per_type_decoder_f NGAP_Presence_decode_aper;
per_type_encoder_f NGAP_Presence_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_Presence_H_ */
#include <asn_internal.h>
