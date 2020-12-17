/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_ExpectedHOInterval_H_
#define	_NGAP_ExpectedHOInterval_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_ExpectedHOInterval {
	NGAP_ExpectedHOInterval_sec15	= 0,
	NGAP_ExpectedHOInterval_sec30	= 1,
	NGAP_ExpectedHOInterval_sec60	= 2,
	NGAP_ExpectedHOInterval_sec90	= 3,
	NGAP_ExpectedHOInterval_sec120	= 4,
	NGAP_ExpectedHOInterval_sec180	= 5,
	NGAP_ExpectedHOInterval_long_time	= 6
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_ExpectedHOInterval;

/* NGAP_ExpectedHOInterval */
typedef long	 NGAP_ExpectedHOInterval_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_ExpectedHOInterval_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_ExpectedHOInterval;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_ExpectedHOInterval_specs_1;
asn_struct_free_f NGAP_ExpectedHOInterval_free;
asn_struct_print_f NGAP_ExpectedHOInterval_print;
asn_constr_check_f NGAP_ExpectedHOInterval_constraint;
ber_type_decoder_f NGAP_ExpectedHOInterval_decode_ber;
der_type_encoder_f NGAP_ExpectedHOInterval_encode_der;
xer_type_decoder_f NGAP_ExpectedHOInterval_decode_xer;
xer_type_encoder_f NGAP_ExpectedHOInterval_encode_xer;
oer_type_decoder_f NGAP_ExpectedHOInterval_decode_oer;
oer_type_encoder_f NGAP_ExpectedHOInterval_encode_oer;
per_type_decoder_f NGAP_ExpectedHOInterval_decode_uper;
per_type_encoder_f NGAP_ExpectedHOInterval_encode_uper;
per_type_decoder_f NGAP_ExpectedHOInterval_decode_aper;
per_type_encoder_f NGAP_ExpectedHOInterval_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_ExpectedHOInterval_H_ */
#include <asn_internal.h>
