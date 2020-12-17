/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_TraceDepth_H_
#define	_NGAP_TraceDepth_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_TraceDepth {
	NGAP_TraceDepth_minimum	= 0,
	NGAP_TraceDepth_medium	= 1,
	NGAP_TraceDepth_maximum	= 2,
	NGAP_TraceDepth_minimumWithoutVendorSpecificExtension	= 3,
	NGAP_TraceDepth_mediumWithoutVendorSpecificExtension	= 4,
	NGAP_TraceDepth_maximumWithoutVendorSpecificExtension	= 5
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_TraceDepth;

/* NGAP_TraceDepth */
typedef long	 NGAP_TraceDepth_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_TraceDepth_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_TraceDepth;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_TraceDepth_specs_1;
asn_struct_free_f NGAP_TraceDepth_free;
asn_struct_print_f NGAP_TraceDepth_print;
asn_constr_check_f NGAP_TraceDepth_constraint;
ber_type_decoder_f NGAP_TraceDepth_decode_ber;
der_type_encoder_f NGAP_TraceDepth_encode_der;
xer_type_decoder_f NGAP_TraceDepth_decode_xer;
xer_type_encoder_f NGAP_TraceDepth_encode_xer;
oer_type_decoder_f NGAP_TraceDepth_decode_oer;
oer_type_encoder_f NGAP_TraceDepth_encode_oer;
per_type_decoder_f NGAP_TraceDepth_decode_uper;
per_type_encoder_f NGAP_TraceDepth_encode_uper;
per_type_decoder_f NGAP_TraceDepth_decode_aper;
per_type_encoder_f NGAP_TraceDepth_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_TraceDepth_H_ */
#include <asn_internal.h>
