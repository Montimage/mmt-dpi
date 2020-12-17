/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_CauseProtocol_H_
#define	_NGAP_CauseProtocol_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_CauseProtocol {
	NGAP_CauseProtocol_transfer_syntax_error	= 0,
	NGAP_CauseProtocol_abstract_syntax_error_reject	= 1,
	NGAP_CauseProtocol_abstract_syntax_error_ignore_and_notify	= 2,
	NGAP_CauseProtocol_message_not_compatible_with_receiver_state	= 3,
	NGAP_CauseProtocol_semantic_error	= 4,
	NGAP_CauseProtocol_abstract_syntax_error_falsely_constructed_message	= 5,
	NGAP_CauseProtocol_unspecified	= 6
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_CauseProtocol;

/* NGAP_CauseProtocol */
typedef long	 NGAP_CauseProtocol_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_CauseProtocol_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_CauseProtocol;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_CauseProtocol_specs_1;
asn_struct_free_f NGAP_CauseProtocol_free;
asn_struct_print_f NGAP_CauseProtocol_print;
asn_constr_check_f NGAP_CauseProtocol_constraint;
ber_type_decoder_f NGAP_CauseProtocol_decode_ber;
der_type_encoder_f NGAP_CauseProtocol_encode_der;
xer_type_decoder_f NGAP_CauseProtocol_decode_xer;
xer_type_encoder_f NGAP_CauseProtocol_encode_xer;
oer_type_decoder_f NGAP_CauseProtocol_decode_oer;
oer_type_encoder_f NGAP_CauseProtocol_encode_oer;
per_type_decoder_f NGAP_CauseProtocol_decode_uper;
per_type_encoder_f NGAP_CauseProtocol_encode_uper;
per_type_decoder_f NGAP_CauseProtocol_decode_aper;
per_type_encoder_f NGAP_CauseProtocol_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_CauseProtocol_H_ */
#include <asn_internal.h>
