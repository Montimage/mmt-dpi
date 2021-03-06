/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "./support/s1ap-r10.5.0/S1AP-IEs.asn"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -fno-include-deps -no-gen-example`
 */

#ifndef	_S1ap_ReportAmountMDT_H_
#define	_S1ap_ReportAmountMDT_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum S1ap_ReportAmountMDT {
	S1ap_ReportAmountMDT_r1	= 0,
	S1ap_ReportAmountMDT_r2	= 1,
	S1ap_ReportAmountMDT_r4	= 2,
	S1ap_ReportAmountMDT_r8	= 3,
	S1ap_ReportAmountMDT_r16	= 4,
	S1ap_ReportAmountMDT_r32	= 5,
	S1ap_ReportAmountMDT_r64	= 6,
	S1ap_ReportAmountMDT_rinfinity	= 7
} e_S1ap_ReportAmountMDT;

/* S1ap-ReportAmountMDT */
typedef long	 S1ap_ReportAmountMDT_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_S1ap_ReportAmountMDT_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_S1ap_ReportAmountMDT;
extern const asn_INTEGER_specifics_t asn_SPC_S1ap_ReportAmountMDT_specs_1;
asn_struct_free_f S1ap_ReportAmountMDT_free;
asn_struct_print_f S1ap_ReportAmountMDT_print;
asn_constr_check_f S1ap_ReportAmountMDT_constraint;
ber_type_decoder_f S1ap_ReportAmountMDT_decode_ber;
der_type_encoder_f S1ap_ReportAmountMDT_encode_der;
xer_type_decoder_f S1ap_ReportAmountMDT_decode_xer;
xer_type_encoder_f S1ap_ReportAmountMDT_encode_xer;
oer_type_decoder_f S1ap_ReportAmountMDT_decode_oer;
oer_type_encoder_f S1ap_ReportAmountMDT_encode_oer;
per_type_decoder_f S1ap_ReportAmountMDT_decode_uper;
per_type_encoder_f S1ap_ReportAmountMDT_encode_uper;
per_type_decoder_f S1ap_ReportAmountMDT_decode_aper;
per_type_encoder_f S1ap_ReportAmountMDT_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _S1ap_ReportAmountMDT_H_ */
#include <asn_internal.h>
