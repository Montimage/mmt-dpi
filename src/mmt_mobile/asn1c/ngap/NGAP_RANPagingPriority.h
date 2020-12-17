/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_RANPagingPriority_H_
#define	_NGAP_RANPagingPriority_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NGAP_RANPagingPriority */
typedef long	 NGAP_RANPagingPriority_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_RANPagingPriority_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_RANPagingPriority;
asn_struct_free_f NGAP_RANPagingPriority_free;
asn_struct_print_f NGAP_RANPagingPriority_print;
asn_constr_check_f NGAP_RANPagingPriority_constraint;
ber_type_decoder_f NGAP_RANPagingPriority_decode_ber;
der_type_encoder_f NGAP_RANPagingPriority_encode_der;
xer_type_decoder_f NGAP_RANPagingPriority_decode_xer;
xer_type_encoder_f NGAP_RANPagingPriority_encode_xer;
oer_type_decoder_f NGAP_RANPagingPriority_decode_oer;
oer_type_encoder_f NGAP_RANPagingPriority_encode_oer;
per_type_decoder_f NGAP_RANPagingPriority_decode_uper;
per_type_encoder_f NGAP_RANPagingPriority_encode_uper;
per_type_decoder_f NGAP_RANPagingPriority_decode_aper;
per_type_encoder_f NGAP_RANPagingPriority_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_RANPagingPriority_H_ */
#include <asn_internal.h>
