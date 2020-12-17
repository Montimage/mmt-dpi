/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#ifndef	_NGAP_NumberOfBroadcasts_H_
#define	_NGAP_NumberOfBroadcasts_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NGAP_NumberOfBroadcasts */
typedef long	 NGAP_NumberOfBroadcasts_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_NumberOfBroadcasts_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_NumberOfBroadcasts;
asn_struct_free_f NGAP_NumberOfBroadcasts_free;
asn_struct_print_f NGAP_NumberOfBroadcasts_print;
asn_constr_check_f NGAP_NumberOfBroadcasts_constraint;
ber_type_decoder_f NGAP_NumberOfBroadcasts_decode_ber;
der_type_encoder_f NGAP_NumberOfBroadcasts_encode_der;
xer_type_decoder_f NGAP_NumberOfBroadcasts_decode_xer;
xer_type_encoder_f NGAP_NumberOfBroadcasts_encode_xer;
oer_type_decoder_f NGAP_NumberOfBroadcasts_decode_oer;
oer_type_encoder_f NGAP_NumberOfBroadcasts_encode_oer;
per_type_decoder_f NGAP_NumberOfBroadcasts_decode_uper;
per_type_encoder_f NGAP_NumberOfBroadcasts_encode_uper;
per_type_decoder_f NGAP_NumberOfBroadcasts_decode_aper;
per_type_encoder_f NGAP_NumberOfBroadcasts_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_NumberOfBroadcasts_H_ */
#include <asn_internal.h>
