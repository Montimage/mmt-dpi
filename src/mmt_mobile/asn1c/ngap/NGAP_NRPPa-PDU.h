/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#ifndef	_NGAP_NRPPa_PDU_H_
#define	_NGAP_NRPPa_PDU_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NGAP_NRPPa-PDU */
typedef OCTET_STRING_t	 NGAP_NRPPa_PDU_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_NRPPa_PDU;
asn_struct_free_f NGAP_NRPPa_PDU_free;
asn_struct_print_f NGAP_NRPPa_PDU_print;
asn_constr_check_f NGAP_NRPPa_PDU_constraint;
ber_type_decoder_f NGAP_NRPPa_PDU_decode_ber;
der_type_encoder_f NGAP_NRPPa_PDU_encode_der;
xer_type_decoder_f NGAP_NRPPa_PDU_decode_xer;
xer_type_encoder_f NGAP_NRPPa_PDU_encode_xer;
oer_type_decoder_f NGAP_NRPPa_PDU_decode_oer;
oer_type_encoder_f NGAP_NRPPa_PDU_encode_oer;
per_type_decoder_f NGAP_NRPPa_PDU_decode_uper;
per_type_encoder_f NGAP_NRPPa_PDU_encode_uper;
per_type_decoder_f NGAP_NRPPa_PDU_decode_aper;
per_type_encoder_f NGAP_NRPPa_PDU_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_NRPPa_PDU_H_ */
#include <asn_internal.h>
