/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "./support/s1ap-r10.5.0/S1AP-IEs.asn"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -fno-include-deps -no-gen-example`
 */

#include "S1ap-CNDomain.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_S1ap_CNDomain_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_S1ap_CNDomain_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_S1ap_CNDomain_value2enum_1[] = {
	{ 0,	2,	"ps" },
	{ 1,	2,	"cs" }
};
static const unsigned int asn_MAP_S1ap_CNDomain_enum2value_1[] = {
	1,	/* cs(1) */
	0	/* ps(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_S1ap_CNDomain_specs_1 = {
	asn_MAP_S1ap_CNDomain_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_S1ap_CNDomain_enum2value_1,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_S1ap_CNDomain_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_S1ap_CNDomain = {
	"S1ap-CNDomain",
	"S1ap-CNDomain",
	&asn_OP_NativeEnumerated,
	asn_DEF_S1ap_CNDomain_tags_1,
	sizeof(asn_DEF_S1ap_CNDomain_tags_1)
		/sizeof(asn_DEF_S1ap_CNDomain_tags_1[0]), /* 1 */
	asn_DEF_S1ap_CNDomain_tags_1,	/* Same as above */
	sizeof(asn_DEF_S1ap_CNDomain_tags_1)
		/sizeof(asn_DEF_S1ap_CNDomain_tags_1[0]), /* 1 */
	{ &asn_OER_type_S1ap_CNDomain_constr_1, &asn_PER_type_S1ap_CNDomain_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_S1ap_CNDomain_specs_1	/* Additional specs */
};

