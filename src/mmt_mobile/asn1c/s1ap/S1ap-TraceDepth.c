/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "./support/s1ap-r10.5.0/S1AP-IEs.asn"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -fno-include-deps -no-gen-example`
 */

#include "S1ap-TraceDepth.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_S1ap_TraceDepth_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_S1ap_TraceDepth_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  3,  3,  0,  5 }	/* (0..5,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_S1ap_TraceDepth_value2enum_1[] = {
	{ 0,	7,	"minimum" },
	{ 1,	6,	"medium" },
	{ 2,	12,	"s1ap-maximum" },
	{ 3,	37,	"minimumWithoutVendorSpecificExtension" },
	{ 4,	36,	"mediumWithoutVendorSpecificExtension" },
	{ 5,	42,	"s1ap-maximumWithoutVendorSpecificExtension" }
	/* This list is extensible */
};
static const unsigned int asn_MAP_S1ap_TraceDepth_enum2value_1[] = {
	1,	/* medium(1) */
	4,	/* mediumWithoutVendorSpecificExtension(4) */
	0,	/* minimum(0) */
	3,	/* minimumWithoutVendorSpecificExtension(3) */
	2,	/* s1ap-maximum(2) */
	5	/* s1ap-maximumWithoutVendorSpecificExtension(5) */
	/* This list is extensible */
};
const asn_INTEGER_specifics_t asn_SPC_S1ap_TraceDepth_specs_1 = {
	asn_MAP_S1ap_TraceDepth_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_S1ap_TraceDepth_enum2value_1,	/* N => "tag"; sorted by N */
	6,	/* Number of elements in the maps */
	7,	/* Extensions before this member */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_S1ap_TraceDepth_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_S1ap_TraceDepth = {
	"S1ap-TraceDepth",
	"S1ap-TraceDepth",
	&asn_OP_NativeEnumerated,
	asn_DEF_S1ap_TraceDepth_tags_1,
	sizeof(asn_DEF_S1ap_TraceDepth_tags_1)
		/sizeof(asn_DEF_S1ap_TraceDepth_tags_1[0]), /* 1 */
	asn_DEF_S1ap_TraceDepth_tags_1,	/* Same as above */
	sizeof(asn_DEF_S1ap_TraceDepth_tags_1)
		/sizeof(asn_DEF_S1ap_TraceDepth_tags_1[0]), /* 1 */
	{ &asn_OER_type_S1ap_TraceDepth_constr_1, &asn_PER_type_S1ap_TraceDepth_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_S1ap_TraceDepth_specs_1	/* Additional specs */
};

