/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#include "NGAP_RIMInformation.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_NGAP_rIM_RSDetection_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_NGAP_rIM_RSDetection_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  1,  1,  0,  1 }	/* (0..1,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_NGAP_rIM_RSDetection_value2enum_3[] = {
	{ 0,	11,	"rs-detected" },
	{ 1,	14,	"rs-disappeared" }
	/* This list is extensible */
};
static const unsigned int asn_MAP_NGAP_rIM_RSDetection_enum2value_3[] = {
	0,	/* rs-detected(0) */
	1	/* rs-disappeared(1) */
	/* This list is extensible */
};
static const asn_INTEGER_specifics_t asn_SPC_NGAP_rIM_RSDetection_specs_3 = {
	asn_MAP_NGAP_rIM_RSDetection_value2enum_3,	/* "tag" => N; sorted by tag */
	asn_MAP_NGAP_rIM_RSDetection_enum2value_3,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	3,	/* Extensions before this member */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_NGAP_rIM_RSDetection_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_NGAP_rIM_RSDetection_3 = {
	"rIM-RSDetection",
	"rIM-RSDetection",
	&asn_OP_NativeEnumerated,
	asn_DEF_NGAP_rIM_RSDetection_tags_3,
	sizeof(asn_DEF_NGAP_rIM_RSDetection_tags_3)
		/sizeof(asn_DEF_NGAP_rIM_RSDetection_tags_3[0]) - 1, /* 1 */
	asn_DEF_NGAP_rIM_RSDetection_tags_3,	/* Same as above */
	sizeof(asn_DEF_NGAP_rIM_RSDetection_tags_3)
		/sizeof(asn_DEF_NGAP_rIM_RSDetection_tags_3[0]), /* 2 */
	{ &asn_OER_type_NGAP_rIM_RSDetection_constr_3, &asn_PER_type_NGAP_rIM_RSDetection_constr_3, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_NGAP_rIM_RSDetection_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_NGAP_RIMInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_RIMInformation, targetgNBSetID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_GNBSetID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"targetgNBSetID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_RIMInformation, rIM_RSDetection),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_rIM_RSDetection_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rIM-RSDetection"
		},
};
static const ber_tlv_tag_t asn_DEF_NGAP_RIMInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NGAP_RIMInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* targetgNBSetID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* rIM-RSDetection */
};
asn_SEQUENCE_specifics_t asn_SPC_NGAP_RIMInformation_specs_1 = {
	sizeof(struct NGAP_RIMInformation),
	offsetof(struct NGAP_RIMInformation, _asn_ctx),
	asn_MAP_NGAP_RIMInformation_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_RIMInformation = {
	"RIMInformation",
	"RIMInformation",
	&asn_OP_SEQUENCE,
	asn_DEF_NGAP_RIMInformation_tags_1,
	sizeof(asn_DEF_NGAP_RIMInformation_tags_1)
		/sizeof(asn_DEF_NGAP_RIMInformation_tags_1[0]), /* 1 */
	asn_DEF_NGAP_RIMInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_NGAP_RIMInformation_tags_1)
		/sizeof(asn_DEF_NGAP_RIMInformation_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_NGAP_RIMInformation_1,
	2,	/* Elements count */
	&asn_SPC_NGAP_RIMInformation_specs_1	/* Additional specs */
};

