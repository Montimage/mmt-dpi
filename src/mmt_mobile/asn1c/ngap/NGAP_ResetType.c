/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#include "NGAP_ResetType.h"

static asn_oer_constraints_t asn_OER_type_NGAP_ResetType_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_NGAP_ResetType_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_NGAP_ResetType_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_ResetType, choice.nG_Interface),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_ResetAll,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nG-Interface"
		},
	{ ATF_POINTER, 0, offsetof(struct NGAP_ResetType, choice.partOfNG_Interface),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_UE_associatedLogicalNG_connectionList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"partOfNG-Interface"
		},
	{ ATF_POINTER, 0, offsetof(struct NGAP_ResetType, choice.choice_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_ProtocolIE_SingleContainer_6979P17,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"choice-Extensions"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_NGAP_ResetType_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* nG-Interface */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* partOfNG-Interface */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* choice-Extensions */
};
static asn_CHOICE_specifics_t asn_SPC_NGAP_ResetType_specs_1 = {
	sizeof(struct NGAP_ResetType),
	offsetof(struct NGAP_ResetType, _asn_ctx),
	offsetof(struct NGAP_ResetType, present),
	sizeof(((struct NGAP_ResetType *)0)->present),
	asn_MAP_NGAP_ResetType_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_ResetType = {
	"ResetType",
	"ResetType",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_NGAP_ResetType_constr_1, &asn_PER_type_NGAP_ResetType_constr_1, CHOICE_constraint },
	asn_MBR_NGAP_ResetType_1,
	3,	/* Elements count */
	&asn_SPC_NGAP_ResetType_specs_1	/* Additional specs */
};

