/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#include "NGAP_UserLocationInformation.h"

static asn_oer_constraints_t asn_OER_type_NGAP_UserLocationInformation_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_NGAP_UserLocationInformation_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_NGAP_UserLocationInformation_1[] = {
	{ ATF_POINTER, 0, offsetof(struct NGAP_UserLocationInformation, choice.userLocationInformationEUTRA),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_UserLocationInformationEUTRA,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"userLocationInformationEUTRA"
		},
	{ ATF_POINTER, 0, offsetof(struct NGAP_UserLocationInformation, choice.userLocationInformationNR),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_UserLocationInformationNR,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"userLocationInformationNR"
		},
	{ ATF_POINTER, 0, offsetof(struct NGAP_UserLocationInformation, choice.userLocationInformationN3IWF),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_UserLocationInformationN3IWF,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"userLocationInformationN3IWF"
		},
	{ ATF_POINTER, 0, offsetof(struct NGAP_UserLocationInformation, choice.choice_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_ProtocolIE_SingleContainer_6979P24,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"choice-Extensions"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_NGAP_UserLocationInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* userLocationInformationEUTRA */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* userLocationInformationNR */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* userLocationInformationN3IWF */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* choice-Extensions */
};
static asn_CHOICE_specifics_t asn_SPC_NGAP_UserLocationInformation_specs_1 = {
	sizeof(struct NGAP_UserLocationInformation),
	offsetof(struct NGAP_UserLocationInformation, _asn_ctx),
	offsetof(struct NGAP_UserLocationInformation, present),
	sizeof(((struct NGAP_UserLocationInformation *)0)->present),
	asn_MAP_NGAP_UserLocationInformation_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_UserLocationInformation = {
	"UserLocationInformation",
	"UserLocationInformation",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_NGAP_UserLocationInformation_constr_1, &asn_PER_type_NGAP_UserLocationInformation_constr_1, CHOICE_constraint },
	asn_MBR_NGAP_UserLocationInformation_1,
	4,	/* Elements count */
	&asn_SPC_NGAP_UserLocationInformation_specs_1	/* Additional specs */
};

