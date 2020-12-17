/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "./support/s1ap-r10.5.0/S1AP-IEs.asn"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -fno-include-deps -no-gen-example`
 */

#include "S1ap-SONInformationReply.h"

#include "S1ap-X2TNLConfigurationInfo.h"
#include "S1ap-IE-Extensions.h"
asn_TYPE_member_t asn_MBR_S1ap_SONInformationReply_1[] = {
	{ ATF_POINTER, 2, offsetof(struct S1ap_SONInformationReply, x2TNLConfigurationInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S1ap_X2TNLConfigurationInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"x2TNLConfigurationInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct S1ap_SONInformationReply, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S1ap_IE_Extensions,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_S1ap_SONInformationReply_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_S1ap_SONInformationReply_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_S1ap_SONInformationReply_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* x2TNLConfigurationInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_S1ap_SONInformationReply_specs_1 = {
	sizeof(struct S1ap_SONInformationReply),
	offsetof(struct S1ap_SONInformationReply, _asn_ctx),
	asn_MAP_S1ap_SONInformationReply_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_S1ap_SONInformationReply_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_S1ap_SONInformationReply = {
	"S1ap-SONInformationReply",
	"S1ap-SONInformationReply",
	&asn_OP_SEQUENCE,
	asn_DEF_S1ap_SONInformationReply_tags_1,
	sizeof(asn_DEF_S1ap_SONInformationReply_tags_1)
		/sizeof(asn_DEF_S1ap_SONInformationReply_tags_1[0]), /* 1 */
	asn_DEF_S1ap_SONInformationReply_tags_1,	/* Same as above */
	sizeof(asn_DEF_S1ap_SONInformationReply_tags_1)
		/sizeof(asn_DEF_S1ap_SONInformationReply_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_S1ap_SONInformationReply_1,
	2,	/* Elements count */
	&asn_SPC_S1ap_SONInformationReply_specs_1	/* Additional specs */
};

