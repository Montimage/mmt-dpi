/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#include "NGAP_DRBsSubjectToStatusTransferItem.h"

#include "NGAP_ProtocolExtensionContainer.h"
asn_TYPE_member_t asn_MBR_NGAP_DRBsSubjectToStatusTransferItem_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_DRBsSubjectToStatusTransferItem, dRB_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_DRB_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dRB-ID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_DRBsSubjectToStatusTransferItem, dRBStatusUL),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_NGAP_DRBStatusUL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dRBStatusUL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_DRBsSubjectToStatusTransferItem, dRBStatusDL),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_NGAP_DRBStatusDL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dRBStatusDL"
		},
	{ ATF_POINTER, 1, offsetof(struct NGAP_DRBsSubjectToStatusTransferItem, iE_Extension),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_ProtocolExtensionContainer_175P34,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extension"
		},
};
static const int asn_MAP_NGAP_DRBsSubjectToStatusTransferItem_oms_1[] = { 3 };
static const ber_tlv_tag_t asn_DEF_NGAP_DRBsSubjectToStatusTransferItem_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NGAP_DRBsSubjectToStatusTransferItem_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dRB-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dRBStatusUL */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* dRBStatusDL */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* iE-Extension */
};
asn_SEQUENCE_specifics_t asn_SPC_NGAP_DRBsSubjectToStatusTransferItem_specs_1 = {
	sizeof(struct NGAP_DRBsSubjectToStatusTransferItem),
	offsetof(struct NGAP_DRBsSubjectToStatusTransferItem, _asn_ctx),
	asn_MAP_NGAP_DRBsSubjectToStatusTransferItem_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_NGAP_DRBsSubjectToStatusTransferItem_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_DRBsSubjectToStatusTransferItem = {
	"DRBsSubjectToStatusTransferItem",
	"DRBsSubjectToStatusTransferItem",
	&asn_OP_SEQUENCE,
	asn_DEF_NGAP_DRBsSubjectToStatusTransferItem_tags_1,
	sizeof(asn_DEF_NGAP_DRBsSubjectToStatusTransferItem_tags_1)
		/sizeof(asn_DEF_NGAP_DRBsSubjectToStatusTransferItem_tags_1[0]), /* 1 */
	asn_DEF_NGAP_DRBsSubjectToStatusTransferItem_tags_1,	/* Same as above */
	sizeof(asn_DEF_NGAP_DRBsSubjectToStatusTransferItem_tags_1)
		/sizeof(asn_DEF_NGAP_DRBsSubjectToStatusTransferItem_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_NGAP_DRBsSubjectToStatusTransferItem_1,
	4,	/* Elements count */
	&asn_SPC_NGAP_DRBsSubjectToStatusTransferItem_specs_1	/* Additional specs */
};

