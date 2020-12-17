/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#include "NGAP_NonDynamic5QIDescriptor.h"

#include "NGAP_ProtocolExtensionContainer.h"
asn_TYPE_member_t asn_MBR_NGAP_NonDynamic5QIDescriptor_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_NonDynamic5QIDescriptor, fiveQI),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_FiveQI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fiveQI"
		},
	{ ATF_POINTER, 4, offsetof(struct NGAP_NonDynamic5QIDescriptor, priorityLevelQos),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_PriorityLevelQos,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"priorityLevelQos"
		},
	{ ATF_POINTER, 3, offsetof(struct NGAP_NonDynamic5QIDescriptor, averagingWindow),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_AveragingWindow,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"averagingWindow"
		},
	{ ATF_POINTER, 2, offsetof(struct NGAP_NonDynamic5QIDescriptor, maximumDataBurstVolume),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_MaximumDataBurstVolume,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maximumDataBurstVolume"
		},
	{ ATF_POINTER, 1, offsetof(struct NGAP_NonDynamic5QIDescriptor, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_ProtocolExtensionContainer_175P71,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_NGAP_NonDynamic5QIDescriptor_oms_1[] = { 1, 2, 3, 4 };
static const ber_tlv_tag_t asn_DEF_NGAP_NonDynamic5QIDescriptor_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NGAP_NonDynamic5QIDescriptor_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fiveQI */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* priorityLevelQos */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* averagingWindow */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* maximumDataBurstVolume */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_NGAP_NonDynamic5QIDescriptor_specs_1 = {
	sizeof(struct NGAP_NonDynamic5QIDescriptor),
	offsetof(struct NGAP_NonDynamic5QIDescriptor, _asn_ctx),
	asn_MAP_NGAP_NonDynamic5QIDescriptor_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_NGAP_NonDynamic5QIDescriptor_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	5,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_NonDynamic5QIDescriptor = {
	"NonDynamic5QIDescriptor",
	"NonDynamic5QIDescriptor",
	&asn_OP_SEQUENCE,
	asn_DEF_NGAP_NonDynamic5QIDescriptor_tags_1,
	sizeof(asn_DEF_NGAP_NonDynamic5QIDescriptor_tags_1)
		/sizeof(asn_DEF_NGAP_NonDynamic5QIDescriptor_tags_1[0]), /* 1 */
	asn_DEF_NGAP_NonDynamic5QIDescriptor_tags_1,	/* Same as above */
	sizeof(asn_DEF_NGAP_NonDynamic5QIDescriptor_tags_1)
		/sizeof(asn_DEF_NGAP_NonDynamic5QIDescriptor_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_NGAP_NonDynamic5QIDescriptor_1,
	5,	/* Elements count */
	&asn_SPC_NGAP_NonDynamic5QIDescriptor_specs_1	/* Additional specs */
};

