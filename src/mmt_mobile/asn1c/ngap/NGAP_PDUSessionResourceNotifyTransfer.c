/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example`
 */

#include "NGAP_PDUSessionResourceNotifyTransfer.h"

static asn_TYPE_member_t asn_MBR_NGAP_PDUSessionResourceNotifyTransfer_1[] = {
	{ ATF_POINTER, 3, offsetof(struct NGAP_PDUSessionResourceNotifyTransfer, qosFlowNotifyList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_QosFlowNotifyList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"qosFlowNotifyList"
		},
	{ ATF_POINTER, 2, offsetof(struct NGAP_PDUSessionResourceNotifyTransfer, qosFlowReleasedList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_QosFlowListWithCause,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"qosFlowReleasedList"
		},
	{ ATF_POINTER, 1, offsetof(struct NGAP_PDUSessionResourceNotifyTransfer, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_ProtocolExtensionContainer_7027P112,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_NGAP_PDUSessionResourceNotifyTransfer_oms_1[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_NGAP_PDUSessionResourceNotifyTransfer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NGAP_PDUSessionResourceNotifyTransfer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* qosFlowNotifyList */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* qosFlowReleasedList */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_NGAP_PDUSessionResourceNotifyTransfer_specs_1 = {
	sizeof(struct NGAP_PDUSessionResourceNotifyTransfer),
	offsetof(struct NGAP_PDUSessionResourceNotifyTransfer, _asn_ctx),
	asn_MAP_NGAP_PDUSessionResourceNotifyTransfer_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_NGAP_PDUSessionResourceNotifyTransfer_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_PDUSessionResourceNotifyTransfer = {
	"PDUSessionResourceNotifyTransfer",
	"PDUSessionResourceNotifyTransfer",
	&asn_OP_SEQUENCE,
	asn_DEF_NGAP_PDUSessionResourceNotifyTransfer_tags_1,
	sizeof(asn_DEF_NGAP_PDUSessionResourceNotifyTransfer_tags_1)
		/sizeof(asn_DEF_NGAP_PDUSessionResourceNotifyTransfer_tags_1[0]), /* 1 */
	asn_DEF_NGAP_PDUSessionResourceNotifyTransfer_tags_1,	/* Same as above */
	sizeof(asn_DEF_NGAP_PDUSessionResourceNotifyTransfer_tags_1)
		/sizeof(asn_DEF_NGAP_PDUSessionResourceNotifyTransfer_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_NGAP_PDUSessionResourceNotifyTransfer_1,
	3,	/* Elements count */
	&asn_SPC_NGAP_PDUSessionResourceNotifyTransfer_specs_1	/* Additional specs */
};

