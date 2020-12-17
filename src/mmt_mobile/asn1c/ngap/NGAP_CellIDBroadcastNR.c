/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./support/ngap-r15.2.0/Information-Element-Definitions.asn1"
 * 	`asn1c -D ./common -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example`
 */

#include "NGAP_CellIDBroadcastNR.h"

#include "NGAP_CellIDBroadcastNR-Item.h"
static asn_oer_constraints_t asn_OER_type_NGAP_CellIDBroadcastNR_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..65535)) */};
asn_per_constraints_t asn_PER_type_NGAP_CellIDBroadcastNR_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 16,  16,  1,  65535 }	/* (SIZE(1..65535)) */,
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_NGAP_CellIDBroadcastNR_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_NGAP_CellIDBroadcastNR_Item,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_NGAP_CellIDBroadcastNR_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SET_OF_specifics_t asn_SPC_NGAP_CellIDBroadcastNR_specs_1 = {
	sizeof(struct NGAP_CellIDBroadcastNR),
	offsetof(struct NGAP_CellIDBroadcastNR, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_CellIDBroadcastNR = {
	"CellIDBroadcastNR",
	"CellIDBroadcastNR",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_NGAP_CellIDBroadcastNR_tags_1,
	sizeof(asn_DEF_NGAP_CellIDBroadcastNR_tags_1)
		/sizeof(asn_DEF_NGAP_CellIDBroadcastNR_tags_1[0]), /* 1 */
	asn_DEF_NGAP_CellIDBroadcastNR_tags_1,	/* Same as above */
	sizeof(asn_DEF_NGAP_CellIDBroadcastNR_tags_1)
		/sizeof(asn_DEF_NGAP_CellIDBroadcastNR_tags_1[0]), /* 1 */
	{ &asn_OER_type_NGAP_CellIDBroadcastNR_constr_1, &asn_PER_type_NGAP_CellIDBroadcastNR_constr_1, SEQUENCE_OF_constraint },
	asn_MBR_NGAP_CellIDBroadcastNR_1,
	1,	/* Single element */
	&asn_SPC_NGAP_CellIDBroadcastNR_specs_1	/* Additional specs */
};

