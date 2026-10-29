/* Generated with MMT Plugin Generator */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dicom.h"
#include "../mmt_core/private_include/dbg.h" /* mmt_stderr_log (issue #545) */
#include "../mmt_core/public_include/extraction_lib.h"
#include <netinet/in.h>
#include "../mmt_tcpip/include/mmt_tcpip_protocols.h"

static int _extraction_att(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data);

static attribute_metadata_t dicom_attributes_metadata[DICOM_ATTRIBUTES_NB] = {
	{DICOM_PDU_TYPE, DICOM_PDU_TYPE_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_PDU_LEN, DICOM_PDU_LEN_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 2, SCOPE_PACKET, _extraction_att},
	{DICOM_PROTO_VERSION, DICOM_PROTO_VERSION_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 6, SCOPE_PACKET, _extraction_att},
	{DICOM_CALLED_AE_TITLE, DICOM_CALLED_AE_TITLE_ALIAS, MMT_STRING_DATA, BINARY_64DATA_TYPE_LEN, 10, SCOPE_PACKET, _extraction_att},
	{DICOM_CALLING_AE_TITLE, DICOM_CALLING_AE_TITLE_ALIAS, MMT_STRING_DATA, BINARY_64DATA_TYPE_LEN, 26, SCOPE_PACKET, _extraction_att},
	{DICOM_APPLICATION_CONTEXT, DICOM_APPLICATION_CONTEXT_ALIAS, MMT_STRING_DATA, BINARY_64DATA_TYPE_LEN, 0, SCOPE_PACKET, _extraction_att},
	{DICOM_PRESENTATION_CONTEXT, DICOM_PRESENTATION_CONTEXT_ALIAS, MMT_STRING_DATA, BINARY_64DATA_TYPE_LEN, 0, SCOPE_PACKET, _extraction_att},
	{DICOM_MAX_PDU_LENGTH, DICOM_MAX_PDU_LENGTH_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_IMPLEMENTATION_CLASS_UID, DICOM_IMPLEMENTATION_CLASS_UID_ALIAS, MMT_STRING_DATA, BINARY_64DATA_TYPE_LEN, 0, SCOPE_PACKET, _extraction_att},
	// P-DATA-TF attributes
	{DICOM_PDV_LENGTH, DICOM_PDV_LENGTH_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 6, SCOPE_PACKET, _extraction_att},
	{DICOM_PDV_CONTEXT, DICOM_PDV_CONTEXT_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 10, SCOPE_PACKET, _extraction_att},
	{DICOM_PDV_FLAGS, DICOM_PDV_FLAGS_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 11, SCOPE_PACKET, _extraction_att},
	{DICOM_COMMAND_GROUP_LENGTH, DICOM_COMMAND_GROUP_LENGTH_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_COMMAND_FIELD, DICOM_COMMAND_FIELD_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_PATIENT_NAME, DICOM_PATIENT_NAME_ALIAS, MMT_STRING_DATA, BINARY_64DATA_TYPE_LEN, 0, SCOPE_PACKET, _extraction_att},
	// New attributes
	{DICOM_STATUS, DICOM_STATUS_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_AFFECTED_SOP_CLASS_UID, DICOM_AFFECTED_SOP_CLASS_UID_ALIAS, MMT_STRING_DATA, BINARY_64DATA_TYPE_LEN, 0, SCOPE_PACKET, _extraction_att},
	{DICOM_MESSAGE_ID, DICOM_MESSAGE_ID_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_ABSTRACT_SYNTAX, DICOM_ABSTRACT_SYNTAX_ALIAS, MMT_STRING_DATA, BINARY_64DATA_TYPE_LEN, 0, SCOPE_PACKET, _extraction_att},
	{DICOM_TRANSFER_SYNTAX, DICOM_TRANSFER_SYNTAX_ALIAS, MMT_STRING_DATA, BINARY_64DATA_TYPE_LEN, 0, SCOPE_PACKET, _extraction_att},
	{DICOM_DATA_SET_TYPE, DICOM_DATA_SET_TYPE_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, _extraction_att},
};

/*
 * Helper: search for a DICOM tag in DIMSE command data (little-endian).
 * DIMSE tags are: group(2 bytes LE) + element(2 bytes LE).
 * Returns byte offset of the tag, or -1 if not found.
 */
static int find_dimse_tag(const uint8_t *data, int start, int end,
                          uint16_t group, uint16_t element) {
	for (int i = start; i <= end - 4; i++) {
		if (data[i]   == (group & 0xFF)   && data[i+1] == (group >> 8) &&
		    data[i+2] == (element & 0xFF) && data[i+3] == (element >> 8)) {
			return i;
		}
	}
	return -1;
}

/*
 * Helper: search for a sub-item by type in A-ASSOCIATE variable items area.
 * Each item: type(1) + reserved(1) + length(2 BE) + value(length bytes).
 * Returns byte offset of the item, or -1 if not found.
 */
static int find_assoc_subitem(const uint8_t *data, int start, int end,
                              uint8_t item_type) {
	int pos = start;
	while (pos <= end - 4) {
		uint8_t type = data[pos];
		uint16_t len = (data[pos+2] << 8) | data[pos+3];
		if (type == item_type)
			return pos;
		if (len > (end - pos - 4))
			break;
		pos += 4 + len;
	}
	return -1;
}

/*
 * DICOM data extraction routines
 */

/*
 * State shared by the extraction helpers below: the packet, the PDU header
 * and the offsets _extraction_att validated before dispatching.
 */
typedef struct dicom_att_ctx_struct {
	const ipacket_t * ipacket;
	const struct dicomhdr * hdr;
	int dicom_offset;
	int attribute_offset;
	unsigned int packet_len;
} dicom_att_ctx_t;

/* Copy len bytes of packet data at offset into a NUL-terminated binary attribute. */
static void _set_binary_att(const dicom_att_ctx_t * c, int offset, uint32_t len, attribute_t * extracted_data) {
	mmt_binary_data_t *binary_data = (mmt_binary_data_t *)extracted_data->data;
	memcpy(binary_data->data, &c->ipacket->data[offset], len);
	binary_data->len = len;
	binary_data->data[len] = '\0';
}

/*
 * Copy the value of the A-ASSOCIATE item or sub-item at item_pos
 * (type(1) + reserved(1) + length(2 BE) + value), capped at 63 bytes.
 * Returns 0 when the value runs past the capture.
 */
static int _set_assoc_item_value(const dicom_att_ctx_t * c, int item_pos, attribute_t * extracted_data) {
	const u_char * data = c->ipacket->data;
	uint16_t sub_len = (data[item_pos + 2] << 8) | data[item_pos + 3];
	int sub_value_offset = item_pos + 4;
	if (sub_value_offset + sub_len > (int)c->ipacket->p_hdr->caplen) return 0;
	if (sub_len > 63) sub_len = 63;

	_set_binary_att(c, sub_value_offset, sub_len, extracted_data);
	return 1;
}

/* End of the value of the item at item_pos, clamped to the capture. */
static int _assoc_item_value_end(const dicom_att_ctx_t * c, int item_pos) {
	const u_char * data = c->ipacket->data;
	uint16_t item_len = (data[item_pos + 2] << 8) | data[item_pos + 3];
	int value_end = item_pos + 4 + item_len;
	if (value_end > (int)c->ipacket->p_hdr->caplen) value_end = c->ipacket->p_hdr->caplen;
	return value_end;
}

/*
 * Scan the A-ASSOCIATE variable items area (starts at offset 74) for an
 * item of the given type. Returns its offset, or -1.
 */
static int _find_assoc_var_item(const dicom_att_ctx_t * c, uint8_t item_type) {
	int var_start = c->dicom_offset + 74;
	int var_end = c->dicom_offset + c->packet_len;
	if (var_start >= var_end) return -1;

	return find_assoc_subitem(c->ipacket->data, var_start, var_end, item_type);
}

/* Find the first Presentation Context item: type 0x20 (RQ) or 0x21 (AC). */
static int _find_presentation_context(const dicom_att_ctx_t * c) {
	uint8_t pres_type = (c->hdr->pdu_type == A_ASSOCIATE_RQ) ? 0x20 : 0x21;
	return _find_assoc_var_item(c, pres_type);
}

/* Called/Calling AE Title: exactly 16 bytes per PS3.8 §9.3.2 */
static int _extraction_ae_title(const dicom_att_ctx_t * c, attribute_t * extracted_data) {
	int start_offset = c->dicom_offset + c->attribute_offset;
	int length = 16; // DICOM AE Title is exactly 16 bytes per PS3.8 §9.3.2
	if (start_offset + length > (int)c->ipacket->p_hdr->caplen) return 0;
	_set_binary_att(c, start_offset, length, extracted_data);
	return 1;
}

/* Abstract Syntax (0x30) sub-item of the first Presentation Context item. */
static int _extraction_presentation_context(const dicom_att_ctx_t * c, attribute_t * extracted_data) {
	const u_char * data = c->ipacket->data;
	int item_pos = _find_presentation_context(c);
	if (item_pos < 0) return 0;

	uint16_t item_len = (data[item_pos + 2] << 8) | data[item_pos + 3];
	int value_offset = item_pos + 4;
	if (value_offset + item_len > (int)c->ipacket->p_hdr->caplen) return 0;

	// Inside the Presentation Context item, find the Abstract Syntax sub-item (type 0x30)
	int sub_pos = find_assoc_subitem(data, value_offset + 4, value_offset + item_len, 0x30);
	if (sub_pos < 0) return 0;

	return _set_assoc_item_value(c, sub_pos, extracted_data);
}

/*
 * Abstract Syntax (0x30) or Transfer Syntax (0x40) sub-item of the first
 * Presentation Context item, whose value end is clamped to the capture.
 */
static int _extraction_presentation_sub_item(const dicom_att_ctx_t * c, uint8_t sub_type, attribute_t * extracted_data) {
	int pres_pos = _find_presentation_context(c);
	if (pres_pos < 0) return 0;

	int pres_value_end = _assoc_item_value_end(c, pres_pos);

	// Skip Presentation Context ID (1 byte) + reserved (3 bytes) = 4 bytes
	int sub_start = pres_pos + 4 + 4;
	int sub_pos = find_assoc_subitem(c->ipacket->data, sub_start, pres_value_end, sub_type);
	if (sub_pos < 0) return 0;

	return _set_assoc_item_value(c, sub_pos, extracted_data);
}

/* Max PDU Length (0x51) or Implementation Class UID (0x52) inside User Info (0x50). */
static int _extraction_user_info(const dicom_att_ctx_t * c, attribute_t * extracted_data) {
	int user_info_pos = _find_assoc_var_item(c, 0x50);
	if (user_info_pos < 0) return 0;

	int ui_value_start = user_info_pos + 4;
	int ui_value_end = _assoc_item_value_end(c, user_info_pos);

	if(extracted_data->field_id == DICOM_MAX_PDU_LENGTH) {
		// Search for Max PDU Length sub-item (type 0x51) inside User Info
		int sub_pos = find_assoc_subitem(c->ipacket->data, ui_value_start, ui_value_end, 0x51);
		if (sub_pos < 0) return 0;

		// Sub-item: type(1) + reserved(1) + length(2 BE) + value(4 bytes BE)
		int val_offset = sub_pos + 4;
		if (val_offset + 4 > (int)c->ipacket->p_hdr->caplen) return 0;
		uint32_t max_pdu;
		memcpy(&max_pdu, &c->ipacket->data[val_offset], sizeof max_pdu);
		*((uint32_t *)extracted_data->data) = ntohl(max_pdu);
	}
	else if(extracted_data->field_id == DICOM_IMPLEMENTATION_CLASS_UID) {
		// Search for Implementation Class UID sub-item (type 0x52) inside User Info
		int sub_pos = find_assoc_subitem(c->ipacket->data, ui_value_start, ui_value_end, 0x52);
		if (sub_pos < 0) return 0;

		return _set_assoc_item_value(c, sub_pos, extracted_data);
	}
	return 1;
}

/* Attributes of an A-ASSOCIATE-RQ/AC PDU (the caller checked the PDU type). */
static int _extraction_assoc_att(const dicom_att_ctx_t * c, attribute_t * extracted_data) {
	switch( extracted_data->field_id ){
	case DICOM_PROTO_VERSION: {
		uint16_t proto_ver;
		memcpy(&proto_ver, &c->ipacket->data[c->dicom_offset + c->attribute_offset], sizeof proto_ver);
		*((unsigned short *) extracted_data->data) = ntohs(proto_ver);
		break;
	}
	case DICOM_CALLED_AE_TITLE:
	case DICOM_CALLING_AE_TITLE:
		return _extraction_ae_title(c, extracted_data);
	case DICOM_APPLICATION_CONTEXT: {
		// Scan variable items area (starts at offset 74) for item type 0x10
		int item_pos = _find_assoc_var_item(c, 0x10);
		if (item_pos < 0) return 0;
		return _set_assoc_item_value(c, item_pos, extracted_data);
	}
	case DICOM_PRESENTATION_CONTEXT:
		return _extraction_presentation_context(c, extracted_data);
	case DICOM_MAX_PDU_LENGTH:
	case DICOM_IMPLEMENTATION_CLASS_UID:
		return _extraction_user_info(c, extracted_data);
	case DICOM_ABSTRACT_SYNTAX:
		return _extraction_presentation_sub_item(c, 0x30, extracted_data);
	case DICOM_TRANSFER_SYNTAX:
		return _extraction_presentation_sub_item(c, 0x40, extracted_data);
	default:
		break;
	}
	return 1;
}

/*
 * Search the P-DATA-TF payload (starts at offset 12) for a DIMSE tag.
 * Returns its offset, or -1.
 */
static int _find_pdata_tag(const dicom_att_ctx_t * c, uint16_t group, uint16_t element) {
	int dimse_start = c->dicom_offset + 12;
	int dimse_end = c->dicom_offset + c->packet_len;
	if (dimse_start >= dimse_end) return -1;

	return find_dimse_tag(c->ipacket->data, dimse_start, dimse_end, group, element);
}

/*
 * 2-byte little-endian value of the DIMSE command tag (0000,element):
 * implicit VR, tag(4) + length(4) + value(2).
 */
static int _extraction_dimse_u16(const dicom_att_ctx_t * c, uint16_t element, attribute_t * extracted_data) {
	int tag_pos = _find_pdata_tag(c, 0x0000, element);
	if (tag_pos < 0) return 0;

	int val_offset = tag_pos + 8; // tag(4) + length(4)
	if (val_offset + 2 > (int)c->ipacket->p_hdr->caplen) return 0;

	uint16_t value = c->ipacket->data[val_offset] | (c->ipacket->data[val_offset + 1] << 8);
	*((uint16_t *)extracted_data->data) = value;
	return 1;
}

/* Command Group Length, tag (0000,0000): 4-byte little-endian value. */
static int _extraction_command_group_length(const dicom_att_ctx_t * c, attribute_t * extracted_data) {
	const u_char * data = c->ipacket->data;
	// Search for tag (0000,0000) = Command Group Length
	int tag_pos = _find_pdata_tag(c, 0x0000, 0x0000);
	if (tag_pos < 0) return 0;

	// Tag(4) + VR/Length(4) + value(4) — implicit VR: tag(4) + length(4) + value(4)
	int val_offset = tag_pos + 8;
	if (val_offset + 4 > (int)c->ipacket->p_hdr->caplen) return 0;

	// Little-endian 4-byte value
	uint32_t group_length = data[val_offset] |
	                        (data[val_offset + 1] << 8) |
	                        (data[val_offset + 2] << 16) |
	                        (data[val_offset + 3] << 24);
	*((uint32_t *)extracted_data->data) = group_length;
	return 1;
}

/* Patient Name, tag (0010,0010), in a dataset (not command) PDV. */
static int _extraction_patient_name(const dicom_att_ctx_t * c, attribute_t * extracted_data) {
	const u_char * data = c->ipacket->data;
	int caplen = (int)c->ipacket->p_hdr->caplen;
	// Check PDV flags: bit 1 = 0 means dataset content
	int flags_off = c->dicom_offset + 11;
	if (flags_off >= caplen) return 0;
	uint8_t pdv_flags = data[flags_off];
	if (pdv_flags & 0x01) return 0; // This is command data, not dataset

	// Scan P-DATA payload for Patient Name tag (0010,0010)
	int tag_pos = _find_pdata_tag(c, 0x0010, 0x0010);
	if (tag_pos < 0) return 0;

	// Parse VR and length
	int vr_offset = tag_pos + 4;
	if (vr_offset + 2 > caplen) return 0;

	char vr0 = data[vr_offset];
	char vr1 = data[vr_offset + 1];
	int length_offset;
	uint16_t length;

	if (vr0 == 'P' && vr1 == 'N') {
		// Explicit VR PN: tag(4) + VR(2) + length(2 LE)
		length_offset = vr_offset + 2;
		if (length_offset + 2 > caplen) return 0;
		length = data[length_offset] | (data[length_offset + 1] << 8);
		length_offset += 2;
	} else {
		// Implicit VR: tag(4) + length(4 LE)
		length_offset = tag_pos + 4;
		if (length_offset + 4 > caplen) return 0;
		length = data[length_offset] | (data[length_offset + 1] << 8);
		length_offset += 4;
	}

	if (length == 0 || length > 63) {
		if (length > 63) length = 63;
		if (length == 0) return 0;
	}
	if (length_offset + length > caplen) return 0;

	_set_binary_att(c, length_offset, length, extracted_data);
	return 1;
}

/* Affected SOP Class UID, tag (0000,0002): implicit VR string value. */
static int _extraction_affected_sop_class_uid(const dicom_att_ctx_t * c, attribute_t * extracted_data) {
	const u_char * data = c->ipacket->data;
	// Search for tag (0000,0002) = Affected SOP Class UID
	int tag_pos = _find_pdata_tag(c, 0x0000, 0x0002);
	if (tag_pos < 0) return 0;

	// Implicit VR: tag(4) + length(4 LE) + value
	int len_offset = tag_pos + 4;
	if (len_offset + 4 > (int)c->ipacket->p_hdr->caplen) return 0;
	uint32_t val_len = data[len_offset] |
	                   (data[len_offset + 1] << 8) |
	                   (data[len_offset + 2] << 16) |
	                   (data[len_offset + 3] << 24);
	int val_offset = len_offset + 4;
	if (val_len == 0 || val_offset + (int)val_len > (int)c->ipacket->p_hdr->caplen) return 0;
	if (val_len > 63) val_len = 63;

	_set_binary_att(c, val_offset, val_len, extracted_data);
	return 1;
}

/* Attributes of a P-DATA-TF PDU (the caller checked the PDU type). */
static int _extraction_pdata_att(const dicom_att_ctx_t * c, attribute_t * extracted_data) {
	int caplen = (int)c->ipacket->p_hdr->caplen;
	int off;
	switch( extracted_data->field_id ){
	case DICOM_PDV_LENGTH: {
		off = c->dicom_offset + 6;
		if (off + 4 > caplen) return 0;
		uint32_t pdv_len;
		memcpy(&pdv_len, &c->ipacket->data[off], sizeof pdv_len);
		*((unsigned int *)extracted_data->data) = ntohl(pdv_len);
		break;
	}
	case DICOM_PDV_CONTEXT:
	case DICOM_PDV_FLAGS:
		off = c->dicom_offset + (extracted_data->field_id == DICOM_PDV_CONTEXT ? 10 : 11);
		if (off + 1 > caplen) return 0;
		*((unsigned char *)extracted_data->data) = c->ipacket->data[off];
		break;
	case DICOM_COMMAND_GROUP_LENGTH:
		return _extraction_command_group_length(c, extracted_data);
	case DICOM_COMMAND_FIELD:
		// Search for tag (0000,0100) = Command Field
		return _extraction_dimse_u16(c, 0x0100, extracted_data);
	case DICOM_PATIENT_NAME:
		return _extraction_patient_name(c, extracted_data);
	case DICOM_STATUS:
		// Search for tag (0000,0900) = Status
		return _extraction_dimse_u16(c, 0x0900, extracted_data);
	case DICOM_AFFECTED_SOP_CLASS_UID:
		return _extraction_affected_sop_class_uid(c, extracted_data);
	case DICOM_MESSAGE_ID:
		// Search for tag (0000,0110) = Message ID
		return _extraction_dimse_u16(c, 0x0110, extracted_data);
	case DICOM_DATA_SET_TYPE:
		// Search for tag (0000,0800) = Data Set Type
		return _extraction_dimse_u16(c, 0x0800, extracted_data);
	default:
		break;
	}
	return 1;
}

static int _extraction_att(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
	int dicom_offset = get_packet_offset_at_index(ipacket, proto_index);
	/* Validate the offset before forming the header pointer: a negative or
	 * out-of-capture offset would make the deref below and the
	 * caplen - dicom_offset length computation read out of bounds (#195). */
	if( dicom_offset < 0 || (size_t)dicom_offset + sizeof(struct dicomhdr) > ipacket->p_hdr->caplen ) {
		return 0;
	}
	struct dicomhdr * hdr = (struct dicomhdr *)&ipacket->data[dicom_offset];
	int attribute_offset = extracted_data->position_in_packet;
	unsigned int packet_len = ipacket->p_hdr->caplen - dicom_offset;

	if((ipacket->p_hdr->caplen - dicom_offset) == 0) {
		return 0;
	}

	if (!mmt_check_dicom(hdr, packet_len)) {
		return 0;
	}

	const dicom_att_ctx_t c = { ipacket, hdr, dicom_offset, attribute_offset, packet_len };

	//depending on id of attribute to be extracted
	switch( extracted_data->field_id ){
	case DICOM_PDU_TYPE:
		*((unsigned char *) extracted_data->data) = *((unsigned char *) &ipacket->data[dicom_offset + attribute_offset]);
		break;
	case DICOM_PDU_LEN: {
		// memcpy: the packet-data offset is not uint32-aligned (UBSan).
		uint32_t pdu_len;
		memcpy(&pdu_len, &ipacket->data[dicom_offset + attribute_offset], sizeof pdu_len);
		*((unsigned int *) extracted_data->data) = ntohl(pdu_len);
		break;
	}
	case DICOM_PROTO_VERSION:
	case DICOM_CALLED_AE_TITLE:
	case DICOM_CALLING_AE_TITLE:
	case DICOM_APPLICATION_CONTEXT:
	case DICOM_PRESENTATION_CONTEXT:
	case DICOM_MAX_PDU_LENGTH:
	case DICOM_IMPLEMENTATION_CLASS_UID:
	case DICOM_ABSTRACT_SYNTAX:
	case DICOM_TRANSFER_SYNTAX:
		if(hdr->pdu_type != A_ASSOCIATE_RQ && hdr->pdu_type != A_ASSOCIATE_AC) return 0;
		return _extraction_assoc_att(&c, extracted_data);
	case DICOM_PDV_LENGTH:
	case DICOM_PDV_CONTEXT:
	case DICOM_PDV_FLAGS:
	case DICOM_COMMAND_GROUP_LENGTH:
	case DICOM_COMMAND_FIELD:
	case DICOM_PATIENT_NAME:
	case DICOM_STATUS:
	case DICOM_AFFECTED_SOP_CLASS_UID:
	case DICOM_MESSAGE_ID:
	case DICOM_DATA_SET_TYPE:
		if(hdr->pdu_type != P_DATA_TF) return 0;
		return _extraction_pdata_att(&c, extracted_data);
	default:
		break;
	}
	return 1;
}

classified_proto_t dicom_stack_classification(ipacket_t * ipacket) {
	classified_proto_t retval;
	retval.offset = 0;
	retval.proto_id = PROTO_DICOM;
	retval.status = Classified;
	return retval;
}

/*
 * DICOM classification routine
 */
int mmt_check_dicom_hdr(struct dicomhdr* header) {
	if (header->pdu_type < 1 || header->pdu_type > 7) {
		return 0;
	}
	return 1;
}

int mmt_check_dicom_payload(struct dicomhdr* header, unsigned int packet_len) {
	if(packet_len < PROTO_DICOM_HDRLEN + DICOM_PAYLOAD_MIN_LEN) return 0;
	uint32_t pdu_len = ntohl(header->pdu_len);

	switch (header->pdu_type) {
	case A_ASSOCIATE_RQ:
	case A_ASSOCIATE_AC:
		// Fixed fields = 68 bytes
		if (pdu_len < 68 || pdu_len > 65535) return 0;
		break;
	case A_ASSOCIATE_RJ:
	case A_RELEASE_RQ:
	case A_RELEASE_RP:
	case A_ABORT:
		// These PDUs have a fixed 4-byte payload, no variable content
		if (pdu_len != 4) return 0;
		break;
	case P_DATA_TF:
		// At minimum: PDV-length(4) + context-id(1) + flags(1) = 6 bytes
		if (pdu_len < 6) return 0;
		break;
	default:
		return 0;
	}
	return 1;
}

int mmt_check_dicom(struct dicomhdr * header, unsigned int packet_len) {
	return mmt_check_dicom_hdr(header) &&
		mmt_check_dicom_payload(header, packet_len);
}

int mmt_check_dicom_tcp(ipacket_t * ipacket, unsigned index) {
	int l3_offset = get_packet_offset_at_index(ipacket, index);
    int dicom_offset = get_packet_offset_at_index(ipacket, index + 1);

	/* A DICOM PDU needs its fixed 6-byte header inside the captured frame:
	 * reject negative/out-of-capture offsets before dereferencing (#195). */
	if( dicom_offset < 0 || (size_t)dicom_offset + sizeof(struct dicomhdr) > ipacket->p_hdr->caplen )
		return 0;
	unsigned int packet_len = ipacket->p_hdr->caplen - dicom_offset;
	struct dicomhdr * dicom_header = (struct dicomhdr *)&ipacket->data[dicom_offset];
	if (!mmt_check_dicom(dicom_header, packet_len))
		return 0;

	classified_proto_t dicom_proto = dicom_stack_classification(ipacket);
	dicom_proto.offset = dicom_offset - l3_offset;
	return set_classified_proto(ipacket, index + 1, dicom_proto);
}

int init_dicom_proto_struct() {
	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DICOM, PROTO_DICOM_ALIAS);

	if (protocol_struct != NULL) {

		int i = 0;
		for(; i < DICOM_ATTRIBUTES_NB; i ++) {
			register_attribute_with_protocol(protocol_struct, &dicom_attributes_metadata[i]);
		}

		// Register classification function of DICOM protocol after TCP
		if(!register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dicom_tcp, 50)){
			mmt_stderr_log("\n[err] init_dicom_proto_struct - cannot register_classification_function_with_parent_protocol: PROTO_TCP\n");
			return -1;
		};
		return register_protocol(protocol_struct, PROTO_DICOM);

	}
	return -1;
}

#ifndef CORE
int init_proto() {
	return init_dicom_proto_struct();
}
int cleanup_proto() {
	return 0;
}
#endif //CORE
