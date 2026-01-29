/* Generated with MMT Plugin Generator */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dicom.h"
#include "../mmt_core/public_include/extraction_lib.h"
#include <netinet/in.h>
#include "../mmt_tcpip/include/mmt_tcpip_protocols.h"

static attribute_metadata_t dicom_attributes_metadata[DICOM_ATTRIBUTES_NB] = {
	{DICOM_PDU_TYPE, DICOM_PDU_TYPE_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_PDU_LEN, DICOM_PDU_LEN_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 2, SCOPE_PACKET, _extraction_att},
	{DICOM_PROTO_VERSION, DICOM_PROTO_VERSION_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 6, SCOPE_PACKET, _extraction_att},
	{DICOM_CALLED_AE_TITLE, DICOM_CALLED_AE_TITLE_ALIAS, MMT_STRING_DATA, 16, 10, SCOPE_PACKET, _extraction_att},
	{DICOM_CALLING_AE_TITLE, DICOM_CALLING_AE_TITLE_ALIAS, MMT_STRING_DATA, 16, 26, SCOPE_PACKET, _extraction_att},
	{DICOM_APPLICATION_CONTEXT, DICOM_APPLICATION_CONTEXT_ALIAS, MMT_STRING_DATA, 64, 0, SCOPE_PACKET, _extraction_att},
	{DICOM_PRESENTATION_CONTEXT, DICOM_PRESENTATION_CONTEXT_ALIAS, MMT_STRING_DATA, 64, 0, SCOPE_PACKET, _extraction_att},
	{DICOM_MAX_PDU_LENGTH, DICOM_MAX_PDU_LENGTH_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_IMPLEMENTATION_CLASS_UID, DICOM_IMPLEMENTATION_CLASS_UID_ALIAS, MMT_STRING_DATA, 64, 0, SCOPE_PACKET, _extraction_att},
	// P-DATA-TF attributes
	{DICOM_PDV_LENGTH, DICOM_PDV_LENGTH_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 6, SCOPE_PACKET, _extraction_att},
	{DICOM_PDV_CONTEXT, DICOM_PDV_CONTEXT_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 10, SCOPE_PACKET, _extraction_att},
	{DICOM_PDV_FLAGS, DICOM_PDV_FLAGS_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 11, SCOPE_PACKET, _extraction_att},
	{DICOM_COMMAND_GROUP_LENGTH, DICOM_COMMAND_GROUP_LENGTH_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_COMMAND_FIELD, DICOM_COMMAND_FIELD_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_PATIENT_NAME, DICOM_PATIENT_NAME_ALIAS, MMT_STRING_DATA, 64, 0, SCOPE_PACKET, _extraction_att},
	// New attributes
	{DICOM_STATUS, DICOM_STATUS_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_AFFECTED_SOP_CLASS_UID, DICOM_AFFECTED_SOP_CLASS_UID_ALIAS, MMT_STRING_DATA, 64, 0, SCOPE_PACKET, _extraction_att},
	{DICOM_MESSAGE_ID, DICOM_MESSAGE_ID_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_ABSTRACT_SYNTAX, DICOM_ABSTRACT_SYNTAX_ALIAS, MMT_STRING_DATA, 64, 0, SCOPE_PACKET, _extraction_att},
	{DICOM_TRANSFER_SYNTAX, DICOM_TRANSFER_SYNTAX_ALIAS, MMT_STRING_DATA, 64, 0, SCOPE_PACKET, _extraction_att},
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
		pos += 4 + len;
	}
	return -1;
}

/*
 * DICOM data extraction routines
 */

static int _extraction_att(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
	int dicom_offset = get_packet_offset_at_index(ipacket, proto_index);
	struct dicomhdr * hdr = (struct dicomhdr *)&ipacket->data[dicom_offset];
	int attribute_offset = extracted_data->position_in_packet;
	unsigned int packet_len = ipacket->p_hdr->caplen - dicom_offset;

	if((ipacket->p_hdr->caplen - dicom_offset) == 0) {
		return 0;
	}

	if (!mmt_check_dicom(hdr, dicom_offset, packet_len)) {
		return 0;
	}

	//depending on id of attribute to be extracted
	switch( extracted_data->field_id ){
	case DICOM_PDU_TYPE:
		*((unsigned char *) extracted_data->data) = *((unsigned char *) &ipacket->data[dicom_offset + attribute_offset]);
		break;
	case DICOM_PDU_LEN:
		*((unsigned int *) extracted_data->data) = ntohl(*((unsigned int *) & ipacket->data[dicom_offset + attribute_offset]));
		break;
	case DICOM_PROTO_VERSION:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC)
			*((unsigned short *) extracted_data->data) = ntohs(*((unsigned short *) & ipacket->data[dicom_offset + attribute_offset]));
		else return 0;
		break;
	case DICOM_CALLED_AE_TITLE:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			int start_offset = dicom_offset + attribute_offset;
			int length = dicom_attributes_metadata[DICOM_CALLED_AE_TITLE - 1].data_len;
			if (start_offset + length > (int)ipacket->p_hdr->caplen) return 0;
			memcpy(binary_data->data, &ipacket->data[start_offset], length);
			binary_data->len = length;
			binary_data->data[length] = '\0';
		} else return 0;
		break;
	case DICOM_CALLING_AE_TITLE:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			int start_offset = dicom_offset + attribute_offset;
			int length = dicom_attributes_metadata[DICOM_CALLING_AE_TITLE - 1].data_len;
			if (start_offset + length > (int)ipacket->p_hdr->caplen) return 0;
			memcpy(binary_data->data, &ipacket->data[start_offset], length);
			binary_data->len = length;
			binary_data->data[length] = '\0';
		} else return 0;
		break;
	case DICOM_APPLICATION_CONTEXT:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			// Scan variable items area (starts at offset 74) for item type 0x10
			int var_start = dicom_offset + 74;
			int var_end = dicom_offset + packet_len;
			if (var_start >= var_end) return 0;

			int item_pos = find_assoc_subitem(ipacket->data, var_start, var_end, 0x10);
			if (item_pos < 0) return 0;

			uint16_t item_len = (ipacket->data[item_pos + 2] << 8) | ipacket->data[item_pos + 3];
			int value_offset = item_pos + 4;
			if (value_offset + item_len > (int)ipacket->p_hdr->caplen) return 0;
			if (item_len > 63) item_len = 63;

			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			memcpy(binary_data->data, &ipacket->data[value_offset], item_len);
			binary_data->len = item_len;
			binary_data->data[item_len] = '\0';
		} else return 0;
		break;
	case DICOM_PRESENTATION_CONTEXT:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			// Scan variable items area (starts at offset 74) for item type 0x20 (RQ) or 0x21 (AC)
			int var_start = dicom_offset + 74;
			int var_end = dicom_offset + packet_len;
			if (var_start >= var_end) return 0;

			uint8_t pres_type = (hdr->pdu_type == A_ASSOCIATE_RQ) ? 0x20 : 0x21;
			int item_pos = find_assoc_subitem(ipacket->data, var_start, var_end, pres_type);
			if (item_pos < 0) return 0;

			uint16_t item_len = (ipacket->data[item_pos + 2] << 8) | ipacket->data[item_pos + 3];
			int value_offset = item_pos + 4;
			if (value_offset + item_len > (int)ipacket->p_hdr->caplen) return 0;

			// Inside the Presentation Context item, find the Abstract Syntax sub-item (type 0x30)
			int sub_pos = find_assoc_subitem(ipacket->data, value_offset + 4, value_offset + item_len, 0x30);
			if (sub_pos < 0) return 0;

			uint16_t sub_len = (ipacket->data[sub_pos + 2] << 8) | ipacket->data[sub_pos + 3];
			int sub_value_offset = sub_pos + 4;
			if (sub_value_offset + sub_len > (int)ipacket->p_hdr->caplen) return 0;
			if (sub_len > 63) sub_len = 63;

			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			memcpy(binary_data->data, &ipacket->data[sub_value_offset], sub_len);
			binary_data->len = sub_len;
			binary_data->data[sub_len] = '\0';
		} else return 0;
		break;
	case DICOM_MAX_PDU_LENGTH:
	case DICOM_IMPLEMENTATION_CLASS_UID:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			// Scan variable items area for User Info item (type 0x50)
			int var_start = dicom_offset + 74;
			int var_end = dicom_offset + packet_len;
			if (var_start >= var_end) return 0;

			int user_info_pos = find_assoc_subitem(ipacket->data, var_start, var_end, 0x50);
			if (user_info_pos < 0) return 0;

			uint16_t user_info_len = (ipacket->data[user_info_pos + 2] << 8) | ipacket->data[user_info_pos + 3];
			int ui_value_start = user_info_pos + 4;
			int ui_value_end = ui_value_start + user_info_len;
			if (ui_value_end > (int)ipacket->p_hdr->caplen) ui_value_end = ipacket->p_hdr->caplen;

			if(extracted_data->field_id == DICOM_MAX_PDU_LENGTH) {
				// Search for Max PDU Length sub-item (type 0x51) inside User Info
				int sub_pos = find_assoc_subitem(ipacket->data, ui_value_start, ui_value_end, 0x51);
				if (sub_pos < 0) return 0;

				// Sub-item: type(1) + reserved(1) + length(2 BE) + value(4 bytes BE)
				int val_offset = sub_pos + 4;
				if (val_offset + 4 > (int)ipacket->p_hdr->caplen) return 0;
				*((uint32_t *)extracted_data->data) = ntohl(*((uint32_t *)&ipacket->data[val_offset]));
			}
			else if(extracted_data->field_id == DICOM_IMPLEMENTATION_CLASS_UID) {
				// Search for Implementation Class UID sub-item (type 0x52) inside User Info
				int sub_pos = find_assoc_subitem(ipacket->data, ui_value_start, ui_value_end, 0x52);
				if (sub_pos < 0) return 0;

				uint16_t sub_len = (ipacket->data[sub_pos + 2] << 8) | ipacket->data[sub_pos + 3];
				int sub_value_offset = sub_pos + 4;
				if (sub_value_offset + sub_len > (int)ipacket->p_hdr->caplen) return 0;
				if (sub_len > 63) sub_len = 63;

				mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
				memcpy(binary_data->data, &ipacket->data[sub_value_offset], sub_len);
				binary_data->len = sub_len;
				binary_data->data[sub_len] = '\0';
			}
		} else return 0;
		break;
	case DICOM_PDV_LENGTH:
		if(hdr->pdu_type == P_DATA_TF) {
			int off = dicom_offset + 6;
			if (off + 4 > (int)ipacket->p_hdr->caplen) return 0;
			*((unsigned int *)extracted_data->data) = ntohl(*((unsigned int *)&ipacket->data[off]));
		} else return 0;
		break;
	case DICOM_PDV_CONTEXT:
		if(hdr->pdu_type == P_DATA_TF) {
			int off = dicom_offset + 10;
			if (off + 1 > (int)ipacket->p_hdr->caplen) return 0;
			*((unsigned char *)extracted_data->data) = ipacket->data[off];
		} else return 0;
		break;
	case DICOM_PDV_FLAGS:
		if(hdr->pdu_type == P_DATA_TF) {
			int off = dicom_offset + 11;
			if (off + 1 > (int)ipacket->p_hdr->caplen) return 0;
			*((unsigned char *)extracted_data->data) = ipacket->data[off];
		} else return 0;
		break;
	case DICOM_COMMAND_GROUP_LENGTH:
		if (hdr->pdu_type == P_DATA_TF) {
			// DIMSE command data starts at dicom_offset + 12
			int dimse_start = dicom_offset + 12;
			int dimse_end = dicom_offset + packet_len;
			if (dimse_start >= dimse_end) return 0;

			// Search for tag (0000,0000) = Command Group Length
			int tag_pos = find_dimse_tag(ipacket->data, dimse_start, dimse_end, 0x0000, 0x0000);
			if (tag_pos < 0) return 0;

			// Tag(4) + VR/Length(4) + value(4) — implicit VR: tag(4) + length(4) + value(4)
			int val_offset = tag_pos + 8;
			if (val_offset + 4 > (int)ipacket->p_hdr->caplen) return 0;

			// Little-endian 4-byte value
			uint32_t group_length = ipacket->data[val_offset] |
			                        (ipacket->data[val_offset + 1] << 8) |
			                        (ipacket->data[val_offset + 2] << 16) |
			                        (ipacket->data[val_offset + 3] << 24);
			*((uint32_t *)extracted_data->data) = group_length;
		} else return 0;
		break;
	case DICOM_COMMAND_FIELD:
		if (hdr->pdu_type == P_DATA_TF) {
			// DIMSE command data starts at dicom_offset + 12
			int dimse_start = dicom_offset + 12;
			int dimse_end = dicom_offset + packet_len;
			if (dimse_start >= dimse_end) return 0;

			// Search for tag (0000,0100) = Command Field
			int tag_pos = find_dimse_tag(ipacket->data, dimse_start, dimse_end, 0x0000, 0x0100);
			if (tag_pos < 0) return 0;

			// Tag(4) + length(4) + value(2) — implicit VR uses 4-byte length
			int val_offset = tag_pos + 8;
			if (val_offset + 2 > (int)ipacket->p_hdr->caplen) return 0;

			uint16_t command_field = ipacket->data[val_offset] |
			                         (ipacket->data[val_offset + 1] << 8);
			*((uint16_t *)extracted_data->data) = command_field;
		} else return 0;
		break;
	case DICOM_PATIENT_NAME:
		if(hdr->pdu_type == P_DATA_TF) {
			// Check PDV flags: bit 1 = 0 means dataset content
			int flags_off = dicom_offset + 11;
			if (flags_off >= (int)ipacket->p_hdr->caplen) return 0;
			uint8_t pdv_flags = ipacket->data[flags_off];
			if (pdv_flags & 0x01) return 0; // This is command data, not dataset

			// Scan P-DATA payload for Patient Name tag (0010,0010)
			int data_start = dicom_offset + 12;
			int data_end = dicom_offset + packet_len;
			if (data_start >= data_end) return 0;

			int tag_pos = find_dimse_tag(ipacket->data, data_start, data_end, 0x0010, 0x0010);
			if (tag_pos < 0) return 0;

			// Parse VR and length
			int vr_offset = tag_pos + 4;
			if (vr_offset + 2 > (int)ipacket->p_hdr->caplen) return 0;

			char vr0 = ipacket->data[vr_offset];
			char vr1 = ipacket->data[vr_offset + 1];
			int length_offset;
			uint16_t length;

			if (vr0 == 'P' && vr1 == 'N') {
				// Explicit VR PN: tag(4) + VR(2) + length(2 LE)
				length_offset = vr_offset + 2;
				if (length_offset + 2 > (int)ipacket->p_hdr->caplen) return 0;
				length = ipacket->data[length_offset] | (ipacket->data[length_offset + 1] << 8);
				length_offset += 2;
			} else {
				// Implicit VR: tag(4) + length(4 LE)
				length_offset = tag_pos + 4;
				if (length_offset + 4 > (int)ipacket->p_hdr->caplen) return 0;
				length = ipacket->data[length_offset] | (ipacket->data[length_offset + 1] << 8);
				length_offset += 4;
			}

			if (length == 0 || length > 63) {
				if (length > 63) length = 63;
				if (length == 0) return 0;
			}
			if (length_offset + length > (int)ipacket->p_hdr->caplen) return 0;

			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			memcpy(binary_data->data, &ipacket->data[length_offset], length);
			binary_data->len = length;
			binary_data->data[length] = '\0';
		} else return 0;
		break;
	case DICOM_STATUS:
		if (hdr->pdu_type == P_DATA_TF) {
			int dimse_start = dicom_offset + 12;
			int dimse_end = dicom_offset + packet_len;
			if (dimse_start >= dimse_end) return 0;

			// Search for tag (0000,0900) = Status
			int tag_pos = find_dimse_tag(ipacket->data, dimse_start, dimse_end, 0x0000, 0x0900);
			if (tag_pos < 0) return 0;

			int val_offset = tag_pos + 8; // tag(4) + length(4)
			if (val_offset + 2 > (int)ipacket->p_hdr->caplen) return 0;

			uint16_t status = ipacket->data[val_offset] | (ipacket->data[val_offset + 1] << 8);
			*((uint16_t *)extracted_data->data) = status;
		} else return 0;
		break;
	case DICOM_AFFECTED_SOP_CLASS_UID:
		if (hdr->pdu_type == P_DATA_TF) {
			int dimse_start = dicom_offset + 12;
			int dimse_end = dicom_offset + packet_len;
			if (dimse_start >= dimse_end) return 0;

			// Search for tag (0000,0002) = Affected SOP Class UID
			int tag_pos = find_dimse_tag(ipacket->data, dimse_start, dimse_end, 0x0000, 0x0002);
			if (tag_pos < 0) return 0;

			// Implicit VR: tag(4) + length(4 LE) + value
			int len_offset = tag_pos + 4;
			if (len_offset + 4 > (int)ipacket->p_hdr->caplen) return 0;
			uint32_t val_len = ipacket->data[len_offset] |
			                   (ipacket->data[len_offset + 1] << 8) |
			                   (ipacket->data[len_offset + 2] << 16) |
			                   (ipacket->data[len_offset + 3] << 24);
			int val_offset = len_offset + 4;
			if (val_len == 0 || val_offset + (int)val_len > (int)ipacket->p_hdr->caplen) return 0;
			if (val_len > 63) val_len = 63;

			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			memcpy(binary_data->data, &ipacket->data[val_offset], val_len);
			binary_data->len = val_len;
			binary_data->data[val_len] = '\0';
		} else return 0;
		break;
	case DICOM_MESSAGE_ID:
		if (hdr->pdu_type == P_DATA_TF) {
			int dimse_start = dicom_offset + 12;
			int dimse_end = dicom_offset + packet_len;
			if (dimse_start >= dimse_end) return 0;

			// Search for tag (0000,0110) = Message ID
			int tag_pos = find_dimse_tag(ipacket->data, dimse_start, dimse_end, 0x0000, 0x0110);
			if (tag_pos < 0) return 0;

			int val_offset = tag_pos + 8; // tag(4) + length(4)
			if (val_offset + 2 > (int)ipacket->p_hdr->caplen) return 0;

			uint16_t message_id = ipacket->data[val_offset] | (ipacket->data[val_offset + 1] << 8);
			*((uint16_t *)extracted_data->data) = message_id;
		} else return 0;
		break;
	case DICOM_ABSTRACT_SYNTAX:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			// Scan variable items area for Abstract Syntax sub-item (type 0x30)
			// This can appear inside Presentation Context items, but also directly
			// First find a Presentation Context item, then find 0x30 inside it
			int var_start = dicom_offset + 74;
			int var_end = dicom_offset + packet_len;
			if (var_start >= var_end) return 0;

			uint8_t pres_type = (hdr->pdu_type == A_ASSOCIATE_RQ) ? 0x20 : 0x21;
			int pres_pos = find_assoc_subitem(ipacket->data, var_start, var_end, pres_type);
			if (pres_pos < 0) return 0;

			uint16_t pres_len = (ipacket->data[pres_pos + 2] << 8) | ipacket->data[pres_pos + 3];
			int pres_value_start = pres_pos + 4;
			int pres_value_end = pres_value_start + pres_len;
			if (pres_value_end > (int)ipacket->p_hdr->caplen) pres_value_end = ipacket->p_hdr->caplen;

			// Skip Presentation Context ID (1 byte) + reserved (3 bytes) = 4 bytes
			int sub_start = pres_value_start + 4;
			int sub_pos = find_assoc_subitem(ipacket->data, sub_start, pres_value_end, 0x30);
			if (sub_pos < 0) return 0;

			uint16_t sub_len = (ipacket->data[sub_pos + 2] << 8) | ipacket->data[sub_pos + 3];
			int sub_val = sub_pos + 4;
			if (sub_val + sub_len > (int)ipacket->p_hdr->caplen) return 0;
			if (sub_len > 63) sub_len = 63;

			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			memcpy(binary_data->data, &ipacket->data[sub_val], sub_len);
			binary_data->len = sub_len;
			binary_data->data[sub_len] = '\0';
		} else return 0;
		break;
	case DICOM_TRANSFER_SYNTAX:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			// Find Presentation Context item, then find Transfer Syntax sub-item (type 0x40)
			int var_start = dicom_offset + 74;
			int var_end = dicom_offset + packet_len;
			if (var_start >= var_end) return 0;

			uint8_t pres_type = (hdr->pdu_type == A_ASSOCIATE_RQ) ? 0x20 : 0x21;
			int pres_pos = find_assoc_subitem(ipacket->data, var_start, var_end, pres_type);
			if (pres_pos < 0) return 0;

			uint16_t pres_len = (ipacket->data[pres_pos + 2] << 8) | ipacket->data[pres_pos + 3];
			int pres_value_start = pres_pos + 4;
			int pres_value_end = pres_value_start + pres_len;
			if (pres_value_end > (int)ipacket->p_hdr->caplen) pres_value_end = ipacket->p_hdr->caplen;

			// Skip Presentation Context ID (1 byte) + reserved (3 bytes) = 4 bytes
			int sub_start = pres_value_start + 4;
			int sub_pos = find_assoc_subitem(ipacket->data, sub_start, pres_value_end, 0x40);
			if (sub_pos < 0) return 0;

			uint16_t sub_len = (ipacket->data[sub_pos + 2] << 8) | ipacket->data[sub_pos + 3];
			int sub_val = sub_pos + 4;
			if (sub_val + sub_len > (int)ipacket->p_hdr->caplen) return 0;
			if (sub_len > 63) sub_len = 63;

			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			memcpy(binary_data->data, &ipacket->data[sub_val], sub_len);
			binary_data->len = sub_len;
			binary_data->data[sub_len] = '\0';
		} else return 0;
		break;
	case DICOM_DATA_SET_TYPE:
		if (hdr->pdu_type == P_DATA_TF) {
			int dimse_start = dicom_offset + 12;
			int dimse_end = dicom_offset + packet_len;
			if (dimse_start >= dimse_end) return 0;

			// Search for tag (0000,0800) = Data Set Type
			int tag_pos = find_dimse_tag(ipacket->data, dimse_start, dimse_end, 0x0000, 0x0800);
			if (tag_pos < 0) return 0;

			int val_offset = tag_pos + 8; // tag(4) + length(4)
			if (val_offset + 2 > (int)ipacket->p_hdr->caplen) return 0;

			uint16_t ds_type = ipacket->data[val_offset] | (ipacket->data[val_offset + 1] << 8);
			*((uint16_t *)extracted_data->data) = ds_type;
		} else return 0;
		break;
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
	if (header->reserved != 0) {
		return 0;
	}
	return 1;
}

int mmt_check_dicom_payload(struct dicomhdr* header, unsigned int packet_len) {
	if(packet_len < PROTO_DICOM_HDRLEN + DICOM_PAYLOAD_MIN_LEN) return 0;
	if(ntohl(header->pdu_len) != packet_len - PROTO_DICOM_HDRLEN) return 0;
	return 1;
}

int mmt_check_dicom(struct dicomhdr * header, int offset, int packet_len) {
	return mmt_check_dicom_hdr(header) &&
		mmt_check_dicom_payload(header, packet_len);
}

int mmt_check_dicom_tcp(ipacket_t * ipacket, unsigned index) {
	int l3_offset = get_packet_offset_at_index(ipacket, index);
    int dicom_offset = get_packet_offset_at_index(ipacket, index + 1);

	unsigned int packet_len = ipacket->p_hdr->caplen - dicom_offset;
	struct dicomhdr * dicom_header = (struct dicomhdr *)&ipacket->data[dicom_offset];
	if (!mmt_check_dicom(dicom_header, dicom_offset, packet_len))
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
			fprintf(stderr, "\n[err] init_dicom_proto_struct - cannot register_classification_function_with_parent_protocol: PROTO_TCP\n");
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
