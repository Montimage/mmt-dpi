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
	{DICOM_APPLICATION_CONTEXT, DICOM_APPLICATION_CONTEXT_ALIAS, MMT_STRING_DATA, 21, 78, SCOPE_PACKET, _extraction_att},
	{DICOM_PRESENTATION_CONTEXT, DICOM_PRESENTATION_CONTEXT_ALIAS, MMT_STRING_DATA, 17, 111, SCOPE_PACKET, _extraction_att},
	{DICOM_MAX_PDU_LENGTH, DICOM_MAX_PDU_LENGTH_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 0, SCOPE_PACKET, _extraction_att},
	{DICOM_IMPLEMENTATION_CLASS_UID, DICOM_IMPLEMENTATION_CLASS_UID_ALIAS, MMT_STRING_DATA, 32, 0, SCOPE_PACKET, _extraction_att},
	// P-DATA-TF attributes
	{DICOM_PDV_LENGTH, DICOM_PDV_LENGTH_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 6, SCOPE_PACKET, _extraction_att},
	{DICOM_PDV_CONTEXT, DICOM_PDV_CONTEXT_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 10, SCOPE_PACKET, _extraction_att},
	{DICOM_PDV_FLAGS, DICOM_PDV_FLAGS_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 11, SCOPE_PACKET, _extraction_att},
	{DICOM_COMMAND_GROUP_LENGTH, DICOM_COMMAND_GROUP_LENGTH_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 20, SCOPE_PACKET, _extraction_att},
	{DICOM_COMMAND_FIELD, DICOM_COMMAND_FIELD_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 68, SCOPE_PACKET, _extraction_att},
};

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
		break;
	case DICOM_CALLED_AE_TITLE:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			int start_offset = dicom_offset + attribute_offset;
			int length = dicom_attributes_metadata[DICOM_CALLED_AE_TITLE].data_len;
			memcpy(binary_data->data, &ipacket->data[start_offset], length);
			binary_data->len = length;
			binary_data->data[length] = '\0';
			//printf("Extracted Called AE Title: %s\n", binary_data->data);
		}
		break;
	case DICOM_CALLING_AE_TITLE:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			int start_offset = dicom_offset + attribute_offset;
			int length = dicom_attributes_metadata[DICOM_CALLING_AE_TITLE].data_len;
			memcpy(binary_data->data, &ipacket->data[start_offset], length);
			binary_data->len = length;
			binary_data->data[length] = '\0';
			//printf("Extracted Calling AE Title: %s\n", binary_data->data);
		}
		break;
	case DICOM_APPLICATION_CONTEXT:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			int start_offset = dicom_offset + attribute_offset;
			int length = dicom_attributes_metadata[DICOM_APPLICATION_CONTEXT].data_len;
			memcpy(binary_data->data, &ipacket->data[start_offset], length);
			binary_data->len = length;
			binary_data->data[length] = '\0';
			//printf("Extracted Application Context Item: %s\n", binary_data->data);
		}
		break;
	case DICOM_PRESENTATION_CONTEXT:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;
			int start_offset = dicom_offset + attribute_offset;
			int length = dicom_attributes_metadata[DICOM_PRESENTATION_CONTEXT].data_len;
			memcpy(binary_data->data, &ipacket->data[start_offset], length);
			binary_data->len = length;
			binary_data->data[length] = '\0';
			//printf("Extracted Presentation Context Item: %s\n", binary_data->data);
		}
		break;
	case DICOM_MAX_PDU_LENGTH:
	case DICOM_IMPLEMENTATION_CLASS_UID:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			// First search for User Info Field
			const uint8_t user_info_tag_rq[] = {0x50, 0x00, 0x00, 0x3e}; // For A_ASSOCIATE_RQ
			const uint8_t user_info_tag_ac[] = {0x50, 0x00, 0x00, 0x3a}; // For A_ASSOCIATE_AC
			const uint8_t *user_info_tag = (hdr->pdu_type == A_ASSOCIATE_RQ) ? user_info_tag_rq : user_info_tag_ac;
			int user_info_found = 0;
			int user_info_offset = 0;

			// Search for User Info tag
			for(int i = 0; i < packet_len - 8; i++) {
				if(memcmp(&ipacket->data[dicom_offset + i], user_info_tag, 4) == 0) {
					user_info_found = 1;
					user_info_offset = i;
					break;
				}
			}

			if(!user_info_found) {
				// Can't find User Info, so can't extract fields
				return 0;
			}

			// Now that we found User Info, use fixed offsets for each attribute
			if(extracted_data->field_id == DICOM_MAX_PDU_LENGTH) {
				// Max PDU Length is at offset user_info + 8
				int max_pdu_offset = user_info_offset + 8;

				if(dicom_offset + max_pdu_offset + 4 <= ipacket->p_hdr->caplen) {
					*((unsigned int *) extracted_data->data) = ntohl(*((unsigned int *) & ipacket->data[dicom_offset + max_pdu_offset]));
				} else {
					return 0; // Not enough data
				}
			}
			else if(extracted_data->field_id == DICOM_IMPLEMENTATION_CLASS_UID) {
				// Implementation Class UID is at offset user_info + 16
				int uid_offset = user_info_offset + 16;
				mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;

				const int rq_len = 32;  // A_ASSOCIATE_RQ length
				const int ac_len = 27;  // A_ASSOCIATE_AC length
				int extract_len = (hdr->pdu_type == A_ASSOCIATE_RQ) ? rq_len : ac_len;

				if(dicom_offset + uid_offset + extract_len > ipacket->p_hdr->caplen) {
					extract_len = ipacket->p_hdr->caplen - (dicom_offset + uid_offset);
					if(extract_len <= 0) return 0; // Not enough data
				}

				// Copy printable characters only
				int valid_len = 0;
				for(int j = 0; j < extract_len; j++) {
					char c = ipacket->data[dicom_offset + uid_offset + j];
					if(c >= 32 && c <= 126) {
						valid_len = j + 1;
					} else {
						break;
					}
				}

				if(valid_len > 0) {
					memcpy(binary_data->data, &ipacket->data[dicom_offset + uid_offset], valid_len);
					binary_data->len = valid_len;
					binary_data->data[valid_len] = '\0';
				} else {
					return 0; // No valid characters
				}
			}
		}
		break;
	case DICOM_PDV_LENGTH:
		if(hdr->pdu_type == P_DATA_TF) {
			*((unsigned int *)extracted_data->data) = ntohl(*((unsigned int *)&ipacket->data[dicom_offset + attribute_offset]));
		}
		break;
	case DICOM_PDV_CONTEXT:
		if(hdr->pdu_type == P_DATA_TF) {
			*((unsigned char *)extracted_data->data) = *((unsigned char *)&ipacket->data[dicom_offset + attribute_offset]);
		}
		break;
	case DICOM_PDV_FLAGS:
		if(hdr->pdu_type == P_DATA_TF) {
			*((unsigned char *)extracted_data->data) = *((unsigned char *)&ipacket->data[dicom_offset + attribute_offset]);
		}
		break;
	case DICOM_COMMAND_GROUP_LENGTH:
		if (hdr->pdu_type == P_DATA_TF) {
			// Print hex values for debugging
			printf("Command Group Length bytes: ");
			for(int i = 0; i < 4; i++) {
				printf("%02x ", ipacket->data[dicom_offset + attribute_offset + i]);
			}
			printf("\n");

			uint32_t group_length = ipacket->data[dicom_offset + attribute_offset];
			*((uint32_t *)extracted_data->data) = group_length;
		}
		break;
	case DICOM_COMMAND_FIELD:
		if (hdr->pdu_type == P_DATA_TF) {
			// Print hex values for debugging
			printf("Command Field bytes: ");
			for(int i = 0; i < 2; i++) {
				printf("%02x ", ipacket->data[dicom_offset + attribute_offset + i]);
			}
			printf("\n");

			// Command Field is 2 bytes in little-endian, manually construct the value
			uint16_t command_field = (ipacket->data[dicom_offset + attribute_offset + 1] << 8) |
			                         ipacket->data[dicom_offset + attribute_offset];
			*((uint16_t *)extracted_data->data) = command_field;

			// Print the command type for debugging
			printf("Command Field value: 0x%04X - ", command_field);
			switch(command_field) {
				case DICOM_C_STORE_RQ:         printf("C-STORE-RQ\n"); break;
				case DICOM_C_STORE_RSP:        printf("C-STORE-RSP\n"); break;
				case DICOM_C_GET_RQ:           printf("C-GET-RQ\n"); break;
				case DICOM_C_GET_RSP:          printf("C-GET-RSP\n"); break;
				case DICOM_C_FIND_RQ:          printf("C-FIND-RQ\n"); break;
				case DICOM_C_FIND_RSP:         printf("C-FIND-RSP\n"); break;
				case DICOM_C_MOVE_RQ:          printf("C-MOVE-RQ\n"); break;
				case DICOM_C_MOVE_RSP:         printf("C-MOVE-RSP\n"); break;
				case DICOM_C_ECHO_RQ:          printf("C-ECHO-RQ\n"); break;
				case DICOM_C_ECHO_RSP:         printf("C-ECHO-RSP\n"); break;
				case DICOM_N_EVENT_REPORT_RQ:  printf("N-EVENT-REPORT-RQ\n"); break;
				case DICOM_N_EVENT_REPORT_RSP: printf("N-EVENT-REPORT-RSP\n"); break;
				case DICOM_N_GET_RQ:           printf("N-GET-RQ\n"); break;
				case DICOM_N_GET_RSP:          printf("N-GET-RSP\n"); break;
				case DICOM_N_SET_RQ:           printf("N-SET-RQ\n"); break;
				case DICOM_N_SET_RSP:          printf("N-SET-RSP\n"); break;
				case DICOM_N_ACTION_RQ:        printf("N-ACTION-RQ\n"); break;
				case DICOM_N_ACTION_RSP:       printf("N-ACTION-RSP\n"); break;
				case DICOM_N_CREATE_RQ:        printf("N-CREATE-RQ\n"); break;
				case DICOM_N_CREATE_RSP:       printf("N-CREATE-RSP\n"); break;
				case DICOM_N_DELETE_RQ:        printf("N-DELETE-RQ\n"); break;
				case DICOM_N_DELETE_RSP:       printf("N-DELETE-RSP\n"); break;
				case DICOM_C_CANCEL_RQ:        printf("C-CANCEL-RQ\n"); break;
				default:                       printf("Unknown Command\n"); break;
			}
		}
		break;
	default:
		printf("Unknown attribute id %d.%d", extracted_data->proto_id, extracted_data->field_id );
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
	// Accept any PDU type for now to debug
	if (header->pdu_type < 1 || header->pdu_type > 7) {
		//printf("Invalid PDU type: %d\n", header->pdu_type);
		return 0;
	}
	if (header->reserved != 0) {
		//printf("Invalid reserved byte: %d\n", header->reserved);
		return 0;
	}
	return 1;
}

int mmt_check_dicom_payload(struct dicomhdr* header, unsigned int packet_len) {
	//printf("DICOM: TYPE= %u LEN= %u\n", header->pdu_type, packet_len);
	// Dicom packets have at least a payload of size 4
	if(packet_len < PROTO_DICOM_HDRLEN + DICOM_PAYLOAD_MIN_LEN) return 0;
	// Check the second condition: PDU length
	if(ntohs(header->pdu_len) != packet_len - PROTO_DICOM_HDRLEN) return 0;
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
	//printf("DICOM: found DICOM packet %lu\n",ipacket->packet_id);
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
		// DICOM can be classified after HTTP -> HTTP 10 DICOM 50
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
#endif //CORE
