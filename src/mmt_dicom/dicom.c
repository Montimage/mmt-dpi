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
	{DICOM_IMPLEMENTATION_UID, DICOM_IMPLEMENTATION_UID_ALIAS, MMT_STRING_DATA, 32, 303, SCOPE_PACKET, _extraction_att}
};

/*
 * DICOM data extraction routines
 */

static int _extraction_att(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
	int dicom_offset = get_packet_offset_at_index(ipacket, proto_index);
	struct dicomhdr * hdr = (struct dicomhdr *)&ipacket->data[dicom_offset];
	int attribute_offset = extracted_data->position_in_packet;
	unsigned int packet_len = ipacket->p_hdr->caplen - dicom_offset;

	if((ipacket->p_hdr->caplen - dicom_offset) == 0) return 0;

	if (!mmt_check_dicom(hdr, dicom_offset, packet_len)) return 0;

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
	case DICOM_IMPLEMENTATION_UID:
		if(hdr->pdu_type == A_ASSOCIATE_RQ || hdr->pdu_type == A_ASSOCIATE_AC) {
			mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)extracted_data->data;

			// Different tag patterns based on PDU type
			const uint8_t tag_rq[] = {0x52, 0x00, 0x00, 0x20}; // For A_ASSOCIATE_RQ
			const uint8_t tag_ac[] = {0x52, 0x00, 0x00, 0x1b}; // For A_ASSOCIATE_AC
			const uint8_t *tag = (hdr->pdu_type == A_ASSOCIATE_RQ) ? tag_rq : tag_ac;
			int found = 0;

			// Expected UID length based on PDU type
			const int rq_len = 32;  // A_ASSOCIATE_RQ length
			const int ac_len = 27;  // A_ASSOCIATE_AC length
			int uid_len = (hdr->pdu_type == A_ASSOCIATE_RQ) ? rq_len : ac_len;

			// Search for the tag pattern in the packet
			for(int i = 0; i < packet_len - 4 - 10; i++) {
				if(memcmp(&ipacket->data[dicom_offset + i], tag, 4) == 0) {
					// Found the tag, extract up to uid_len bytes or until non-printable character
					int extract_len = uid_len;
					if(dicom_offset + i + 4 + extract_len > ipacket->p_hdr->caplen) {
						extract_len = ipacket->p_hdr->caplen - (dicom_offset + i + 4);
					}

					// Find valid string length (stop at non-printable chars)
					int valid_len = 0;
					for(int j = 0; j < extract_len; j++) {
						char c = ipacket->data[dicom_offset + i + 4 + j];
						if(c >= 32 && c <= 126) {
							valid_len = j + 1;
						} else {
							break;
						}
					}

					// Copy data if we found valid characters
					if(valid_len > 0) {
						memcpy(binary_data->data, &ipacket->data[dicom_offset + i + 4], valid_len);
						binary_data->len = valid_len;
						binary_data->data[valid_len] = '\0';
						found = 1;
						break;
					}
				}
			}
			//printf("Extracted Implementation UID: %s\n", binary_data->data);
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
	if (header->pdu_type < A_ASSOCIATE_RQ || header->pdu_type > A_ABORT) return 0; // Check the first condition: DICOM types: 1 - 7
	if (header->reserved != 0) return 0; // Check the second condition: Byte 0 after type.
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
