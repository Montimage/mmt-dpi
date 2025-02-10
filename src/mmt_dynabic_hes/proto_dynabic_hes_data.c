/*
 * proto_ocpp_data.c
 *
 *  Created on: Nov 20, 2024
 *      Author: vietpham
 */


#include "mmt_dynabic_hes_internal.h"
#include <string.h>

static int dynabic_hes_data_classify_next_proto(ipacket_t *packet, unsigned index) {
	int offset = get_packet_offset_at_index(packet, index);
	const int data_len = packet->p_hdr->caplen - offset;
	const char* data = (char *)&packet->data[offset];
	if( data_len <= 0 )
		return 0;
	//started by "timestamp" ??
	if( strncmp("timestamp", data, 9) != 0 )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_DYNABIC_HES_DATA;
	retval.offset = 0;
	retval.status = Classified;
	return set_classified_proto(packet, index + 1, retval);
	return 0;
}

//get the pointer to the position right after the first occurrence of "sub" in "main"
static inline const char *_get_pos( int main_length, const char *main, const char *sub ){
	int i, j;
	if( main == NULL || sub == NULL || main_length == 0 )
		return NULL;

	const size_t sub_length = strlen( sub );
	for( i=0; i<main_length; i++ ){
		for( j=0; j<sub_length; j++ )
			if( i + j >= main_length || main[i+j] != sub[j] )
				break;
		//find a full sub
		if( j == sub_length )
			return & main[i+j];
	}
	return NULL;
}

static inline void _assign_uint32_t(const char* ptr, attribute_t * extracted_data){
	if( ptr )
		*((uint32_t *) extracted_data->data) = (uint32_t)atol( ptr );
	else
		*((uint32_t *) extracted_data->data) = 0;
}

// static inline void _assign_float(const char* ptr, attribute_t * extracted_data){
// 	if( ptr )
// 		*((float *) extracted_data->data) = atof( ptr );
// 	else
// 		*((float *) extracted_data->data) = 0;
// }

static inline void _assign_string(const char* ptr, attribute_t *extracted_data, char delimiter) {
    if (ptr) {
        mmt_binary_data_t *b = (mmt_binary_data_t *)extracted_data->data;
        
        // Find the first occurrence of the delimiter in the string
        const char *delimiter_pos = strchr(ptr, delimiter);

        size_t length;
        if (delimiter_pos) {
            // Calculate the length of the substring up to the delimiter
            length = delimiter_pos - ptr;
        } else {
            // If the delimiter is not found, use the full string length or limit to 15
            length = strlen(ptr);
            if (length > 15) length = 15;
        }

        // Set the length of data in the binary data structure
        b->len = length;
        
        // Ensure the length does not exceed the size of the data array
        if (b->len > sizeof(b->data) - 1) {
            b->len = sizeof(b->data) - 1;
        }

        // Copy the substring up to the delimiter
        memcpy(b->data, ptr, b->len);

        // Ensure null termination
        b->data[b->len] = '\0';
    } else {
        // If ptr is NULL, assign an empty string
        mmt_binary_data_t *b = (mmt_binary_data_t *)extracted_data->data;
        b->len = 0;
        //strcpy(b->data, "");
    }
}

static int _extraction_att(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {
	int offset = get_packet_offset_at_index(packet, proto_index);
	const int data_len = packet->p_hdr->caplen - offset;
	const char* data = (char *)&packet->data[offset];
	const char* ptr;
	if( data_len <= 0 )
		return 0;

	switch (extracted_data->field_id) {
    case DYNABIC_HES_DATA_TIMESTAMP:
        ptr = _get_pos(data_len, data, "timestamp:");
        _assign_string(ptr, extracted_data, ',');
        break;
	
	case DYNABIC_HES_DATA_PROTOCOL:
        ptr = _get_pos(data_len, data, "protocol:");
        _assign_string(ptr, extracted_data, ',');
        break;

	case DYNABIC_HES_DATA_SRC_IP:
        ptr = _get_pos(data_len, data, "src_ip:");
        _assign_string(ptr, extracted_data, ',');
        break;

	case DYNABIC_HES_DATA_DST_IP:
        ptr = _get_pos(data_len, data, "dst_ip:");
        _assign_string(ptr, extracted_data, ',');
        break;
	
	case DYNABIC_HES_DATA_SRC_PORT:
        ptr = _get_pos(data_len, data, "src_port:");
        _assign_uint32_t(ptr, extracted_data);
        break;
	
	case DYNABIC_HES_DATA_DST_PORT:
        ptr = _get_pos(data_len, data, "dst_port:");
        _assign_uint32_t(ptr, extracted_data);
        break;
	
	case DYNABIC_HES_DATA_LENGTH:
        ptr = _get_pos(data_len, data, "length:");
        _assign_uint32_t(ptr, extracted_data);
        break;
	
	case DYNABIC_HES_DATA_TCP_FLAGS:
        ptr = _get_pos(data_len, data, "tcp_flags:");
        _assign_string(ptr, extracted_data, ',');
        break;
	
	case DYNABIC_HES_DATA_PAYLOAD_SIZE:
        ptr = _get_pos(data_len, data, "payload_size:");
        _assign_uint32_t(ptr, extracted_data);
        break;
	
	default:
        // Handle unknown field IDs if necessary
        break;
	}

	return 1;
}

attribute_metadata_t _attributes_metadata[] = {
    {DYNABIC_HES_DATA_TIMESTAMP,		DYNABIC_HES_DATA_TIMESTAMP_ALIAS, 		MMT_STRING_DATA,		BINARY_64DATA_LEN,		POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
	{DYNABIC_HES_DATA_PROTOCOL,			DYNABIC_HES_DATA_PROTOCOL_ALIAS,		MMT_STRING_DATA,		BINARY_64DATA_LEN,		POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
	{DYNABIC_HES_DATA_SRC_IP,			DYNABIC_HES_DATA_SRC_IP_ALIAS,			MMT_STRING_DATA,		BINARY_64DATA_LEN,		POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
	{DYNABIC_HES_DATA_DST_IP,			DYNABIC_HES_DATA_DST_IP_ALIAS,			MMT_STRING_DATA,		BINARY_64DATA_LEN,		POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
	{DYNABIC_HES_DATA_SRC_PORT,			DYNABIC_HES_DATA_SRC_PORT_ALIAS,		MMT_U32_DATA,			sizeof(uint32_t),		POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
	{DYNABIC_HES_DATA_DST_PORT,			DYNABIC_HES_DATA_DST_PORT_ALIAS,		MMT_U32_DATA,			sizeof(uint32_t),		POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {DYNABIC_HES_DATA_LENGTH,			DYNABIC_HES_DATA_LENGTH_ALIAS,			MMT_U32_DATA,			sizeof(uint32_t),		POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {DYNABIC_HES_DATA_TCP_FLAGS,		DYNABIC_HES_DATA_TCP_FLAGS_ALIAS,		MMT_STRING_DATA,		BINARY_64DATA_LEN,		POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
	{DYNABIC_HES_DATA_PAYLOAD_SIZE,		DYNABIC_HES_DATA_PAYLOAD_SIZE_ALIAS,	MMT_U32_DATA,			sizeof(uint32_t),		POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
};

static classified_proto_t dynabic_hes_data_stack_classification(ipacket_t * ipacket) {
	classified_proto_t retval;
	retval.offset = 0;
	retval.proto_id = PROTO_DYNABIC_HES_DATA;
	retval.status = Classified;
	return retval;
}

int init_proto_dynabic_hes_data(){
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_DYNABIC_HES_DATA, PROTO_DYNABIC_HES_DATA_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i;
	int len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_DYNABIC_HES_DATA_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	if( register_classification_function(protocol_struct, dynabic_hes_data_classify_next_proto) == 0 )
		return 0;

	// OCPP_DATA is a single, independent protocol, register it as a stack
	if( register_protocol_stack(PROTO_DYNABIC_HES_DATA, PROTO_DYNABIC_HES_DATA_ALIAS, dynabic_hes_data_stack_classification) == 0 ){
		fprintf(stderr, "Cannot register protocol stack %s", PROTO_DYNABIC_HES_DATA_ALIAS );
		return 0;
	}
	return register_protocol(protocol_struct, PROTO_DYNABIC_HES_DATA);
}
