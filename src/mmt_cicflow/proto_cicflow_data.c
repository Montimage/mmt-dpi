/*
 * proto_cicflow_data.c
 *
 *  Created on: Nov 20, 2024
 *      Author: vietpham
 */


 #include "mmt_cicflow_internal.h"
 #include <string.h>

 static int cicflow_data_classify_next_proto(ipacket_t *packet, unsigned index) {
	int offset = get_packet_offset_at_index(packet, index);
	const int data_len = packet->p_hdr->caplen - offset;
	const char* data = (char *)&packet->data[offset];
	if( data_len <= 0 )
		return 0;
	//started by "Flow ID"
	if( strncmp("id", data, 2) != 0 )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_CICFLOW_DATA;
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

static inline void _assign_float(const char* ptr, attribute_t * extracted_data){
	if( ptr )
		*((float *) extracted_data->data) = atof( ptr );
	else
		*((float *) extracted_data->data) = 0;
}

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
        //strcpy(b->data, ":");
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
        case CICFLOW_DATA_ID:
            ptr = _get_pos(data_len, data, "id:");
            _assign_string(ptr, extracted_data, ',');
            break;
        case CICFLOW_DATA_SRC_IP:
            ptr = _get_pos(data_len, data, "Src_IP:");
            _assign_string(ptr, extracted_data, ',');
            break;
        case CICFLOW_DATA_SRC_PORT:
            ptr = _get_pos(data_len, data, "Src_Port:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_DST_IP:
            ptr = _get_pos(data_len, data, "Dst_IP:");
            _assign_string(ptr, extracted_data, ',');
            break;
        case CICFLOW_DATA_DST_PORT:
            ptr = _get_pos(data_len, data, "Dst_Port:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_PROTOCOL:
            ptr = _get_pos(data_len, data, "Protocol:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_TIMESTAMP:
            ptr = _get_pos(data_len, data, "Timestamp:");
            _assign_string(ptr, extracted_data, ',');
            break;
        case CICFLOW_DATA_FLOW_DURATION:
            ptr = _get_pos(data_len, data, "Flow_Duration:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_TOTAL_FWD_PACKET:
            ptr = _get_pos(data_len, data, "Total_Fwd_Packet:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_TOTAL_BWD_PACKETS:
            ptr = _get_pos(data_len, data, "Total_Bwd_packets:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_TOTAL_LENGTH_OF_FWD_PACKET:
            ptr = _get_pos(data_len, data, "Total_Length_of_Fwd_Packet:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_TOTAL_LENGTH_OF_BWD_PACKET:
            ptr = _get_pos(data_len, data, "Total_Length_of_Bwd_Packet:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_PACKET_LENGTH_MAX:
            ptr = _get_pos(data_len, data, "Fwd_Packet_Length_Max:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_PACKET_LENGTH_MIN:
            ptr = _get_pos(data_len, data, "Fwd_Packet_Length_Min:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_PACKET_LENGTH_MEAN:
            ptr = _get_pos(data_len, data, "Fwd_Packet_Length_Mean:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_PACKET_LENGTH_STD:
            ptr = _get_pos(data_len, data, "Fwd_Packet_Length_Std:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_PACKET_LENGTH_MAX:
            ptr = _get_pos(data_len, data, "Bwd_Packet_Length_Max:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_PACKET_LENGTH_MIN:
            ptr = _get_pos(data_len, data, "Bwd_Packet_Length_Min:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_PACKET_LENGTH_MEAN:
            ptr = _get_pos(data_len, data, "Bwd_Packet_Length_Mean:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_PACKET_LENGTH_STD:
            ptr = _get_pos(data_len, data, "Bwd_Packet_Length_Std:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FLOW_BYTES_S:
            ptr = _get_pos(data_len, data, "Flow_Bytes_per_s:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FLOW_PACKETS_S:
            ptr = _get_pos(data_len, data, "Flow_Packets_per_s:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FLOW_IAT_MEAN:
            ptr = _get_pos(data_len, data, "Flow_IAT_Mean:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FLOW_IAT_STD:
            ptr = _get_pos(data_len, data, "Flow_IAT_Std:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FLOW_IAT_MAX:
            ptr = _get_pos(data_len, data, "Flow_IAT_Max:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FLOW_IAT_MIN:
            ptr = _get_pos(data_len, data, "Flow_IAT_Min:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_IAT_TOTAL:
            ptr = _get_pos(data_len, data, "Fwd_IAT_Total:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_IAT_MEAN:
            ptr = _get_pos(data_len, data, "Fwd_IAT_Mean:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_IAT_STD:
            ptr = _get_pos(data_len, data, "Fwd_IAT_Std:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_IAT_MAX:
            ptr = _get_pos(data_len, data, "Fwd_IAT_Max:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_IAT_MIN:
            ptr = _get_pos(data_len, data, "Fwd_IAT_Min:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_IAT_TOTAL:
            ptr = _get_pos(data_len, data, "Bwd_IAT_Total:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_IAT_MEAN:
            ptr = _get_pos(data_len, data, "Bwd_IAT_Mean:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_IAT_STD:
            ptr = _get_pos(data_len, data, "Bwd_IAT_Std:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_IAT_MAX:
            ptr = _get_pos(data_len, data, "Bwd_IAT_Max:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_IAT_MIN:
            ptr = _get_pos(data_len, data, "Bwd_IAT_Min:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_PSH_FLAGS:
            ptr = _get_pos(data_len, data, "Fwd_PSH_Flags:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_PSH_FLAGS:
            ptr = _get_pos(data_len, data, "Bwd_PSH_Flags:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_URG_FLAGS:
            ptr = _get_pos(data_len, data, "Fwd_URG_Flags:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_URG_FLAGS:
            ptr = _get_pos(data_len, data, "Bwd_URG_Flags:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_HEADER_LENGTH:
            ptr = _get_pos(data_len, data, "Fwd_Header_Length:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_HEADER_LENGTH:
            ptr = _get_pos(data_len, data, "Bwd_Header_Length:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_PACKETS_S:
            ptr = _get_pos(data_len, data, "Fwd_Packets_per_s:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_PACKETS_S:
            ptr = _get_pos(data_len, data, "Bwd_Packets_per_s:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_PACKET_LENGTH_MIN:
            ptr = _get_pos(data_len, data, "Packet_Length_Min:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_PACKET_LENGTH_MAX:
            ptr = _get_pos(data_len, data, "Packet_Length_Max:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_PACKET_LENGTH_MEAN:
            ptr = _get_pos(data_len, data, "Packet_Length_Mean:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_PACKET_LENGTH_STD:
            ptr = _get_pos(data_len, data, "Packet_Length_Std:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_PACKET_LENGTH_VARIANCE:
            ptr = _get_pos(data_len, data, "Packet_Length_Variance:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FIN_FLAG_COUNT:
            ptr = _get_pos(data_len, data, "FIN_Flag_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_SYN_FLAG_COUNT:
            ptr = _get_pos(data_len, data, "SYN_Flag_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_RST_FLAG_COUNT:
            ptr = _get_pos(data_len, data, "RST_Flag_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_PSH_FLAG_COUNT:
            ptr = _get_pos(data_len, data, "PSH_Flag_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_ACK_FLAG_COUNT:
            ptr = _get_pos(data_len, data, "ACK_Flag_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_URG_FLAG_COUNT:
            ptr = _get_pos(data_len, data, "URG_Flag_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_CWR_FLAG_COUNT:
            ptr = _get_pos(data_len, data, "CWR_Flag_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_ECE_FLAG_COUNT:
            ptr = _get_pos(data_len, data, "ECE_Flag_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_DOWN_UP_RATIO:
            ptr = _get_pos(data_len, data, "Down_per_Up_Ratio:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_AVERAGE_PACKET_SIZE:
            ptr = _get_pos(data_len, data, "Average_Packet_Size:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_SEGMENT_SIZE_AVG:
            ptr = _get_pos(data_len, data, "Fwd_Segment_Size_Avg:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_SEGMENT_SIZE_AVG:
            ptr = _get_pos(data_len, data, "Bwd_Segment_Size_Avg:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_BYTES_BULK_AVG:
            ptr = _get_pos(data_len, data, "Fwd_Bytes_per_Bulk_Avg:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_PACKET_BULK_AVG:
            ptr = _get_pos(data_len, data, "Fwd_Packet_per_Bulk_Avg:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_BULK_RATE_AVG:
            ptr = _get_pos(data_len, data, "Fwd_Bulk_Rate_Avg:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_BYTES_BULK_AVG:
            ptr = _get_pos(data_len, data, "Bwd_Bytes_per_Bulk_Avg:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_PACKET_BULK_AVG:
            ptr = _get_pos(data_len, data, "Bwd_Packet_per_Bulk_Avg:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_BULK_RATE_AVG:
            ptr = _get_pos(data_len, data, "Bwd_Bulk_Rate_Avg:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_SUBFLOW_FWD_PACKETS:
            ptr = _get_pos(data_len, data, "Subflow_Fwd_Packets:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_SUBFLOW_FWD_BYTES:
            ptr = _get_pos(data_len, data, "Subflow_Fwd_Bytes:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_SUBFLOW_BWD_PACKETS:
            ptr = _get_pos(data_len, data, "Subflow_Bwd_Packets:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_SUBFLOW_BWD_BYTES:
            ptr = _get_pos(data_len, data, "Subflow_Bwd_Bytes:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_INIT_WIN_BYTES:
            ptr = _get_pos(data_len, data, "FWD_Init_Win_Bytes:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_INIT_WIN_BYTES:
            ptr = _get_pos(data_len, data, "Bwd_Init_Win_Bytes:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_ACT_DATA_PKTS:
            ptr = _get_pos(data_len, data, "Fwd_Act_Data_Pkts:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_SEG_SIZE_MIN:
            ptr = _get_pos(data_len, data, "Fwd_Seg_Size_Min:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_ACTIVE_MEAN:
            ptr = _get_pos(data_len, data, "Active_Mean:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_ACTIVE_STD:
            ptr = _get_pos(data_len, data, "Active_Std:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_ACTIVE_MAX:
            ptr = _get_pos(data_len, data, "Active_Max:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_ACTIVE_MIN:
            ptr = _get_pos(data_len, data, "Active_Min:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_IDLE_MEAN:
            ptr = _get_pos(data_len, data, "Idle_Mean:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_IDLE_STD:
            ptr = _get_pos(data_len, data, "Idle_Std:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_IDLE_MAX:
            ptr = _get_pos(data_len, data, "Idle_Max:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_IDLE_MIN:
            ptr = _get_pos(data_len, data, "Idle_Min:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_ACT_DATA_PKTS:
            ptr = _get_pos(data_len, data, "Bwd_Act_Data_Pkts:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_RST_FLAGS:
            ptr = _get_pos(data_len, data, "Bwd_RST_Flags:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_SEG_SIZE_MIN:
            ptr = _get_pos(data_len, data, "Bwd_Seg_Size_Min:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_BWD_TCP_RETRANS_COUNT:
            ptr = _get_pos(data_len, data, "Bwd_TCP_Retrans_dot_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_RST_FLAGS:
            ptr = _get_pos(data_len, data, "Fwd_RST_Flags:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_FWD_TCP_RETRANS_COUNT:
            ptr = _get_pos(data_len, data, "Fwd_TCP_Retrans_dot_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_ICMP_CODE:
            ptr = _get_pos(data_len, data, "ICMP_Code:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_ICMP_TYPE:
            ptr = _get_pos(data_len, data, "ICMP_Type:");
            _assign_uint32_t(ptr, extracted_data);
            break;
        case CICFLOW_DATA_TOTAL_CONNECTION_FLOW_TIME:
            ptr = _get_pos(data_len, data, "Total_Connection_Flow_Time:");
            _assign_float(ptr, extracted_data);
            break;
        case CICFLOW_DATA_TOTAL_TCP_RETRANS_COUNT:
            ptr = _get_pos(data_len, data, "Total_TCP_Retrans_dot_Count:");
            _assign_uint32_t(ptr, extracted_data);
            break;

        default:
        // Handle unknown field IDs if necessary
            break;
	}

	return 1;
}

static attribute_metadata_t _attributes_metadata[] = {
    {CICFLOW_DATA_ID,  CICFLOW_DATA_ID_ALIAS,                      MMT_STRING_DATA, BINARY_64DATA_LEN, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_SRC_IP,  CICFLOW_DATA_SRC_IP_ALIAS,                      MMT_STRING_DATA, BINARY_64DATA_LEN, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_SRC_PORT,  CICFLOW_DATA_SRC_PORT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_DST_IP,  CICFLOW_DATA_DST_IP_ALIAS,                      MMT_STRING_DATA, BINARY_64DATA_LEN, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_DST_PORT,  CICFLOW_DATA_DST_PORT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_PROTOCOL,  CICFLOW_DATA_PROTOCOL_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_TIMESTAMP,  CICFLOW_DATA_TIMESTAMP_ALIAS,                      MMT_STRING_DATA, BINARY_64DATA_LEN, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FLOW_DURATION,  CICFLOW_DATA_FLOW_DURATION_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_TOTAL_FWD_PACKET,  CICFLOW_DATA_TOTAL_FWD_PACKET_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_TOTAL_BWD_PACKETS,  CICFLOW_DATA_TOTAL_BWD_PACKETS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_TOTAL_LENGTH_OF_FWD_PACKET,  CICFLOW_DATA_TOTAL_LENGTH_OF_FWD_PACKET_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_TOTAL_LENGTH_OF_BWD_PACKET,  CICFLOW_DATA_TOTAL_LENGTH_OF_BWD_PACKET_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_PACKET_LENGTH_MAX,  CICFLOW_DATA_FWD_PACKET_LENGTH_MAX_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_PACKET_LENGTH_MIN,  CICFLOW_DATA_FWD_PACKET_LENGTH_MIN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_PACKET_LENGTH_MEAN,  CICFLOW_DATA_FWD_PACKET_LENGTH_MEAN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_PACKET_LENGTH_STD,  CICFLOW_DATA_FWD_PACKET_LENGTH_STD_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_PACKET_LENGTH_MAX,  CICFLOW_DATA_BWD_PACKET_LENGTH_MAX_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_PACKET_LENGTH_MIN,  CICFLOW_DATA_BWD_PACKET_LENGTH_MIN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_PACKET_LENGTH_MEAN,  CICFLOW_DATA_BWD_PACKET_LENGTH_MEAN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_PACKET_LENGTH_STD,  CICFLOW_DATA_BWD_PACKET_LENGTH_STD_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FLOW_BYTES_S,  CICFLOW_DATA_FLOW_BYTES_S_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FLOW_PACKETS_S,  CICFLOW_DATA_FLOW_PACKETS_S_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FLOW_IAT_MEAN,  CICFLOW_DATA_FLOW_IAT_MEAN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FLOW_IAT_STD,  CICFLOW_DATA_FLOW_IAT_STD_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FLOW_IAT_MAX,  CICFLOW_DATA_FLOW_IAT_MAX_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FLOW_IAT_MIN,  CICFLOW_DATA_FLOW_IAT_MIN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_IAT_TOTAL,  CICFLOW_DATA_FWD_IAT_TOTAL_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_IAT_MEAN,  CICFLOW_DATA_FWD_IAT_MEAN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_IAT_STD,  CICFLOW_DATA_FWD_IAT_STD_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_IAT_MAX,  CICFLOW_DATA_FWD_IAT_MAX_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_IAT_MIN,  CICFLOW_DATA_FWD_IAT_MIN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_IAT_TOTAL,  CICFLOW_DATA_BWD_IAT_TOTAL_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_IAT_MEAN,  CICFLOW_DATA_BWD_IAT_MEAN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_IAT_STD,  CICFLOW_DATA_BWD_IAT_STD_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_IAT_MAX,  CICFLOW_DATA_BWD_IAT_MAX_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_IAT_MIN,  CICFLOW_DATA_BWD_IAT_MIN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_PSH_FLAGS,  CICFLOW_DATA_FWD_PSH_FLAGS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_PSH_FLAGS,  CICFLOW_DATA_BWD_PSH_FLAGS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_URG_FLAGS,  CICFLOW_DATA_FWD_URG_FLAGS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_URG_FLAGS,  CICFLOW_DATA_BWD_URG_FLAGS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_HEADER_LENGTH,  CICFLOW_DATA_FWD_HEADER_LENGTH_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_HEADER_LENGTH,  CICFLOW_DATA_BWD_HEADER_LENGTH_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_PACKETS_S,  CICFLOW_DATA_FWD_PACKETS_S_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_PACKETS_S,  CICFLOW_DATA_BWD_PACKETS_S_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_PACKET_LENGTH_MIN,  CICFLOW_DATA_PACKET_LENGTH_MIN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_PACKET_LENGTH_MAX,  CICFLOW_DATA_PACKET_LENGTH_MAX_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_PACKET_LENGTH_MEAN,  CICFLOW_DATA_PACKET_LENGTH_MEAN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_PACKET_LENGTH_STD,  CICFLOW_DATA_PACKET_LENGTH_STD_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_PACKET_LENGTH_VARIANCE,  CICFLOW_DATA_PACKET_LENGTH_VARIANCE_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FIN_FLAG_COUNT,  CICFLOW_DATA_FIN_FLAG_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_SYN_FLAG_COUNT,  CICFLOW_DATA_SYN_FLAG_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_RST_FLAG_COUNT,  CICFLOW_DATA_RST_FLAG_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_PSH_FLAG_COUNT,  CICFLOW_DATA_PSH_FLAG_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_ACK_FLAG_COUNT,  CICFLOW_DATA_ACK_FLAG_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_URG_FLAG_COUNT,  CICFLOW_DATA_URG_FLAG_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_CWR_FLAG_COUNT,  CICFLOW_DATA_CWR_FLAG_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_ECE_FLAG_COUNT,  CICFLOW_DATA_ECE_FLAG_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_DOWN_UP_RATIO,  CICFLOW_DATA_DOWN_UP_RATIO_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_AVERAGE_PACKET_SIZE,  CICFLOW_DATA_AVERAGE_PACKET_SIZE_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_SEGMENT_SIZE_AVG,  CICFLOW_DATA_FWD_SEGMENT_SIZE_AVG_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_SEGMENT_SIZE_AVG,  CICFLOW_DATA_BWD_SEGMENT_SIZE_AVG_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_BYTES_BULK_AVG,  CICFLOW_DATA_FWD_BYTES_BULK_AVG_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_PACKET_BULK_AVG,  CICFLOW_DATA_FWD_PACKET_BULK_AVG_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_BULK_RATE_AVG,  CICFLOW_DATA_FWD_BULK_RATE_AVG_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_BYTES_BULK_AVG,  CICFLOW_DATA_BWD_BYTES_BULK_AVG_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_PACKET_BULK_AVG,  CICFLOW_DATA_BWD_PACKET_BULK_AVG_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_BULK_RATE_AVG,  CICFLOW_DATA_BWD_BULK_RATE_AVG_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_SUBFLOW_FWD_PACKETS,  CICFLOW_DATA_SUBFLOW_FWD_PACKETS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_SUBFLOW_FWD_BYTES,  CICFLOW_DATA_SUBFLOW_FWD_BYTES_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_SUBFLOW_BWD_PACKETS,  CICFLOW_DATA_SUBFLOW_BWD_PACKETS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_SUBFLOW_BWD_BYTES,  CICFLOW_DATA_SUBFLOW_BWD_BYTES_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_INIT_WIN_BYTES,  CICFLOW_DATA_FWD_INIT_WIN_BYTES_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_INIT_WIN_BYTES,  CICFLOW_DATA_BWD_INIT_WIN_BYTES_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_ACT_DATA_PKTS,  CICFLOW_DATA_FWD_ACT_DATA_PKTS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_SEG_SIZE_MIN,  CICFLOW_DATA_FWD_SEG_SIZE_MIN_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_ACTIVE_MEAN,  CICFLOW_DATA_ACTIVE_MEAN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_ACTIVE_STD,  CICFLOW_DATA_ACTIVE_STD_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_ACTIVE_MAX,  CICFLOW_DATA_ACTIVE_MAX_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_ACTIVE_MIN,  CICFLOW_DATA_ACTIVE_MIN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_IDLE_MEAN,  CICFLOW_DATA_IDLE_MEAN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_IDLE_STD,  CICFLOW_DATA_IDLE_STD_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_IDLE_MAX,  CICFLOW_DATA_IDLE_MAX_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_IDLE_MIN,  CICFLOW_DATA_IDLE_MIN_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_ACT_DATA_PKTS,  CICFLOW_DATA_BWD_ACT_DATA_PKTS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_RST_FLAGS,  CICFLOW_DATA_BWD_RST_FLAGS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_SEG_SIZE_MIN,  CICFLOW_DATA_BWD_SEG_SIZE_MIN_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_BWD_TCP_RETRANS_COUNT,  CICFLOW_DATA_BWD_TCP_RETRANS_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_RST_FLAGS,  CICFLOW_DATA_FWD_RST_FLAGS_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_FWD_TCP_RETRANS_COUNT,  CICFLOW_DATA_FWD_TCP_RETRANS_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_ICMP_CODE,  CICFLOW_DATA_ICMP_CODE_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_ICMP_TYPE,  CICFLOW_DATA_ICMP_TYPE_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_TOTAL_CONNECTION_FLOW_TIME,  CICFLOW_DATA_TOTAL_CONNECTION_FLOW_TIME_ALIAS,                      MMT_DATA_FLOAT, sizeof(float_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {CICFLOW_DATA_TOTAL_TCP_RETRANS_COUNT,  CICFLOW_DATA_TOTAL_TCP_RETRANS_COUNT_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
};

static classified_proto_t cicflow_data_stack_classification(ipacket_t * ipacket) {
	classified_proto_t retval;
	retval.offset = 0;
	retval.proto_id = PROTO_CICFLOW_DATA;
	retval.status = Classified;
	return retval;
}

int init_proto_cicflow_data(){
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_CICFLOW_DATA, PROTO_CICFLOW_DATA_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i;
	int len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_CICFLOW_DATA_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	if( register_classification_function(protocol_struct, cicflow_data_classify_next_proto) == 0 )
		return 0;

	// CICFLOW_DATA is a single, independent protocol, register it as a stack
	if( register_protocol_stack(PROTO_CICFLOW_DATA, PROTO_CICFLOW_DATA_ALIAS, cicflow_data_stack_classification) == 0 ){
		fprintf(stderr, "Cannot register protocol stack %s", PROTO_CICFLOW_DATA_ALIAS );
		return 0;
	}
	return register_protocol(protocol_struct, PROTO_CICFLOW_DATA);
}