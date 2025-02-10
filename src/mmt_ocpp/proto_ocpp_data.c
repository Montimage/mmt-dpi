/*
 * proto_ocpp_data.c
 *
 *  Created on: Nov 20, 2024
 *      Author: vietpham
 */


#include "mmt_ocpp_internal.h"
#include <string.h>


static int ocpp_data_classify_next_proto(ipacket_t *packet, unsigned index) {
	int offset = get_packet_offset_at_index(packet, index);
	const int data_len = packet->p_hdr->caplen - offset;
	const char* data = (char *)&packet->data[offset];
	if( data_len <= 0 )
		return 0;
	//started by "level_0" ??
	if( strncmp("level_0", data, 7) != 0 )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_OCPP_DATA;
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
        //strcpy(b->data, "");
    }
}




// static inline void _assign_timeval(const char* ptr, attribute_t * extracted_data){
// 	char* end;
//     double timestamp;
//     struct timeval tv; 
//     if( ptr ) {
//         timestamp = strtod(ptr, &end);      
        
//         double fractional_part;
//         tv.tv_sec = (time_t)timestamp; // Integer seconds part
//         fractional_part = timestamp - tv.tv_sec; // Fractional seconds part
//         // Convert fractional part to microseconds
//         tv.tv_usec = (suseconds_t)(fractional_part * 1000000); // 1 second = 1,000,000 microseconds
        
//         memcpy(extracted_data->data, &tv, sizeof (struct timeval));
//     }else
//         tv.tv_sec = (time_t)(0.0);
//         tv.tv_usec = (suseconds_t)(0.0);
// 		memcpy(extracted_data->data, &tv, sizeof (struct timeval));
// }

static int _extraction_att(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {
	int offset = get_packet_offset_at_index(packet, proto_index);
	const int data_len = packet->p_hdr->caplen - offset;
	const char* data = (char *)&packet->data[offset];
	const char* ptr;
	if( data_len <= 0 )
		return 0;

	switch (extracted_data->field_id) {
    case OCPP_DATA_LEVEL_0:
        ptr = _get_pos(data_len, data, "level_0:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_INDEX:
        ptr = _get_pos(data_len, data, "index:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_ID:
        ptr = _get_pos(data_len, data, "flow_id:");
        _assign_string(ptr, extracted_data, ',');
        break;

    case OCPP_DATA_SRC_IP:
        ptr = _get_pos(data_len, data, "src_ip:");
        _assign_string(ptr, extracted_data, ',');
        break;

    case OCPP_DATA_DST_IP:
        ptr = _get_pos(data_len, data, "dst_ip:");
        _assign_string(ptr, extracted_data, ',');
        break;

    case OCPP_DATA_SRC_PORT:
        ptr = _get_pos(data_len, data, "src_port:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_DST_PORT:
        ptr = _get_pos(data_len, data, "dst_port:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_TOTAL_FLOW_PACKETS:
        ptr = _get_pos(data_len, data, "total_flow_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_TOTAL_FW_PACKETS:
        ptr = _get_pos(data_len, data, "total_fw_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_TOTAL_BW_PACKETS:
        ptr = _get_pos(data_len, data, "total_bw_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_DURATION:
        ptr = _get_pos(data_len, data, "flow_duration:");
        _assign_float(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_DOWN_UP_RATIO:
        ptr = _get_pos(data_len, data, "flow_down_up_ratio:");
        _assign_float(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_SYN_FLAG:
        ptr = _get_pos(data_len, data, "flow_total_SYN_flag:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_RST_FLAG:
        ptr = _get_pos(data_len, data, "flow_total_RST_flag:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_PSH_FLAG:
        ptr = _get_pos(data_len, data, "flow_total_PSH_flag:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_ACK_FLAG:
        ptr = _get_pos(data_len, data, "flow_total_ACK_flag:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_URG_FLAG:
        ptr = _get_pos(data_len, data, "flow_total_URG_flag:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_CWE_FLAG:
        ptr = _get_pos(data_len, data, "flow_total_CWE_flag:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_ECE_FLAG:
        ptr = _get_pos(data_len, data, "flow_total_ECE_flag:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_FIN_FLAG:
        ptr = _get_pos(data_len, data, "flow_total_FIN_flag:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_START_TIMESTAMP:
        ptr = _get_pos(data_len, data, "flow_start_timestamp:");
        _assign_string(ptr, extracted_data, ',');
        break;

    case OCPP_DATA_FLOW_END_TIMESTAMP:
        ptr = _get_pos(data_len, data, "flow_end_timestamp:");
        _assign_string(ptr, extracted_data, ',');
        break;

    case OCPP_DATA_FLOW_TOTAL_HTTP_GET_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_http_get_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_HTTP_2XX_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_http_2xx_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_HTTP_4XX_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_http_4xx_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_HTTP_5XX_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_http_5xx_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_WEBSOCKET_PACKETS_PER_SECOND:
        ptr = _get_pos(data_len, data, "flow_websocket_packts_per_second:");
        _assign_float(ptr, extracted_data);
        break;

    case OCPP_DATA_FW_WEBSOCKET_PACKETS_PER_SECOND:
        ptr = _get_pos(data_len, data, "fw_websocket_packts_per_second:");
        _assign_float(ptr, extracted_data);
        break;

    case OCPP_DATA_BW_WEBSOCKET_PACKETS_PER_SECOND:
        ptr = _get_pos(data_len, data, "bw_websocket_packts_per_second:");
        _assign_float(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_WEBSOCKET_BYTES_PER_SECOND:
        ptr = _get_pos(data_len, data, "flow_websocket_bytes_per_second:");
        _assign_float(ptr, extracted_data);
        break;

    case OCPP_DATA_FW_WEBSOCKET_BYTES_PER_SECOND:
        ptr = _get_pos(data_len, data, "fw_websocket_bytes_per_second:");
        _assign_float(ptr, extracted_data);
        break;

    case OCPP_DATA_BW_WEBSOCKET_BYTES_PER_SECOND:
        ptr = _get_pos(data_len, data, "bw_websocket_bytes_per_second:");
        _assign_float(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_WEBSOCKET_PING_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_websocket_ping_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_WEBSOCKET_PONG_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_websocket_pong_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_WEBSOCKET_CLOSE_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_websocket_close_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_WEBSOCKET_DATA_MESSAGES:
        ptr = _get_pos(data_len, data, "flow_total_websocket_data_messages:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_OCPP16_HEARTBEAT_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_ocpp16_heartbeat_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_OCPP16_RESETHARD_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_ocpp16_resetHard_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_OCPP16_RESETSOFT_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_ocpp16_resetSoft_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_OCPP16_UNLOCKCONNECTOR_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_ocpp16_unlockconnector_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_OCPP16_STARTTRANSACTION_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_ocpp16_starttransaction_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_OCPP16_REMOTESTARTTRANSACTION_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_ocpp16_remotestarttransaction_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_OCPP16_AUTHORIZE_NOT_ACCEPTED_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_ocpp16_authorize_not_accepted_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_OCPP16_SETCHARGINGPROFILE_PACKETS:
        ptr = _get_pos(data_len, data, "flow_total_ocpp16_setchargingprofile_packets:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_AVG_OCPP16_SETCHARGINGPROFILE_LIMIT:
        ptr = _get_pos(data_len, data, "flow_avg_ocpp16_setchargingprofile_limit:");
        _assign_uint32_t(ptr, extracted_data);
        break;

        case OCPP_DATA_FLOW_MAX_OCPP16_SETCHARGINGPROFILE_LIMIT:
        ptr = _get_pos(data_len, data, "flow_max_ocpp16_setchargingprofile_limit:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_MIN_OCPP16_SETCHARGINGPROFILE_LIMIT:
        ptr = _get_pos(data_len, data, "flow_min_ocpp16_setchargingprofile_limit:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_AVG_OCPP16_SETCHARGINGPROFILE_MINCHARGINGRATE:
        ptr = _get_pos(data_len, data, "flow_avg_ocpp16_setchargingprofile_minchargingrate:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_MIN_OCPP16_SETCHARGINGPROFILE_MINCHARGINGRATE:
        ptr = _get_pos(data_len, data, "flow_min_ocpp16_setchargingprofile_minchargingrate:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_MAX_OCPP16_SETCHARGINGPROFILE_MINCHARGINGRATE:
        ptr = _get_pos(data_len, data, "flow_max_ocpp16_setchargingprofile_minchargingrate:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_TOTAL_OCPP16_METERVALUE:
        ptr = _get_pos(data_len, data, "flow_total_ocpp16_metervalues:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_MIN_OCPP16_METERVALUE_SOC:
        ptr = _get_pos(data_len, data, "flow_min_ocpp16_metervalues_soc:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_MAX_OCPP16_METERVALUE_SOC:
        ptr = _get_pos(data_len, data, "flow_max_ocpp16_metervalues_soc:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_AVG_OCPP16_METERVALUE_WH_DIFF:
        ptr = _get_pos(data_len, data, "flow_avg_ocpp16_metervalues_wh_diff:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_MAX_OCPP16_METERVALUE_WH_DIFF:
        ptr = _get_pos(data_len, data, "flow_max_ocpp16_metervalues_wh_diff:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    case OCPP_DATA_FLOW_MIN_OCPP16_METERVALUE_WH_DIFF:
        ptr = _get_pos(data_len, data, "flow_min_ocpp16_metervalues_wh_diff:");
        _assign_uint32_t(ptr, extracted_data);
        break;

    default:
        // Handle unknown field IDs if necessary
        break;
	}

	return 1;
}

attribute_metadata_t _attributes_metadata[] = {
    {OCPP_DATA_LEVEL_0,                      OCPP_DATA_LEVEL_0_ALIAS,                      MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_INDEX,                        OCPP_DATA_INDEX_ALIAS,                        MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_ID,                      OCPP_DATA_FLOW_ID_ALIAS,                      MMT_STRING_DATA,    BINARY_64DATA_LEN,    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    //Ask about handling IP address
    {OCPP_DATA_SRC_IP,                       OCPP_DATA_SRC_IP_ALIAS,                       MMT_STRING_DATA,    BINARY_64DATA_LEN,    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_DST_IP,                       OCPP_DATA_DST_IP_ALIAS,                       MMT_STRING_DATA,    BINARY_64DATA_LEN,    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    //
    {OCPP_DATA_SRC_PORT,                     OCPP_DATA_SRC_PORT_ALIAS,                     MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_DST_PORT,                     OCPP_DATA_DST_PORT_ALIAS,                     MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_TOTAL_FLOW_PACKETS,           OCPP_DATA_TOTAL_FLOW_PACKETS_ALIAS,           MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_TOTAL_FW_PACKETS,             OCPP_DATA_TOTAL_FW_PACKETS_ALIAS,             MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_TOTAL_BW_PACKETS,             OCPP_DATA_TOTAL_BW_PACKETS_ALIAS,             MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_DURATION,                OCPP_DATA_FLOW_DURATION_ALIAS,                MMT_DATA_FLOAT,    sizeof(float),    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_DOWN_UP_RATIO,           OCPP_DATA_FLOW_DOWN_UP_RATIO_ALIAS,           MMT_DATA_FLOAT,    sizeof(float),    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_SYN_FLAG,          OCPP_DATA_FLOW_TOTAL_SYN_FLAG_ALIAS,          MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_RST_FLAG,          OCPP_DATA_FLOW_TOTAL_RST_FLAG_ALIAS,          MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_PSH_FLAG,          OCPP_DATA_FLOW_TOTAL_PSH_FLAG_ALIAS,          MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_ACK_FLAG,          OCPP_DATA_FLOW_TOTAL_ACK_FLAG_ALIAS,          MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_URG_FLAG,          OCPP_DATA_FLOW_TOTAL_URG_FLAG_ALIAS,          MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_CWE_FLAG,          OCPP_DATA_FLOW_TOTAL_CWE_FLAG_ALIAS,          MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_ECE_FLAG,          OCPP_DATA_FLOW_TOTAL_ECE_FLAG_ALIAS,          MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_FIN_FLAG,          OCPP_DATA_FLOW_TOTAL_FIN_FLAG_ALIAS,          MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    //Verify the following fields
    //{OCPP_DATA_FLOW_START_TIMESTAMP,         OCPP_DATA_FLOW_START_TIMESTAMP_ALIAS,         MMT_DATA_TIMEVAL,   sizeof(struct timeval),   POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    //{OCPP_DATA_FLOW_END_TIMESTAMP,           OCPP_DATA_FLOW_END_TIMESTAMP_ALIAS,           MMT_DATA_TIMEVAL,   sizeof(struct timeval),   POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_START_TIMESTAMP,         OCPP_DATA_FLOW_START_TIMESTAMP_ALIAS,         MMT_STRING_DATA,   BINARY_64DATA_LEN,   POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_END_TIMESTAMP,           OCPP_DATA_FLOW_END_TIMESTAMP_ALIAS,           MMT_STRING_DATA,   BINARY_64DATA_LEN,   POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    //Verify the above fields
    {OCPP_DATA_FLOW_TOTAL_HTTP_GET_PACKETS,  OCPP_DATA_FLOW_TOTAL_HTTP_GET_PACKETS_ALIAS,  MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_HTTP_2XX_PACKETS,  OCPP_DATA_FLOW_TOTAL_HTTP_2XX_PACKETS_ALIAS,  MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_HTTP_4XX_PACKETS,  OCPP_DATA_FLOW_TOTAL_HTTP_4XX_PACKETS_ALIAS,  MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_HTTP_5XX_PACKETS,  OCPP_DATA_FLOW_TOTAL_HTTP_5XX_PACKETS_ALIAS,  MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_WEBSOCKET_PACKETS_PER_SECOND, OCPP_DATA_FLOW_WEBSOCKET_PACKETS_PER_SECOND_ALIAS, MMT_DATA_FLOAT, sizeof(float), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FW_WEBSOCKET_PACKETS_PER_SECOND, OCPP_DATA_FW_WEBSOCKET_PACKETS_PER_SECOND_ALIAS, MMT_DATA_FLOAT, sizeof(float), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_BW_WEBSOCKET_PACKETS_PER_SECOND, OCPP_DATA_BW_WEBSOCKET_PACKETS_PER_SECOND_ALIAS, MMT_DATA_FLOAT, sizeof(float), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_WEBSOCKET_BYTES_PER_SECOND, OCPP_DATA_FLOW_WEBSOCKET_BYTES_PER_SECOND_ALIAS, MMT_DATA_FLOAT, sizeof(float), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FW_WEBSOCKET_BYTES_PER_SECOND, OCPP_DATA_FW_WEBSOCKET_BYTES_PER_SECOND_ALIAS, MMT_DATA_FLOAT, sizeof(float), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_BW_WEBSOCKET_BYTES_PER_SECOND, OCPP_DATA_BW_WEBSOCKET_BYTES_PER_SECOND_ALIAS, MMT_DATA_FLOAT, sizeof(float), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_WEBSOCKET_PING_PACKETS, OCPP_DATA_FLOW_TOTAL_WEBSOCKET_PING_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_WEBSOCKET_PONG_PACKETS, OCPP_DATA_FLOW_TOTAL_WEBSOCKET_PONG_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_WEBSOCKET_CLOSE_PACKETS, OCPP_DATA_FLOW_TOTAL_WEBSOCKET_CLOSE_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_WEBSOCKET_DATA_MESSAGES, OCPP_DATA_FLOW_TOTAL_WEBSOCKET_DATA_MESSAGES_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_OCPP16_HEARTBEAT_PACKETS, OCPP_DATA_FLOW_TOTAL_OCPP16_HEARTBEAT_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_OCPP16_RESETHARD_PACKETS, OCPP_DATA_FLOW_TOTAL_OCPP16_RESETHARD_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_OCPP16_RESETSOFT_PACKETS, OCPP_DATA_FLOW_TOTAL_OCPP16_RESETSOFT_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_OCPP16_UNLOCKCONNECTOR_PACKETS, OCPP_DATA_FLOW_TOTAL_OCPP16_UNLOCKCONNECTOR_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_OCPP16_STARTTRANSACTION_PACKETS, OCPP_DATA_FLOW_TOTAL_OCPP16_STARTTRANSACTION_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_OCPP16_REMOTESTARTTRANSACTION_PACKETS, OCPP_DATA_FLOW_TOTAL_OCPP16_REMOTESTARTTRANSACTION_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_OCPP16_AUTHORIZE_NOT_ACCEPTED_PACKETS, OCPP_DATA_FLOW_TOTAL_OCPP16_AUTHORIZE_NOT_ACCEPTED_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_OCPP16_SETCHARGINGPROFILE_PACKETS, OCPP_DATA_FLOW_TOTAL_OCPP16_SETCHARGINGPROFILE_PACKETS_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_AVG_OCPP16_SETCHARGINGPROFILE_LIMIT, OCPP_DATA_FLOW_AVG_OCPP16_SETCHARGINGPROFILE_LIMIT_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_MAX_OCPP16_SETCHARGINGPROFILE_LIMIT, OCPP_DATA_FLOW_MAX_OCPP16_SETCHARGINGPROFILE_LIMIT_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_MIN_OCPP16_SETCHARGINGPROFILE_LIMIT, OCPP_DATA_FLOW_MIN_OCPP16_SETCHARGINGPROFILE_LIMIT_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_AVG_OCPP16_SETCHARGINGPROFILE_MINCHARGINGRATE, OCPP_DATA_FLOW_AVG_OCPP16_SETCHARGINGPROFILE_MINCHARGINGRATE_ALIAS, MMT_U32_DATA, sizeof(float), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_MIN_OCPP16_SETCHARGINGPROFILE_MINCHARGINGRATE, OCPP_DATA_FLOW_MIN_OCPP16_SETCHARGINGPROFILE_MINCHARGINGRATE_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_MAX_OCPP16_SETCHARGINGPROFILE_MINCHARGINGRATE, OCPP_DATA_FLOW_MAX_OCPP16_SETCHARGINGPROFILE_MINCHARGINGRATE_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_TOTAL_OCPP16_METERVALUE, OCPP_DATA_FLOW_TOTAL_OCPP16_METERVALUE_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_MIN_OCPP16_METERVALUE_SOC, OCPP_DATA_FLOW_MIN_OCPP16_METERVALUE_SOC_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_MAX_OCPP16_METERVALUE_SOC, OCPP_DATA_FLOW_MAX_OCPP16_METERVALUE_SOC_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_AVG_OCPP16_METERVALUE_WH_DIFF, OCPP_DATA_FLOW_AVG_OCPP16_METERVALUE_WH_DIFF_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_MAX_OCPP16_METERVALUE_WH_DIFF, OCPP_DATA_FLOW_MAX_OCPP16_METERVALUE_WH_DIFF_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
    {OCPP_DATA_FLOW_MIN_OCPP16_METERVALUE_WH_DIFF, OCPP_DATA_FLOW_MIN_OCPP16_METERVALUE_WH_DIFF_ALIAS, MMT_U32_DATA, sizeof(uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att}
};

static classified_proto_t ocpp_data_stack_classification(ipacket_t * ipacket) {
	classified_proto_t retval;
	retval.offset = 0;
	retval.proto_id = PROTO_OCPP_DATA;
	retval.status = Classified;
	return retval;
}

int init_proto_ocpp_data(){
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_OCPP_DATA, PROTO_OCPP_DATA_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i;
	int len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_OCPP_DATA_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	if( register_classification_function(protocol_struct, ocpp_data_classify_next_proto) == 0 )
		return 0;

	// OCPP_DATA is a single, independent protocol, register it as a stack
	if( register_protocol_stack(PROTO_OCPP_DATA, PROTO_OCPP_DATA_ALIAS, ocpp_data_stack_classification) == 0 ){
		fprintf(stderr, "Cannot register protocol stack %s", PROTO_OCPP_DATA_ALIAS );
		return 0;
	}
	return register_protocol(protocol_struct, PROTO_OCPP_DATA);
}
