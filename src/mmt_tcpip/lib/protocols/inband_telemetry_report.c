/*
 * inband_telemetry_report.c
 *
 *  Created on: Jan 19, 2022
 *      Author: nhnghia
 */

#include "inband_telemetry.h"
#include "inband_telemetry_report.h"
#include "mmt_tcpip_protocols.h"

struct udphdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
};

struct ethhdr{
	uint64_t dst:48;
	uint64_t src:48;
	uint16_t type;
} __attribute__((packed));

#define ETH_TYPE_IP 0x0800
#define IP_PROTO_UDP 17
#define IP_PROTO_TCP  6
#define TCP_HDR_SIZE 20
#define UDP_HDR_SIZE  8

struct iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t ihl : 4, version : 4;
#elif BYTE_ORDER == BIG_ENDIAN
	uint8_t version : 4, ihl : 4;
#else
#error "BYTE_ORDER must be defined"
#endif
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
}__attribute__((packed));

#define INT_UDP_DST_PORT 6000

static int _classify_inband_network_telemetry_from_udp(ipacket_t * ipacket, unsigned index) {
	int offset = get_packet_offset_at_index(ipacket, index);

	const struct udphdr *udp = (struct udphdr *) & ipacket->data[offset];
	if( ntohs(udp->dest) != INT_UDP_DST_PORT )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_INT_REPORT;
	retval.status   = Classified;
	retval.offset   = sizeof( struct udphdr ); //the next protocol is started after x bytes of UDP header

	 //HN: do not copy session proto path into ipacket's proto path.
	//As we know explicitly the protocol at index-th position in the hierarchy,
	// so we limit the length of hierarchy for now.
	//This length will be increased by another classification function
	//  if further protocols will classified latter.
	ipacket->proto_hierarchy->len = index + 1 + 1;

	return set_classified_proto(ipacket, index + 1, retval);
}

#define advance_pointer( var, var_type, cursor, end_cursor, msg )\
	if( cursor + sizeof(var_type) > end_cursor ){\
		debug(msg);\
		return 0;\
	} else {\
		var = (var_type *) cursor;\
		cursor += sizeof(var_type);\
	}



#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
static int _extraction_int_report_att(const ipacket_t *ipacket, unsigned index,
		attribute_t * extracted_data) {
	int i, offset = get_packet_offset_at_index(ipacket, index);
	const unsigned int packet_len = ipacket->p_hdr->caplen;
	const u_char *cursor = &ipacket->data[offset], *end_cursor = &ipacket->data[packet_len];

	const int FOUND = 1, NOT_FOUND = 0;
	// INT Raport structure
	// [Eth][IP][UDP][INT RAPORT HDR][ETH][IP][UDP/TCP][INT SHIM][INT DATA]
	// We are here --------^
	const int_report_v10_t *int_header = (int_report_v10_t *) &ipacket->data[offset];
	offset += sizeof( int_report_v10_t );
	if( offset >= packet_len )
		return 0;

	if( int_header->version != 1 ){
		debug("Unsupported INT version %d", int_header->version);
		return 0;
	}
	//parse inner: ETH -> IP -> UDP/TCP->INT
	const struct ethhdr *eth = (struct ethhdr *)&ipacket->data[offset];
	offset += sizeof( struct ethhdr );
	if( offset >= packet_len ){
		debug("No Ethernet");
		return 0;
	}

	if( ntohs(eth->type) != ETH_TYPE_IP ){
		//TODO support IPv6?
		debug("No IPv4 after Ethernet");
		return 0;
	}

	const struct iphdr *ip = (struct iphdr *)&ipacket->data[offset];
	offset += sizeof( struct iphdr );
	if( offset >= packet_len ){
		debug("Not enough room for IPv4");
		return 0;
	}

	//Although the next proto can be TCP but we can use UDP to get src/dst ports
	//as the src/dst ports of TCP are in the same position as the ones of UDP
	const struct udphdr *ports = (struct udphdr *)&ipacket->data[offset];
	switch( ip->protocol ){
	case IP_PROTO_UDP:
		offset += UDP_HDR_SIZE;
		break;
	case IP_PROTO_TCP:
		offset += TCP_HDR_SIZE;
		break;
	default:
		debug("Neither UDP, nor TCP is found after IP. Need to support INT over other proto than TCP/UDP");
		return 0;
	}

	if( offset >= packet_len ){
		debug("Not enough room for UDP/TCP");
		return 0;
	}

	int_shim_tcpudp_v10_t *shim = (int_shim_tcpudp_v10_t*) &ipacket->data[offset];
	offset += sizeof(int_shim_tcpudp_v10_t );
	if( offset >= packet_len ){
		debug("Not enough room for int_shim_tcpudp_v10_t");
		return 0;
	}

	int_hop_by_hop_v10_t *hbh_report = (int_hop_by_hop_v10_t*) &ipacket->data[offset];
	offset += sizeof( int_hop_by_hop_v10_t );
	if( offset >= packet_len ){
		debug("Not enough room for int_hop_by_hop_v10_t");
		return 0;
	}


	int num_hops = 0;
	//3 is sizeof INT shim and md fix headers in words
	if( shim->length >= 3 )
		num_hops = (shim->length - 3)/hbh_report->hop_ml;

	uint16_t ins_bits = ntohs( hbh_report->instructions );

	switch( extracted_data->field_id ){
	case INT_REPORT_SWITCH_ID:
		(*(uint32_t *) extracted_data->data) = ntohl( int_header->switch_id );
		return FOUND;
	case INT_REPORT_SEQ_NUMBER:
		(*(uint32_t *) extracted_data->data) = ntohl( int_header->seq_number );
		return FOUND;
	case INT_REPORT_HW_ID:
		(*(uint32_t *) extracted_data->data) = int_header->hw_id;
		return FOUND;

	//flow info
	case INT_REPORT_FLOW_IP_SRC:
		(*(uint32_t *) extracted_data->data) = ntohl( ip->saddr );
		return FOUND;
	case INT_REPORT_FLOW_IP_DST:
		(*(uint32_t *) extracted_data->data) = ntohl( ip->daddr );
		return FOUND;
	case INT_REPORT_FLOW_PORT_SRC:
		(*(uint16_t *) extracted_data->data) = ntohs( ports->source );
		return FOUND;
	case INT_REPORT_FLOW_PORT_DST:
		(*(uint16_t *) extracted_data->data) = ntohs( ports->dest );
		return FOUND;

	case INT_REPORT_SINK_TIME:
		(*(uint32_t *) extracted_data->data) = ntohl( int_header->ingress_timestamp );
		return FOUND;
	case INT_REPORT_METADATA_BITS:
		(*(uint8_t *) extracted_data->data) = ins_bits;
		return FOUND;
	case INT_REPORT_NUM_HOP:
		(*(uint8_t *) extracted_data->data) = num_hops;
		return FOUND;
	default:
		break;
	}

	//no INT data => no need to extract other attributes
	if( num_hops == 0 )
		return NOT_FOUND;

	uint8_t is_switches_id       = (ins_bits >> 15) & 0x1;
	uint8_t is_in_e_port_ids     = (ins_bits >> 14) & 0x1;
	uint8_t is_hop_latencies     = (ins_bits >> 13) & 0x1;
	uint8_t is_queue_occups      = (ins_bits >> 12) & 0x1;
	uint8_t is_ingr_times        = (ins_bits >> 11) & 0x1;
	uint8_t is_egr_times         = (ins_bits >> 10) & 0x1;
	uint8_t is_lv2_in_e_port_ids = (ins_bits >>  9) & 0x1;
	uint8_t is_tx_utilizes       = (ins_bits >>  8) & 0x1;

	switch( extracted_data->field_id ){
	case INT_REPORT_IS_QUEUE_ID_OCCUP:
		(*(uint8_t *) extracted_data->data) = 1;
		break;
	case INT_REPORT_HOP_SWITCH_IDS:

		break;
	}

	uint32_t *u32;
	mmt_u32_array_t data;
	data.len = num_hops;

	for( i=0; i<num_hops; i++ ){
		if( is_switches_id ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No SW_IDS");
			if( extracted_data->field_id == INT_REPORT_HOP_SWITCH_IDS )
				data.data[i] = ntohl( *u32 );
		}

		if( is_in_e_port_ids ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No In Egress port IDs");
			if( extracted_data->field_id == INT_REPORT_HOP_INGRESS_PORT_IDS )
				data.data[i] = (ntohl( *u32 ) >> 16) & 0xffff;
			else if( extracted_data->field_id == INT_REPORT_HOP_EGRESS_PORT_IDS )
				data.data[i] = (ntohl( *u32 ) ) & 0xffff;
		}

		if( is_hop_latencies ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No Hop latencies");
			if( extracted_data->field_id == INT_REPORT_HOP_LATENCIES )
				data.data[i] = ntohl( *u32 );
		}

		if( is_queue_occups ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No queue occups");
			if( extracted_data->field_id == INT_REPORT_HOP_QUEUE_IDS )
				data.data[i] = (ntohl( *u32 ) >> 24) & 0xffff;
			else if( extracted_data->field_id == INT_REPORT_HOP_QUEUE_OCCUPS )
				data.data[i] = (ntohl( *u32 ) ) & 0xffff;
		}

		if( is_ingr_times ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No Ingrees time");
			if( extracted_data->field_id == INT_REPORT_HOP_INGRESS_TIMES )
				data.data[i] = ntohl( *u32 );
		}

		if( is_egr_times ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No Egress Time");
			if( extracted_data->field_id == INT_REPORT_HOP_EGRESS_TIMES )
				data.data[i] = ntohl( *u32 );
		}

		if( is_lv2_in_e_port_ids ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No LV2");
			if( extracted_data->field_id == INT_REPORT_HOP_LV2_IE_PORT_IDS )
				data.data[i] = ntohl( *u32 );
		}

		if( is_tx_utilizes ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No TX Utilize");
			if( extracted_data->field_id == INT_REPORT_HOP_TX_UTILIZES )
				data.data[i] = ntohl( *u32 );
		}
	}

	switch( extracted_data->field_id ){
	case INT_REPORT_HOP_SWITCH_IDS:
		if( ! is_switches_id )
			return NOT_FOUND;
		memcpy( extracted_data->data, &data, sizeof(mmt_u32_array_t) );
		return FOUND;
	case INT_REPORT_HOP_INGRESS_PORT_IDS:
		if( ! is_in_e_port_ids )
			return NOT_FOUND;
		memcpy( extracted_data->data, &data, sizeof(mmt_u32_array_t) );
		return FOUND;
	case INT_REPORT_HOP_EGRESS_PORT_IDS:
		if( ! is_in_e_port_ids )
			return NOT_FOUND;
		memcpy( extracted_data->data, &data, sizeof(mmt_u32_array_t) );
		return FOUND;
	}

	return NOT_FOUND;
}

#define def_att(id, data_type, data_len ) { id, id##_ALIAS, data_type, data_len, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_int_report_att}
static attribute_metadata_t _attributes_metadata[] = {
	def_att( INT_REPORT_SWITCH_ID,   MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_REPORT_HW_ID ,      MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_REPORT_SEQ_NUMBER , MMT_U32_DATA, sizeof(uint32_t) ),

	def_att( INT_REPORT_FLOW_IP_SRC, MMT_DATA_IP_ADDR, sizeof( uint32_t) ),
	def_att( INT_REPORT_FLOW_IP_DST, MMT_DATA_IP_ADDR, sizeof( uint32_t) ),
	def_att( INT_REPORT_FLOW_PORT_SRC, MMT_U16_DATA,   sizeof( uint16_t) ),
	def_att( INT_REPORT_FLOW_PORT_DST, MMT_U16_DATA,   sizeof( uint16_t) ),

	def_att( INT_REPORT_HOP_LATENCY, MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_REPORT_SINK_TIME,   MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_REPORT_METADATA_BITS , MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_NUM_HOP ,       MMT_U8_DATA, sizeof(uint8_t) ),

	def_att( INT_REPORT_HOP_SWITCH_IDS ,       MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_INGRESS_PORT_IDS , MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_EGRESS_PORT_IDS ,  MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_LATENCIES ,        MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_QUEUE_IDS ,        MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_QUEUE_OCCUPS ,     MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_INGRESS_TIMES ,    MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_EGRESS_TIMES ,     MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_LV2_IE_PORT_IDS ,  MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_TX_UTILIZES ,      MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),

	def_att( INT_REPORT_IS_IN_EGRESS_PORT_ID , MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_HOP_LATENCY ,       MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_QUEUE_ID_OCCUP ,    MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_EGRESS_TIME ,       MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_QUEUE_ID_DROP_REASON_PADDING , MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_TX_UTILIZE ,        MMT_U8_DATA, sizeof(uint8_t) )
};



int init_proto_inband_network_telemetry_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_INT_REPORT, PROTO_INT_REPORT_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i, len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_INT_REPORT_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	int ret = register_classification_function_with_parent_protocol( PROTO_UDP, _classify_inband_network_telemetry_from_udp, 100 );
	if( ret == 0 ){
		fprintf(stderr, "Need mmt_tcpip library containing PROTO_UDP having id = %d", PROTO_UDP);
		return PROTO_NOT_REGISTERED;
	}
	return register_protocol(protocol_struct, PROTO_INT_REPORT);
}
