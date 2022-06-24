/*
 * inband_telemetry_report.c
 *
 *  Created on: Jan 19, 2022
 *      Author: nhnghia
 */

#include "proto_int_report.h"
#include "mmt_tcpip_protocols.h"

#include "../mmt_common_internal_include.h"

#define INT_UDP_DST_PORT 6000

#define advance_pointer( var, var_type, cursor, end_cursor, msg )\
	if( cursor + sizeof(var_type) > end_cursor ){\
		debug(msg);\
		return 0;\
	} else {\
		var = (var_type *) cursor;\
		cursor += sizeof(var_type);\
	}


#ifndef debug
	#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define ETH_TYPE_IP 0x0800
#define IP_PROTO_UDP 17
#define IP_PROTO_TCP  6
#define TCP_HDR_SIZE (sizeof(struct tcphdr))
#define UDP_HDR_SIZE (sizeof(struct udphdr))


/**
 * Get size of data of INT report headers: that consists of [INT][ETH][IP][TCP/UDP]
 * @param ipacket
 * @param index
 * @param extracted_data
 * @return
 */
size_t proto_int_get_int_report_header_size(const u_char *cursor, const u_char *end_cursor) {
	const u_char *init_cursor = cursor;

	// INT Raport structure
	// [Eth][IP][UDP][INT RAPORT HDR][ETH][IP][UDP/TCP][INT SHIM][INT DATA]
	// We are here --------^
	const int_report_v10_t *int_header;
	advance_pointer(int_header, int_report_v10_t, cursor, end_cursor, "No INT header");

	if( int_header->version != 1 ){
		debug("Unsupported INT version %d", int_header->version);
		return 0;
	}
	//parse inner: ETH -> IP -> UDP/TCP->INT
	const struct ethhdr *eth;
	advance_pointer(eth, struct ethhdr, cursor, end_cursor, "No INT.Ethernet");

	if( ntohs(eth->h_proto) != ETH_TYPE_IP ){
		//TODO support IPv6?
		debug("No IPv4 after Ethernet");
		return 0;
	}

	const struct iphdr *ip;
	advance_pointer( ip, struct iphdr, cursor, end_cursor, "No INT.Ethernet.IP");

	switch( ip->protocol ){
	case IP_PROTO_UDP:
		//jump over UDP header
		cursor += UDP_HDR_SIZE;
		if( cursor >= end_cursor ){
			debug("No INT.Ethernet.IP.UDP");
			return 0;
		}
		break;
	case IP_PROTO_TCP:
		//jump over TCP header
		cursor += TCP_HDR_SIZE;
		if( cursor >= end_cursor ){
			debug("No INT.Ethernet.IP.TCP");
			return 0;
		}
		break;
	default:
		debug("Neither UDP, nor TCP is found after IP. Need to support INT over other protocol than TCP/UDP over IP");
		return 0;
	}
	//get offset of cursor wrt the initial offset
	return (cursor - init_cursor);
}

static int _classify_inband_network_telemetry_from_udp(ipacket_t * ipacket, unsigned index) {
	//the current (index) protocol is UDP
	int offset = get_packet_offset_at_index(ipacket, index);

	const struct udphdr *udp = (struct udphdr *) & ipacket->data[offset];
	const u_char *cursor = &ipacket->data[offset + UDP_HDR_SIZE], *end_cursor = &ipacket->data[ipacket->p_hdr->caplen];

	//the port is correct?
	if( ntohs(udp->dest) != INT_UDP_DST_PORT )
		goto _not_found_int_report;
	//the size is correct?
	// INT Raport structure
	//    [Eth][IP][UDP][INT RAPORT HDR][ETH][IP][UDP/TCP][INT SHIM][INT DATA]
	// We are here --^
	if( proto_int_get_int_report_header_size( cursor, end_cursor) == 0 )
		goto _not_found_int_report;

	//return set_classified_proto(ipacket, index + 1, retval);
	mmt_internal_add_connection(ipacket, PROTO_INT_REPORT, MMT_REAL_PROTOCOL);
	return 1;

	_not_found_int_report:
	//=> exclude from the next check
	MMT_ADD_PROTOCOL_TO_BITMASK(ipacket->internal_packet->flow->excluded_protocol_bitmask, PROTO_INT_REPORT);
	return 0;
}

static int _classify_int_report_next(ipacket_t * ipacket, unsigned index) {
	//the current (index) protocol is PROT_INT_REPORT
	int offset = get_packet_offset_at_index(ipacket, index);
	const u_char *cursor = &ipacket->data[offset], *end_cursor = &ipacket->data[ipacket->p_hdr->caplen];

	size_t int_report_len = proto_int_get_int_report_header_size(cursor, end_cursor);
	debug("offset : %zu\n", int_report_len );

	classified_proto_t retval;

	if( int_report_len == 0 )
		return 0;

	retval.proto_id = PROTO_INT;
	retval.status   = Classified;
	retval.offset   = int_report_len;

	return set_classified_proto(ipacket, index + 1, retval);
}

static int _extraction_int_report_att(const ipacket_t *ipacket, unsigned index,
		attribute_t * extracted_data) {
	int offset = get_packet_offset_at_index(ipacket, index);
	const u_char *cursor = &ipacket->data[offset], *end_cursor = &ipacket->data[ipacket->p_hdr->caplen];

	const int FOUND = 1, NOT_FOUND = 0;
	// INT Raport structure
	// [Eth][IP][UDP][INT RAPORT HDR][ETH][IP][UDP/TCP][INT SHIM][INT DATA]
	// We are here --------^
	const int_report_v10_t *int_header;
	advance_pointer(int_header, int_report_v10_t, cursor, end_cursor, "No INT header");

	if( int_header->version != 1 ){
		debug("Unsupported INT version %d", int_header->version);
		return 0;
	}
	//parse inner: ETH -> IP -> UDP/TCP->INT
	const struct ethhdr *eth;
	advance_pointer(eth, struct ethhdr, cursor, end_cursor, "No INT.Ethernet");

	if( ntohs(eth->h_proto) != ETH_TYPE_IP ){
		//TODO support IPv6?
		debug("No IPv4 after Ethernet");
		return NOT_FOUND;
	}

	const struct iphdr *ip;
	advance_pointer( ip, struct iphdr, cursor, end_cursor, "No INT.Ethernet.IP");

	//Although the next proto can be TCP but we can use UDP to get src/dst ports
	//as the src/dst ports of TCP are in the same position as the ones of UDP
	const struct udphdr *ports;
	advance_pointer( ports, struct udphdr, cursor, end_cursor, "No INT.Ethernet.IP.UDP");
	switch( ip->protocol ){
	case IP_PROTO_UDP:
		break;
	case IP_PROTO_TCP:
		//jump over TCP header
		cursor += (TCP_HDR_SIZE - UDP_HDR_SIZE);
		if( cursor >= end_cursor ){
			debug("No INT.Ethernet.IP.TCP");
			return NOT_FOUND;
		}
		break;
	default:
		debug("Neither UDP, nor TCP is found after IP. Need to support INT over other proto than TCP/UDP");
		return NOT_FOUND;
	}

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
	default:
		break;
	}
	return NOT_FOUND;
}

#define def_att(id, data_type, data_len ) { id, id##_ALIAS, data_type, data_len, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_int_report_att}
static attribute_metadata_t _attributes_metadata[] = {
	def_att( INT_REPORT_SWITCH_ID,   MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_REPORT_HW_ID ,      MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_REPORT_SEQ_NUMBER , MMT_U32_DATA, sizeof(uint32_t) ),

	def_att( INT_REPORT_FLOW_IP_SRC,   MMT_DATA_IP_ADDR, sizeof( uint32_t) ),
	def_att( INT_REPORT_FLOW_IP_DST,   MMT_DATA_IP_ADDR, sizeof( uint32_t) ),
	def_att( INT_REPORT_FLOW_PORT_SRC, MMT_U16_DATA,     sizeof( uint16_t) ),
	def_att( INT_REPORT_FLOW_PORT_DST, MMT_U16_DATA,     sizeof( uint16_t) ),

	def_att( INT_REPORT_SINK_TIME,         MMT_U32_DATA, sizeof(uint32_t) )
};


int init_proto_inband_network_telemetry_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_INT_REPORT, PROTO_INT_REPORT_ALIAS);
	if (protocol_struct == NULL){
		log_err("Cannot initialize PROTO_INT_REPORT: id %d is not available", PROTO_INT_REPORT );
		return PROTO_NOT_REGISTERED;
	}
	//register attributes
	int i, len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_INT_REPORT_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}

	int ret = register_classification_function_with_parent_protocol( PROTO_UDP, _classify_inband_network_telemetry_from_udp, 100 );
	if( ret == 0 ){
		log_err( "Need mmt_tcpip library containing PROTO_UDP having id = %d", PROTO_UDP);
		return PROTO_NOT_REGISTERED;
	}

	ret = register_classification_function( protocol_struct, _classify_int_report_next );
	if( ret == 0 ){
		log_err( "Cannot register the function to classify the next protocols from PROTO_INT_REPORT");
		return PROTO_NOT_REGISTERED;
	}

	return register_protocol(protocol_struct, PROTO_INT_REPORT);
}
