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

#define ETH_TYPE_IP   0x0800
#define ETH_TYPE_IPV6 0x86DD
#define IP_PROTO_UDP 17
#define IP_PROTO_TCP  6
#define TCP_HDR_SIZE (sizeof(struct tcphdr))
#define UDP_HDR_SIZE (sizeof(struct udphdr))
#define IPV4_MIN_HDR_SIZE 20
#define IPV6_HDR_SIZE     40
#define IPV6_ADDR_LEN     16

/* Network layer of the reported (inner) packet. The fields are read with byte
 * loads: the inner headers are only byte-aligned inside the report. */
typedef struct {
	uint8_t version;     //4 or 6
	uint8_t l4_proto;    //IPv4 Protocol / IPv6 Next Header
	const u_char *src;   //4 bytes for IPv4, 16 bytes for IPv6
	const u_char *dst;
} _inner_ip_t;

/**
 * Parses the inner IPv4 (options included) or IPv6 header at *cursor and moves
 * *cursor past it. IPv6 extension headers are not walked: the Next Header must
 * be the transport protocol.
 * @return false if the EtherType is neither IPv4 nor IPv6 or the header is
 *         truncated or malformed
 */
static bool _parse_inner_ip(uint16_t eth_type, const u_char **cursor, const u_char *end_cursor, _inner_ip_t *ip) {
	const u_char *p = *cursor;
	size_t avail = (end_cursor > p) ? (size_t)(end_cursor - p) : 0;
	size_t hdr_len;

	switch( eth_type ){
	case ETH_TYPE_IP:
		if( avail < IPV4_MIN_HDR_SIZE || (p[0] >> 4) != 4 )
			return false;
		hdr_len = (size_t)(p[0] & 0x0f) * 4; //IHL in 4-byte words
		if( hdr_len < IPV4_MIN_HDR_SIZE || hdr_len > avail )
			return false;
		ip->version  = 4;
		ip->l4_proto = p[9];
		ip->src      = p + 12;
		ip->dst      = p + 16;
		break;
	case ETH_TYPE_IPV6:
		if( avail < IPV6_HDR_SIZE || (p[0] >> 4) != 6 )
			return false;
		hdr_len = IPV6_HDR_SIZE;
		ip->version  = 6;
		ip->l4_proto = p[6];
		ip->src      = p + 8;
		ip->dst      = p + 24;
		break;
	default:
		return false;
	}
	*cursor = p + hdr_len;
	return true;
}


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

	_inner_ip_t ip;
	if( !_parse_inner_ip( ntohs(eth->h_proto), &cursor, end_cursor, &ip ) ){
		debug("No IPv4/IPv6 after INT.Ethernet");
		return 0;
	}

	switch( ip.l4_proto ){
	case IP_PROTO_UDP:
		//jump over UDP header: need also at least one byte after it
		if( (size_t)(end_cursor - cursor) <= UDP_HDR_SIZE ){
			debug("No INT.Ethernet.IP.UDP");
			return 0;
		}
		cursor += UDP_HDR_SIZE;
		break;
	case IP_PROTO_TCP:
		//jump over TCP header: need also at least one byte after it
		if( (size_t)(end_cursor - cursor) <= TCP_HDR_SIZE ){
			debug("No INT.Ethernet.IP.TCP");
			return 0;
		}
		cursor += TCP_HDR_SIZE;
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
	if( offset < 0 || !mmt_have_bytes(ipacket, (size_t)offset, UDP_HDR_SIZE) )
		goto _not_found_int_report;

	const u_char *cursor = &ipacket->data[offset + UDP_HDR_SIZE], *end_cursor = &ipacket->data[ipacket->p_hdr->caplen];

	//the port is correct? (UDP destination port at offset 2)
	if( ntohs( get_u16(&ipacket->data[offset], 2) ) != INT_UDP_DST_PORT )
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

	_inner_ip_t ip;
	if( !_parse_inner_ip( ntohs(eth->h_proto), &cursor, end_cursor, &ip ) ){
		debug("No IPv4/IPv6 after INT.Ethernet");
		return NOT_FOUND;
	}

	//Although the next proto can be TCP but we can use UDP to get src/dst ports
	//as the src/dst ports of TCP are in the same position as the ones of UDP
	const struct udphdr *ports;
	advance_pointer( ports, struct udphdr, cursor, end_cursor, "No INT.Ethernet.IP.UDP");
	switch( ip.l4_proto ){
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
		if( ip.version != 4 )
			return NOT_FOUND;
		(*(uint32_t *) extracted_data->data) = ntohl( get_u32(ip.src, 0) );
		return FOUND;
	case INT_REPORT_FLOW_IP_DST:
		if( ip.version != 4 )
			return NOT_FOUND;
		(*(uint32_t *) extracted_data->data) = ntohl( get_u32(ip.dst, 0) );
		return FOUND;
	case INT_REPORT_FLOW_IP6_SRC:
		if( ip.version != 6 )
			return NOT_FOUND;
		memcpy( extracted_data->data, ip.src, IPV6_ADDR_LEN );
		return FOUND;
	case INT_REPORT_FLOW_IP6_DST:
		if( ip.version != 6 )
			return NOT_FOUND;
		memcpy( extracted_data->data, ip.dst, IPV6_ADDR_LEN );
		return FOUND;
	case INT_REPORT_FLOW_PORT_SRC:
		(*(uint16_t *) extracted_data->data) = ntohs( get_u16(ports, 0) );
		return FOUND;
	case INT_REPORT_FLOW_PORT_DST:
		(*(uint16_t *) extracted_data->data) = ntohs( get_u16(ports, 2) );
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
	def_att( INT_REPORT_FLOW_IP6_SRC,  MMT_DATA_IP6_ADDR, IPV6_ADDR_LEN ),
	def_att( INT_REPORT_FLOW_IP6_DST,  MMT_DATA_IP6_ADDR, IPV6_ADDR_LEN ),
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
