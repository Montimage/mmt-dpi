/*
 * inband_telemetry.c
 *
 *  Created on: Jan 03, 2022
 *      Author: nhnghia
 */

#include "inband_telemetry.h"
#include "inband_telemetry_report.h"
#include "mmt_tcpip_protocols.h"

// indicates an INT header in the packet
#define IPv4_DSCP_INT 0x20

struct iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t
		ihl     : 4,
		version : 4,
		ecn     : 2,
		dscp    : 6;
#elif BYTE_ORDER == BIG_ENDIAN
	uint8_t
		version : 4,
		ihl     : 4,
		dscp    : 6,
		enc     : 2;
#else
#error "BYTE_ORDER must be defined"
#endif
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
}__attribute__((packed));
#define TCP_HDR_SIZE 20
#define UDP_HDR_SIZE  8

#define NOT_FOUND 0
#define FOUND 1
static int _classify_int_from_udp_or_tcp(ipacket_t * ipacket, unsigned index, bool is_udp) {
	if( index <=1 )
		return 0;
	//must be preceded by IPv4 (TODO: need to support IPv6)
	if( get_protocol_id_at_index(ipacket, index - 1) != PROTO_IP )
		return 0;

	int offset = get_packet_offset_at_index(ipacket, index);
	//must be enough room for ipv4
	if( offset <= sizeof( struct iphdr ) )
		return 0;

	const struct iphdr *ip = (struct iphdr *) & ipacket->data[offset - sizeof(struct iphdr)];
	//not found specific DSCP in IP
	if( ip->dscp != IPv4_DSCP_INT )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_INT;
	retval.status   = Classified;
	retval.offset   = is_udp? UDP_HDR_SIZE : TCP_HDR_SIZE;

	 //HN: do not copy session proto path into ipacket's proto path.
	//As we know explicitly the protocol at index-th position in the hierarchy,
	// so we limit the length of hierarchy for now.
	//This length will be increased by another classification function
	//  if further protocols will classified latter.
	ipacket->proto_hierarchy->len = index + 1 + 1;

	return set_classified_proto(ipacket, index + 1, retval);
}

static int _classify_int_from_udp(ipacket_t * ipacket, unsigned index) {
	return _classify_int_from_udp_or_tcp( ipacket, index, true );
}

static int _classify_int_from_tcp(ipacket_t * ipacket, unsigned index) {
	return _classify_int_from_udp_or_tcp( ipacket, index, false );
}

static int _extraction_int_report_att(const ipacket_t *ipacket, unsigned index,
		attribute_t * extracted_data) {
	return 0;
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

	def_att( INT_REPORT_HOP_LATENCY,       MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_REPORT_SINK_TIME,         MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_REPORT_INSTRUCTION_BITS , MMT_U16_DATA, sizeof(uint16_t) ),
	def_att( INT_REPORT_NUM_HOP ,          MMT_U8_DATA,  sizeof(uint8_t) ),

	def_att( INT_REPORT_HOP_SWITCH_IDS ,       MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_INGRESS_PORT_IDS , MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_EGRESS_PORT_IDS ,  MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_LATENCIES ,        MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_QUEUE_IDS ,        MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_QUEUE_OCCUPS ,     MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),

	def_att( INT_REPORT_HOP_INGRESS_TIMES ,    MMT_U64_ARRAY, sizeof(mmt_u64_array_t) ),
	def_att( INT_REPORT_HOP_EGRESS_TIMES ,     MMT_U64_ARRAY, sizeof(mmt_u64_array_t) ),

	def_att( INT_REPORT_HOP_LV2_INGRESS_PORT_IDS , MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_LV2_EGRESS_PORT_IDS ,  MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_REPORT_HOP_TX_UTILIZES ,      MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),

	def_att( INT_REPORT_IS_SWITCH_ID,          MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_IN_EGRESS_PORT_ID , MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_HOP_LATENCY ,       MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_QUEUE_ID_OCCUP ,    MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_INGRESS_TIME ,      MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_EGRESS_TIME ,       MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_LV2_IN_EGRESS_PORT_ID, MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_REPORT_IS_TX_UTILIZE ,        MMT_U8_DATA, sizeof(uint8_t) )
};


int init_proto_int_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_INT, PROTO_INT_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i, len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_INT_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	int ret = register_classification_function_with_parent_protocol( PROTO_UDP, _classify_int_from_udp, 100 );
	if( ret == 0 ){
		fprintf(stderr, "Need mmt_tcpip library containing PROTO_UDP having id = %d", PROTO_UDP);
		return PROTO_NOT_REGISTERED;
	}
	ret = register_classification_function_with_parent_protocol( PROTO_TCP, _classify_int_from_tcp, 100 );
	if( ret == 0 ){
		fprintf(stderr, "Need mmt_tcpip library containing PROTO_TCP having id = %d", PROTO_TCP);
		return PROTO_NOT_REGISTERED;
	}
	return register_protocol(protocol_struct, PROTO_INT);
}
