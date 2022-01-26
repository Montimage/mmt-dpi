/*
 * inband_telemetry_report.c
 *
 *  Created on: Jan 19, 2022
 *      Author: nhnghia
 */

#include "inband_telemetry_report.h"
#include "mmt_tcpip_protocols.h"

struct udphdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
};

#define INT_UDP_DST_PORT 5001

static int _classify_inband_network_telemetry_from_udp(ipacket_t * ipacket, unsigned index) {
	int offset = get_packet_offset_at_index(ipacket, index);

	const struct udphdr *udp = (struct udphdr *) & ipacket->data[offset];
	if( ntohs(udp->dest) != INT_UDP_DST_PORT )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_INT_REPORT;
	retval.status   = Classified;
	retval.offset   = sizeof( *udp ); //the next protocol is started after x bytes of UDP header

	 //HN: do not copy session proto path into ipacket's proto path.
	//As we know explicitly the protocol at index-th position in the hierarchy,
	// so we limit the length of hierarchy for now.
	//This length will be increased by another classification function
	//  if further protocols will classified latter.
	ipacket->proto_hierarchy->len = index + 1 + 1;

	return set_classified_proto(ipacket, index + 1, retval);
}

static int _extraction_int_report_att(const ipacket_t *ipacket, unsigned index,
		attribute_t * extracted_data) {
	int offset = get_packet_offset_at_index(ipacket, index);
	const int_report_v10_t *int_header = (int_report_v10_t *) &ipacket->data[offset];
	if( int_header->version != 1 ){
		debug("Unsupported INT version %d", int_header->version);
		//return 0;
	}
	switch( extracted_data->field_id ){
	case INT_REPORT_SWITCH_ID:
		(*(uint32_t *) extracted_data->data) = ntohl( int_header->switch_id );
		break;
	case INT_REPORT_SEQ_NUMBER:
		(*(uint32_t *) extracted_data->data) = ntohl( int_header->seq_number );
		break;
	case INT_REPORT_HW_ID:
		(*(uint32_t *) extracted_data->data) = int_header->hw_id;
		break;

	case INT_REPORT_SINK_TIME:
		(*(uint32_t *) extracted_data->data) = ntohl( int_header->ingress_timestamp );
		break;
	case INT_REPORT_METADATA_BITS:
		(*(uint8_t *) extracted_data->data) = int_header->report_metadata_bits;
		break;
	default:
		return 0;
	}
	return 1;
}

#define def_att(id, data_type, data_len ) { id, id##_ALIAS, data_type, data_len, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_int_report_att}
static attribute_metadata_t _attributes_metadata[] = {
	def_att( INT_REPORT_SWITCH_ID,   MMT_U32_DATA, sizeof(uint32_t) ),

	def_att( INT_REPORT_SEQ_NUMBER , MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_REPORT_HW_ID ,      MMT_U32_DATA, sizeof(uint32_t) ),
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
