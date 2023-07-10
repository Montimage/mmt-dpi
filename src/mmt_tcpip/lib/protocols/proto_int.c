/*
 * inband_telemetry.c
 *
 *  Created on: Jan 03, 2022
 *      Author: nhnghia
 */

#include "proto_int.h"
#include "proto_int_report.h"
#include "mmt_tcpip_protocols.h"

#include "../mmt_common_internal_include.h"

// indicates an INT header in the packet
#define IPv4_DSCP_INT 0x20

struct _iphdr {
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

#define NOT_FOUND 0
#define FOUND     1

static int _classify_int_from_udp_or_tcp(ipacket_t * ipacket, unsigned index, bool is_udp) {
	//need IP.UDP/TCP
	if( index <=1 )
		return 0;
	//must be preceded by IPv4 (TODO: need to support IPv6)
	if( get_protocol_id_at_index(ipacket, index - 1) != PROTO_IP )
		goto _not_found_int;

	int offset = get_packet_offset_at_index(ipacket, index);
	//must be enough room for ipv4
	if( offset <= sizeof( struct _iphdr ) )
		goto _not_found_int;

	const struct _iphdr *ip = (struct _iphdr *) & ipacket->data[offset - sizeof(struct _iphdr)];
	//not found specific DSCP in IP
	if( ip->dscp != IPv4_DSCP_INT )
		goto _not_found_int;

	//return set_classified_proto(ipacket, index + 1, retval);
	mmt_internal_add_connection(ipacket, PROTO_INT, MMT_REAL_PROTOCOL);
	return FOUND;

	_not_found_int:
	//checked but not found
	//=> exclude from the next check
	MMT_ADD_PROTOCOL_TO_BITMASK(ipacket->internal_packet->flow->excluded_protocol_bitmask, PROTO_INT);
	return NOT_FOUND;

}

static int _classify_int_from_udp(ipacket_t * ipacket, unsigned index) {
	return _classify_int_from_udp_or_tcp( ipacket, index, true );
}

static int _classify_int_from_tcp(ipacket_t * ipacket, unsigned index) {
	return _classify_int_from_udp_or_tcp( ipacket, index, false );
}

static int _int_classify_me(ipacket_t * ipacket, unsigned index) {
	classified_proto_t retval;
	retval.offset = 56;
	retval.proto_id = 0; //FIXME: need to update to QUIC_IETF
	retval.status = NonClassified;
	set_classified_proto(ipacket, index+1, retval);
	return NOT_FOUND;
}

#define advance_pointer( var, var_type, cursor, end_cursor, msg )\
	if( cursor + sizeof(var_type) > end_cursor ){\
		debug(msg);\
		return NOT_FOUND;\
	} else {\
		var = (var_type *) cursor;\
		cursor += sizeof(var_type);\
	}

#ifndef debug
#define debug(M, ...)\
	fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define extract_u8( v )\
	if( v ){\
		(*(uint8_t *) extracted_data->data) = 1;\
		return FOUND;\
	} else return NOT_FOUND;

#define assign_if( cond, target, src )\
	if( ! cond )\
		return NOT_FOUND;\
	target = src;\
	break;

typedef struct {
	uint32_t  first_ip_dd;
	uint32_t  second_ip_ad;
	uint16_t  nb_pkt_window_up;
	uint16_t  nb_pkt_window_down;
	uint32_t  sum_pkts_size_window_up;
	uint32_t  sum_pkts_size_window_down;
	uint32_t  sum_iat_window_up;
	uint32_t  sum_iat_window_down;
} cloud_gaming_data_t;


static int _extraction_int_cloud_gaming_report_att(const cloud_gaming_data_t *p_cg, const ipacket_t *ipacket, unsigned index,
	attribute_t * extracted_data) {
	cloud_gaming_data_t d_cg;
		// jsonReport = [ recv_firstIP, 2152, recv_secondIP, 8787,
		//                [recv_nbPktWindowDown, meanPktSizeLastWindowDown, 0, meanIATLastWindowDown,  0, recv_sumPktsSizeWindowDown] ,
		//                [recv_nbPktWindowUp, meanPktSizeLastWindowUp, 0, meanIATLastWindowUp,  0, recv_sumPktsSizeWindowUp]
		//              ]
	switch( extracted_data->field_id ){
	case INT_CLOUD_GAMING_IP_SRC:
		(*(uint32_t *) extracted_data->data) = p_cg->first_ip_dd;
		return FOUND;
	case INT_CLOUD_GAMING_IP_DST:
		(*(uint32_t *) extracted_data->data) = p_cg->second_ip_ad;
		return FOUND;
	}

	//convert values from network order to host order
	d_cg.nb_pkt_window_down  = ntohs( p_cg->nb_pkt_window_down );
	d_cg.nb_pkt_window_up    = ntohs( p_cg->nb_pkt_window_up );
	d_cg.sum_iat_window_down = ntohl( p_cg->sum_iat_window_down );
	d_cg.sum_iat_window_up   = ntohl( p_cg->sum_iat_window_up );
	d_cg.sum_pkts_size_window_down = ntohl( p_cg->sum_pkts_size_window_down );
	d_cg.sum_pkts_size_window_up   = ntohl( p_cg->sum_pkts_size_window_up );


	//# We received IAT values on the 64µs basis
	//# Need to multiply it by 64 to have the correct value on a 1µs basis
	d_cg.sum_iat_window_up *= 64;
	d_cg.sum_iat_window_down *= 64;

	//calculate other synthetic values
	uint32_t mean_pkt_size_last_window_up = 0;
	if( d_cg.nb_pkt_window_up != 0 )
		mean_pkt_size_last_window_up = d_cg.sum_pkts_size_window_up / d_cg.nb_pkt_window_up;
	uint32_t mean_pkt_size_last_window_down = 0;
	if( d_cg.nb_pkt_window_down != 0 )
		mean_pkt_size_last_window_down = d_cg.sum_pkts_size_window_down / d_cg.nb_pkt_window_down;

	//not sure why does it take this default value: https://github.com/mosaico-anr/P4_NFV_CG_Detector/blob/main/Controler.py#L78-L84C13
	uint32_t mean_iat_last_window_up =  32960;
	if( d_cg.nb_pkt_window_up != 0 ){
		if( d_cg.nb_pkt_window_up == 1 )
			mean_iat_last_window_up = 16448;
		else
			mean_iat_last_window_up = d_cg.sum_iat_window_up / d_cg.nb_pkt_window_up;
	}

	uint32_t mean_iat_last_window_down =  32960;
	if( d_cg.nb_pkt_window_down != 0 ){
		if( d_cg.nb_pkt_window_down == 1 )
			mean_iat_last_window_down = 16448;
		else
			mean_iat_last_window_down = d_cg.sum_iat_window_down / d_cg.nb_pkt_window_down;
	}

	/*
		string->len = snprintf((char*)string->data, sizeof(string->data),
				"[\"%d.%d.%d.%d\",2152,\"%d.%d.%d.%d\",8787,"
				"[%d,%d,0,%d,0,%d]," //down
				"[%d,%d,0,%d,0,%d]]" //up
				,
				ip_a->a, ip_a->b, ip_a->c, ip_a->d, ip_b->a, ip_b->b, ip_b->c, ip_b->d,
				//down
				d_cg.nb_pkt_window_down, mean_pkt_size_last_window_down, mean_iat_last_window_down, d_cg.sum_pkts_size_window_down,
				// up
				d_cg.nb_pkt_window_up, mean_pkt_size_last_window_up, mean_iat_last_window_up, d_cg.sum_pkts_size_window_up
			);
	*/

	switch( extracted_data->field_id ){
	case INT_CLOUD_GAMING_NB_PKT_DOWN:
		(*(uint32_t *) extracted_data->data) = d_cg.nb_pkt_window_down;
		return FOUND;
	case INT_CLOUD_GAMING_MEAN_PKT_SIZE_DOWN:
		(*(uint32_t *) extracted_data->data) = mean_pkt_size_last_window_down;
		return FOUND;
	case INT_CLOUD_GAMING_MEAN_IAT_DOWN:
		(*(uint32_t *) extracted_data->data) = mean_iat_last_window_down;
		return FOUND;
	case INT_CLOUD_GAMING_SUM_PKT_SIZE_DOWN:
		(*(uint32_t *) extracted_data->data) = d_cg.sum_pkts_size_window_down;
		return FOUND;

	case INT_CLOUD_GAMING_NB_PKT_UP:
		(*(uint32_t *) extracted_data->data) = d_cg.nb_pkt_window_up;
		return FOUND;
	case INT_CLOUD_GAMING_MEAN_PKT_SIZE_UP:
		(*(uint32_t *) extracted_data->data) = mean_pkt_size_last_window_up;
		return FOUND;
	case INT_CLOUD_GAMING_MEAN_IAT_UP:
		(*(uint32_t *) extracted_data->data) = mean_iat_last_window_up;
		return FOUND;
	case INT_CLOUD_GAMING_SUM_PKT_SIZE_UP:
		(*(uint32_t *) extracted_data->data) = d_cg.sum_pkts_size_window_up;
		return FOUND;
	}

	return NOT_FOUND;
}
static int _extraction_int_report_att(const ipacket_t *ipacket, unsigned index,
		attribute_t * extracted_data) {
	int i, offset = get_packet_offset_at_index(ipacket, index);
	const u_char *cursor = &ipacket->data[offset], *end_cursor = &ipacket->data[ipacket->p_hdr->caplen];

	// INT over TCP/UDP structure
	// [Eth][IP][UDP/TCP][SHIM][INT RAPORT HDR][INT DATA][UDP/TCP payload]
	// We are here --------^
	int_shim_tcpudp_v10_t *shim;
	advance_pointer( shim, int_shim_tcpudp_v10_t, cursor, end_cursor, "No Shim");

	if( shim->type != 1 && shim->type != 0 ){
		debug("Does not support type=%d", shim->type );
		return NOT_FOUND;
	}

	int_hop_by_hop_v10_t *hbh_report;
	advance_pointer( hbh_report, int_hop_by_hop_v10_t, cursor, end_cursor, "No Shim.HopByHopReport");


	int num_hops = 0;
	//3 is sizeof INT shim and md fix headers in words
	if( shim->length >= 3 )
		num_hops = (shim->length - 3)/hbh_report->hop_ml;

	uint16_t ins_bits = ntohs( hbh_report->instructions );

	switch( extracted_data->field_id ){
	case INT_INSTRUCTION_BITS:
		(*(uint16_t *) extracted_data->data) = ins_bits;
		return FOUND;
	case INT_NUM_HOP:
		(*(uint8_t *) extracted_data->data) = num_hops;
		return FOUND;
	default:
		break;
	}

	uint8_t is_switches_id       = (ins_bits >> 15) & 0x1;
	uint8_t is_in_e_port_ids     = (ins_bits >> 14) & 0x1;
	uint8_t is_hop_latencies     = (ins_bits >> 13) & 0x1;
	uint8_t is_queue_occups      = (ins_bits >> 12) & 0x1;
	uint8_t is_ingr_times        = (ins_bits >> 11) & 0x1;
	uint8_t is_egr_times         = (ins_bits >> 10) & 0x1;
	uint8_t is_lv2_in_e_port_ids = (ins_bits >>  9) & 0x1;
	uint8_t is_tx_utilizes       = (ins_bits >>  8) & 0x1;
	uint8_t is_l4s_mark_drop     = (ins_bits >>  7) & 0x1;
	uint8_t is_cloud_gaming_meta = (ins_bits >>  6) & 0x1;


	switch( extracted_data->field_id ){
	case INT_IS_SWITCH_ID:
		extract_u8( is_switches_id );
	case INT_IS_IN_EGRESS_PORT_ID:
		extract_u8( is_in_e_port_ids );
	case INT_IS_HOP_LATENCY:
		extract_u8( is_hop_latencies );
	case INT_IS_QUEUE_ID_OCCUP:
		extract_u8( is_queue_occups );
	case INT_IS_INGRESS_TIME:
		extract_u8( is_ingr_times );
	case INT_IS_EGRESS_TIME:
		extract_u8( is_egr_times );
	case INT_IS_LV2_IN_EGRESS_PORT_ID:
		extract_u8( is_lv2_in_e_port_ids );
	case INT_IS_TX_UTILIZE:
		extract_u8( is_tx_utilizes );
	case INT_IS_L4S_MARK_DROP:
		extract_u8( is_l4s_mark_drop );
	case INT_IS_CLOUD_GAMING:
		extract_u8( is_cloud_gaming_meta );
	default:
		break;
	}

	uint32_t *u32;
	uint64_t *u64;
	struct {
		mmt_u32_array_t
		sw_ids,
		in_port_ids, e_port_ids,
		hop_latencies,
		queue_ids, queue_occups,
		lv2_in_port_ids, lv2_e_port_ids,
		tx_utilizes,
		l4s_mark,
		l4s_drop,
		l4s_mark_probability;
		mmt_u64_array_t ingress_times, egress_times;
	}data;

	memset( &data, 0, sizeof(data) );

	//TODO: limit number of hops by 64
	//we can increase size of "data" in "mmt_u32_array_t" to contain more hops
	// but 64 should be further than enough
	//This check is to avoid overflow attack that should never occurs in a normal condition
	if( num_hops > BINARY_64DATA_LEN )
		num_hops = BINARY_64DATA_LEN;

	uint32_t total_latency = 0;

	for( i=0; i<num_hops; i++ ){
		if( is_switches_id ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No SW_IDS");
			data.sw_ids.data[i] = ntohl( *u32 );
		}

		if( is_in_e_port_ids ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No In Egress port IDs");
			data.in_port_ids.data[i] = (ntohl( *u32 ) >> 16) & 0xffff;
			data.e_port_ids.data[i]  = (ntohl( *u32 ) ) & 0xffff;
		}

		if( is_hop_latencies ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No Hop latencies");
			data.hop_latencies.data[i] = ntohl( *u32 );
			total_latency += ntohl( *u32 );
		}

		if( is_queue_occups ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No queue occups");
			data.queue_ids.data[i]    = (ntohl( *u32 ) >> 24) & 0xffff;
			data.queue_occups.data[i] = (ntohl( *u32 ) ) & 0xffff;
		}

		//Some implementation uses 64 bit to store timestamp
		//https://github.com/GEANT-DataPlaneProgramming/int-platforms/blob/master/p4src/int_v1.0/include/headers.p4#L124
		if( is_ingr_times ){
			advance_pointer( u64, uint64_t, cursor, end_cursor, "No Ingress time");
			data.ingress_times.data[i] = ntohll( *u64 );
		}

		if( is_egr_times ){
			advance_pointer( u64, uint64_t, cursor, end_cursor, "No Egress Time");
			data.egress_times.data[i] = ntohll( *u64 );
		}

		if( is_lv2_in_e_port_ids ){
			//TODO: somewho no LV2 Egress Port in
			//4.7 INT Hop-by-Hop Metadata Header Format (page 15)
			//Level 2 Ingress Port ID + Egress Port ID (4 bytes each)
			//
			//In this implementation:
			//https://github.com/GEANT-DataPlaneProgramming/int-platforms/blob/master/p4src/int_v1.0/include/headers.p4#L131
			// they use 16bits for ingress, and 16 bit for egress
			// we adapt here to test their pcap files
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No LV2 Ingress");
			data.lv2_in_port_ids.data[i] = (ntohl( *u32 ) >> 16) & 0xffff;
			//advance_pointer( u32, uint32_t, cursor, end_cursor, "No LV2 Egress");
			data.lv2_e_port_ids.data[i]  = (ntohl( *u32 ) ) & 0xffff;
		}

		if( is_tx_utilizes ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No TX Utilize");
			data.tx_utilizes.data[i] = ntohl( *u32 );
		}
		if( is_l4s_mark_drop ){
			advance_pointer( u32, uint32_t, cursor, end_cursor, "No L4S Mark-Drop");
			data.l4s_mark.data[i] = (ntohl( *u32 ) >> 16) & 0xffff;
			data.l4s_drop.data[i] = (ntohl( *u32 ) ) & 0xffff;

			advance_pointer( u32, uint32_t, cursor, end_cursor, "No L4S Mark Probability");
			data.l4s_mark_probability.data[i] = ntohl( *u32 );
		}

		//specific data for cloudgaming reports
		if( is_cloud_gaming_meta ){
			cloud_gaming_data_t *p_cg;
			advance_pointer( p_cg, cloud_gaming_data_t, cursor, end_cursor, "No CloudGaming data" );
			if( _extraction_int_cloud_gaming_report_att(p_cg, ipacket, index, extracted_data) == FOUND)
				return FOUND;
		}
	}

	mmt_u32_array_t *ptr = NULL;
	mmt_u64_array_t *ptr64 = NULL;
	switch( extracted_data->field_id ){
	//total latency of all hops
	case INT_HOP_LATENCY:
		if( !is_hop_latencies )
			return NOT_FOUND;
		(*(uint32_t *) extracted_data->data) = total_latency;
		return FOUND;
	case INT_HOP_SWITCH_IDS:
		assign_if( is_switches_id, ptr, &data.sw_ids );
	case INT_HOP_INGRESS_PORT_IDS:
		assign_if( is_in_e_port_ids, ptr, &data.in_port_ids );
	case INT_HOP_EGRESS_PORT_IDS:
		assign_if( is_in_e_port_ids, ptr, &data.e_port_ids );
	case INT_HOP_LATENCIES:
		assign_if( is_hop_latencies, ptr, &data.hop_latencies );
	case INT_HOP_QUEUE_IDS:
		assign_if( is_queue_occups, ptr, &data.queue_ids );
	case INT_HOP_QUEUE_OCCUPS:
		assign_if( is_queue_occups, ptr, &data.queue_occups );
	case INT_HOP_INGRESS_TIMES:
		assign_if( is_ingr_times, ptr64, &data.ingress_times );
	case INT_HOP_EGRESS_TIMES:
		assign_if( is_egr_times, ptr64, &data.egress_times );
	case INT_HOP_LV2_INGRESS_PORT_IDS:
		assign_if( is_lv2_in_e_port_ids, ptr, &data.lv2_in_port_ids );
	case INT_HOP_LV2_EGRESS_PORT_IDS:
		assign_if( is_lv2_in_e_port_ids, ptr, &data.lv2_e_port_ids );
	case INT_HOP_TX_UTILIZES:
		assign_if( is_tx_utilizes, ptr, &data.tx_utilizes );
	case INT_HOP_L4S_MARK:
		assign_if( is_l4s_mark_drop, ptr, &data.l4s_mark );
	case INT_HOP_L4S_DROP:
		assign_if( is_l4s_mark_drop, ptr, &data.l4s_drop );
	case INT_HOP_L4S_MARK_PROBABILITY:
		assign_if( is_l4s_mark_drop, ptr, &data.l4s_mark_probability );
	default:
		break;
	}
	if( ptr != NULL ){
		ptr->len = num_hops;
		memcpy( extracted_data->data, ptr, sizeof(mmt_u32_array_t) );
		return FOUND;
	} else if( ptr64 != NULL ){
		ptr64->len = num_hops;
		memcpy( extracted_data->data, ptr64, sizeof(mmt_u64_array_t) );
		return FOUND;
	}
	return NOT_FOUND;
}


#define def_att(id, data_type, data_len ) { id, id##_ALIAS, data_type, data_len, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_int_report_att}
static attribute_metadata_t _attributes_metadata[] = {

	def_att( INT_INSTRUCTION_BITS , MMT_U16_DATA, sizeof(uint16_t) ),
	def_att( INT_NUM_HOP ,          MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( INT_HOP_LATENCY,       MMT_U32_DATA, sizeof(uint32_t) ),

	def_att( INT_HOP_SWITCH_IDS ,       MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_INGRESS_PORT_IDS , MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_EGRESS_PORT_IDS ,  MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_LATENCIES ,        MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_QUEUE_IDS ,        MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_QUEUE_OCCUPS ,     MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),

	def_att( INT_HOP_INGRESS_TIMES ,    MMT_U64_ARRAY, sizeof(mmt_u64_array_t) ),
	def_att( INT_HOP_EGRESS_TIMES ,     MMT_U64_ARRAY, sizeof(mmt_u64_array_t) ),

	def_att( INT_HOP_LV2_INGRESS_PORT_IDS , MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_LV2_EGRESS_PORT_IDS ,  MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_TX_UTILIZES ,          MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_L4S_MARK,              MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_L4S_DROP,              MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),
	def_att( INT_HOP_L4S_MARK_PROBABILITY,  MMT_U32_ARRAY, sizeof(mmt_u32_array_t) ),

	def_att( INT_IS_SWITCH_ID,          MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_IS_IN_EGRESS_PORT_ID , MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_IS_HOP_LATENCY ,       MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_IS_QUEUE_ID_OCCUP ,    MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_IS_INGRESS_TIME ,      MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_IS_EGRESS_TIME ,       MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_IS_LV2_IN_EGRESS_PORT_ID, MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_IS_TX_UTILIZE ,        MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_IS_L4S_MARK_DROP ,     MMT_U8_DATA, sizeof(uint8_t) ),
	//cloud gaming data
	def_att( INT_IS_CLOUD_GAMING ,      MMT_U8_DATA, sizeof(uint8_t) ),
	def_att( INT_CLOUD_GAMING_IP_SRC,   MMT_DATA_IP_ADDR, sizeof(uint32_t) ),
	def_att( INT_CLOUD_GAMING_IP_DST,   MMT_DATA_IP_ADDR, sizeof(uint32_t) ),
	def_att( INT_CLOUD_GAMING_NB_PKT_DOWN,         MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_CLOUD_GAMING_MEAN_PKT_SIZE_DOWN,  MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_CLOUD_GAMING_MEAN_IAT_DOWN,       MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_CLOUD_GAMING_SUM_PKT_SIZE_DOWN,   MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_CLOUD_GAMING_NB_PKT_UP,           MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_CLOUD_GAMING_MEAN_PKT_SIZE_UP,    MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_CLOUD_GAMING_MEAN_IAT_UP,         MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( INT_CLOUD_GAMING_SUM_PKT_SIZE_UP,     MMT_U32_DATA, sizeof(uint32_t) )
};


int init_proto_int_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_INT, PROTO_INT_ALIAS);
	if (protocol_struct == NULL){
		log_err("Cannot initialize PROTO_INT: id %d is not available", PROTO_INT );
		return PROTO_NOT_REGISTERED;
	}

	//register attributes
	int i, len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_INT_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}

	int ret = register_classification_function_with_parent_protocol( PROTO_UDP, _classify_int_from_udp, 100 );
	if( ret == 0 ){
		log_err("Need mmt_tcpip library containing PROTO_UDP having id = %d", PROTO_UDP);
		return PROTO_NOT_REGISTERED;
	}
	ret = register_classification_function_with_parent_protocol( PROTO_TCP, _classify_int_from_tcp, 100 );
	if( ret == 0 ){
		log_err( "Need mmt_tcpip library containing PROTO_TCP having id = %d", PROTO_TCP);
		return PROTO_NOT_REGISTERED;
	}

	register_classification_function(protocol_struct, _int_classify_me);

	return register_protocol(protocol_struct, PROTO_INT);
}
