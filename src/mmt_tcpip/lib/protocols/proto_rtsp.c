#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#ifndef PROTO_RTP
#error RTSP requires RTP detection to work correctly
#endif
#ifndef PROTO_RTSP
#error RTSP requires RTSP detection to work correctly
#endif
#ifndef PROTO_RDP
#error RTSP requires RDP detection to work correctly
#endif
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_RTSP_TIMEOUT                    5

/* unused
static uint32_t rtsp_connection_timeout = MMT_RTSP_TIMEOUT * MMT_MICRO_IN_SEC;
*/

static void mmt_int_rtsp_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type)
{
	mmt_internal_add_connection(ipacket, PROTO_RTSP, protocol_type);
}

/* this function searches for a rtsp-"handshake" over tcp or udp. */
void mmt_classify_me_rtsp(ipacket_t * ipacket, unsigned index) {
    

  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  struct mmt_internal_tcpip_session_struct *flow = packet->flow;
	struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
	struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

	MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "calling mmt_search_rtsp_tcp_udp.\n");


	if (flow->rtsprdt_stage == 0
#ifdef IPOQUE_PROTOCOL_RTCP
		&& !(packet->detected_protocol_stack[0] == IPOQUE_PROTOCOL_RTCP)
#endif
		) {
		flow->rtsprdt_stage = 1 + ipacket->session->last_packet_direction;

		MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "maybe handshake 1; need next packet, return.\n");
		return;
	}

	if (ipacket->session->data_packet_count < 3 && flow->rtsprdt_stage == 1 + ipacket->session->last_packet_direction) {

		MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "maybe handshake 2; need next packet.\n");
		return;
	}

	if (packet->payload_packet_len > 20 && flow->rtsprdt_stage == 2 - ipacket->session->last_packet_direction) {

		// RTSP Server Message
		if (mmt_memcmp(packet->payload, "RTSP/1.0 ", 9) == 0) {


			MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "found RTSP/1.0 .\n");

			if (dst != NULL) {
				MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "found dst.\n");
				mmt_get_source_ip_from_packet(packet, &dst->rtsp_ip_address);
				dst->rtsp_timer = packet->tick_timestamp;
				dst->rtsp_ts_set = 1;
			}
			if (src != NULL) {
				MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "found src.\n");
				mmt_get_destination_ip_from_packet(packet, &src->rtsp_ip_address);
				src->rtsp_timer = packet->tick_timestamp;
				src->rtsp_ts_set = 1;
			}
			MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "found RTSP.\n");
			flow->rtsp_control_flow = 1;
			mmt_int_rtsp_add_connection(ipacket, MMT_REAL_PROTOCOL);
			return;
		}
	}
	if (packet->udp != NULL && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
		&& ((MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RTP) == 0)
#ifdef IPOQUE_PROTOCOL_RTCP
			|| (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_RTCP) == 0)
#endif
		)) {
		MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG,
				"maybe RTSP RTP, RTSP RTCP, RDT; need next packet.\n");
		return;
	}


	MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "didn't find handshake, exclude.\n");
	MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RTSP);
	return;
}


/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_rtsp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_RTSP, PROTO_RTSP_ALIAS);
    if (protocol_struct != NULL) { 
        return register_protocol(protocol_struct, PROTO_RTSP);
    } else {
        return 0;
    }
}


