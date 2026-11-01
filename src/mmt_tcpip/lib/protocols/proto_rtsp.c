#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

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
int mmt_classify_rtsp(ipacket_t * ipacket, unsigned index) {
    

  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  struct mmt_internal_tcpip_session_struct *flow = packet->flow;
	struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
	struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;



	if (flow->rtsprdt_stage == 0
#ifdef PROTOCOL_RTCP
		&& !(packet->detected_protocol_stack[0] == PROTOCOL_RTCP)
#endif
		) {
		flow->rtsprdt_stage = 1 + ipacket->session->last_packet_direction;

		return 4;
	}

	if (ipacket->session->data_packet_count < 3 && flow->rtsprdt_stage == 1 + ipacket->session->last_packet_direction) {

		return 4;
	}

	if (packet->payload_packet_len > 20 && flow->rtsprdt_stage == 2 - ipacket->session->last_packet_direction) {

		// RTSP Server Message
		if (mmt_memcmp(packet->payload, "RTSP/1.0 ", 9) == 0) {



			if (dst != NULL) {
				mmt_get_source_ip_from_packet(packet, &dst->rtsp_ip_address);
				dst->rtsp_timer = packet->tick_timestamp;
				dst->rtsp_ts_set = 1;
			}
			if (src != NULL) {
				mmt_get_destination_ip_from_packet(packet, &src->rtsp_ip_address);
				src->rtsp_timer = packet->tick_timestamp;
				src->rtsp_ts_set = 1;
			}
			flow->rtsp_control_flow = 1;
			mmt_int_rtsp_add_connection(ipacket, MMT_REAL_PROTOCOL);
			return 1;
		}
	}
	if (packet->udp != NULL && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
		&& ((MMT_FLOW_EXCLUDES(flow, PROTO_RTP) == 0)
#ifdef PROTOCOL_RTCP
			|| (MMT_FLOW_EXCLUDES(flow, PROTOCOL_RTCP) == 0)
#endif
		)) {
		return 4;
	}


	MMT_EXCLUDE_PROTOCOL(flow, PROTO_RTSP);
	return 0;
}

int mmt_check_rtsp(ipacket_t * ipacket, unsigned index) {
    { /* guard evaluated by the classifier walk (issue #561) */
        	return mmt_classify_rtsp(ipacket, index);
    }
    return 4;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_rtsp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_RTSP, PROTO_RTSP_ALIAS);
    if (protocol_struct != NULL) { 
        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_RTSP);
        return register_protocol(protocol_struct, PROTO_RTSP);
    } else {
        return 0;
    }
}


