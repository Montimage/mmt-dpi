#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_vnc_add_connection(ipacket_t * ipacket)
{
	mmt_internal_add_connection(ipacket, PROTO_VNC, MMT_REAL_PROTOCOL);
}

/*
  return 0 if nothing has been detected
  return 1 if it is a http packet
*/

void mmt_classify_me_vnc(ipacket_t * ipacket, unsigned index) {
    

  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  struct mmt_internal_tcpip_session_struct *flow = packet->flow;


	if (flow->l4.tcp.vnc_stage == 0) {
		if (packet->payload_packet_len == 12
			&& memcmp(packet->payload, "RFB 003.00", 10) == 0 && packet->payload[11] == 0x0a) {
			MMT_LOG(PROTO_POPO, MMT_LOG_DEBUG, "reached vnc stage one\n");
			flow->l4.tcp.vnc_stage = 1 + ipacket->session->last_packet_direction;
			return;
		}
	} else if (flow->l4.tcp.vnc_stage == 2 - ipacket->session->last_packet_direction) {
		if (packet->payload_packet_len == 12
			&& memcmp(packet->payload, "RFB 003.00", 10) == 0 && packet->payload[11] == 0x0a) {
			MMT_LOG(PROTO_VNC, MMT_LOG_DEBUG, "found vnc\n");
			mmt_int_vnc_add_connection(ipacket);
			return;
		}
	}
	MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_VNC);

}

int mmt_check_vnc(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_vnc(ipacket, index);
    }
    return 2;
}

void mmt_init_classify_me_vnc() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_VNC);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_vnc_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_VNC, PROTO_VNC_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_vnc();
        
        return register_protocol(protocol_struct, PROTO_VNC);
    } else {
        return 0;
    }
}


