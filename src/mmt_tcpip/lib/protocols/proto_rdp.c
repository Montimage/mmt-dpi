#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
/* BW: Remote Desktop protocol */
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_rdp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_RDP, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_rdp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len > 10
            && get_u8(packet->payload, 0) > 0
            && get_u8(packet->payload, 0) < 4 && get_u16(packet->payload, 2) == ntohs(packet->payload_packet_len)
            && get_u8(packet->payload, 4) == packet->payload_packet_len - 5
            && get_u8(packet->payload, 5) == 0xe0
            && get_u16(packet->payload, 6) == 0 && get_u16(packet->payload, 8) == 0 && get_u8(packet->payload, 10) == 0) {
        MMT_LOG(PROTO_RDP, MMT_LOG_DEBUG, "RDP detected.\n");
        mmt_int_rdp_add_connection(ipacket);
        return;
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RDP);
}

int mmt_check_rdp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 10
                && get_u8(packet->payload, 0) > 0
                && get_u8(packet->payload, 0) < 4 && get_u16(packet->payload, 2) == ntohs(packet->payload_packet_len)
                && get_u8(packet->payload, 4) == packet->payload_packet_len - 5
                && get_u8(packet->payload, 5) == 0xe0
                && get_u16(packet->payload, 6) == 0 && get_u16(packet->payload, 8) == 0 && get_u8(packet->payload, 10) == 0) {
            MMT_LOG(PROTO_RDP, MMT_LOG_DEBUG, "RDP detected.\n");
            mmt_int_rdp_add_connection(ipacket);
        } else {
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RDP);
        }
    }
    return 1;
}

void mmt_init_classify_me_rdp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_RDP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_rdp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_RDP, PROTO_RDP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_rdp();

        return register_protocol(protocol_struct, PROTO_RDP);
    } else {
        return 0;
    }
}


