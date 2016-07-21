#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_steam_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_STEAM, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_steam(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (flow->l4.tcp.steam_stage == 0) {
        if (packet->payload_packet_len == 4
                && ntohl(get_u32(packet->payload, 0)) <= 0x07
                && ntohs(packet->tcp->dest) >= 27030 && ntohs(packet->tcp->dest) <= 27040) {
            flow->l4.tcp.steam_stage = 1 + ipacket->session->last_packet_direction;
            MMT_LOG(PROTO_STEAM, MMT_LOG_DEBUG, "steam stage 1\n");
            return;
        }

    } else if (flow->l4.tcp.steam_stage == 2 - ipacket->session->last_packet_direction) {
        if ((packet->payload_packet_len == 1 || packet->payload_packet_len == 5)
                && packet->payload[0] == 0x01) {
            mmt_int_steam_add_connection(ipacket);
            MMT_LOG(PROTO_STEAM, MMT_LOG_DEBUG, "steam detected\n");
            return;
        }
    }

    MMT_LOG(PROTO_STEAM, MMT_LOG_DEBUG, "steam excluded.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_STEAM);
}

int mmt_check_steam(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->l4.tcp.steam_stage == 0) {
            if (packet->payload_packet_len == 4
                    && ntohl(get_u32(packet->payload, 0)) <= 0x07
                    && ntohs(packet->tcp->dest) >= 27030 && ntohs(packet->tcp->dest) <= 27040) {
                flow->l4.tcp.steam_stage = 1 + ipacket->session->last_packet_direction;
                MMT_LOG(PROTO_STEAM, MMT_LOG_DEBUG, "steam stage 1\n");
                return 1;
            }

        } else if (flow->l4.tcp.steam_stage == 2 - ipacket->session->last_packet_direction) {
            if ((packet->payload_packet_len == 1 || packet->payload_packet_len == 5)
                    && packet->payload[0] == 0x01) {
                mmt_int_steam_add_connection(ipacket);
                MMT_LOG(PROTO_STEAM, MMT_LOG_DEBUG, "steam detected\n");
                return 1;
            }
        }

        MMT_LOG(PROTO_STEAM, MMT_LOG_DEBUG, "steam excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_STEAM);

    }
    return 0;
}

void mmt_init_classify_me_steam() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_STEAM);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_steam_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_STEAM, PROTO_STEAM_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_steam();

        return register_protocol(protocol_struct, PROTO_STEAM);
    } else {
        return 0;
    }
}


