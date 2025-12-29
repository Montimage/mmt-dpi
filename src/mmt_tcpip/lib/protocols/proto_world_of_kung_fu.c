#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_world_of_kung_fu_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_WORLD_OF_KUNG_FU, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_world_of_kung_fu(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_WORLD_OF_KUNG_FU, MMT_LOG_DEBUG, "search world_of_kung_fu.\n");

    if ((packet->payload_packet_len == 16)
            && ntohl(get_u32(packet->payload, 0)) == 0x0c000000 && ntohl(get_u32(packet->payload, 4)) == 0xd2000c00
            && (packet->payload[9]
            == 0x16) && ntohs(get_u16(packet->payload, 10)) == 0x0000 && ntohs(get_u16(packet->payload, 14)) == 0x0000) {
        MMT_LOG(PROTO_WORLD_OF_KUNG_FU, MMT_LOG_DEBUG, "detected world_of_kung_fu.\n");
        mmt_int_world_of_kung_fu_add_connection(ipacket);
        return;
    }

    MMT_LOG(PROTO_WORLD_OF_KUNG_FU, MMT_LOG_DEBUG, "exclude world_of_kung_fu.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_WORLD_OF_KUNG_FU);
}

int mmt_check_world_of_kung_fu(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_WORLD_OF_KUNG_FU, MMT_LOG_DEBUG, "search world_of_kung_fu.\n");

        if ((packet->payload_packet_len == 16)
                && ntohl(get_u32(packet->payload, 0)) == 0x0c000000 && ntohl(get_u32(packet->payload, 4)) == 0xd2000c00
                && (packet->payload[9]
                == 0x16) && ntohs(get_u16(packet->payload, 10)) == 0x0000 && ntohs(get_u16(packet->payload, 14)) == 0x0000) {
            MMT_LOG(PROTO_WORLD_OF_KUNG_FU, MMT_LOG_DEBUG, "detected world_of_kung_fu.\n");
            mmt_int_world_of_kung_fu_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_WORLD_OF_KUNG_FU, MMT_LOG_DEBUG, "exclude world_of_kung_fu.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_WORLD_OF_KUNG_FU);
    }
    return 0;
}

void mmt_init_classify_me_world_of_kung_fu() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_WORLD_OF_KUNG_FU);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_world_of_kung_fu_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_WORLD_OF_KUNG_FU, PROTO_WORLD_OF_KUNG_FU_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_world_of_kung_fu();

        return register_protocol(protocol_struct, PROTO_WORLD_OF_KUNG_FU);
    } else {
        return 0;
    }
}
