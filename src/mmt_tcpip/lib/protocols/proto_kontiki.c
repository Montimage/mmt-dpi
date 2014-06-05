#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_kontiki_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_KONTIKI, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_kontiki(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len == 4 && (get_u32(packet->payload, 0) == htonl(0x02010100))) {
        MMT_LOG(PROTO_KONTIKI, MMT_LOG_DEBUG, "Kontiki UDP detected.\n");
        mmt_int_kontiki_add_connection(ipacket);
        return;
    }
    if (packet->payload_packet_len > 0 && packet->payload[0] == 0x02) {

        if (packet->payload_packet_len == 20 && (get_u32(packet->payload, 16) == htonl(0x02040100))) {
            MMT_LOG(PROTO_KONTIKI, MMT_LOG_DEBUG, "Kontiki UDP detected.\n");
            mmt_int_kontiki_add_connection(ipacket);
            return;
        }
        if (packet->payload_packet_len == 16 && (get_u32(packet->payload, 12) == htonl(0x000004e4))) {
            MMT_LOG(PROTO_KONTIKI, MMT_LOG_DEBUG, "Kontiki UDP detected.\n");
            mmt_int_kontiki_add_connection(ipacket);
            return;
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_KONTIKI);
}

int mmt_check_kontiki(ipacket_t * ipacket, unsigned index)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len == 4 && (get_u32(packet->payload, 0) == htonl(0x02010100))) {
            MMT_LOG(PROTO_KONTIKI, MMT_LOG_DEBUG, "Kontiki UDP detected.\n");
            mmt_int_kontiki_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len > 0 && packet->payload[0] == 0x02) {

            if (packet->payload_packet_len == 20 && (get_u32(packet->payload, 16) == htonl(0x02040100))) {
                MMT_LOG(PROTO_KONTIKI, MMT_LOG_DEBUG, "Kontiki UDP detected.\n");
                mmt_int_kontiki_add_connection(ipacket);
                return 1;
            }
            if (packet->payload_packet_len == 16 && (get_u32(packet->payload, 12) == htonl(0x000004e4))) {
                MMT_LOG(PROTO_KONTIKI, MMT_LOG_DEBUG, "Kontiki UDP detected.\n");
                mmt_int_kontiki_add_connection(ipacket);
                return 1;
            }
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_KONTIKI);
    }
    return 1;
}

void mmt_init_classify_me_kontiki() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_KONTIKI);
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_kontiki_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_KONTIKI, PROTO_KONTIKI_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_kontiki();

        return register_protocol(protocol_struct, PROTO_KONTIKI);
    } else {
        return 0;
    }
}


