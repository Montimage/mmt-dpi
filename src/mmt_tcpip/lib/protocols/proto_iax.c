#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_IAX_MAX_INFORMATION_ELEMENTS 15

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_iax_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_IAX, MMT_REAL_PROTOCOL);
}

static void mmt_search_setup_iax(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    uint8_t i;
    uint16_t packet_len;

    if (/* 1. iax is udp based, port 4569 */
            (packet->udp->source == htons(4569) || packet->udp->dest == htons(4569))
            /* check for iax new packet */
            && packet->payload_packet_len >= 12
            /* check for dst call id == 0, do not check for highest bit (packet retransmission) */
            // && (ntohs(get_u16(packet->payload, 2)) & 0x7FFF) == 0
            /* check full IAX packet  */
            && (packet->payload[0] & 0x80) != 0
            /* outbound seq == 0 */
            && packet->payload[8] == 0
            /* inbound seq == 0 || 1  */
            && (packet->payload[9] == 0 || packet->payload[9] == 0x01)
            /*  */
            && packet->payload[10] == 0x06
            /* IAX type: 0-15 */
            && packet->payload[11] <= 15) {

        if (packet->payload_packet_len == 12) {
            MMT_LOG(PROTO_IAX, MMT_LOG_DEBUG, "found IAX.\n");
            mmt_int_iax_add_connection(ipacket);
            return;
        }
        packet_len = 12;
        for (i = 0; i < MMT_IAX_MAX_INFORMATION_ELEMENTS; i++) {
            packet_len = packet_len + 2 + packet->payload[packet_len + 1];
            if (packet_len == packet->payload_packet_len) {
                MMT_LOG(PROTO_IAX, MMT_LOG_DEBUG, "found IAX.\n");
                mmt_int_iax_add_connection(ipacket);
                return;
            }
            if (packet_len > packet->payload_packet_len) {
                break;
            }
        }

    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_IAX);

}

void mmt_classify_me_iax(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN)
        mmt_search_setup_iax(ipacket);
}

int mmt_check_iax(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN) {
            mmt_search_setup_iax(ipacket);
        }
    }
    return 2;
}

void mmt_init_classify_me_iax() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_IAX);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_IAX);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_iax_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_IAX, PROTO_IAX_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_iax();

        return register_protocol(protocol_struct, PROTO_IAX);
    } else {
        return 0;
    }
}


