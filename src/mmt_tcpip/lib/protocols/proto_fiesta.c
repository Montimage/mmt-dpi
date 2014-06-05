#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_fiesta_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_FIESTA, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_fiesta(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "search fiesta.\n");

    if (flow->l4.tcp.fiesta_stage == 0 && packet->payload_packet_len == 5
            && get_u16(packet->payload, 0) == ntohs(0x0407)
            && (packet->payload[2] == 0x08)
            && (packet->payload[4] == 0x00 || packet->payload[4] == 0x01)) {

        MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "maybe fiesta symmetric, first packet.\n");
        flow->l4.tcp.fiesta_stage = 1 + ipacket->session->last_packet_direction;
        goto maybe_fiesta;
    }
    if (flow->l4.tcp.fiesta_stage == (2 - ipacket->session->last_packet_direction)
            && ((packet->payload_packet_len > 1 && packet->payload_packet_len - 1 == packet->payload[0])
            || (packet->payload_packet_len > 3 && packet->payload[0] == 0
            && get_l16(packet->payload, 1) == packet->payload_packet_len - 3))) {
        MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "Maybe fiesta.\n");
        goto maybe_fiesta;
    }
    if (flow->l4.tcp.fiesta_stage == (1 + ipacket->session->last_packet_direction)) {
        if (packet->payload_packet_len == 4 && get_u32(packet->payload, 0) == htonl(0x03050c01)) {
            goto add_fiesta;
        }
        if (packet->payload_packet_len == 5 && get_u32(packet->payload, 0) == htonl(0x04030c01)
                && packet->payload[4] == 0) {
            goto add_fiesta;
        }
        if (packet->payload_packet_len == 6 && get_u32(packet->payload, 0) == htonl(0x050e080b)) {
            goto add_fiesta;
        }
        if (packet->payload_packet_len == 100 && packet->payload[0] == 0x63 && packet->payload[61] == 0x52
                && packet->payload[81] == 0x5a && get_u16(packet->payload, 1) == htons(0x3810)
                && get_u16(packet->payload, 62) == htons(0x6f75)) {
            goto add_fiesta;
        }
        if (packet->payload_packet_len > 3 && packet->payload_packet_len - 1 == packet->payload[0]
                && get_u16(packet->payload, 1) == htons(0x140c)) {
            goto add_fiesta;
        }
    }

    MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "exclude fiesta.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FIESTA);
    return;

maybe_fiesta:
    MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "Stage is set to %d.\n", flow->l4.tcp.fiesta_stage);
    return;

add_fiesta:
    MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "detected fiesta.\n");
    mmt_int_fiesta_add_connection(ipacket);
    return;
}

int mmt_check_fiesta(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "search fiesta.\n");

        if (flow->l4.tcp.fiesta_stage == 0 && packet->payload_packet_len == 5
                && get_u16(packet->payload, 0) == ntohs(0x0407)
                && (packet->payload[2] == 0x08)
                && (packet->payload[4] == 0x00 || packet->payload[4] == 0x01)) {

            MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "maybe fiesta symmetric, first packet.\n");
            flow->l4.tcp.fiesta_stage = 1 + ipacket->session->last_packet_direction;
            goto maybe_fiesta;
        }
        if (flow->l4.tcp.fiesta_stage == (2 - ipacket->session->last_packet_direction)
                && ((packet->payload_packet_len > 1 && packet->payload_packet_len - 1 == packet->payload[0])
                || (packet->payload_packet_len > 3 && packet->payload[0] == 0
                && get_l16(packet->payload, 1) == packet->payload_packet_len - 3))) {
            MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "Maybe fiesta.\n");
            goto maybe_fiesta;
        }
        if (flow->l4.tcp.fiesta_stage == (1 + ipacket->session->last_packet_direction)) {
            if (packet->payload_packet_len == 4 && get_u32(packet->payload, 0) == htonl(0x03050c01)) {
                goto add_fiesta;
            }
            if (packet->payload_packet_len == 5 && get_u32(packet->payload, 0) == htonl(0x04030c01)
                    && packet->payload[4] == 0) {
                goto add_fiesta;
            }
            if (packet->payload_packet_len == 6 && get_u32(packet->payload, 0) == htonl(0x050e080b)) {
                goto add_fiesta;
            }
            if (packet->payload_packet_len == 100 && packet->payload[0] == 0x63 && packet->payload[61] == 0x52
                    && packet->payload[81] == 0x5a && get_u16(packet->payload, 1) == htons(0x3810)
                    && get_u16(packet->payload, 62) == htons(0x6f75)) {
                goto add_fiesta;
            }
            if (packet->payload_packet_len > 3 && packet->payload_packet_len - 1 == packet->payload[0]
                    && get_u16(packet->payload, 1) == htons(0x140c)) {
                goto add_fiesta;
            }
        }

        MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "exclude fiesta.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FIESTA);
        return 1;

maybe_fiesta:
        MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "Stage is set to %d.\n", flow->l4.tcp.fiesta_stage);
        return 1;

add_fiesta:
        MMT_LOG(PROTO_FIESTA, MMT_LOG_DEBUG, "detected fiesta.\n");
        mmt_int_fiesta_add_connection(ipacket);
        return 1;
    }
    return 1;
}

void mmt_init_classify_me_fiesta() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FIESTA);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_fiesta_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FIESTA, PROTO_FIESTA_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_fiesta();

        return register_protocol(protocol_struct, PROTO_FIESTA);
    } else {
        return 0;
    }
}


