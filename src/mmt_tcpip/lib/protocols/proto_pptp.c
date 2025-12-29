#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_pptp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_PPTP, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_pptp(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len >= 10 && get_u16(packet->payload, 0) == htons(packet->payload_packet_len)
            && get_u16(packet->payload, 2) == htons(0x0001) /* message type: control message */
            && get_u32(packet->payload, 4) == htonl(0x1a2b3c4d) /* cookie: correct */
            && (get_u16(packet->payload, 8) == htons(0x0001) /* control type: start-control-connection-request */
            )) {

        MMT_LOG(PROTO_PPTP, MMT_LOG_DEBUG, "found pptp.\n");
        mmt_int_pptp_add_connection(ipacket);
        return;
    }

    MMT_LOG(PROTO_PPTP, MMT_LOG_DEBUG, "exclude pptp.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_PPTP);
}

int mmt_check_pptp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len >= 10 && get_u16(packet->payload, 0) == htons(packet->payload_packet_len)
                && get_u16(packet->payload, 2) == htons(0x0001) /* message type: control message */
                && get_u32(packet->payload, 4) == htonl(0x1a2b3c4d) /* cookie: correct */
                && (get_u16(packet->payload, 8) == htons(0x0001) /* control type: start-control-connection-request */
                )) {

            MMT_LOG(PROTO_PPTP, MMT_LOG_DEBUG, "found pptp.\n");
            mmt_int_pptp_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_PPTP, MMT_LOG_DEBUG, "exclude pptp.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_PPTP);
    }
    return 0;
}

void mmt_init_classify_me_pptp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_PPTP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_pptp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_PPTP, PROTO_PPTP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_pptp();

        return register_protocol(protocol_struct, PROTO_PPTP);
    } else {
        return 0;
    }
}
