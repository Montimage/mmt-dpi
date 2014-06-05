#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_afp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_AFP, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_afp(ipacket_t * ipacket, unsigned index) {

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    /*
     * this will detect the OpenSession command of the Data Stream Interface (DSI) protocol
     * which is exclusively used by the Apple Filing Protocol (AFP) on TCP/IP networks
     */
    if (packet->payload_packet_len >= 22 && get_u16(packet->payload, 0) == htons(0x0004) &&
            get_u16(packet->payload, 2) == htons(0x0001) && get_u32(packet->payload, 4) == 0 &&
            get_u32(packet->payload, 8) == htonl(packet->payload_packet_len - 16) &&
            get_u32(packet->payload, 12) == 0 && get_u16(packet->payload, 16) == htons(0x0104)) {

        MMT_LOG(PROTO_AFP, MMT_LOG_DEBUG, "AFP: DSI OpenSession detected.\n");
        mmt_int_afp_add_connection(ipacket);
        return;
    }

    /*
     * detection of GetStatus command of DSI protocl
     */
    if (packet->payload_packet_len >= 18 && get_u16(packet->payload, 0) == htons(0x0003) &&
            get_u16(packet->payload, 2) == htons(0x0001) && get_u32(packet->payload, 4) == 0 &&
            get_u32(packet->payload, 8) == htonl(packet->payload_packet_len - 16) &&
            get_u32(packet->payload, 12) == 0 && get_u16(packet->payload, 16) == htons(0x0f00)) {

        MMT_LOG(PROTO_AFP, MMT_LOG_DEBUG, "AFP: DSI GetStatus detected.\n");
        mmt_int_afp_add_connection(ipacket);
        return;
    }


    MMT_LOG(PROTO_AFP, MMT_LOG_DEBUG, "AFP excluded.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_AFP);
}

int mmt_check_afp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /*
         * this will detect the OpenSession command of the Data Stream Interface (DSI) protocol
         * which is exclusively used by the Apple Filing Protocol (AFP) on TCP/IP networks
         */
        if (packet->payload_packet_len >= 22 && get_u16(packet->payload, 0) == htons(0x0004) &&
                get_u16(packet->payload, 2) == htons(0x0001) && get_u32(packet->payload, 4) == 0 &&
                get_u32(packet->payload, 8) == htonl(packet->payload_packet_len - 16) &&
                get_u32(packet->payload, 12) == 0 && get_u16(packet->payload, 16) == htons(0x0104)) {

            MMT_LOG(PROTO_AFP, MMT_LOG_DEBUG, "AFP: DSI OpenSession detected.\n");
            mmt_int_afp_add_connection(ipacket);
            return 1;
        }

        /*
         * detection of GetStatus command of DSI protocl
         */
        if (packet->payload_packet_len >= 18 && get_u16(packet->payload, 0) == htons(0x0003) &&
                get_u16(packet->payload, 2) == htons(0x0001) && get_u32(packet->payload, 4) == 0 &&
                get_u32(packet->payload, 8) == htonl(packet->payload_packet_len - 16) &&
                get_u32(packet->payload, 12) == 0 && get_u16(packet->payload, 16) == htons(0x0f00)) {

            MMT_LOG(PROTO_AFP, MMT_LOG_DEBUG, "AFP: DSI GetStatus detected.\n");
            mmt_int_afp_add_connection(ipacket);
            return 1;
        }
        MMT_LOG(PROTO_AFP, MMT_LOG_DEBUG, "AFP excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_AFP);
    }
    return 1;
}

void mmt_init_classify_me_afp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_AFP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_afp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_AFP, PROTO_AFP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_afp();

        return register_protocol(protocol_struct, PROTO_AFP);
    } else {
        return 0;
    }
}


