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

int mmt_check_afp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /*
         * this will detect the OpenSession command of the Data Stream Interface (DSI) protocol
         * which is exclusively used by the Apple Filing Protocol (AFP) on TCP/IP networks
         */
        if (packet->payload_packet_len >= 22 && get_u16(packet->payload, 0) == htons(0x0004) &&
                get_u16(packet->payload, 2) == htons(0x0001) && get_u32(packet->payload, 4) == 0 &&
                get_u32(packet->payload, 8) == htonl(packet->payload_packet_len - 16) &&
                get_u32(packet->payload, 12) == 0 && get_u16(packet->payload, 16) == htons(0x0104)) {

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

            mmt_int_afp_add_connection(ipacket);
            return 1;
        }
        MMT_EXCLUDE_PROTOCOL(flow, PROTO_AFP);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_afp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_AFP, PROTO_AFP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_AFP);

        return register_protocol(protocol_struct, PROTO_AFP);
    } else {
        return 0;
    }
}
