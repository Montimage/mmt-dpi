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

int mmt_check_pptp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len >= 10 && get_u16(packet->payload, 0) == htons(packet->payload_packet_len)
                && get_u16(packet->payload, 2) == htons(0x0001) /* message type: control message */
                && get_u32(packet->payload, 4) == htonl(0x1a2b3c4d) /* cookie: correct */
                && (get_u16(packet->payload, 8) == htons(0x0001) /* control type: start-control-connection-request */
                )) {

            mmt_int_pptp_add_connection(ipacket);
            return 1;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_PPTP);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_pptp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_PPTP, PROTO_PPTP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_PPTP);

        return register_protocol(protocol_struct, PROTO_PPTP);
    } else {
        return 0;
    }
}
