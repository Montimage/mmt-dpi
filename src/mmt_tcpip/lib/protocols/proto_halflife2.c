#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_halflife2_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_HALFLIFE2, MMT_REAL_PROTOCOL);
}

int mmt_check_halflife2(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->l4.udp.halflife2_stage == 0) {
            if (packet->payload_packet_len >= 20
                    && get_u32(packet->payload, 0) == 0xFFFFFFFF
                    && get_u32(packet->payload, packet->payload_packet_len - 4) == htonl(0x30303000)) {
                flow->l4.udp.halflife2_stage = 1 + ipacket->session->last_packet_direction;
                return 4;
            }
        } else if (flow->l4.udp.halflife2_stage == 2 - ipacket->session->last_packet_direction) {
            if (packet->payload_packet_len >= 20
                    && get_u32(packet->payload, 0) == 0xFFFFFFFF
                    && get_u32(packet->payload, packet->payload_packet_len - 4) == htonl(0x30303000)) {
                mmt_int_halflife2_add_connection(ipacket);
                return 1;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_HALFLIFE2);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_halflife2_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_HALFLIFE2, PROTO_HALFLIFE2_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_HALFLIFE2);

        return register_protocol(protocol_struct, PROTO_HALFLIFE2);
    } else {
        return 0;
    }
}
