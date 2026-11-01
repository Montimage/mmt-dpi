#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_florensia_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_FLORENSIA, MMT_REAL_PROTOCOL);
}

int mmt_check_florensia_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if (packet->payload_packet_len == 5 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && packet->payload[2] == 0x65 && packet->payload[4] == 0xff) {
            if (flow->florensia_stage == 1) {
                mmt_florensia_add_connection(ipacket);
                return 1;
            }
            flow->florensia_stage = 1;
            return 4;
        }
        if (packet->payload_packet_len > 8 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && get_u16(packet->payload, 2) == htons(0x0201) && get_u32(packet->payload, 4) == htonl(0xFFFFFFFF)) {
            flow->florensia_stage = 1;
            return 4;
        }
        if (packet->payload_packet_len == 406 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && packet->payload[2] == 0x63) {
            flow->florensia_stage = 1;
            return 4;
        }
        if (packet->payload_packet_len == 12 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && get_u16(packet->payload, 2) == htons(0x0301)) {
            if (flow->florensia_stage == 1) {
                mmt_florensia_add_connection(ipacket);
                return 1;
            }
            flow->florensia_stage = 1;
            return 4;
        }

        if (flow->florensia_stage == 1) {
            if (packet->payload_packet_len == 8 && get_l16(packet->payload, 0) == packet->payload_packet_len
                    && get_u16(packet->payload, 2) == htons(0x0302) && get_u32(packet->payload, 4) == htonl(0xFFFFFFFF)) {
                mmt_florensia_add_connection(ipacket);
                return 1;
            }
            if (packet->payload_packet_len == 24 && get_l16(packet->payload, 0) == packet->payload_packet_len
                    && get_u16(packet->payload, 2) == htons(0x0202)
                    && get_u32(packet->payload, packet->payload_packet_len - 4) == htonl(0xFFFFFFFF)) {
                mmt_florensia_add_connection(ipacket);
                return 1;
            }
            if (ipacket->session->data_packet_count < 10 && get_l16(packet->payload, 0) == packet->payload_packet_len) {
                return 4;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_FLORENSIA);
    }
    return 0;
}

int mmt_check_florensia_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if (flow->florensia_stage == 0 && packet->payload_packet_len == 6
                && get_u16(packet->payload, 0) == ntohs(0x0503) && get_u32(packet->payload, 2) == htonl(0xFFFF0000)) {
            flow->florensia_stage = 1;
            return 4;
        }
        if (flow->florensia_stage == 1 && packet->payload_packet_len == 8
                && get_u16(packet->payload, 0) == ntohs(0x0500) && get_u16(packet->payload, 4) == htons(0x4191)) {
            mmt_florensia_add_connection(ipacket);
            return 1;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_FLORENSIA);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_florensia_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FLORENSIA, PROTO_FLORENSIA_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_FLORENSIA);

        return register_protocol(protocol_struct, PROTO_FLORENSIA);
    } else {
        return 0;
    }
}
