#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_warcraft3_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_WARCRAFT3, MMT_REAL_PROTOCOL);
}

int mmt_check_warcraft3(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint16_t l;

        if (ipacket->session->data_packet_count == 1 && packet->payload_packet_len == 1 && packet->payload[0] == 0x01) {
            return 4;
        } else if (packet->payload_packet_len >= 4 && (packet->payload[0] == 0xf7 || packet->payload[0] == 0xff)) {
            l = packet->payload[2] + (packet->payload[3] << 8); // similar to ntohs
            while (l <= (packet->payload_packet_len - 4)) {
                if (packet->payload[l] == 0xf7) {
                    uint16_t temp = (packet->payload[l + 2 + 1] << 8) + packet->payload[l + 2];
                    if (temp <= 2) {
                        break;
                    } else {
                        l += temp;
                    }
                } else {
                    break;
                }
            }

            if (l == packet->payload_packet_len) {
                if (ipacket->session->data_packet_count > 2) {
                    mmt_int_warcraft3_add_connection(ipacket);
                    return 1;
                }
                return 4;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_WARCRAFT3);

    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_warcraft3_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_WARCRAFT3, PROTO_WARCRAFT3_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
                PROTO_WARCRAFT3, PROTO_WARCRAFT3);

        return register_protocol(protocol_struct, PROTO_WARCRAFT3);
    } else {
        return 0;
    }
}
