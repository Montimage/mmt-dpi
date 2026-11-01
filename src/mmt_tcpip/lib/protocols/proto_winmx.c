#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_winmx_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_WINMX, MMT_REAL_PROTOCOL);
}

int mmt_check_winmx(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->l4.tcp.winmx_stage == 0) {
            if (packet->payload_packet_len == 1 || (packet->payload_packet_len > 1 && packet->payload[0] == 0x31)) {
                return 4;
            }
            /* did not see this pattern in any trace that we have */
            if (((packet->payload_packet_len) == 4)
                    && (mmt_memcmp(packet->payload, "SEND", 4) == 0)) {

                flow->l4.tcp.winmx_stage = 1;
                return 4;
            }

            if (((packet->payload_packet_len) == 3)
                    && (mmt_memcmp(packet->payload, "GET", 3) == 0)) {
                mmt_int_winmx_add_connection(ipacket);
                return 1;
            }

            if (packet->payload_packet_len == 149 && packet->payload[0] == '8') {
                if (get_u32(packet->payload, 17) == 0
                        && get_u32(packet->payload, 21) == 0
                        && get_u32(packet->payload, 25) == 0
                        && get_u16(packet->payload, 39) == 0 && get_u16(packet->payload, 135) == htons(0x7edf)
                        && get_u16(packet->payload, 147) == htons(0xf792)) {

                    mmt_int_winmx_add_connection(ipacket);
                    return 1;
                }
            }
            /* did not see this pattern in any trace that we have */
        } else if (flow->l4.tcp.winmx_stage == 1) {
            if (packet->payload_packet_len > 10 && packet->payload_packet_len < 1000) {
                uint16_t left = packet->payload_packet_len - 1;
                while (left > 0) {
                    if (packet->payload[left] == ' ') {
                        mmt_int_winmx_add_connection(ipacket);
                        return 1;
                    } else if (packet->payload[left] < '0' || packet->payload[left] > '9') {
                        break;
                    }
                    left--;
                }
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_WINMX);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_winmx_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_WINMX, PROTO_WINMX_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_WINMX);
        
        return register_protocol(protocol_struct, PROTO_WINMX);
    } else {
        return 0;
    }
}
