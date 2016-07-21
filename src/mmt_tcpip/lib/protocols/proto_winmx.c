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

void mmt_classify_me_winmx_tcp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    if (flow->l4.tcp.winmx_stage == 0) {
        if (packet->payload_packet_len == 1 || (packet->payload_packet_len > 1 && packet->payload[0] == 0x31)) {
            return;
        }
        /* did not see this pattern in any trace that we have */
        if (((packet->payload_packet_len) == 4)
                && (memcmp(packet->payload, "SEND", 4) == 0)) {

            MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG, "maybe WinMX Send\n");
            flow->l4.tcp.winmx_stage = 1;
            return;
        }

        if (((packet->payload_packet_len) == 3)
                && (memcmp(packet->payload, "GET", 3) == 0)) {
            MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG, "found winmx by GET\n");
            mmt_int_winmx_add_connection(ipacket);
            return;
        }


        if (packet->payload_packet_len == 149 && packet->payload[0] == '8') {
            MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG, "maybe WinMX\n");
            if (get_u32(packet->payload, 17) == 0
                    && get_u32(packet->payload, 21) == 0
                    && get_u32(packet->payload, 25) == 0
                    && get_u16(packet->payload, 39) == 0 && get_u16(packet->payload, 135) == htons(0x7edf)
                    && get_u16(packet->payload, 147) == htons(0xf792)) {

                MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG,
                        "found winmx by pattern in first packet\n");
                mmt_int_winmx_add_connection(ipacket);
                return;
            }
        }
        /* did not see this pattern in any trace that we have */
    } else if (flow->l4.tcp.winmx_stage == 1) {
        if (packet->payload_packet_len > 10 && packet->payload_packet_len < 1000) {
            uint16_t left = packet->payload_packet_len - 1;
            while (left > 0) {
                if (packet->payload[left] == ' ') {
                    MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG, "found winmx in second packet\n");
                    mmt_int_winmx_add_connection(ipacket);
                    return;
                } else if (packet->payload[left] < '0' || packet->payload[left] > '9') {
                    break;
                }
                left--;
            }
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_WINMX);
}

int mmt_check_winmx(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->l4.tcp.winmx_stage == 0) {
            if (packet->payload_packet_len == 1 || (packet->payload_packet_len > 1 && packet->payload[0] == 0x31)) {
                return 1;
            }
            /* did not see this pattern in any trace that we have */
            if (((packet->payload_packet_len) == 4)
                    && (memcmp(packet->payload, "SEND", 4) == 0)) {

                MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG, "maybe WinMX Send\n");
                flow->l4.tcp.winmx_stage = 1;
                return 1;
            }

            if (((packet->payload_packet_len) == 3)
                    && (memcmp(packet->payload, "GET", 3) == 0)) {
                MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG, "found winmx by GET\n");
                mmt_int_winmx_add_connection(ipacket);
                return 1;
            }


            if (packet->payload_packet_len == 149 && packet->payload[0] == '8') {
                MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG, "maybe WinMX\n");
                if (get_u32(packet->payload, 17) == 0
                        && get_u32(packet->payload, 21) == 0
                        && get_u32(packet->payload, 25) == 0
                        && get_u16(packet->payload, 39) == 0 && get_u16(packet->payload, 135) == htons(0x7edf)
                        && get_u16(packet->payload, 147) == htons(0xf792)) {

                    MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG,
                            "found winmx by pattern in first packet\n");
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
                        MMT_LOG(PROTO_WINMX, MMT_LOG_DEBUG, "found winmx in second packet\n");
                        mmt_int_winmx_add_connection(ipacket);
                        return 1;
                    } else if (packet->payload[left] < '0' || packet->payload[left] > '9') {
                        break;
                    }
                    left--;
                }
            }
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_WINMX);
    }
    return 0;
}

void mmt_init_classify_me_winmx() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_WINMX);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_winmx_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_WINMX, PROTO_WINMX_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_winmx();
        
        return register_protocol(protocol_struct, PROTO_WINMX);
    } else {
        return 0;
    }
}


