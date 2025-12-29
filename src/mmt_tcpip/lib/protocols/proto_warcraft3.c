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

void mmt_classify_me_warcraft3(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint16_t l;

    MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "search WARCRAFT3\n");


    if (ipacket->session->data_packet_count == 1 && packet->payload_packet_len == 1 && packet->payload[0] == 0x01) {
        MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "maybe warcraft3: packet_len == 1\n");
        return;
    } else if (packet->payload_packet_len >= 4 && (packet->payload[0] == 0xf7 || packet->payload[0] == 0xff)) {

        MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "packet_payload begins with 0xf7 or 0xff\n");

        l = packet->payload[2] + (packet->payload[3] << 8); // similar to ntohs

        MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "l = %u \n", l);

        while (l <= (packet->payload_packet_len - 4)) {
            if (packet->payload[l] == 0xf7) {
                uint16_t temp = (packet->payload[l + 2 + 1] << 8) + packet->payload[l + 2];
                MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "another f7 visited.\n");
                if (temp <= 2) {
                    MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "break\n");
                    break;
                } else {
                    l += temp;
                    MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "l = %u \n", l);
                }
            } else {
                MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "break\n");
                break;
            }
        }


        if (l == packet->payload_packet_len) {
            MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "maybe WARCRAFT3\n");
            MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "flow->packet_counter = %u \n",
                    flow->data_packet_count);
            if (ipacket->session->data_packet_count > 2) {
                MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "detected WARCRAFT3\n");
                mmt_int_warcraft3_add_connection(ipacket);
                return;
            }
            return;
        }


    }


    MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "no warcraft3 detected.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_WARCRAFT3);
}

int mmt_check_warcraft3(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint16_t l;
        MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "search WARCRAFT3\n");

        if (ipacket->session->data_packet_count == 1 && packet->payload_packet_len == 1 && packet->payload[0] == 0x01) {
            MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "maybe warcraft3: packet_len == 1\n");
            return 4;
        } else if (packet->payload_packet_len >= 4 && (packet->payload[0] == 0xf7 || packet->payload[0] == 0xff)) {
            MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "packet_payload begins with 0xf7 or 0xff\n");
            l = packet->payload[2] + (packet->payload[3] << 8); // similar to ntohs
            MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "l = %u \n", l);
            while (l <= (packet->payload_packet_len - 4)) {
                if (packet->payload[l] == 0xf7) {
                    uint16_t temp = (packet->payload[l + 2 + 1] << 8) + packet->payload[l + 2];
                    MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "another f7 visited.\n");
                    if (temp <= 2) {
                        MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "break\n");
                        break;
                    } else {
                        l += temp;
                        MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "l = %u \n", l);
                    }
                } else {
                    MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "break\n");
                    break;
                }
            }

            if (l == packet->payload_packet_len) {
                MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "maybe WARCRAFT3\n");
                MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "flow->packet_counter = %u \n",
                        flow->data_packet_count);
                if (ipacket->session->data_packet_count > 2) {
                    MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "detected WARCRAFT3\n");
                    mmt_int_warcraft3_add_connection(ipacket);
                    return 1;
                }
                return 4;
            }
        }

        MMT_LOG(PROTO_WARCRAFT3, MMT_LOG_DEBUG, "no warcraft3 detected.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_WARCRAFT3);

    }
    return 0;
}

void mmt_init_classify_me_warcraft3() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WARCRAFT3);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_WARCRAFT3);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_warcraft3_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_WARCRAFT3, PROTO_WARCRAFT3_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_warcraft3();

        return register_protocol(protocol_struct, PROTO_WARCRAFT3);
    } else {
        return 0;
    }
}
