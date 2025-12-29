#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_filetopia_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_FILETOPIA, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_filetopia(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (flow->l4.tcp.filetopia_stage == 0) {
        if (packet->payload_packet_len >= 50 && packet->payload_packet_len <= 70
                && packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
                && packet->payload[3] == 0x22 && packet->payload[packet->payload_packet_len - 1] == 0x2b) {
            MMT_LOG(PROTO_FILETOPIA, MMT_LOG_DEBUG, "Filetopia stage 1 detected\n");
            flow->l4.tcp.filetopia_stage = 1;
            return;
        }

    } else if (flow->l4.tcp.filetopia_stage == 1) {
        if (packet->payload_packet_len >= 100 && packet->payload[0] == 0x03
                && packet->payload[1] == 0x9a && (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {

            int i;
            for (i = 0; i < 10; i++) { // check 10 bytes for valid ASCII printable characters
                if (!(packet->payload[5 + i] >= 0x20 && packet->payload[5 + i] <= 0x7e)) {
                    goto end_filetopia_nothing_found;
                }
            }

            MMT_LOG(PROTO_FILETOPIA, MMT_LOG_DEBUG, "Filetopia stage 2 detected\n");
            flow->l4.tcp.filetopia_stage = 2;
            return;
        }


    } else if (flow->l4.tcp.filetopia_stage == 2) {
        if (packet->payload_packet_len >= 4 && packet->payload_packet_len <= 100
                && packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
                && (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {
            MMT_LOG(PROTO_FILETOPIA, MMT_LOG_DEBUG, "Filetopia detected\n");
            mmt_int_filetopia_add_connection(ipacket);
            return;
        }

    }

end_filetopia_nothing_found:
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FILETOPIA);
}

int mmt_check_filetopia(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->l4.tcp.filetopia_stage == 0) {
            if (packet->payload_packet_len >= 50 && packet->payload_packet_len <= 70
                    && packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
                    && packet->payload[3] == 0x22 && packet->payload[packet->payload_packet_len - 1] == 0x2b) {
                MMT_LOG(PROTO_FILETOPIA, MMT_LOG_DEBUG, "Filetopia stage 1 detected\n");
                flow->l4.tcp.filetopia_stage = 1;
                return 4;
            }

        } else if (flow->l4.tcp.filetopia_stage == 1) {
            if (packet->payload_packet_len >= 100 && packet->payload[0] == 0x03
                    && packet->payload[1] == 0x9a && (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {

                int i;
                for (i = 0; i < 10; i++) { // check 10 bytes for valid ASCII printable characters
                    if (!(packet->payload[5 + i] >= 0x20 && packet->payload[5 + i] <= 0x7e)) {
                        goto end_filetopia_nothing_found;
                    }
                }

                MMT_LOG(PROTO_FILETOPIA, MMT_LOG_DEBUG, "Filetopia stage 2 detected\n");
                flow->l4.tcp.filetopia_stage = 2;
                return 4;
            }

        } else if (flow->l4.tcp.filetopia_stage == 2) {
            if (packet->payload_packet_len >= 4 && packet->payload_packet_len <= 100
                    && packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
                    && (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {
                MMT_LOG(PROTO_FILETOPIA, MMT_LOG_DEBUG, "Filetopia detected\n");
                mmt_int_filetopia_add_connection(ipacket);
                return 1;
            }
        }

end_filetopia_nothing_found:
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FILETOPIA);
    }
    return 0;
}

void mmt_init_classify_me_filetopia() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FILETOPIA);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_filetopia_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FILETOPIA, PROTO_FILETOPIA_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_filetopia();

        return register_protocol(protocol_struct, PROTO_FILETOPIA);
    } else {
        return 0;
    }
}
