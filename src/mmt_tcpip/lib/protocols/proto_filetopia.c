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

int mmt_check_filetopia(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->l4.tcp.filetopia_stage == 0) {
            if (packet->payload_packet_len >= 50 && packet->payload_packet_len <= 70
                    && packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
                    && packet->payload[3] == 0x22 && packet->payload[packet->payload_packet_len - 1] == 0x2b) {
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

                flow->l4.tcp.filetopia_stage = 2;
                return 4;
            }

        } else if (flow->l4.tcp.filetopia_stage == 2) {
            if (packet->payload_packet_len >= 4 && packet->payload_packet_len <= 100
                    && packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
                    && (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {
                mmt_int_filetopia_add_connection(ipacket);
                return 1;
            }
        }

end_filetopia_nothing_found:
        MMT_EXCLUDE_PROTOCOL(flow, PROTO_FILETOPIA);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_filetopia_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FILETOPIA, PROTO_FILETOPIA_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_FILETOPIA);

        return register_protocol(protocol_struct, PROTO_FILETOPIA);
    } else {
        return 0;
    }
}
