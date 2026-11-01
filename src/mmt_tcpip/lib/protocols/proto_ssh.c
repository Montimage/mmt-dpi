#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ssh_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SSH, MMT_REAL_PROTOCOL);
}

int mmt_check_ssh(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->l4.tcp.ssh_stage == 0) {
            if (packet->payload_packet_len > 7 && packet->payload_packet_len < 100
                    && mmt_memcmp(packet->payload, "SSH-", 4) == 0) {
                flow->l4.tcp.ssh_stage = 1 + ipacket->session->last_packet_direction;
                return 4;
            }
        } else if (flow->l4.tcp.ssh_stage == (2 - ipacket->session->last_packet_direction)) {
            if (packet->payload_packet_len > 7 && packet->payload_packet_len < 100
                    && mmt_memcmp(packet->payload, "SSH-", 4) == 0) {
                mmt_int_ssh_add_connection(ipacket);
                return 1;

            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_SSH);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ssh_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SSH, PROTO_SSH_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_SSH);

        return register_protocol(protocol_struct, PROTO_SSH);
    } else {
        return 0;
    }
}
