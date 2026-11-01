#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_tftp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_TFTP, MMT_REAL_PROTOCOL);
}

int mmt_check_tftp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if (packet->payload_packet_len > 3 && flow->l4.udp.tftp_stage == 0
                && ntohl(get_u32(packet->payload, 0)) == 0x00030001) {
            flow->l4.udp.tftp_stage = 1;
            return 4;
        }
        if (packet->payload_packet_len > 3 && (flow->l4.udp.tftp_stage == 1)
                && ntohl(get_u32(packet->payload, 0)) == 0x00040001) {

            mmt_int_tftp_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len > 1
                && ((packet->payload[0] == 0 && packet->payload[packet->payload_packet_len - 1] == 0)
                || (packet->payload_packet_len == 4 && ntohl(get_u32(packet->payload, 0)) == 0x00040000))) {
            return 4;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_TFTP);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_tftp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TFTP, PROTO_TFTP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_TFTP);

        return register_protocol(protocol_struct, PROTO_TFTP);
    } else {
        return 0;
    }
}
