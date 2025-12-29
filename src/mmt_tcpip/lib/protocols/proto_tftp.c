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

void mmt_classify_me_tftp(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;



    MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "search TFTP.\n");



    if (packet->payload_packet_len > 3 && flow->l4.udp.tftp_stage == 0
            && ntohl(get_u32(packet->payload, 0)) == 0x00030001) {
        MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "maybe tftp. need next packet.\n");
        flow->l4.udp.tftp_stage = 1;
        return;
    }
    if (packet->payload_packet_len > 3 && (flow->l4.udp.tftp_stage == 1)
            && ntohl(get_u32(packet->payload, 0)) == 0x00040001) {

        MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "found tftp.\n");
        mmt_int_tftp_add_connection(ipacket);
        return;
    }
    if (packet->payload_packet_len > 1
            && ((packet->payload[0] == 0 && packet->payload[packet->payload_packet_len - 1] == 0)
            || (packet->payload_packet_len == 4 && ntohl(get_u32(packet->payload, 0)) == 0x00040000))) {
        MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "skip initial packet.\n");
        return;
    }

    MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "exclude TFTP.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TFTP);
}

int mmt_check_tftp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "search TFTP.\n");

        if (packet->payload_packet_len > 3 && flow->l4.udp.tftp_stage == 0
                && ntohl(get_u32(packet->payload, 0)) == 0x00030001) {
            MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "maybe tftp. need next packet.\n");
            flow->l4.udp.tftp_stage = 1;
            return 4;
        }
        if (packet->payload_packet_len > 3 && (flow->l4.udp.tftp_stage == 1)
                && ntohl(get_u32(packet->payload, 0)) == 0x00040001) {

            MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "found tftp.\n");
            mmt_int_tftp_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len > 1
                && ((packet->payload[0] == 0 && packet->payload[packet->payload_packet_len - 1] == 0)
                || (packet->payload_packet_len == 4 && ntohl(get_u32(packet->payload, 0)) == 0x00040000))) {
            MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "skip initial packet.\n");
            return 4;
        }

        MMT_LOG(PROTO_TFTP, MMT_LOG_DEBUG, "exclude TFTP.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TFTP);
    }
    return 0;
}

void mmt_init_classify_me_tftp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_TFTP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_tftp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TFTP, PROTO_TFTP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_tftp();

        return register_protocol(protocol_struct, PROTO_TFTP);
    } else {
        return 0;
    }
}
