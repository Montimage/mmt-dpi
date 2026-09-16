#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE bgp_selection_bitmask;

static void mmt_int_bgp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_BGP, MMT_REAL_PROTOCOL);
}

/* this detection also works asymmetrically */

int mmt_check_bgp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((bgp_selection_bitmask & packet->mmt_selection_packet) == bgp_selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 18 &&
                get_u64(packet->payload, 0) == 0xffffffffffffffffULL &&
                get_u64(packet->payload, 8) == 0xffffffffffffffffULL &&
                ntohs(get_u16(packet->payload, 16)) <= packet->payload_packet_len &&
                (packet->tcp->dest == htons(179) || packet->tcp->source == htons(179))
                && packet->payload[18] < 5) {
            MMT_LOG(PROTO_BGP, MMT_LOG_DEBUG, "BGP detected.\n");
            mmt_int_bgp_add_connection(ipacket);
            return 1;
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_BGP);

    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_bgp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_BGP, PROTO_BGP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&bgp_selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_BGP);

        return register_protocol(protocol_struct, PROTO_BGP);
    } else {
        return 0;
    }
}
