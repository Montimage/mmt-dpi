#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_dcerpc_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_DCERPC, MMT_REAL_PROTOCOL);
}

int mmt_check_dcerpc(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* Same corrected threshold: payload[1] < 16 for pkt_type */
        if ((packet->payload_packet_len >= 16)
                && ((ntohs(packet->tcp->source) == 135) || (ntohs(packet->tcp->dest) == 135))
                && (packet->payload[0] == 0x05) /* version 5 */
                && (packet->payload[1] < 16)    /* Packet type (was payload[2]) */
                ) {
            MMT_LOG(MMT_PROTOCOL_DCERPC, MMT_LOG_DEBUG, "DCERPC match\n");
            mmt_int_dcerpc_add_connection(ipacket);
            return 1;
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DCERPC);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_dcerpc_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DCERPC, PROTO_DCERPC_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_DCERPC, PROTO_DCERPC);
        
        return register_protocol(protocol_struct, PROTO_DCERPC);
    } else {
        return 0;
    }
}
