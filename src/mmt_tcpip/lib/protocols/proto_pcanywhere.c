#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_pcanywhere_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_PCANYWHERE, MMT_REAL_PROTOCOL);
}

int mmt_check_pcanywhere(ipacket_t * ipacket, unsigned index)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->udp != NULL && packet->udp->dest == htons(5632)
                && packet->payload_packet_len == 2
                && (mmt_mem_cmp(packet->payload, "NQ", 2) == 0 || mmt_mem_cmp(packet->payload, "ST", 2) == 0)) {
            mmt_int_pcanywhere_add_connection(ipacket);
            return 1;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_PCANYWHERE);

    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_pcanywhere_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_PCANYWHERE, PROTO_PCANYWHERE_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_PCANYWHERE);

        return register_protocol(protocol_struct, PROTO_PCANYWHERE);
    } else {
        return 0;
    }
}
