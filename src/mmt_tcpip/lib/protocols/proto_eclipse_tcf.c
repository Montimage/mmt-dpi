#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define ECLIPSE_TCF_START "TCF2"

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_eclipse_tcf_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_ECLIPSE_TCF, MMT_REAL_PROTOCOL);
}

int mmt_check_eclipse_tcf(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len >= 8 && (ntohs(packet->udp->source) == 1534 || ntohs(packet->udp->dest) == 1534 )) {
            if (mmt_memcmp(packet->payload, ECLIPSE_TCF_START, strlen(ECLIPSE_TCF_START)) == 0) {
                mmt_int_eclipse_tcf_add_connection(ipacket);
                return 1;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_ECLIPSE_TCF);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_eclipse_tcf_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_ECLIPSE_TCF, PROTO_ECLIPSE_TCF_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_ECLIPSE_TCF);

        return register_protocol(protocol_struct, PROTO_ECLIPSE_TCF);
    } else {
        return 0;
    }
}


