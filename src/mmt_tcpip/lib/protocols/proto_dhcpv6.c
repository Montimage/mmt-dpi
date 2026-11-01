#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_dhcpv6_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_DHCPV6, MMT_REAL_PROTOCOL);
}

int mmt_check_dhcpv6(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len >= 4 &&
                (packet->udp->source == htons(546) || packet->udp->source == htons(547)) &&
                (packet->udp->dest == htons(546) || packet->udp->dest == htons(547)) &&
                packet->payload[0] >= 1 && packet->payload[0] <= 13) {

            mmt_int_dhcpv6_add_connection(ipacket);
            return 1;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_DHCPV6);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_dhcpv6_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DHCPV6, PROTO_DHCPV6_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_DHCPV6);

        return register_protocol(protocol_struct, PROTO_DHCPV6);
    } else {
        return 0;
    }
}
