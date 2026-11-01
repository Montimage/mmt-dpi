#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_dhcp_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_DHCP, MMT_REAL_PROTOCOL);
}

int mmt_check_dhcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* this detection also works for asymmetric dhcp traffic */
        /*check standard DHCP 0.0.0.0:68 -> 255.255.255.255:67 */
        if (packet->payload_packet_len >= 244 && (packet->udp->source == htons(67)
                || packet->udp->source == htons(68))
                && (packet->udp->dest == htons(67) || packet->udp->dest == htons(68))
                && get_u32(packet->payload, 236) == htonl(0x63825363)
                && get_u16(packet->payload, 240) == htons(0x3501)) {

            mmt_int_dhcp_add_connection(ipacket);
            return 1;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_DHCP);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_dhcp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DHCP, PROTO_DHCP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_DHCP);

        return register_protocol(protocol_struct, PROTO_DHCP);
    } else {
        return 0;
    }
}
