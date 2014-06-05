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

void mmt_classify_me_dhcp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* this detection also works for asymmetric dhcp traffic */

    /*check standard DHCP 0.0.0.0:68 -> 255.255.255.255:67 */
    if (packet->payload_packet_len >= 244 && (packet->udp->source == htons(67)
            || packet->udp->source == htons(68))
            && (packet->udp->dest == htons(67) || packet->udp->dest == htons(68))
            && get_u32(packet->payload, 236) == htonl(0x63825363)
            && get_u16(packet->payload, 240) == htons(0x3501)) {

        MMT_LOG(PROTO_DHCP, MMT_LOG_DEBUG, "DHCP request\n");

        mmt_int_dhcp_add_connection(ipacket);
        return;
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DHCP);
}

int mmt_check_dhcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* this detection also works for asymmetric dhcp traffic */
        /*check standard DHCP 0.0.0.0:68 -> 255.255.255.255:67 */
        if (packet->payload_packet_len >= 244 && (packet->udp->source == htons(67)
                || packet->udp->source == htons(68))
                && (packet->udp->dest == htons(67) || packet->udp->dest == htons(68))
                && get_u32(packet->payload, 236) == htonl(0x63825363)
                && get_u16(packet->payload, 240) == htons(0x3501)) {

            MMT_LOG(PROTO_DHCP, MMT_LOG_DEBUG, "DHCP request\n");
            mmt_int_dhcp_add_connection(ipacket);
            return 1;
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DHCP);
    }
    return 1;
}

void mmt_init_classify_me_dhcp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_DHCP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_dhcp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DHCP, PROTO_DHCP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_dhcp();

        return register_protocol(protocol_struct, PROTO_DHCP);
    } else {
        return 0;
    }
}


