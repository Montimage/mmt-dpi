#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_xdmcp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_XDMCP, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_xdmcp(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "search xdmcp.\n");

    if (packet->tcp != NULL && (ntohs(packet->tcp->dest) >= 6000 && ntohs(packet->tcp->dest) <= 6005)
            && packet->payload_packet_len == 48
            && packet->payload[0] == 0x6c && packet->payload[1] == 0x00
            && ntohs(get_u16(packet->payload, 6)) == 0x1200 && ntohs(get_u16(packet->payload, 8)) == 0x1000) {

        MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "found xdmcp over tcp.\n");
        mmt_int_xdmcp_add_connection(ipacket);
        return;
    }
    if (packet->udp != NULL && ntohs(packet->udp->dest) == 177
            && packet->payload_packet_len >= 6 && packet->payload_packet_len == 6 + ntohs(get_u16(packet->payload, 4))
            && ntohs(get_u16(packet->payload, 0)) == 0x0001 && ntohs(get_u16(packet->payload, 2)) == 0x0002) {

        MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "found xdmcp over udp.\n");
        mmt_int_xdmcp_add_connection(ipacket);
        return;
    }


    MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "exclude xdmcp.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_XDMCP);
}

int mmt_check_xdmcp_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "search xdmcp.\n");

        if ((ntohs(packet->tcp->dest) >= 6000 && ntohs(packet->tcp->dest) <= 6005)
                && packet->payload_packet_len == 48
                && packet->payload[0] == 0x6c && packet->payload[1] == 0x00
                && ntohs(get_u16(packet->payload, 6)) == 0x1200 && ntohs(get_u16(packet->payload, 8)) == 0x1000) {

            MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "found xdmcp over tcp.\n");
            mmt_int_xdmcp_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "exclude xdmcp.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_XDMCP);
    }
    return 0;
}

int mmt_check_xdmcp_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "search xdmcp.\n");

        if (ntohs(packet->udp->dest) == 177
                && packet->payload_packet_len >= 6 && packet->payload_packet_len == 6 + ntohs(get_u16(packet->payload, 4))
                && ntohs(get_u16(packet->payload, 0)) == 0x0001 && ntohs(get_u16(packet->payload, 2)) == 0x0002) {

            MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "found xdmcp over udp.\n");
            mmt_int_xdmcp_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_XDMCP, MMT_LOG_DEBUG, "exclude xdmcp.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_XDMCP);
    }
    return 0;
}

void mmt_init_classify_me_xdmcp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_XDMCP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_XDMCP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_xdmcp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_XDMCP, PROTO_XDMCP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_xdmcp();

        return register_protocol(protocol_struct, PROTO_XDMCP);
    } else {
        return 0;
    }
}
