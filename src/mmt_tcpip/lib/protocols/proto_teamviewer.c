#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void ntop_int_teamview_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_TEAMVIEWER, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_teamview(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->udp != NULL) {
        if (packet->payload_packet_len > 13) {
            if (packet->payload[0] == 0x00 && packet->payload[11] == 0x17 && packet->payload[12] == 0x24) { /* byte 0 is a counter/seq number, and at the start is 0 */
                flow->l4.udp.teamviewer_stage++;
                if (flow->l4.udp.teamviewer_stage == 4 ||
                        packet->udp->dest == ntohs(5938) || packet->udp->source == ntohs(5938)) {
                    ntop_int_teamview_add_connection(ipacket);
                }
                return;
            }
        }
    } else if (packet->tcp != NULL) {
        if (packet->payload_packet_len > 2) {
            if (packet->payload[0] == 0x17 && packet->payload[1] == 0x24) {
                flow->l4.udp.teamviewer_stage++;
                if (flow->l4.udp.teamviewer_stage == 4 ||
                        packet->tcp->dest == ntohs(5938) || packet->tcp->source == ntohs(5938)) {
                    ntop_int_teamview_add_connection(ipacket);
                }
                return;
            } else if (flow->l4.udp.teamviewer_stage) {
                if (packet->payload[0] == 0x11 && packet->payload[1] == 0x30) {
                    flow->l4.udp.teamviewer_stage++;
                    if (flow->l4.udp.teamviewer_stage == 4)
                        ntop_int_teamview_add_connection(ipacket);
                }
                return;
            }
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TEAMVIEWER);
}

int mmt_check_teamviewer_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 2) {
            if (packet->payload[0] == 0x17 && packet->payload[1] == 0x24) {
                flow->l4.udp.teamviewer_stage++;
                if (flow->l4.udp.teamviewer_stage == 4 ||
                        packet->tcp->dest == ntohs(5938) || packet->tcp->source == ntohs(5938)) {
                    ntop_int_teamview_add_connection(ipacket);
                }
                return 1;
            } else if (flow->l4.udp.teamviewer_stage) {
                if (packet->payload[0] == 0x11 && packet->payload[1] == 0x30) {
                    flow->l4.udp.teamviewer_stage++;
                    if (flow->l4.udp.teamviewer_stage == 4)
                        ntop_int_teamview_add_connection(ipacket);
                }
                return 1;
            }
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TEAMVIEWER);

    }
    return 0;
}

int mmt_check_teamviewer_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 13) {
            if (packet->payload[0] == 0x00 && packet->payload[11] == 0x17 && packet->payload[12] == 0x24) { /* byte 0 is a counter/seq number, and at the start is 0 */
                flow->l4.udp.teamviewer_stage++;
                if (flow->l4.udp.teamviewer_stage == 4 ||
                        packet->udp->dest == ntohs(5938) || packet->udp->source == ntohs(5938)) {
                    ntop_int_teamview_add_connection(ipacket);
                }
                return 1;
            }
        }


        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TEAMVIEWER);

    }
    return 0;
}

void mmt_init_classify_me_teamviewer() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TEAMVIEWER);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_TEAMVIEWER);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_teamviewer_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TEAMVIEWER, PROTO_TEAMVIEWER_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_teamviewer();

        return register_protocol(protocol_struct, PROTO_TEAMVIEWER);
    } else {
        return 0;
    }
}


