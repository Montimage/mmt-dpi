#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_teamview_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_TEAMVIEWER, MMT_REAL_PROTOCOL);
}

int mmt_check_teamviewer_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 2) {
            if (packet->payload[0] == 0x17 && packet->payload[1] == 0x24) {
                flow->l4.udp.teamviewer_stage++;
                if (flow->l4.udp.teamviewer_stage == 4 ||
                        packet->tcp->dest == ntohs(5938) || packet->tcp->source == ntohs(5938)) {
                    mmt_int_teamview_add_connection(ipacket);
                    return 1;
                }
                return 4;
            } else if (flow->l4.udp.teamviewer_stage) {
                if (packet->payload[0] == 0x11 && packet->payload[1] == 0x30) {
                    flow->l4.udp.teamviewer_stage++;
                    if (flow->l4.udp.teamviewer_stage == 4)
                        mmt_int_teamview_add_connection(ipacket);
                    return 1;
                }
                return 4;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_TEAMVIEWER);

    }
    return 0;
}

int mmt_check_teamviewer_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 13) {
            if (packet->payload[0] == 0x00 && packet->payload[11] == 0x17 && packet->payload[12] == 0x24) { /* byte 0 is a counter/seq number, and at the start is 0 */
                flow->l4.udp.teamviewer_stage++;
                if (flow->l4.udp.teamviewer_stage == 4 ||
                        packet->udp->dest == ntohs(5938) || packet->udp->source == ntohs(5938)) {
                    mmt_int_teamview_add_connection(ipacket);
                    return 1;
                }
                return 4;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_TEAMVIEWER);

    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_teamviewer_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TEAMVIEWER, PROTO_TEAMVIEWER_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
                PROTO_TEAMVIEWER, PROTO_TEAMVIEWER);

        return register_protocol(protocol_struct, PROTO_TEAMVIEWER);
    } else {
        return 0;
    }
}
