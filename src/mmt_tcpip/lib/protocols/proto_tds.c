#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_tds_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_TDS, MMT_REAL_PROTOCOL);
}

int mmt_check_tds(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct * flow = packet->flow;

        if (packet->payload_packet_len > 8
                && packet->payload_packet_len < 512
                && packet->payload[1] < 0x02
                && ntohs(get_u16(packet->payload, 2)) == packet->payload_packet_len && get_u16(packet->payload, 4) == 0x0000) {

            if (flow->l4.tcp.tds_stage == 0) {
                if (packet->payload[0] != 0x02 && packet->payload[0] != 0x07 && packet->payload[0] != 0x12) {
                    goto exclude_tds;
                } else {
                    flow->l4.tcp.tds_stage = 1 + ipacket->session->last_packet_direction;
                    flow->l4.tcp.tds_login_version = packet->payload[0];
                    return 4;
                }
            } else if (flow->l4.tcp.tds_stage == 2 - ipacket->session->last_packet_direction) {
                switch (flow->l4.tcp.tds_login_version) {
                    case 0x12:
                        if (packet->payload[0] == 0x04) {
                            flow->l4.tcp.tds_stage = 3 + ipacket->session->last_packet_direction;
                            return 4;
                        } else {
                            goto exclude_tds;
                        }
                    /* Only the TDS 7.1+ pre-login exchange (0x12) is confirmed;
                     * other login versions are excluded rather than guessed. */
                    default:
                        goto exclude_tds;
                }
            } else if (flow->l4.tcp.tds_stage == 4 - ipacket->session->last_packet_direction) {
                switch (flow->l4.tcp.tds_login_version) {
                    case 0x12:
                        if (packet->payload[0] == 0x12) {
                            mmt_int_tds_add_connection(ipacket);
                            return 1;
                        } else {
                            goto exclude_tds;
                        }
                    default:
                        goto exclude_tds;
                }
            }
        }

exclude_tds:
        MMT_EXCLUDE_PROTOCOL(flow, PROTO_TDS);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_tds_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TDS, PROTO_TDS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_TDS);

        return register_protocol(protocol_struct, PROTO_TDS);
    } else {
        return 0;
    }
}
