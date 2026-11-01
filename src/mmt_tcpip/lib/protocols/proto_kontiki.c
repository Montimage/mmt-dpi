#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_kontiki_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_KONTIKI, MMT_REAL_PROTOCOL);
}

int mmt_check_kontiki(ipacket_t * ipacket, unsigned index)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len == 4 && (get_u32(packet->payload, 0) == htonl(0x02010100))) {
            mmt_int_kontiki_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len > 0 && packet->payload[0] == 0x02) {

            if (packet->payload_packet_len == 20 && (get_u32(packet->payload, 16) == htonl(0x02040100))) {
                mmt_int_kontiki_add_connection(ipacket);
                return 1;
            }
            if (packet->payload_packet_len == 16 && (get_u32(packet->payload, 12) == htonl(0x000004e4))) {
                mmt_int_kontiki_add_connection(ipacket);
                return 1;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_KONTIKI);
    }
    return 0;
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_kontiki_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_KONTIKI, PROTO_KONTIKI_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_KONTIKI);

        return register_protocol(protocol_struct, PROTO_KONTIKI);
    } else {
        return 0;
    }
}
