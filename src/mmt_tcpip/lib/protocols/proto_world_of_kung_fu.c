#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_world_of_kung_fu_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_WORLD_OF_KUNG_FU, MMT_REAL_PROTOCOL);
}

int mmt_check_world_of_kung_fu(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if ((packet->payload_packet_len == 16)
                && ntohl(get_u32(packet->payload, 0)) == 0x0c000000 && ntohl(get_u32(packet->payload, 4)) == 0xd2000c00
                && (packet->payload[9]
                == 0x16) && ntohs(get_u16(packet->payload, 10)) == 0x0000 && ntohs(get_u16(packet->payload, 14)) == 0x0000) {
            mmt_int_world_of_kung_fu_add_connection(ipacket);
            return 1;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_WORLD_OF_KUNG_FU);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_world_of_kung_fu_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_WORLD_OF_KUNG_FU, PROTO_WORLD_OF_KUNG_FU_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_WORLD_OF_KUNG_FU);

        return register_protocol(protocol_struct, PROTO_WORLD_OF_KUNG_FU);
    } else {
        return 0;
    }
}
