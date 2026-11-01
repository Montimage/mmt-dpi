#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_guildwars_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_GUILDWARS, MMT_REAL_PROTOCOL);
}

int mmt_check_guildwars(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if (packet->payload_packet_len == 64 && get_u16(packet->payload, 1) == ntohs(0x050c)
                && mmt_memcmp(&packet->payload[50], "@2&P", 4) == 0) {
            mmt_int_guildwars_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len == 16 && get_u16(packet->payload, 1) == ntohs(0x040c)
                && get_u16(packet->payload, 4) == ntohs(0xa672)
                && packet->payload[8] == 0x01 && packet->payload[12] == 0x04) {
            mmt_int_guildwars_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len == 21 && get_u16(packet->payload, 0) == ntohs(0x0100)
                && get_u32(packet->payload, 5) == ntohl(0xf1001000)
                && packet->payload[9] == 0x01) {
            mmt_int_guildwars_add_connection(ipacket);
            return 1;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_GUILDWARS);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_guildwars_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_GUILDWARS, PROTO_GUILDWARS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_GUILDWARS);

        return register_protocol(protocol_struct, PROTO_GUILDWARS);
    } else {
        return 0;
    }
}
