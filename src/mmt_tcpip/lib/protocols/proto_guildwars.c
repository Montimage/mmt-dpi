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

void mmt_classify_me_guildwars(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "search guildwars.\n");

    if (packet->payload_packet_len == 64 && get_u16(packet->payload, 1) == ntohs(0x050c)
            && memcmp(&packet->payload[50], "@2&P", 4) == 0) {
        MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "GuildWars version 29.350: found.\n");
        mmt_int_guildwars_add_connection(ipacket);
        return;
    }
    if (packet->payload_packet_len == 16 && get_u16(packet->payload, 1) == ntohs(0x040c)
            && get_u16(packet->payload, 4) == ntohs(0xa672)
            && packet->payload[8] == 0x01 && packet->payload[12] == 0x04) {
        MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "GuildWars version 29.350: found.\n");
        mmt_int_guildwars_add_connection(ipacket);
        return;
    }
    if (packet->payload_packet_len == 21 && get_u16(packet->payload, 0) == ntohs(0x0100)
            && get_u32(packet->payload, 5) == ntohl(0xf1001000)
            && packet->payload[9] == 0x01) {
        MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "GuildWars version 216.107.245.50: found.\n");
        mmt_int_guildwars_add_connection(ipacket);
        return;
    }

    MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "exclude guildwars.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_GUILDWARS);
}

int mmt_check_guildwars(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "search guildwars.\n");

        if (packet->payload_packet_len == 64 && get_u16(packet->payload, 1) == ntohs(0x050c)
                && memcmp(&packet->payload[50], "@2&P", 4) == 0) {
            MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "GuildWars version 29.350: found.\n");
            mmt_int_guildwars_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len == 16 && get_u16(packet->payload, 1) == ntohs(0x040c)
                && get_u16(packet->payload, 4) == ntohs(0xa672)
                && packet->payload[8] == 0x01 && packet->payload[12] == 0x04) {
            MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "GuildWars version 29.350: found.\n");
            mmt_int_guildwars_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len == 21 && get_u16(packet->payload, 0) == ntohs(0x0100)
                && get_u32(packet->payload, 5) == ntohl(0xf1001000)
                && packet->payload[9] == 0x01) {
            MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "GuildWars version 216.107.245.50: found.\n");
            mmt_int_guildwars_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_GUILDWARS, MMT_LOG_DEBUG, "exclude guildwars.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_GUILDWARS);
    }
    return 0;
}

void mmt_init_classify_me_guildwars() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_GUILDWARS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_guildwars_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_GUILDWARS, PROTO_GUILDWARS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_guildwars();

        return register_protocol(protocol_struct, PROTO_GUILDWARS);
    } else {
        return 0;
    }
}


