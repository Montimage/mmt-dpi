#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_quake_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_QUAKE, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_quake(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if ((packet->payload_packet_len == 14
            && get_u16(packet->payload, 0) == 0xffff && mmt_mem_cmp(&packet->payload[2], "getInfo", 7) == 0)
            || (packet->payload_packet_len == 17
            && get_u16(packet->payload, 0) == 0xffff && mmt_mem_cmp(&packet->payload[2], "challenge", 9) == 0)
            || (packet->payload_packet_len > 20
            && packet->payload_packet_len < 30
            && get_u16(packet->payload, 0) == 0xffff && mmt_mem_cmp(&packet->payload[2], "getServers", 10) == 0)) {
        MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake IV detected.\n");
        mmt_int_quake_add_connection(ipacket);
        return;
    }

    /* Quake III/Quake Live */
    if (packet->payload_packet_len == 15 && get_u32(packet->payload, 0) == 0xffffffff
            && mmt_memcmp(&packet->payload[4], "getinfo", 7) == 0) {
        MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
        mmt_int_quake_add_connection(ipacket);
        return;
    }
    if (packet->payload_packet_len == 16 && get_u32(packet->payload, 0) == 0xffffffff
            && mmt_memcmp(&packet->payload[4], "getchallenge", 12) == 0) {
        MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
        mmt_int_quake_add_connection(ipacket);
        return;
    }
    if (packet->payload_packet_len > 20 && packet->payload_packet_len < 30
            && get_u32(packet->payload, 0) == 0xffffffff
            && mmt_memcmp(&packet->payload[4], "getservers", 10) == 0) {
        MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
        mmt_int_quake_add_connection(ipacket);
        return;
    }



    /* ports for startup packet:
       Quake I        26000 (starts with 0x8000)
       Quake II       27910
       Quake III      27960 (increases with each player)
       Quake IV       27650
       Quake World    27500
       Quake Wars     ?????
     */

    MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake excluded.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_QUAKE);
}

int mmt_check_quake(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if ((packet->payload_packet_len == 14
                && get_u16(packet->payload, 0) == 0xffff && mmt_mem_cmp(&packet->payload[2], "getInfo", 7) == 0)
                || (packet->payload_packet_len == 17
                && get_u16(packet->payload, 0) == 0xffff && mmt_mem_cmp(&packet->payload[2], "challenge", 9) == 0)
                || (packet->payload_packet_len > 20
                && packet->payload_packet_len < 30
                && get_u16(packet->payload, 0) == 0xffff && mmt_mem_cmp(&packet->payload[2], "getServers", 10) == 0)) {
            MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake IV detected.\n");
            mmt_int_quake_add_connection(ipacket);
            return 1;
        }

        /* Quake III/Quake Live */
        if (packet->payload_packet_len == 15 && get_u32(packet->payload, 0) == 0xffffffff
                && mmt_memcmp(&packet->payload[4], "getinfo", 7) == 0) {
            MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
            mmt_int_quake_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len == 16 && get_u32(packet->payload, 0) == 0xffffffff
                && mmt_memcmp(&packet->payload[4], "getchallenge", 12) == 0) {
            MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
            mmt_int_quake_add_connection(ipacket);
            return 1;
        }
        if (packet->payload_packet_len > 20 && packet->payload_packet_len < 30
                && get_u32(packet->payload, 0) == 0xffffffff
                && mmt_memcmp(&packet->payload[4], "getservers", 10) == 0) {
            MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
            mmt_int_quake_add_connection(ipacket);
            return 1;
        }
        /* ports for startup packet:
           Quake I        26000 (starts with 0x8000)
           Quake II       27910
           Quake III      27960 (increases with each player)
           Quake IV       27650
           Quake World    27500
           Quake Wars     ?????
         */

        MMT_LOG(PROTO_QUAKE, MMT_LOG_DEBUG, "Quake excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_QUAKE);

    }
    return 0;
}

void mmt_init_classify_me_quake() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_QUAKE);
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_quake_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_QUAKE, PROTO_QUAKE_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_quake();

        return register_protocol(protocol_struct, PROTO_QUAKE);
    } else {
        return 0;
    }
}


