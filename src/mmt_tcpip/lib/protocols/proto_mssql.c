#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_mssql_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_MSSQL, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_mssql(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_MSSQL, MMT_LOG_DEBUG, "search mssql.\n");


    if (packet->payload_packet_len > 51 && ntohs(get_u32(packet->payload, 0)) == 0x1201
            && ntohs(get_u16(packet->payload, 2)) == packet->payload_packet_len
            && ntohl(get_u32(packet->payload, 4)) == 0x00000100 && memcmp(&packet->payload[41], "sqlexpress", 10) == 0) {
        MMT_LOG(PROTO_MSSQL, MMT_LOG_DEBUG, "found mssql.\n");
        mmt_int_mssql_add_connection(ipacket);
        return;
    }


    MMT_LOG(PROTO_MSSQL, MMT_LOG_DEBUG, "exclude mssql.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MSSQL);
}

int mmt_check_mssql(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_MSSQL, MMT_LOG_DEBUG, "search mssql.\n");

        if (packet->payload_packet_len > 51 && ntohs(get_u32(packet->payload, 0)) == 0x1201
                && ntohs(get_u16(packet->payload, 2)) == packet->payload_packet_len
                && ntohl(get_u32(packet->payload, 4)) == 0x00000100 && memcmp(&packet->payload[41], "sqlexpress", 10) == 0) {
            MMT_LOG(PROTO_MSSQL, MMT_LOG_DEBUG, "found mssql.\n");
            mmt_int_mssql_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_MSSQL, MMT_LOG_DEBUG, "exclude mssql.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MSSQL);
    }
    return 0;
}

void mmt_init_classify_me_mssql() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_MSSQL);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_mssql_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MSSQL, PROTO_MSSQL_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_mssql();

        return register_protocol(protocol_struct, PROTO_MSSQL);
    } else {
        return 0;
    }
}


