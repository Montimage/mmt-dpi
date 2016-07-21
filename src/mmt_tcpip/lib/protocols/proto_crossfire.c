#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_crossfire_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {

    mmt_internal_add_connection(ipacket, PROTO_CROSSFIRE, protocol_type);
}

void mmt_classify_me_crossfire(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "search crossfire.\n");


    if (packet->udp != 0) {
        if (packet->payload_packet_len == 25 && get_u32(packet->payload, 0) == ntohl(0xc7d91999)
                && get_u16(packet->payload, 4) == ntohs(0x0200)
                && get_u16(packet->payload, 22) == ntohs(0x7d00)
                ) {
            MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "Crossfire: found udp packet.\n");
            mmt_int_crossfire_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

    } else if (packet->tcp != 0) {

        if (packet->payload_packet_len > 4 && memcmp(packet->payload, "GET /", 5) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->parsed_lines == 8
                    && (packet->line[0].ptr != NULL && packet->line[0].len >= 30
                    && (memcmp(&packet->payload[5], "notice/login_big", 16) == 0
                    || memcmp(&packet->payload[5], "notice/login_small", 18) == 0))
                    && memcmp(&packet->payload[packet->line[0].len - 19], "/index.asp HTTP/1.", 18) == 0
                    && (packet->host_line.ptr != NULL && packet->host_line.len >= 13
                    && (memcmp(packet->host_line.ptr, "crossfire", 9) == 0
                    || memcmp(packet->host_line.ptr, "www.crossfire", 13) == 0))
                    ) {
                MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "Crossfire: found HTTP request.\n");
                mmt_int_crossfire_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }

    }

    MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "exclude crossfire.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_CROSSFIRE);
}

int mmt_check_crossfire_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "search crossfire.\n");

        if (packet->payload_packet_len > 4 && memcmp(packet->payload, "GET /", 5) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->parsed_lines == 8
                    && (packet->line[0].ptr != NULL && packet->line[0].len >= 30
                    && (memcmp(&packet->payload[5], "notice/login_big", 16) == 0
                    || memcmp(&packet->payload[5], "notice/login_small", 18) == 0))
                    && memcmp(&packet->payload[packet->line[0].len - 19], "/index.asp HTTP/1.", 18) == 0
                    && (packet->host_line.ptr != NULL && packet->host_line.len >= 13
                    && (memcmp(packet->host_line.ptr, "crossfire", 9) == 0
                    || memcmp(packet->host_line.ptr, "www.crossfire", 13) == 0))
                    ) {
                MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "Crossfire: found HTTP request.\n");
                mmt_int_crossfire_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            }
        }

        MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "exclude crossfire.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_CROSSFIRE);
    }
    return 0;
}

int mmt_check_crossfire_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "search crossfire.\n");

        if (packet->payload_packet_len == 25 && get_u32(packet->payload, 0) == ntohl(0xc7d91999)
                && get_u16(packet->payload, 4) == ntohs(0x0200)
                && get_u16(packet->payload, 22) == ntohs(0x7d00)
                ) {
            MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "Crossfire: found udp packet.\n");
            mmt_int_crossfire_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        MMT_LOG(PROTO_CROSSFIRE, MMT_LOG_DEBUG, "exclude crossfire.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_CROSSFIRE);
    }
    return 0;
}

void mmt_init_classify_me_crossfire() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_CROSSFIRE);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_crossfire_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_CROSSFIRE, PROTO_CROSSFIRE_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_crossfire();

        return register_protocol(protocol_struct, PROTO_CROSSFIRE);
    } else {
        return 0;
    }
}


