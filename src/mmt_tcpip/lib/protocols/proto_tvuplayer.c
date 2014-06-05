#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_tvuplayer_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_TVUPLAYER, protocol_type);
}

void mmt_classify_me_tvuplayer(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "search tvuplayer.  \n");



    if (packet->tcp != NULL) {
        if ((packet->payload_packet_len == 36 || packet->payload_packet_len == 24)
                && packet->payload[0] == 0x00
                && ntohl(get_u32(packet->payload, 2)) == 0x31323334
                && ntohl(get_u32(packet->payload, 6)) == 0x35363837 && packet->payload[10] == 0x01) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer over tcp.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        if (packet->payload_packet_len >= 50) {

            if (memcmp(packet->payload, "POST", 4) || memcmp(packet->payload, "GET", 3)) {
                MMT_PARSE_PACKET_LINE_INFO(ipacket, packet);
                if (packet->user_agent_line.ptr != NULL &&
                        packet->user_agent_line.len >= 8 && (memcmp(packet->user_agent_line.ptr, "MacTVUP", 7) == 0)) {
                    MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "Found user agent as MacTVUP.\n");
                    mmt_int_tvuplayer_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
        }
    }

    if (packet->udp != NULL) {

        if (packet->payload_packet_len == 56 &&
                packet->payload[0] == 0xff
                && packet->payload[1] == 0xff && packet->payload[2] == 0x00
                && packet->payload[3] == 0x01
                && packet->payload[12] == 0x02 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x2c && ((packet->payload[26] == 0x05 && packet->payload[27] == 0x14)
                || (packet->payload[26] == 0x14 && packet->payload[27] == 0x05))) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type I.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 82
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x01 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x14 && packet->payload[32] == 0x03
                && packet->payload[33] == 0xff && packet->payload[34] == 0x01
                && packet->payload[39] == 0x32 && ((packet->payload[46] == 0x05 && packet->payload[47] == 0x14)
                || (packet->payload[46] == 0x14 && packet->payload[47] == 0x05))) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type II.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 32
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && (packet->payload[10] == 0x00 || packet->payload[10] == 0x65
                || packet->payload[10] == 0x7e || packet->payload[10] == 0x49)
                && (packet->payload[11] == 0x00 || packet->payload[11] == 0x57
                || packet->payload[11] == 0x06 || packet->payload[11] == 0x22)
                && packet->payload[12] == 0x01 && (packet->payload[13] == 0xff || packet->payload[13] == 0x01)
                && packet->payload[19] == 0x14) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type III.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 84
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x01 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x14 && packet->payload[32] == 0x03
                && packet->payload[33] == 0xff && packet->payload[34] == 0x01 && packet->payload[39] == 0x34) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type IV.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 102
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x01 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x14 && packet->payload[33] == 0xff && packet->payload[39] == 0x14) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type V.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 62 && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                //&& packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x03 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x32 && ((packet->payload[26] == 0x05 && packet->payload[27] == 0x14)
                || (packet->payload[26] == 0x14 && packet->payload[27] == 0x05))) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type VI.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        // to check, if byte 26, 27, 33,39 match
        if (packet->payload_packet_len == 60
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x06 && packet->payload[13] == 0x00 && packet->payload[19] == 0x30) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type VII.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
    }

    MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "exclude tvuplayer.  \n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TVUPLAYER);

}

int mmt_check_tvuplayer_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "search tvuplayer.  \n");

        if ((packet->payload_packet_len == 36 || packet->payload_packet_len == 24)
                && packet->payload[0] == 0x00
                && ntohl(get_u32(packet->payload, 2)) == 0x31323334
                && ntohl(get_u32(packet->payload, 6)) == 0x35363837 && packet->payload[10] == 0x01) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer over tcp.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        if (packet->payload_packet_len >= 50) {
            if (memcmp(packet->payload, "POST", 4) || memcmp(packet->payload, "GET", 3)) {
                MMT_PARSE_PACKET_LINE_INFO(ipacket, packet);
                if (packet->user_agent_line.ptr != NULL &&
                        packet->user_agent_line.len >= 8 && (memcmp(packet->user_agent_line.ptr, "MacTVUP", 7) == 0)) {
                    MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "Found user agent as MacTVUP.\n");
                    mmt_int_tvuplayer_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return 1;
                }
            }
        }

        MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "exclude tvuplayer.  \n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TVUPLAYER);


    }
    return 1;
}

int mmt_check_tvuplayer_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "search tvuplayer.  \n");

        if (packet->payload_packet_len == 56 &&
                packet->payload[0] == 0xff
                && packet->payload[1] == 0xff && packet->payload[2] == 0x00
                && packet->payload[3] == 0x01
                && packet->payload[12] == 0x02 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x2c && ((packet->payload[26] == 0x05 && packet->payload[27] == 0x14)
                || (packet->payload[26] == 0x14 && packet->payload[27] == 0x05))) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type I.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 82
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x01 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x14 && packet->payload[32] == 0x03
                && packet->payload[33] == 0xff && packet->payload[34] == 0x01
                && packet->payload[39] == 0x32 && ((packet->payload[46] == 0x05 && packet->payload[47] == 0x14)
                || (packet->payload[46] == 0x14 && packet->payload[47] == 0x05))) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type II.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 32
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && (packet->payload[10] == 0x00 || packet->payload[10] == 0x65
                || packet->payload[10] == 0x7e || packet->payload[10] == 0x49)
                && (packet->payload[11] == 0x00 || packet->payload[11] == 0x57
                || packet->payload[11] == 0x06 || packet->payload[11] == 0x22)
                && packet->payload[12] == 0x01 && (packet->payload[13] == 0xff || packet->payload[13] == 0x01)
                && packet->payload[19] == 0x14) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type III.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 84
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x01 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x14 && packet->payload[32] == 0x03
                && packet->payload[33] == 0xff && packet->payload[34] == 0x01 && packet->payload[39] == 0x34) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type IV.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 102
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x01 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x14 && packet->payload[33] == 0xff && packet->payload[39] == 0x14) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type V.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 62 && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                //&& packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x03 && packet->payload[13] == 0xff
                && packet->payload[19] == 0x32 && ((packet->payload[26] == 0x05 && packet->payload[27] == 0x14)
                || (packet->payload[26] == 0x14 && packet->payload[27] == 0x05))) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type VI.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        // to check, if byte 26, 27, 33,39 match
        if (packet->payload_packet_len == 60
                && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[10] == 0x00 && packet->payload[11] == 0x00
                && packet->payload[12] == 0x06 && packet->payload[13] == 0x00 && packet->payload[19] == 0x30) {
            MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "found tvuplayer pattern type VII.  \n");
            mmt_int_tvuplayer_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        MMT_LOG(PROTO_TVUPLAYER, MMT_LOG_DEBUG, "exclude tvuplayer.  \n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TVUPLAYER);
    }
    return 1;
}

void mmt_init_classify_me_tvuplayer() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_TVUPLAYER);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_tvuplayer_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TVUPLAYER, PROTO_TVUPLAYER_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_tvuplayer();

        return register_protocol(protocol_struct, PROTO_TVUPLAYER);
    } else {
        return 0;
    }
}


