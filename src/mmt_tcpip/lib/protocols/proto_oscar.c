#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_oscar_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    mmt_internal_add_connection(ipacket, PROTO_OSCAR, protocol_type);

    if (src != NULL) {
        src->oscar_last_safe_access_time = packet->tick_timestamp;
    }
    if (dst != NULL) {
        dst->oscar_last_safe_access_time = packet->tick_timestamp;
    }
}

void mmt_classify_me_oscar(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    if (packet->tcp != NULL) {
        MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR :: TCP\n");
        if (packet->payload_packet_len >= 10 && packet->payload[0] == 0x2a) {

            /* if is a oscar connection, 10 bytes long */

            /* OSCAR Connection :: Connection detected at initial packets only
             * +----+----+------+------+---------------+
             * |0x2a|Code|SeqNum|PktLen|ProtcolVersion |
             * +----+----+------+------+---------------+
             * Code 1 Byte : 0x01 Oscar Connection
             * SeqNum and PktLen are 2 Bytes each and ProtcolVersion: 0x00000001
             * */
            if (get_u8(packet->payload, 1) == 0x01 && get_u16(packet->payload, 4) == htons(packet->payload_packet_len - 6)
                    && get_u32(packet->payload, 6) == htonl(0x0000000001)) {
                MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR Connection FOUND \n");
                mmt_int_oscar_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }

            /* OSCAR IM
             * +----+----+------+------+----------+-----------+
             * |0x2a|Code|SeqNum|PktLen|FNACfamily|FNACsubtype|
             * +----+----+------+------+----------+-----------+
             * Code 1 Byte : 0x02 SNAC Header Code;
             * SeqNum and PktLen are 2 Bytes each
             * FNACfamily   2 Byte : 0x0004 IM Messaging
             * FNACEsubtype 2 Byte : 0x0006 IM Outgoing Message, 0x000c IM Message Acknowledgment
             * */
            if (packet->payload[1] == 0x02
                    && ntohs(get_u16(packet->payload, 4)) >=
                    packet->payload_packet_len - 6 && get_u16(packet->payload, 6) == htons(0x0004)
                    && (get_u16(packet->payload, 8) == htons(0x0006)
                    || get_u16(packet->payload, 8) == htons(0x000c))) {
                MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR IM Detected \n");
                mmt_int_oscar_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }


        /* detect http connections */
        if (packet->payload_packet_len >= 18) {
            if ((packet->payload[0] == 'P') && (memcmp(packet->payload, "POST /photo/upload", 18) == 0)) {
                MMT_PARSE_PACKET_LINE_INFO(ipacket, packet);
                if (packet->host_line.len >= 18 && packet->host_line.ptr != NULL) {
                    if (memcmp(packet->host_line.ptr, "lifestream.aol.com", 18) == 0) {
                        MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG,
                                "OSCAR over HTTP found, POST method\n");
                        mmt_int_oscar_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return;
                    }
                }
            }
        }
        if (packet->payload_packet_len > 40) {
            if ((packet->payload[0] == 'G') && (memcmp(packet->payload, "GET /", 5) == 0)) {
                if ((memcmp(&packet->payload[5], "aim/fetchEvents?aimsid=", 23) == 0) ||
                        (memcmp(&packet->payload[5], "aim/startSession?", 17) == 0) ||
                        (memcmp(&packet->payload[5], "aim/gromit/aim_express", 22) == 0) ||
                        (memcmp(&packet->payload[5], "b/ss/aolwpaim", 13) == 0) ||
                        (memcmp(&packet->payload[5], "hss/storage/aimtmpshare", 23) == 0)) {
                    MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR over HTTP found, GET /aim/\n");
                    mmt_int_oscar_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }

                if ((memcmp(&packet->payload[5], "aim", 3) == 0) || (memcmp(&packet->payload[5], "im", 2) == 0)) {
                    MMT_PARSE_PACKET_LINE_INFO(ipacket, packet);
                    if (packet->user_agent_line.len > 15 && packet->user_agent_line.ptr != NULL &&
                            ((memcmp(packet->user_agent_line.ptr, "mobileAIM/", 10) == 0) ||
                            (memcmp(packet->user_agent_line.ptr, "ICQ/", 4) == 0) ||
                            (memcmp(packet->user_agent_line.ptr, "mobileICQ/", 10) == 0) ||
                            (memcmp(packet->user_agent_line.ptr, "AIM%20Free/", MMT_STATICSTRING_LEN("AIM%20Free/")) == 0) ||
                            (memcmp(packet->user_agent_line.ptr, "AIM/", 4) == 0))) {
                        MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR over HTTP found\n");
                        mmt_int_oscar_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return;
                    }
                }
                MMT_PARSE_PACKET_LINE_INFO(ipacket, packet);
                if (packet->referer_line.ptr != NULL && packet->referer_line.len >= 22) {

                    if (memcmp(&packet->referer_line.ptr[packet->referer_line.len - MMT_STATICSTRING_LEN("WidgetMain.swf")],
                            "WidgetMain.swf", MMT_STATICSTRING_LEN("WidgetMain.swf")) == 0) {
                        uint16_t i;
                        for (i = 0; i < (packet->referer_line.len - 22); i++) {
                            if (packet->referer_line.ptr[i] == 'a') {
                                if (memcmp(&packet->referer_line.ptr[i + 1], "im/gromit/aim_express", 21) == 0) {
                                    MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG,
                                            "OSCAR over HTTP found : aim/gromit/aim_express\n");
                                    mmt_int_oscar_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            if (memcmp(packet->payload, "CONNECT ", 8) == 0) {
                if (memcmp(packet->payload, "CONNECT login.icq.com:443 HTTP/1.", 33) == 0) {
                    MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR ICQ-HTTP FOUND\n");
                    mmt_int_oscar_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
                if (memcmp(packet->payload, "CONNECT login.oscar.aol.com:5190 HTTP/1.", 40) == 0) {
                    MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR AIM-HTTP FOUND\n");
                    mmt_int_oscar_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }

            }
        }

        if (packet->payload_packet_len > 43
                && memcmp(packet->payload, "GET http://http.proxy.icq.com/hello HTTP/1.", 43) == 0) {
            MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR ICQ-HTTP PROXY FOUND\n");
            mmt_int_oscar_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }

        if (packet->payload_packet_len > 46
                && memcmp(packet->payload, "GET http://aimhttp.oscar.aol.com/hello HTTP/1.", 46) == 0) {
            MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR AIM-HTTP PROXY FOUND\n");
            mmt_int_oscar_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }

        if (packet->payload_packet_len > 5 && get_u32(packet->payload, 0) == htonl(0x05010003)) {
            MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "Maybe OSCAR Picturetransfer\n");
            return;
        }

        if (packet->payload_packet_len == 10 && get_u32(packet->payload, 0) == htonl(0x05000001) &&
                get_u32(packet->payload, 4) == 0) {
            MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "Maybe OSCAR Picturetransfer\n");
            return;
        }

        if (packet->payload_packet_len >= 70 &&
                memcmp(&packet->payload[packet->payload_packet_len - 26],
                "\x67\x00\x65\x00\x74\x00\x43\x00\x61\x00\x74\x00\x61\x00\x6c\x00\x6f\x00\x67", 19) == 0) {
            MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR PICTURE TRANSFER\n");
            mmt_int_oscar_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        if (MMT_SRC_OR_DST_HAS_PROTOCOL(src, dst, PROTO_OSCAR) != 0) {

            if (ipacket->session->data_packet_count == 1
                    &&
                    ((packet->payload_packet_len == 9
                    && memcmp(packet->payload, "\x00\x09\x00\x00\x83\x01\xc0\x00\x00", 9) == 0)
                    || (packet->payload_packet_len == 13
                    && (memcmp(packet->payload, "\x00\x0d\x00\x87\x01\xc0", 6) == 0
                    || memcmp(packet->payload, "\x00\x0d\x00\x87\x01\xc1", 6) == 0)))) {
                flow->oscar_video_voice = 1;
            }
            if (flow->oscar_video_voice && ntohs(get_u16(packet->payload, 0)) == packet->payload_packet_len
                    && packet->payload[2] == 0x00 && packet->payload[3] == 0x00) {
            }

            if (packet->payload_packet_len >= 70 && ntohs(get_u16(packet->payload, 4)) == packet->payload_packet_len) {
                if (memcmp(packet->payload, "OFT", 3) == 0 &&
                        ((packet->payload[3] == '3' && ((memcmp(&packet->payload[4], "\x01\x00\x01\x01", 4) == 0)
                        || (memcmp(&packet->payload[6], "\x01\x01\x00", 3) == 0)))
                        || (packet->payload[3] == '2' && ((memcmp(&packet->payload[6], "\x01\x01", 2)
                        == 0)
                        )))) {
                    // FILE TRANSFER PATTERN:: OFT3 or OFT2
                    MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR FILE TRANSFER\n");
                    mmt_int_oscar_add_connection(ipacket, MMT_REAL_PROTOCOL);
                    return;
                }

                if (memcmp(packet->payload, "ODC2", 4) == 0 && memcmp(&packet->payload[6], "\x00\x01\x00\x06", 4) == 0) {
                    //PICTURE TRANSFER PATTERN EXMAPLE::
                    //4f 44 43 32 00 4c 00 01 00 06 00 00 00 00 00 00  ODC2.L..........
                    MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR PICTURE TRANSFER\n");
                    mmt_int_oscar_add_connection(ipacket, MMT_REAL_PROTOCOL);
                    return;
                }
            }
            if (packet->payload_packet_len > 40 && (memcmp(&packet->payload[2], "\x04\x4a\x00", 3) == 0)
                    && (memcmp(&packet->payload[6], "\x00\x00", 2) == 0)
                    && packet->payload[packet->payload_packet_len - 15] == 'F'
                    && packet->payload[packet->payload_packet_len - 12] == 'L'
                    && (memcmp(&packet->payload[packet->payload_packet_len - 6], "DEST", 4) == 0)
                    && (memcmp(&packet->payload[packet->payload_packet_len - 2], "\x00\x00", 2) == 0)) {
                MMT_LOG(PROTO_OSCAR, MMT_LOG_DEBUG, "OSCAR PICTURE TRANSFER\n");
                mmt_int_oscar_add_connection(ipacket, MMT_REAL_PROTOCOL);
                if (ntohs(packet->tcp->dest) == 443 || ntohs(packet->tcp->source) == 443) {
                    flow->oscar_ssl_voice_stage = 1;
                }
                return;

            }
        }
        if (ipacket->session->data_packet_count < 3 && packet->payload_packet_len > 11 && (memcmp(packet->payload, "\x00\x37\x04\x4a", 4)
                || memcmp(packet->payload, "\x00\x0a\x04\x4a",
                4))) {
            return;
        }


        if (packet->detected_protocol_stack[0] != PROTO_OSCAR) {
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_OSCAR);
            return;
        }
    }
}

int mmt_check_oscar(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_oscar(ipacket, index); //BW: TODO: the calssification of oscar seems to be for TCP only
    }
    return 1;
}

void mmt_init_classify_me_oscar() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_OSCAR);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_OSCAR);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_oscar_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_OSCAR, PROTO_OSCAR_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_oscar();
        
        return register_protocol(protocol_struct, PROTO_OSCAR);
    } else {
        return 0;
    }
}


