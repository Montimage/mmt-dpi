#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_secondlife_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_SECONDLIFE, protocol_type);
}

void mmt_classify_me_secondlife(ipacket_t * ipacket, unsigned index) {
    
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    //      struct mmt_id_struct         *src=mmt_struct->src;
    //      struct mmt_id_struct         *dst=mmt_struct->dst;

    //  if ((ntohs(packet->udp->dest) == 12035 || ntohs(packet->udp->dest) == 12036 || (ntohs(packet->udp->dest) >= 13000 && ntohs(packet->udp->dest) <= 13050))    //port
    //      && packet->payload_packet_len > 6   // min length with no extra header, high frequency and 1 byte message body
    //      && get_u8(packet->payload, 0) == 0x40   // reliable packet
    //      && ntohl(get_u32(packet->payload, 1)) == 0x00000001 // sequence number equals 1
    //      //ntohl (get_u32 (packet->payload, 5)) == 0x00FFFF00      // no extra header, low frequency message - can't use, message may have higher frequency
    //      ) {
    //      IPQ_LOG(IPOQUE_PROTOCOL_SECONDLIFE, IPQ_LOG_DEBUG, "Second Life detected.\n");
    //      mmt_int_secondlife_add_connection(mmt_struct);
    //      return;
    //  }

    if (packet->tcp != NULL) {
        if (packet->payload_packet_len > 5
                && memcmp(packet->payload, "GET /", 5) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life HTTP 'GET /'' found.\n");
            mmt_parse_packet_line_info(ipacket);
            if (packet->user_agent_line.ptr != NULL
                    && packet->user_agent_line.len >
                    97
                    && memcmp(&packet->user_agent_line.ptr[86],
                    "SecondLife/", 11) == 0) {
                MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG,
                        "Second Life TCP HTTP User Agent detected.\n");
                mmt_int_secondlife_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
            if (packet->host_line.ptr != NULL && packet->host_line.len > 20) {
                uint8_t x;
                for (x = 2; x < 6; x++) {
                    if (packet->host_line.ptr[packet->host_line.len - (1 + x)] == ':') {
                        if ((1 + x + 19) < packet->host_line.len
                                && memcmp(&packet->host_line.ptr[packet->host_line.len -
                                (1 + x + 19)],
                                ".agni.lindenlab.com", 19) == 0) {
                            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG,
                                    "Second Life TCP HTTP Host detected.\n");
                            mmt_int_secondlife_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                            return;
                        }
                        break;
                    }
                }
            }
        }
    }
    if (packet->udp != NULL) {
        if (packet->payload_packet_len == 46
                && memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\xff\xff\x00\x03", 10) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life 0xffff0003 detected.\n");
            mmt_int_secondlife_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 54
                && memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\xff\xff\x00\x52", 10) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life 0xffff0052 detected.\n");
            mmt_int_secondlife_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 58
                && memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\xff\xff\x00\xa9", 10) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life 0xffff00a9 detected.\n");
            mmt_int_secondlife_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len > 54 && memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\x08", 7) == 0 &&
                get_u32(packet->payload, packet->payload_packet_len - 4) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life 0x08 detected.\n");
            mmt_int_secondlife_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
    }


    MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life excluded.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SECONDLIFE);
}

int mmt_check_secondlife_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 5
                && memcmp(packet->payload, "GET /", 5) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life HTTP 'GET /'' found.\n");
            mmt_parse_packet_line_info(ipacket);
            if (packet->user_agent_line.ptr != NULL
                    && packet->user_agent_line.len >
                    97
                    && memcmp(&packet->user_agent_line.ptr[86],
                    "SecondLife/", 11) == 0) {
                MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG,
                        "Second Life TCP HTTP User Agent detected.\n");
                mmt_int_secondlife_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            }
            if (packet->host_line.ptr != NULL && packet->host_line.len > 20) {
                uint8_t x;
                for (x = 2; x < 6; x++) {
                    if (packet->host_line.ptr[packet->host_line.len - (1 + x)] == ':') {
                        if ((1 + x + 19) < packet->host_line.len
                                && memcmp(&packet->host_line.ptr[packet->host_line.len -
                                (1 + x + 19)],
                                ".agni.lindenlab.com", 19) == 0) {
                            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG,
                                    "Second Life TCP HTTP Host detected.\n");
                            mmt_int_secondlife_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                            return 1;
                        }
                        break;
                    }
                }
            }
        }


        MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SECONDLIFE);

    }
    return 0;
}

int mmt_check_secondlife_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if (packet->payload_packet_len == 46
                && memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\xff\xff\x00\x03", 10) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life 0xffff0003 detected.\n");
            mmt_int_secondlife_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 54
                && memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\xff\xff\x00\x52", 10) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life 0xffff0052 detected.\n");
            mmt_int_secondlife_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 58
                && memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\xff\xff\x00\xa9", 10) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life 0xffff00a9 detected.\n");
            mmt_int_secondlife_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len > 54 && memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\x08", 7) == 0 &&
                get_u32(packet->payload, packet->payload_packet_len - 4) == 0) {
            MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life 0x08 detected.\n");
            mmt_int_secondlife_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        MMT_LOG(PROTO_SECONDLIFE, MMT_LOG_DEBUG, "Second Life excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SECONDLIFE);

    }
    return 0;
}

void mmt_init_classify_me_secondlife() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SSL);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SECONDLIFE);
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_secondlife_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SECONDLIFE, PROTO_SECONDLIFE_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_secondlife();

        return register_protocol(protocol_struct, PROTO_SECONDLIFE);
    } else {
        return 0;
    }
}


