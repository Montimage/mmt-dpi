#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_socrates_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SOCRATES, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_socrates(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;



    MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "search socrates.\n");
    if (packet->udp != NULL) {
        if (packet->payload_packet_len > 9 && packet->payload[0] == 0xfe
                && packet->payload[packet->payload_packet_len - 1] == 0x05) {
            MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "found fe.\n");

            MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "len match.\n");
            if (memcmp(&packet->payload[2], "socrates", 8) == 0) {
                MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "found socrates udp.\n");
                mmt_socrates_add_connection(ipacket);
            }

        }
    } else if (packet->tcp != NULL) {
        if (packet->payload_packet_len > 13 && packet->payload[0] == 0xfe
                && packet->payload[packet->payload_packet_len - 1] == 0x05) {
            MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "found fe.\n");
            if (packet->payload_packet_len == ntohl(get_u32(packet->payload, 2))) {
                MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "len match.\n");
                if (memcmp(&packet->payload[6], "socrates", 8) == 0) {
                    MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "found socrates tcp.\n");
                    mmt_socrates_add_connection(ipacket);
                }
            }
        }
    }




    MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "exclude socrates.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SOCRATES);
}

int mmt_check_socrates_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "search socrates.\n");

        if (packet->payload_packet_len > 13 && packet->payload[0] == 0xfe
                && packet->payload[packet->payload_packet_len - 1] == 0x05) {
            MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "found fe.\n");
            if (packet->payload_packet_len == ntohl(get_u32(packet->payload, 2))) {
                MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "len match.\n");
                if (memcmp(&packet->payload[6], "socrates", 8) == 0) {
                    MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "found socrates tcp.\n");
                    mmt_socrates_add_connection(ipacket);
                    return 1;
                }
            }
        }

        MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "exclude socrates.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SOCRATES);
    }
    return 0;
}

int mmt_check_socrates_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "search socrates.\n");

        if (packet->payload_packet_len > 9 && packet->payload[0] == 0xfe
                && packet->payload[packet->payload_packet_len - 1] == 0x05) {
            MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "found fe.\n");
            MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "len match.\n");
            if (memcmp(&packet->payload[2], "socrates", 8) == 0) {
                MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "found socrates udp.\n");
                mmt_socrates_add_connection(ipacket);
                return 1;
            }
        }

        MMT_LOG(PROTO_SOCRATES, MMT_LOG_DEBUG, "exclude socrates.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SOCRATES);
    }
    return 0;
}

void mmt_init_classify_me_socrates() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SOCRATES);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_socrates_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SOCRATES, PROTO_SOCRATES_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_socrates();

        return register_protocol(protocol_struct, PROTO_SOCRATES);
    } else {
        return 0;
    }
}


