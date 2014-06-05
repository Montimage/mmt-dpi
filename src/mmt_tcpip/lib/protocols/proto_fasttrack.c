#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_fasttrack_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_FASTTRACK, MMT_CORRELATED_PROTOCOL);
}

void mmt_classify_me_fasttrack_tcp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len > 6 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {
        MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE, "detected 0d0a at the end of the packet.\n");

        if (memcmp(packet->payload, "GIVE ", 5) == 0 && packet->payload_packet_len >= 8) {
            uint16_t i;
            for (i = 5; i < (packet->payload_packet_len - 2); i++) {
                // make shure that the argument to GIVE is numeric
                if (!(packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
                    goto exclude_fasttrack;
                }
            }

            MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE, "FASTTRACK GIVE DETECTED\n");
            mmt_int_fasttrack_add_connection(ipacket);
            return;
        }

        if (packet->payload_packet_len > 50 && memcmp(packet->payload, "GET /", 5) == 0) {
            uint8_t a = 0;
            MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE, "detected GET /. \n");
            mmt_parse_packet_line_info(ipacket);
            for (a = 0; a < packet->parsed_lines; a++) {
                if ((packet->line[a].len > 17 && memcmp(packet->line[a].ptr, "X-Kazaa-Username: ", 18) == 0)
                        || (packet->line[a].len > 23 && memcmp(packet->line[a].ptr, "User-Agent: PeerEnabler/", 24) == 0)) {
                    MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE,
                            "detected X-Kazaa-Username: || User-Agent: PeerEnabler/\n");
                    mmt_int_fasttrack_add_connection(ipacket);
                    return;
                }
            }
        }
    }

exclude_fasttrack:
    MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE, "fasttrack/kazaa excluded.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FASTTRACK);
}

int mmt_check_fasttrack(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 6 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {
            MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE, "detected 0d0a at the end of the packet.\n");

            if (memcmp(packet->payload, "GIVE ", 5) == 0 && packet->payload_packet_len >= 8) {
                uint16_t i;
                for (i = 5; i < (packet->payload_packet_len - 2); i++) {
                    // make shure that the argument to GIVE is numeric
                    if (!(packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
                        goto exclude_fasttrack;
                    }
                }

                MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE, "FASTTRACK GIVE DETECTED\n");
                mmt_int_fasttrack_add_connection(ipacket);
                return 1;
            }

            if (packet->payload_packet_len > 50 && memcmp(packet->payload, "GET /", 5) == 0) {
                uint8_t a = 0;
                MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE, "detected GET /. \n");
                mmt_parse_packet_line_info(ipacket);
                for (a = 0; a < packet->parsed_lines; a++) {
                    if ((packet->line[a].len > 17 && memcmp(packet->line[a].ptr, "X-Kazaa-Username: ", 18) == 0)
                            || (packet->line[a].len > 23 && memcmp(packet->line[a].ptr, "User-Agent: PeerEnabler/", 24) == 0)) {
                        MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE,
                                "detected X-Kazaa-Username: || User-Agent: PeerEnabler/\n");
                        mmt_int_fasttrack_add_connection(ipacket);
                        return 1;
                    }
                }
            }
        }

exclude_fasttrack:
        MMT_LOG(PROTO_FASTTRACK, MMT_LOG_TRACE, "fasttrack/kazaa excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FASTTRACK);
    }
    return 1;
}

void mmt_init_classify_me_fasttrack() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FASTTRACK);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_fasttrack_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FASTTRACK, PROTO_FASTTRACK_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_fasttrack();

        return register_protocol(protocol_struct, PROTO_FASTTRACK);
    } else {
        return 0;
    }
}


