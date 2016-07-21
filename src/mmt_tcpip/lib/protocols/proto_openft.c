#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_openft_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_OPENFT, MMT_CORRELATED_PROTOCOL);
}

void mmt_classify_me_openft(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len > 5 && memcmp(packet->payload, "GET /", 5) == 0) {
        MMT_LOG(PROTO_OPENFT, MMT_LOG_DEBUG, "HTTP packet detected.\n");
        mmt_parse_packet_line_info(ipacket);
        if (packet->parsed_lines >= 2
                && packet->line[1].len > 13 && mmt_mem_cmp(packet->line[1].ptr, "X-OpenftAlias:", 14) == 0) {
            MMT_LOG(PROTO_OPENFT, MMT_LOG_DEBUG, "OpenFT detected.\n");
            mmt_int_openft_add_connection(ipacket);
            return;
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_OPENFT);
}

int mmt_check_openft(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 5 && memcmp(packet->payload, "GET /", 5) == 0) {
            MMT_LOG(PROTO_OPENFT, MMT_LOG_DEBUG, "HTTP packet detected.\n");
            mmt_parse_packet_line_info(ipacket);
            if (packet->parsed_lines >= 2
                    && packet->line[1].len > 13 && mmt_mem_cmp(packet->line[1].ptr, "X-OpenftAlias:", 14) == 0) {
                MMT_LOG(PROTO_OPENFT, MMT_LOG_DEBUG, "OpenFT detected.\n");
                mmt_int_openft_add_connection(ipacket);
                return 1;
            }
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_OPENFT);
    }
    return 0;
}

void mmt_init_classify_me_openft() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_OPENFT);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_openft_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_OPENFT, PROTO_OPENFT_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_openft();

        return register_protocol(protocol_struct, PROTO_OPENFT);
    } else {
        return 0;
    }
}


