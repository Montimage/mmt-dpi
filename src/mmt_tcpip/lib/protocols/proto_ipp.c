#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ipp_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_IPP, protocol_type);
}

void mmt_classify_me_ipp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint8_t i;

    MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "search ipp\n");
    if (packet->payload_packet_len > 20) {

        MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG,
                "searching for a payload with a pattern like 'number(1to8)blanknumber(1to3)ipp://.\n");
        /* this pattern means that there is a printer saying that his state is idle,
         * means that he is not printing anything at the moment */
        i = 0;

        if (packet->payload[i] < '0' || packet->payload[i] > '9') {
            MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "payload does not begin with a number.\n");
            goto search_for_next_pattern;
        }

        for (;;) {
            i++;
            if (!((packet->payload[i] >= '0' && packet->payload[i] <= '9') ||
                    (packet->payload[i] >= 'a' && packet->payload[i] <= 'f') ||
                    (packet->payload[i] >= 'A' && packet->payload[i] <= 'F')) || i > 8) {
                MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG,
                        "read symbols while the symbol is a number.\n");
                break;
            }
        }

        if (packet->payload[i++] != ' ') {
            MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "there is no blank following the number.\n");
            goto search_for_next_pattern;
        }

        if (packet->payload[i] < '0' || packet->payload[i] > '9') {
            MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "no number following the blank.\n");
            goto search_for_next_pattern;
        }

        for (;;) {
            i++;
            if (packet->payload[i] < '0' || packet->payload[i] > '9' || i > 12) {
                MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG,
                        "read symbols while the symbol is a number.\n");
                break;
            }
        }

        if (mmt_mem_cmp(&packet->payload[i], " ipp://", 7) != 0) {
            MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "the string ' ipp://' does not follow.\n");
            goto search_for_next_pattern;
        }

        MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "found ipp\n");
        mmt_int_ipp_add_connection(ipacket, MMT_REAL_PROTOCOL);
        return;
    }

search_for_next_pattern:

    if (packet->payload_packet_len > 3 && mmt_memcmp(packet->payload, "POST", 4) == 0) {
        mmt_parse_packet_line_info(ipacket);
        if (packet->content_line.ptr != NULL && packet->content_line.len > 14
                && mmt_memcmp(packet->content_line.ptr, "application/ipp", 15) == 0) {
            MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "found ipp via POST ... application/ipp.\n");
            mmt_int_ipp_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }
    }
    MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "no ipp detected.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_IPP);
}

int mmt_check_ipp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct * flow = packet->flow;

        uint8_t i;

        MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "search ipp\n");
        if (packet->payload_packet_len > 20) {

            MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG,
                    "searching for a payload with a pattern like 'number(1to8)blanknumber(1to3)ipp://.\n");
            /* this pattern means that there is a printer saying that his state is idle,
             * means that he is not printing anything at the moment */
            i = 0;

            if (packet->payload[i] < '0' || packet->payload[i] > '9') {
                MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "payload does not begin with a number.\n");
                goto search_for_next_pattern;
            }

            for (;;) {
                i++;
                if (!((packet->payload[i] >= '0' && packet->payload[i] <= '9') ||
                        (packet->payload[i] >= 'a' && packet->payload[i] <= 'f') ||
                        (packet->payload[i] >= 'A' && packet->payload[i] <= 'F')) || i > 8) {
                    MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG,
                            "read symbols while the symbol is a number.\n");
                    break;
                }
            }

            if (packet->payload[i++] != ' ') {
                MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "there is no blank following the number.\n");
                goto search_for_next_pattern;
            }

            if (packet->payload[i] < '0' || packet->payload[i] > '9') {
                MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "no number following the blank.\n");
                goto search_for_next_pattern;
            }

            for (;;) {
                i++;
                if (packet->payload[i] < '0' || packet->payload[i] > '9' || i > 12) {
                    MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG,
                            "read symbols while the symbol is a number.\n");
                    break;
                }
            }

            if (mmt_mem_cmp(&packet->payload[i], " ipp://", 7) != 0) {
                MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "the string ' ipp://' does not follow.\n");
                goto search_for_next_pattern;
            }

            MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "found ipp\n");
            mmt_int_ipp_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

search_for_next_pattern:
        if (packet->payload_packet_len > 3 && mmt_memcmp(packet->payload, "POST", 4) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->content_line.ptr != NULL && packet->content_line.len > 14
                    && mmt_memcmp(packet->content_line.ptr, "application/ipp", 15) == 0) {
                MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "found ipp via POST ... application/ipp.\n");
                mmt_int_ipp_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            }
        }
        MMT_LOG(PROTO_IPP, MMT_LOG_DEBUG, "no ipp detected.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_IPP);

    }
    return 0;
}

void mmt_init_classify_me_ipp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_IPP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ipp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_IPP, PROTO_IPP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_ipp();

        return register_protocol(protocol_struct, PROTO_IPP);
    } else {
        return 0;
    }
}


