#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_meebo_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_MEEBO, MMT_CORRELATED_PROTOCOL);
}

void mmt_classify_meebo(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;



    /* catch audio/video flows which are flash (rtmp) */
    if (
#ifdef PROTO_FLASH
            packet->detected_protocol_stack[0] == PROTO_FLASH
#else
            (packet->tcp->source == htons(1935) || packet->tcp->dest == htons(1935))
#endif
            ) {

        /* Without an AMF decoder the tokbox/ marker is matched at the two
         * fixed offsets it was observed at. */
        if (packet->payload_packet_len > 900) {
            if (mmt_memcmp(packet->payload + 116, "tokbox/", 7) == 0 ||
                    mmt_memcmp(packet->payload + 316, "tokbox/", 7) == 0) {
                mmt_int_meebo_add_connection(ipacket);
                return;
            }
        }

        if (ipacket->session->data_packet_count < 16 && ipacket->session->data_packet_count_direction[ipacket->session->setup_packet_direction] < 6) {
            return;
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MEEBO);
        return;
    }

    if ((
#ifdef	PROTO_HTTP
            packet->detected_protocol_stack[0] == PROTO_HTTP ||
#endif
            ((packet->payload_packet_len > 3 && mmt_memcmp(packet->payload, "GET ", 4) == 0)
            || (packet->payload_packet_len > 4 && mmt_memcmp(packet->payload, "POST ", 5) == 0))
            ) && ipacket->session->data_packet_count == 1) {
        uint8_t host_or_referer_match = 0;

        mmt_parse_packet_line_info(ipacket);
        if (packet->host_line.ptr != NULL
                && packet->host_line.len >= 9
                && mmt_memcmp(&packet->host_line.ptr[packet->host_line.len - 9], "meebo.com", 9) == 0) {

            host_or_referer_match = 1;
        } else if (packet->host_line.ptr != NULL
                && packet->host_line.len >= 10
                && mmt_memcmp(&packet->host_line.ptr[packet->host_line.len - 10], "tokbox.com", 10) == 0) {

            /* set it to 2 to avoid having plain tokbox traffic detected as meebo */
            host_or_referer_match = 2;
        } else if (packet->host_line.ptr != NULL && packet->host_line.len >= 13
                && mmt_memcmp(&packet->host_line.ptr[packet->host_line.len - 13],
                "74.114.28.110", 13) == 0) {

            host_or_referer_match = 1;
        } else if (packet->referer_line.ptr != NULL &&
                packet->referer_line.len >= 21 &&
                mmt_memcmp(packet->referer_line.ptr, "http://www.meebo.com/",
                21) == 0) {

            host_or_referer_match = 1;
        } else if (packet->referer_line.ptr != NULL &&
                packet->referer_line.len >= 22 &&
                mmt_memcmp(packet->referer_line.ptr, "http://mee.tokbox.com/",
                22) == 0) {

            host_or_referer_match = 1;
        } else if (packet->referer_line.ptr != NULL &&
                packet->referer_line.len >= 21 &&
                mmt_memcmp(packet->referer_line.ptr, "http://74.114.28.110/",
                21) == 0) {

            host_or_referer_match = 1;
        }

        if (host_or_referer_match) {
            if (host_or_referer_match == 1) {
                mmt_int_meebo_add_connection(ipacket);
                return;
            }
        }
    }

    if (packet->detected_protocol_stack[0] == PROTO_MEEBO) {
        return;
    }

    if (flow!=NULL && ipacket->session->data_packet_count < 5 && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
            && MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SSL) == 0) {
        return;
    }
#ifdef PROTO_FLASH
    if (ipacket->session->data_packet_count < 5 && packet->detected_protocol_stack[0] == PROTO_UNKNOWN &&
            !MMT_FLOW_PROTOCOL_EXCLUDED(flow, PROTO_FLASH)) {
        return;
    }
#endif

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MEEBO);
}

int mmt_check_meebo(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_meebo(ipacket, index);
    }
    return 4;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_meebo_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MEEBO, PROTO_MEEBO_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_FLASH, PROTO_MEEBO);

        return register_protocol(protocol_struct, PROTO_MEEBO);
    } else {
        return 0;
    }
}


