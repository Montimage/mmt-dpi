#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_icecast_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_ICECAST, MMT_CORRELATED_PROTOCOL);
}

void mmt_classify_me_icecast(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint8_t i;

    MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "search icecast.\n");

    if ((packet->payload_packet_len < 500 &&
            packet->payload_packet_len >= 7 && mmt_mem_cmp(packet->payload, "SOURCE ", 7) == 0)
            || flow->l4.tcp.icecast_stage) {
        mmt_parse_packet_line_info_unix(ipacket);
        MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "Icecast lines=%d\n", packet->parsed_unix_lines);
        for (i = 0; i < packet->parsed_unix_lines; i++) {
            if (packet->unix_line[i].ptr != NULL && packet->unix_line[i].len > 4
                    && mmt_mem_cmp(packet->unix_line[i].ptr, "ice-", 4) == 0) {
                MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "Icecast detected.\n");
                mmt_int_icecast_add_connection(ipacket);
                return;
            }
        }

        if (packet->parsed_unix_lines < 1 && !flow->l4.tcp.icecast_stage) {
            flow->l4.tcp.icecast_stage = 1;
            return;
        }
    }
#ifdef PROTO_HTTP
    if (MMT_FLOW_PROTOCOL_EXCLUDED(flow, PROTO_HTTP)) {
        goto icecast_exclude;
    }
#endif

    if (ipacket->session->last_packet_direction == ipacket->session->setup_packet_direction && ipacket->session->data_packet_count < 10) {
        return;
    }

    if (ipacket->session->last_packet_direction != ipacket->session->setup_packet_direction) {
        /* server answer, now test Server for Icecast */


        mmt_parse_packet_line_info(ipacket);

        if (packet->server_line.ptr != NULL && packet->server_line.len > MMT_STATICSTRING_LEN("Icecast") &&
                memcmp(packet->server_line.ptr, "Icecast", MMT_STATICSTRING_LEN("Icecast")) == 0) {
            MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "Icecast detected.\n");
            /* TODO maybe store the previous protocol type as subtype?
             *      e.g. ogg or mpeg
             */
            mmt_int_icecast_add_connection(ipacket);
            return;
        }
    }

icecast_exclude:
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_ICECAST);
    MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "Icecast excluded.\n");
}

int mmt_check_icecast(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint8_t i;
        MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "search icecast.\n");

        if ((packet->payload_packet_len < 500 &&
                packet->payload_packet_len >= 7 && mmt_mem_cmp(packet->payload, "SOURCE ", 7) == 0)
                || flow->l4.tcp.icecast_stage) {
            mmt_parse_packet_line_info_unix(ipacket);
            MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "Icecast lines=%d\n", packet->parsed_unix_lines);
            for (i = 0; i < packet->parsed_unix_lines; i++) {
                if (packet->unix_line[i].ptr != NULL && packet->unix_line[i].len > 4
                        && mmt_mem_cmp(packet->unix_line[i].ptr, "ice-", 4) == 0) {
                    MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "Icecast detected.\n");
                    mmt_int_icecast_add_connection(ipacket);
                    return 1;
                }
            }

            if (packet->parsed_unix_lines < 1 && !flow->l4.tcp.icecast_stage) {
                flow->l4.tcp.icecast_stage = 1;
                return 4;
            }
        }
        if (MMT_FLOW_PROTOCOL_EXCLUDED(flow, PROTO_HTTP)) {
            goto icecast_exclude;
        }

        if (ipacket->session->last_packet_direction == ipacket->session->setup_packet_direction && ipacket->session->data_packet_count < 10) {
            return 4;
        }

        if (ipacket->session->last_packet_direction != ipacket->session->setup_packet_direction) {
            /* server answer, now test Server for Icecast */
            mmt_parse_packet_line_info(ipacket);
            if (packet->server_line.ptr != NULL && packet->server_line.len > MMT_STATICSTRING_LEN("Icecast") &&
                    memcmp(packet->server_line.ptr, "Icecast", MMT_STATICSTRING_LEN("Icecast")) == 0) {
                MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "Icecast detected.\n");
                /* TODO maybe store the previous protocol type as subtype?
                 *      e.g. ogg or mpeg
                 */
                mmt_int_icecast_add_connection(ipacket);
                return 1;
            }
        }
icecast_exclude:
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_ICECAST);
        MMT_LOG(PROTO_ICECAST, MMT_LOG_DEBUG, "Icecast excluded.\n");
    }
    return 0;
}

void mmt_init_classify_me_icecast() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MPEG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_QUICKTIME);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_REALMEDIA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WINDOWSMEDIA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AVI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_OGG);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_ICECAST);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_icecast_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_ICECAST, PROTO_ICECAST_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_icecast();

        return register_protocol(protocol_struct, PROTO_ICECAST);
    } else {
        return 0;
    }
}


