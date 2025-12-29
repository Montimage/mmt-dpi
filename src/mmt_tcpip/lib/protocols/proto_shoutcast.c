#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_shoutcast_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SHOUTCAST, MMT_CORRELATED_PROTOCOL);
}

void mmt_classify_me_shoutcast(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "search shoutcast.\n");

    if (ipacket->session->data_packet_count == 1) {
        /* this case in paul_upload_oddcast_002.pcap */
        if (packet->payload_packet_len >= 6
                && packet->payload_packet_len < 80 && mmt_memcmp(packet->payload, "123456", 6) == 0) {
            MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast stage 1, \"123456\".\n");
            return;
        }
        if (ipacket->session->data_packet_count < 3
#ifdef PROTO_HTTP
                && packet->detected_protocol_stack[0] == PROTO_HTTP
#endif
                ) {
            MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG,
                    "http detected, need next packet for shoutcast detection.\n");
            if (packet->payload_packet_len > 4
                    && get_u32(packet->payload, packet->payload_packet_len - 4) != htonl(0x0d0a0d0a)) {
                MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "segmented packet found.\n");
                flow->l4.tcp.shoutcast_stage = 1 + ipacket->session->last_packet_direction;
            }
            return;
        }


        /*  else
           goto exclude_shoutcast; */

    }
    /* evtl. f�r asym detection noch User-Agent:Winamp dazunehmen. */
    if (packet->payload_packet_len > 11 && mmt_memcmp(packet->payload, "ICY 200 OK\x0d\x0a", 12) == 0) {
        MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "found shoutcast by ICY 200 OK.\n");
        mmt_int_shoutcast_add_connection(ipacket);
        return;
    }
    if (flow->l4.tcp.shoutcast_stage == 1 + ipacket->session->last_packet_direction
            && ipacket->session->data_packet_count_direction[ipacket->session->last_packet_direction] < 5) {
        return;
    }

    if (ipacket->session->data_packet_count == 2) {
        if (packet->payload_packet_len == 2 && mmt_memcmp(packet->payload, "\x0d\x0a", 2) == 0) {
            MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast stage 1 continuation.\n");
            return;
        } else if (packet->payload_packet_len > 3 && mmt_mem_cmp(&packet->payload[0], "OK2", 3) == 0) {
            MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast stage 2, OK2 found.\n");
            return;
        } else
            goto exclude_shoutcast;
    } else if (ipacket->session->data_packet_count == 3 || ipacket->session->data_packet_count == 4) {
        if (packet->payload_packet_len > 3 && mmt_mem_cmp(&packet->payload[0], "OK2", 3) == 0) {
            MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast stage 2, OK2 found.\n");
            return;
        } else if (packet->payload_packet_len > 4 && mmt_mem_cmp(&packet->payload[0], "icy-", 4) == 0) {
            MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast detected.\n");
            mmt_int_shoutcast_add_connection(ipacket);
            return;
        } else
            goto exclude_shoutcast;
    }

exclude_shoutcast:
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SHOUTCAST);
    MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast excluded.\n");
}

int mmt_check_shoutcast(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "search shoutcast.\n");

        if (ipacket->session->data_packet_count == 1) {
            /* this case in paul_upload_oddcast_002.pcap */
            if (packet->payload_packet_len >= 6
                    && packet->payload_packet_len < 80 && mmt_memcmp(packet->payload, "123456", 6) == 0) {
                MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast stage 1, \"123456\".\n");
                return 4;
            }
            if (packet->detected_protocol_stack[0] == PROTO_HTTP) {
                MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG,
                        "http detected, need next packet for shoutcast detection.\n");
                if (packet->payload_packet_len > 4 && get_u32(packet->payload, packet->payload_packet_len - 4) != htonl(0x0d0a0d0a)) {
                    MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "segmented packet found.\n");
                    flow->l4.tcp.shoutcast_stage = 1 + ipacket->session->last_packet_direction;
                }
                return 4;
            }
        }
        /* evtl. for asym detection noch User-Agent:Winamp dazunehmen. */
        if (packet->payload_packet_len > 11 && mmt_memcmp(packet->payload, "ICY 200 OK\x0d\x0a", 12) == 0) {
            MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "found shoutcast by ICY 200 OK.\n");
            mmt_int_shoutcast_add_connection(ipacket);
            return 1;
        }
        if (flow->l4.tcp.shoutcast_stage == 1 + ipacket->session->last_packet_direction
                && ipacket->session->data_packet_count_direction[ipacket->session->last_packet_direction] < 5) {
            return 4;
        }

        if (ipacket->session->data_packet_count == 2) {
            if (packet->payload_packet_len == 2 && mmt_memcmp(packet->payload, "\x0d\x0a", 2) == 0) {
                MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast stage 1 continuation.\n");
                return 4;
            } else if (packet->payload_packet_len > 3 && mmt_mem_cmp(&packet->payload[0], "OK2", 3) == 0) {
                MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast stage 2, OK2 found.\n");
                return 4;
            } else
                goto exclude_shoutcast;
        } else if (ipacket->session->data_packet_count == 3 || ipacket->session->data_packet_count == 4) {
            if (packet->payload_packet_len > 3 && mmt_mem_cmp(&packet->payload[0], "OK2", 3) == 0) {
                MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast stage 2, OK2 found.\n");
                return 4;
            } else if (packet->payload_packet_len > 4 && mmt_mem_cmp(&packet->payload[0], "icy-", 4) == 0) {
                MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast detected.\n");
                mmt_int_shoutcast_add_connection(ipacket);
                return 1;
            } else
                goto exclude_shoutcast;
        }
exclude_shoutcast:
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SHOUTCAST);
        MMT_LOG(PROTO_SHOUTCAST, MMT_LOG_DEBUG, "Shoutcast excluded.\n");
    }
    return 0;
}

void mmt_init_classify_me_shoutcast() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SHOUTCAST);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_shoutcast_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SHOUTCAST, PROTO_SHOUTCAST_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_shoutcast();

        return register_protocol(protocol_struct, PROTO_SHOUTCAST);
    } else {
        return 0;
    }
}
