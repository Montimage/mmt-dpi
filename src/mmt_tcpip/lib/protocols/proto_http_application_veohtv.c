#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_veohtv_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_HTTP_APPLICATION_VEOHTV, protocol_type);
}

void mmt_classify_me_veohtv(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->detected_protocol_stack[0] == PROTO_HTTP_APPLICATION_VEOHTV)
        return;

    if (flow->l4.tcp.veoh_tv_stage == 1 || flow->l4.tcp.veoh_tv_stage == 2) {
        if (ipacket->session->last_packet_direction != ipacket->session->setup_packet_direction &&
                packet->payload_packet_len > MMT_STATICSTRING_LEN("HTTP/1.1 20")
                && memcmp(packet->payload, "HTTP/1.1 ", MMT_STATICSTRING_LEN("HTTP/1.1 ")) == 0 &&
                (packet->payload[MMT_STATICSTRING_LEN("HTTP/1.1 ")] == '2' ||
                packet->payload[MMT_STATICSTRING_LEN("HTTP/1.1 ")] == '3' ||
                packet->payload[MMT_STATICSTRING_LEN("HTTP/1.1 ")] == '4' ||
                packet->payload[MMT_STATICSTRING_LEN("HTTP/1.1 ")] == '5')) {
#ifdef PROTO_FLASH
            mmt_parse_packet_line_info(ipacket);
            if (packet->detected_protocol_stack[0] == PROTO_FLASH &&
                    packet->server_line.ptr != NULL &&
                    packet->server_line.len > MMT_STATICSTRING_LEN("Veoh-") &&
                    memcmp(packet->server_line.ptr, "Veoh-", MMT_STATICSTRING_LEN("Veoh-")) == 0) {
                MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "VeohTV detected.\n");
                mmt_int_veohtv_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
#endif
            if (flow->l4.tcp.veoh_tv_stage == 2) {
                MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask,
                        PROTO_HTTP_APPLICATION_VEOHTV);
                return;
            }
            MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "VeohTV detected.\n");
            mmt_int_veohtv_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        } else if (ipacket->session->data_packet_count_direction[(ipacket->session->setup_packet_direction == 1) ? 0 : 1] > 3) {
            if (flow->l4.tcp.veoh_tv_stage == 2) {
                MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask,
                        PROTO_HTTP_APPLICATION_VEOHTV);
                return;
            }
            MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "VeohTV detected.\n");
            mmt_int_veohtv_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        } else {
            if (ipacket->session->data_packet_count > 10) {
                if (flow->l4.tcp.veoh_tv_stage == 2) {
                    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask,
                            PROTO_HTTP_APPLICATION_VEOHTV);
                    return;
                }
                MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "VeohTV detected.\n");
                mmt_int_veohtv_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
            return;
        }
    } else if (packet->udp) {
        /* UDP packets from Veoh Client Player
         *
         * packet starts with 16 byte random? value
         * then a 4 byte mode value
         *   values between 21 and 26 has been seen
         * then a 4 byte counter */

        if (packet->payload_packet_len == 28 &&
                get_u32(packet->payload, 16) == htonl(0x00000021) &&
                get_u32(packet->payload, 20) == htonl(0x00000000) && get_u32(packet->payload, 24) == htonl(0x01040000)) {
            MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "UDP VeohTV found.\n");
            mmt_int_veohtv_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
    }


    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP_APPLICATION_VEOHTV);
}

int mmt_check_veohtv_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->detected_protocol_stack[0] == PROTO_HTTP_APPLICATION_VEOHTV)
            return 1;

        if (flow->l4.tcp.veoh_tv_stage == 1 || flow->l4.tcp.veoh_tv_stage == 2) {
            if (ipacket->session->last_packet_direction != ipacket->session->setup_packet_direction &&
                    packet->payload_packet_len > MMT_STATICSTRING_LEN("HTTP/1.1 20")
                    && memcmp(packet->payload, "HTTP/1.1 ", MMT_STATICSTRING_LEN("HTTP/1.1 ")) == 0 &&
                    (packet->payload[MMT_STATICSTRING_LEN("HTTP/1.1 ")] == '2' ||
                    packet->payload[MMT_STATICSTRING_LEN("HTTP/1.1 ")] == '3' ||
                    packet->payload[MMT_STATICSTRING_LEN("HTTP/1.1 ")] == '4' ||
                    packet->payload[MMT_STATICSTRING_LEN("HTTP/1.1 ")] == '5')) {
                mmt_parse_packet_line_info(ipacket);
                if (packet->detected_protocol_stack[0] == PROTO_FLASH &&
                        packet->server_line.ptr != NULL &&
                        packet->server_line.len > MMT_STATICSTRING_LEN("Veoh-") &&
                        memcmp(packet->server_line.ptr, "Veoh-", MMT_STATICSTRING_LEN("Veoh-")) == 0) {
                    MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "VeohTV detected.\n");
                    mmt_int_veohtv_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return 1;
                }
                if (flow->l4.tcp.veoh_tv_stage == 2) {
                    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask,
                            PROTO_HTTP_APPLICATION_VEOHTV);
                    return 0;
                }
                MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "VeohTV detected.\n");
                mmt_int_veohtv_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            } else if (ipacket->session->data_packet_count_direction[(ipacket->session->setup_packet_direction == 1) ? 0 : 1] > 3) {
                if (flow->l4.tcp.veoh_tv_stage == 2) {
                    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP_APPLICATION_VEOHTV);
                    return 0;
                }
                MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "VeohTV detected.\n");
                mmt_int_veohtv_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            } else {
                if (ipacket->session->data_packet_count > 10) {
                    if (flow->l4.tcp.veoh_tv_stage == 2) {
                        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP_APPLICATION_VEOHTV);
                        return 0;
                    }
                    MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "VeohTV detected.\n");
                    mmt_int_veohtv_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return 1;
                }
                return 1;
            }
        } 
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP_APPLICATION_VEOHTV);
    }
    return 0;
}

int mmt_check_veohtv_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->detected_protocol_stack[0] == PROTO_HTTP_APPLICATION_VEOHTV)
            return 1;

        /* UDP packets from Veoh Client Player
         *
         * packet starts with 16 byte random? value
         * then a 4 byte mode value
         *   values between 21 and 26 has been seen
         * then a 4 byte counter */

        if (packet->payload_packet_len == 28 &&
                get_u32(packet->payload, 16) == htonl(0x00000021) &&
                get_u32(packet->payload, 20) == htonl(0x00000000) && get_u32(packet->payload, 24) == htonl(0x01040000)) {
            MMT_LOG(PROTO_HTTP_APPLICATION_VEOHTV, MMT_LOG_DEBUG, "UDP VeohTV found.\n");
            mmt_int_veohtv_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP_APPLICATION_VEOHTV);
    }
    return 0;
}

void mmt_init_classify_me_veohtv() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_HTTP_APPLICATION_VEOHTV);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_http_application_veohtv_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_HTTP_APPLICATION_VEOHTV, PROTO_HTTP_APPLICATION_VEOHTV_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_veohtv();

        return register_protocol(protocol_struct, PROTO_HTTP_APPLICATION_VEOHTV);
    } else {
        return 0;
    }
}


