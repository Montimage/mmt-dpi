#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_aimini_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_AIMINI, protocol_type);
}

static uint8_t is_special_aimini_host(struct mmt_int_one_line_struct host_line) {
    if (host_line.ptr != NULL && host_line.len >= 18) {
        if ((get_u32(host_line.ptr, 0) & htonl(0x00ff00ff)) == htonl(0x002e002e) &&
                (get_u32(host_line.ptr, 4) & htonl(0x00ff00ff)) == htonl(0x002e002e) &&
                mmt_memcmp(&host_line.ptr[8], "aimini.net", 10) == 0) {
            return 1;
        }
    }
    return 0;
}

int mmt_check_aimini_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if ((packet->payload_packet_len > 12 &&
                (mmt_memcmp(packet->payload, "GET /player/", 12) == 0)) ||
                (packet->payload_packet_len > 15 &&
                (mmt_memcmp(packet->payload, "GET /play/?fid=", 15) == 0))) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->host_line.ptr != NULL && packet->host_line.len > 11
                    && (mmt_memcmp(&packet->host_line.ptr[packet->host_line.len - 11], ".aimini.net", 11) == 0)) {
                mmt_int_aimini_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            }
        }
        if (packet->payload_packet_len > 100) {
            if (mmt_memcmp(packet->payload, "GET /", 5) == 0) {
                if (mmt_memcmp(&packet->payload[5], "play/",
                        5) == 0 ||
                        mmt_memcmp(&packet->payload[5], "download/",
                        9) == 0) {
                    mmt_parse_packet_line_info(ipacket);
                    if (is_special_aimini_host(packet->host_line) == 1) {
                        mmt_int_aimini_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return 1;
                    }
                }
            } else if (mmt_memcmp(packet->payload, "POST /", 6) == 0) {
                if (mmt_memcmp(&packet->payload[6], "upload/",
                        7) == 0) {
                    mmt_parse_packet_line_info(ipacket);
                    if (is_special_aimini_host(packet->host_line) == 1) {
                        mmt_int_aimini_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return 1;
                    }
                }
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_AIMINI);
    }
    return 0;
}

int mmt_check_aimini_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if (flow->l4.udp.aimini_stage == 0) {
            if (packet->payload_packet_len == 64 && ntohs(get_u16(packet->payload, 0)) == 0x010b) {
                flow->l4.udp.aimini_stage = 1;
                return 4;
            }
            if (packet->payload_packet_len == 136
                    && (ntohs(get_u16(packet->payload, 0)) == 0x01c9 || ntohs(get_u16(packet->payload, 0)) == 0x0165)) {
                flow->l4.udp.aimini_stage = 4;
                return 4;
            }
            if (packet->payload_packet_len == 88 && ntohs(get_u16(packet->payload, 0)) == 0x0101) {
                flow->l4.udp.aimini_stage = 7;
                return 4;
            }
            if (packet->payload_packet_len == 104 && ntohs(get_u16(packet->payload, 0)) == 0x0102) {
                flow->l4.udp.aimini_stage = 10;
                return 4;
            }
            if (packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca) {
                flow->l4.udp.aimini_stage = 13;
                return 4;
            }
            if (packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c) {
                flow->l4.udp.aimini_stage = 16;
                return 4;
            }
        }
        /* first packet chronology: (len, value): (64, 0x010b), (>100, 0x0115), (16, 0x010c || 64, 0x010b || 88, 0x0115),
         * (16, 0x010c || 64, 0x010b || >100, 0x0115)
         */
        if (flow->l4.udp.aimini_stage == 1 && packet->payload_packet_len > 100
                && ntohs(get_u16(packet->payload, 0)) == 0x0115) {
            flow->l4.udp.aimini_stage = 2;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 2 &&
                ((packet->payload_packet_len == 16 && get_u16(packet->payload, 0) == htons(0x010c)) ||
                (packet->payload_packet_len == 64 && get_u16(packet->payload, 0) == htons(0x010b)) ||
                (packet->payload_packet_len == 88 && get_u16(packet->payload, 0) == ntohs(0x0115)))) {
            flow->l4.udp.aimini_stage = 3;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 3
                && ((packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c)
                || (packet->payload_packet_len == 64 && ntohs(get_u16(packet->payload, 0)) == 0x010b)
                || (packet->payload_packet_len > 100 && ntohs(get_u16(packet->payload, 0)) == 0x0115))) {
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* second packet chronology: (len, value): (136, 0x01c9), (136, 0x01c9),(136, 0x01c9),(136, 0x01c9 || 32, 0x01ca) */

        if (flow->l4.udp.aimini_stage == 4 && packet->payload_packet_len == 136
                && (ntohs(get_u16(packet->payload, 0)) == 0x01c9 || ntohs(get_u16(packet->payload, 0)) == 0x0165)) {
            flow->l4.udp.aimini_stage = 5;
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 5 && (packet->payload_packet_len == 136
                && (ntohs(get_u16(packet->payload, 0)) == 0x01c9
                || ntohs(get_u16(packet->payload, 0)) == 0x0165))) {
            flow->l4.udp.aimini_stage = 6;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 6 && ((packet->payload_packet_len == 136
                && ((ntohs(get_u16(packet->payload, 0)) == 0x0165)
                || ntohs(get_u16(packet->payload, 0)) == 0x01c9))
                || (packet->payload_packet_len == 32
                && ntohs(get_u16(packet->payload, 0)) == 0x01ca))) {
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* third packet chronology: (len, value): (88, 0x0101), (88, 0x0101),(88, 0x0101),(88, 0x0101) */

        if (flow->l4.udp.aimini_stage == 7 && packet->payload_packet_len == 88
                && ntohs(get_u16(packet->payload, 0)) == 0x0101) {
            flow->l4.udp.aimini_stage = 8;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 8
                && (packet->payload_packet_len == 88 && ntohs(get_u16(packet->payload, 0)) == 0x0101)) {
            flow->l4.udp.aimini_stage = 9;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 9
                && (packet->payload_packet_len == 88 && ntohs(get_u16(packet->payload, 0)) == 0x0101)) {
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* fourth packet chronology: (len, value): (104, 0x0102), (104, 0x0102), (104, 0x0102), (104, 0x0102) */

        if (flow->l4.udp.aimini_stage == 10 && packet->payload_packet_len == 104
                && ntohs(get_u16(packet->payload, 0)) == 0x0102) {
            flow->l4.udp.aimini_stage = 11;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 11
                && (packet->payload_packet_len == 104 && ntohs(get_u16(packet->payload, 0)) == 0x0102)) {
            flow->l4.udp.aimini_stage = 12;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 12
                && ((packet->payload_packet_len == 104 && ntohs(get_u16(packet->payload, 0)) == 0x0102)
                || (packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca))) {
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* fifth packet chronology (len, value): (32,0x01ca), (32,0x01ca), (32,0x01ca), ((136, 0x0166) || (32,0x01ca)) */

        if (flow->l4.udp.aimini_stage == 13 && packet->payload_packet_len == 32
                && ntohs(get_u16(packet->payload, 0)) == 0x01ca) {
            flow->l4.udp.aimini_stage = 14;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 14
                && ((packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca)
                || (packet->payload_packet_len == 136 && ntohs(get_u16(packet->payload, 0)) == 0x0166))) {
            flow->l4.udp.aimini_stage = 15;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 15
                && ((packet->payload_packet_len == 136 && ntohs(get_u16(packet->payload, 0)) == 0x0166)
                || (packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca))) {
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* sixth packet chronology (len, value): (16, 0x010c), (16, 0x010c), (16, 0x010c), (16, 0x010c) */

        if (flow->l4.udp.aimini_stage == 16 && packet->payload_packet_len == 16
                && ntohs(get_u16(packet->payload, 0)) == 0x010c) {
            flow->l4.udp.aimini_stage = 17;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 17
                && (packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c)) {
            flow->l4.udp.aimini_stage = 18;
            return 4;
        }
        if (flow->l4.udp.aimini_stage == 18
                && (packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c)) {
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_AIMINI);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_aimini_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_AIMINI, PROTO_AIMINI_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_AIMINI);

        return register_protocol(protocol_struct, PROTO_AIMINI);
    } else {
        return 0;
    }
}
