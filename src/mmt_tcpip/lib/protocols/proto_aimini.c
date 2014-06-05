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
    if (host_line.ptr != NULL && host_line.len >= MMT_STATICSTRING_LEN("X.X.X.X.aimini.net")) {
        if ((get_u32(host_line.ptr, 0) & htonl(0x00ff00ff)) == htonl(0x002e002e) &&
                (get_u32(host_line.ptr, 4) & htonl(0x00ff00ff)) == htonl(0x002e002e) &&
                memcmp(&host_line.ptr[8], "aimini.net", MMT_STATICSTRING_LEN("aimini.net")) == 0) {
            return 1;
        }
    }
    return 0;
}

void mmt_classify_me_aimini(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "search aimini.\n");

    if (packet->udp != NULL) {
        if (flow->l4.udp.aimini_stage == 0) {
            if (packet->payload_packet_len == 64 && ntohs(get_u16(packet->payload, 0)) == 0x010b) {
                flow->l4.udp.aimini_stage = 1;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 1.\n");
                return;
            }
            if (packet->payload_packet_len == 136
                    && (ntohs(get_u16(packet->payload, 0)) == 0x01c9 || ntohs(get_u16(packet->payload, 0)) == 0x0165)) {
                flow->l4.udp.aimini_stage = 4;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 4.\n");
                return;
            }
            if (packet->payload_packet_len == 88 && ntohs(get_u16(packet->payload, 0)) == 0x0101) {
                flow->l4.udp.aimini_stage = 7;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 7.\n");
                return;
            }
            if (packet->payload_packet_len == 104 && ntohs(get_u16(packet->payload, 0)) == 0x0102) {
                flow->l4.udp.aimini_stage = 10;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 10.\n");
                return;
            }
            if (packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca) {
                flow->l4.udp.aimini_stage = 13;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 13.\n");
                return;
            }
            if (packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c) {
                flow->l4.udp.aimini_stage = 16;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 16.\n");
                return;
            }
        }
        /* first packet chronology: (len, value): (64, 0x010b), (>100, 0x0115), (16, 0x010c || 64, 0x010b || 88, 0x0115),
         * (16, 0x010c || 64, 0x010b || >100, 0x0115)
         */
        if (flow->l4.udp.aimini_stage == 1 && packet->payload_packet_len > 100
                && ntohs(get_u16(packet->payload, 0)) == 0x0115) {
            flow->l4.udp.aimini_stage = 2;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 2.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 2 &&
                ((packet->payload_packet_len == 16 && get_u16(packet->payload, 0) == htons(0x010c)) ||
                (packet->payload_packet_len == 64 && get_u16(packet->payload, 0) == htons(0x010b)) ||
                (packet->payload_packet_len == 88 && get_u16(packet->payload, 0) == ntohs(0x0115)))) {
            flow->l4.udp.aimini_stage = 3;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 3.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 3
                && ((packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c)
                || (packet->payload_packet_len == 64 && ntohs(get_u16(packet->payload, 0)) == 0x010b)
                || (packet->payload_packet_len > 100 && ntohs(get_u16(packet->payload, 0)) == 0x0115))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "found aimini (64, 0x010b), (>300, 0x0115), "
                    "(16, 0x010c || 64, 0x010b), (16, 0x010c || 64, 0x010b || >100, 0x0115).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        /* second packet chronology: (len, value): (136, 0x01c9), (136, 0x01c9),(136, 0x01c9),(136, 0x01c9 || 32, 0x01ca) */

        if (flow->l4.udp.aimini_stage == 4 && packet->payload_packet_len == 136
                && (ntohs(get_u16(packet->payload, 0)) == 0x01c9 || ntohs(get_u16(packet->payload, 0)) == 0x0165)) {
            flow->l4.udp.aimini_stage = 5;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 5.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 5 && (packet->payload_packet_len == 136
                && (ntohs(get_u16(packet->payload, 0)) == 0x01c9
                || ntohs(get_u16(packet->payload, 0)) == 0x0165))) {
            flow->l4.udp.aimini_stage = 6;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 6.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 6 && ((packet->payload_packet_len == 136
                && ((ntohs(get_u16(packet->payload, 0)) == 0x0165)
                || ntohs(get_u16(packet->payload, 0)) == 0x01c9))
                || (packet->payload_packet_len == 32
                && ntohs(get_u16(packet->payload, 0)) == 0x01ca))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (136, 0x01c9), (136, 0x01c9)," "(136, 0x01c9),(136, 0x01c9 || 32, 0x01ca).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        /* third packet chronology: (len, value): (88, 0x0101), (88, 0x0101),(88, 0x0101),(88, 0x0101) */

        if (flow->l4.udp.aimini_stage == 7 && packet->payload_packet_len == 88
                && ntohs(get_u16(packet->payload, 0)) == 0x0101) {
            flow->l4.udp.aimini_stage = 8;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 8.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 8
                && (packet->payload_packet_len == 88 && ntohs(get_u16(packet->payload, 0)) == 0x0101)) {
            flow->l4.udp.aimini_stage = 9;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 9.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 9
                && (packet->payload_packet_len == 88 && ntohs(get_u16(packet->payload, 0)) == 0x0101)) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (88, 0x0101), (88, 0x0101)," "(88, 0x0101),(88, 0x0101).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        /* fourth packet chronology: (len, value): (104, 0x0102), (104, 0x0102), (104, 0x0102), (104, 0x0102) */

        if (flow->l4.udp.aimini_stage == 10 && packet->payload_packet_len == 104
                && ntohs(get_u16(packet->payload, 0)) == 0x0102) {
            flow->l4.udp.aimini_stage = 11;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 11.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 11
                && (packet->payload_packet_len == 104 && ntohs(get_u16(packet->payload, 0)) == 0x0102)) {
            flow->l4.udp.aimini_stage = 12;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 12.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 12
                && ((packet->payload_packet_len == 104 && ntohs(get_u16(packet->payload, 0)) == 0x0102)
                || (packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (104, 0x0102), (104, 0x0102), " "(104, 0x0102), (104, 0x0102).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        /* fifth packet chronology (len, value): (32,0x01ca), (32,0x01ca), (32,0x01ca), ((136, 0x0166) || (32,0x01ca)) */

        if (flow->l4.udp.aimini_stage == 13 && packet->payload_packet_len == 32
                && ntohs(get_u16(packet->payload, 0)) == 0x01ca) {
            flow->l4.udp.aimini_stage = 14;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 14.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 14
                && ((packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca)
                || (packet->payload_packet_len == 136 && ntohs(get_u16(packet->payload, 0)) == 0x0166))) {
            flow->l4.udp.aimini_stage = 15;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 15.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 15
                && ((packet->payload_packet_len == 136 && ntohs(get_u16(packet->payload, 0)) == 0x0166)
                || (packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (32,0x01ca), (32,0x01ca), (32,0x01ca), ((136, 0x0166)||(32,0x01ca)).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        /* sixth packet chronology (len, value): (16, 0x010c), (16, 0x010c), (16, 0x010c), (16, 0x010c) */

        if (flow->l4.udp.aimini_stage == 16 && packet->payload_packet_len == 16
                && ntohs(get_u16(packet->payload, 0)) == 0x010c) {
            flow->l4.udp.aimini_stage = 17;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 17.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 17
                && (packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c)) {
            flow->l4.udp.aimini_stage = 18;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 18.\n");
            return;
        }
        if (flow->l4.udp.aimini_stage == 18
                && (packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c)) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (16, 0x010c), (16, 0x010c), (16, 0x010c), (16, 0x010c).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
    } else if (packet->tcp != NULL) {
        if ((packet->payload_packet_len > MMT_STATICSTRING_LEN("GET /player/") &&
                (memcmp(packet->payload, "GET /player/", MMT_STATICSTRING_LEN("GET /player/")) == 0)) ||
                (packet->payload_packet_len > MMT_STATICSTRING_LEN("GET /play/?fid=") &&
                (memcmp(packet->payload, "GET /play/?fid=", MMT_STATICSTRING_LEN("GET /play/?fid=")) == 0))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "HTTP packet detected.\n");
            mmt_parse_packet_line_info(ipacket);
            if (packet->host_line.ptr != NULL && packet->host_line.len > 11
                    && (memcmp(&packet->host_line.ptr[packet->host_line.len - 11], ".aimini.net", 11) == 0)) {
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "AIMINI HTTP traffic detected.\n");
                mmt_int_aimini_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }
        if (packet->payload_packet_len > 100) {
            if (memcmp(packet->payload, "GET /", MMT_STATICSTRING_LEN("GET /")) == 0) {
                if (memcmp(&packet->payload[MMT_STATICSTRING_LEN("GET /")], "play/",
                        MMT_STATICSTRING_LEN("play/")) == 0 ||
                        memcmp(&packet->payload[MMT_STATICSTRING_LEN("GET /")], "download/",
                        MMT_STATICSTRING_LEN("download/")) == 0) {
                    mmt_parse_packet_line_info(ipacket);
                    if (is_special_aimini_host(packet->host_line) == 1) {
                        MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                                "AIMINI HTTP traffic detected.\n");
                        mmt_int_aimini_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return;
                    }
                }
            } else if (memcmp(packet->payload, "POST /", MMT_STATICSTRING_LEN("POST /")) == 0) {
                if (memcmp(&packet->payload[MMT_STATICSTRING_LEN("POST /")], "upload/",
                        MMT_STATICSTRING_LEN("upload/")) == 0) {
                    mmt_parse_packet_line_info(ipacket);
                    if (is_special_aimini_host(packet->host_line) == 1) {
                        MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                                "AIMINI HTTP traffic detected.\n");
                        mmt_int_aimini_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return;
                    }
                }
            }
        }
    }

    MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "exclude aimini.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_AIMINI);

}

int mmt_check_aimini_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "search aimini.\n");

        if ((packet->payload_packet_len > MMT_STATICSTRING_LEN("GET /player/") &&
                (memcmp(packet->payload, "GET /player/", MMT_STATICSTRING_LEN("GET /player/")) == 0)) ||
                (packet->payload_packet_len > MMT_STATICSTRING_LEN("GET /play/?fid=") &&
                (memcmp(packet->payload, "GET /play/?fid=", MMT_STATICSTRING_LEN("GET /play/?fid=")) == 0))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "HTTP packet detected.\n");
            mmt_parse_packet_line_info(ipacket);
            if (packet->host_line.ptr != NULL && packet->host_line.len > 11
                    && (memcmp(&packet->host_line.ptr[packet->host_line.len - 11], ".aimini.net", 11) == 0)) {
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "AIMINI HTTP traffic detected.\n");
                mmt_int_aimini_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            }
        }
        if (packet->payload_packet_len > 100) {
            if (memcmp(packet->payload, "GET /", MMT_STATICSTRING_LEN("GET /")) == 0) {
                if (memcmp(&packet->payload[MMT_STATICSTRING_LEN("GET /")], "play/",
                        MMT_STATICSTRING_LEN("play/")) == 0 ||
                        memcmp(&packet->payload[MMT_STATICSTRING_LEN("GET /")], "download/",
                        MMT_STATICSTRING_LEN("download/")) == 0) {
                    mmt_parse_packet_line_info(ipacket);
                    if (is_special_aimini_host(packet->host_line) == 1) {
                        MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                                "AIMINI HTTP traffic detected.\n");
                        mmt_int_aimini_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return 1;
                    }
                }
            } else if (memcmp(packet->payload, "POST /", MMT_STATICSTRING_LEN("POST /")) == 0) {
                if (memcmp(&packet->payload[MMT_STATICSTRING_LEN("POST /")], "upload/",
                        MMT_STATICSTRING_LEN("upload/")) == 0) {
                    mmt_parse_packet_line_info(ipacket);
                    if (is_special_aimini_host(packet->host_line) == 1) {
                        MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                                "AIMINI HTTP traffic detected.\n");
                        mmt_int_aimini_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return 1;
                    }
                }
            }
        }

        MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "exclude aimini.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_AIMINI);
    }
    return 1;
}

int mmt_check_aimini_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "search aimini.\n");

        if (flow->l4.udp.aimini_stage == 0) {
            if (packet->payload_packet_len == 64 && ntohs(get_u16(packet->payload, 0)) == 0x010b) {
                flow->l4.udp.aimini_stage = 1;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 1.\n");
                return 1;
            }
            if (packet->payload_packet_len == 136
                    && (ntohs(get_u16(packet->payload, 0)) == 0x01c9 || ntohs(get_u16(packet->payload, 0)) == 0x0165)) {
                flow->l4.udp.aimini_stage = 4;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 4.\n");
                return 1;
            }
            if (packet->payload_packet_len == 88 && ntohs(get_u16(packet->payload, 0)) == 0x0101) {
                flow->l4.udp.aimini_stage = 7;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 7.\n");
                return 1;
            }
            if (packet->payload_packet_len == 104 && ntohs(get_u16(packet->payload, 0)) == 0x0102) {
                flow->l4.udp.aimini_stage = 10;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 10.\n");
                return 1;
            }
            if (packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca) {
                flow->l4.udp.aimini_stage = 13;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 13.\n");
                return 1;
            }
            if (packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c) {
                flow->l4.udp.aimini_stage = 16;
                MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 16.\n");
                return 1;
            }
        }
        /* first packet chronology: (len, value): (64, 0x010b), (>100, 0x0115), (16, 0x010c || 64, 0x010b || 88, 0x0115),
         * (16, 0x010c || 64, 0x010b || >100, 0x0115)
         */
        if (flow->l4.udp.aimini_stage == 1 && packet->payload_packet_len > 100
                && ntohs(get_u16(packet->payload, 0)) == 0x0115) {
            flow->l4.udp.aimini_stage = 2;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 2.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 2 &&
                ((packet->payload_packet_len == 16 && get_u16(packet->payload, 0) == htons(0x010c)) ||
                (packet->payload_packet_len == 64 && get_u16(packet->payload, 0) == htons(0x010b)) ||
                (packet->payload_packet_len == 88 && get_u16(packet->payload, 0) == ntohs(0x0115)))) {
            flow->l4.udp.aimini_stage = 3;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 3.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 3
                && ((packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c)
                || (packet->payload_packet_len == 64 && ntohs(get_u16(packet->payload, 0)) == 0x010b)
                || (packet->payload_packet_len > 100 && ntohs(get_u16(packet->payload, 0)) == 0x0115))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "found aimini (64, 0x010b), (>300, 0x0115), "
                    "(16, 0x010c || 64, 0x010b), (16, 0x010c || 64, 0x010b || >100, 0x0115).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* second packet chronology: (len, value): (136, 0x01c9), (136, 0x01c9),(136, 0x01c9),(136, 0x01c9 || 32, 0x01ca) */

        if (flow->l4.udp.aimini_stage == 4 && packet->payload_packet_len == 136
                && (ntohs(get_u16(packet->payload, 0)) == 0x01c9 || ntohs(get_u16(packet->payload, 0)) == 0x0165)) {
            flow->l4.udp.aimini_stage = 5;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 5.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 5 && (packet->payload_packet_len == 136
                && (ntohs(get_u16(packet->payload, 0)) == 0x01c9
                || ntohs(get_u16(packet->payload, 0)) == 0x0165))) {
            flow->l4.udp.aimini_stage = 6;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 6.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 6 && ((packet->payload_packet_len == 136
                && ((ntohs(get_u16(packet->payload, 0)) == 0x0165)
                || ntohs(get_u16(packet->payload, 0)) == 0x01c9))
                || (packet->payload_packet_len == 32
                && ntohs(get_u16(packet->payload, 0)) == 0x01ca))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (136, 0x01c9), (136, 0x01c9)," "(136, 0x01c9),(136, 0x01c9 || 32, 0x01ca).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* third packet chronology: (len, value): (88, 0x0101), (88, 0x0101),(88, 0x0101),(88, 0x0101) */

        if (flow->l4.udp.aimini_stage == 7 && packet->payload_packet_len == 88
                && ntohs(get_u16(packet->payload, 0)) == 0x0101) {
            flow->l4.udp.aimini_stage = 8;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 8.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 8
                && (packet->payload_packet_len == 88 && ntohs(get_u16(packet->payload, 0)) == 0x0101)) {
            flow->l4.udp.aimini_stage = 9;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 9.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 9
                && (packet->payload_packet_len == 88 && ntohs(get_u16(packet->payload, 0)) == 0x0101)) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (88, 0x0101), (88, 0x0101)," "(88, 0x0101),(88, 0x0101).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* fourth packet chronology: (len, value): (104, 0x0102), (104, 0x0102), (104, 0x0102), (104, 0x0102) */

        if (flow->l4.udp.aimini_stage == 10 && packet->payload_packet_len == 104
                && ntohs(get_u16(packet->payload, 0)) == 0x0102) {
            flow->l4.udp.aimini_stage = 11;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 11.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 11
                && (packet->payload_packet_len == 104 && ntohs(get_u16(packet->payload, 0)) == 0x0102)) {
            flow->l4.udp.aimini_stage = 12;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 12.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 12
                && ((packet->payload_packet_len == 104 && ntohs(get_u16(packet->payload, 0)) == 0x0102)
                || (packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (104, 0x0102), (104, 0x0102), " "(104, 0x0102), (104, 0x0102).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* fifth packet chronology (len, value): (32,0x01ca), (32,0x01ca), (32,0x01ca), ((136, 0x0166) || (32,0x01ca)) */

        if (flow->l4.udp.aimini_stage == 13 && packet->payload_packet_len == 32
                && ntohs(get_u16(packet->payload, 0)) == 0x01ca) {
            flow->l4.udp.aimini_stage = 14;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 14.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 14
                && ((packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca)
                || (packet->payload_packet_len == 136 && ntohs(get_u16(packet->payload, 0)) == 0x0166))) {
            flow->l4.udp.aimini_stage = 15;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 15.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 15
                && ((packet->payload_packet_len == 136 && ntohs(get_u16(packet->payload, 0)) == 0x0166)
                || (packet->payload_packet_len == 32 && ntohs(get_u16(packet->payload, 0)) == 0x01ca))) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (32,0x01ca), (32,0x01ca), (32,0x01ca), ((136, 0x0166)||(32,0x01ca)).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* sixth packet chronology (len, value): (16, 0x010c), (16, 0x010c), (16, 0x010c), (16, 0x010c) */

        if (flow->l4.udp.aimini_stage == 16 && packet->payload_packet_len == 16
                && ntohs(get_u16(packet->payload, 0)) == 0x010c) {
            flow->l4.udp.aimini_stage = 17;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 17.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 17
                && (packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c)) {
            flow->l4.udp.aimini_stage = 18;
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "stage = 18.\n");
            return 1;
        }
        if (flow->l4.udp.aimini_stage == 18
                && (packet->payload_packet_len == 16 && ntohs(get_u16(packet->payload, 0)) == 0x010c)) {
            MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG,
                    "found aimini (16, 0x010c), (16, 0x010c), (16, 0x010c), (16, 0x010c).\n");
            mmt_int_aimini_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        MMT_LOG(PROTO_AIMINI, MMT_LOG_DEBUG, "exclude aimini.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_AIMINI);
    }
    return 1;
}

void mmt_init_classify_me_aimini() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_AIMINI);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_aimini_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_AIMINI, PROTO_AIMINI_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_aimini();

        return register_protocol(protocol_struct, PROTO_AIMINI);
    } else {
        return 0;
    }
}


