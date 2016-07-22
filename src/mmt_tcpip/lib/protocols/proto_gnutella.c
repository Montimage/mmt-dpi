#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_GNUTELLA_TIMEOUT                60

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static uint32_t gnutella_timeout = MMT_GNUTELLA_TIMEOUT * MMT_MICRO_IN_SEC;

static void mmt_int_gnutella_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    mmt_internal_add_connection(ipacket, PROTO_GNUTELLA, protocol_type);

    if (src != NULL) {
        src->gnutella_ts = packet->tick_timestamp;
        if (packet->udp != NULL) {
            if (!src->detected_gnutella_udp_port1) {
                src->detected_gnutella_udp_port1 = (packet->udp->source);
                MMT_LOG_GNUTELLA(PROTO_GNUTELLA, 
                        MMT_LOG_DEBUG, "GNUTELLA UDP PORT1 DETECTED as %u\n",
                        src->detected_gnutella_udp_port1);

            } else if ((ntohs(packet->udp->source) != src->detected_gnutella_udp_port1)
                    && !src->detected_gnutella_udp_port2) {
                src->detected_gnutella_udp_port2 = (packet->udp->source);
                MMT_LOG_GNUTELLA(PROTO_GNUTELLA, 
                        MMT_LOG_DEBUG, "GNUTELLA UDP PORT2 DETECTED as %u\n",
                        src->detected_gnutella_udp_port2);

            }
        }
    }
    if (dst != NULL) {
        dst->gnutella_ts = packet->tick_timestamp;
    }
}

void mmt_classify_me_gnutella(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    uint16_t c;
    if (packet->detected_protocol_stack[0] == PROTO_GNUTELLA) {
        if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - src->gnutella_ts) < gnutella_timeout)) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, 
                    MMT_LOG_DEBUG, "gnutella : save src connection packet detected\n");
            src->gnutella_ts = packet->tick_timestamp;
        } else if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - dst->gnutella_ts) < gnutella_timeout)) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, 
                    MMT_LOG_DEBUG, "gnutella : save dst connection packet detected\n");
            dst->gnutella_ts = packet->tick_timestamp;
        }
        if (src != NULL && (packet->tick_timestamp - src->gnutella_ts) > gnutella_timeout) {
            src->detected_gnutella_udp_port1 = 0;
            src->detected_gnutella_udp_port2 = 0;
        }
        if (dst != NULL && (packet->tick_timestamp - dst->gnutella_ts) > gnutella_timeout) {
            dst->detected_gnutella_udp_port1 = 0;
            dst->detected_gnutella_udp_port2 = 0;
        }

        return;
    }

    /* skip packets without payload */
    if (packet->payload_packet_len < 2) {
        return;
    }
    if (packet->tcp != NULL) {
        /* this case works asymmetrically */
        if (packet->payload_packet_len > 10 && memcmp(packet->payload, "GNUTELLA/", 9) == 0) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_TRACE, "GNUTELLA DETECTED\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        /* this case works asymmetrically */
        if (packet->payload_packet_len > 17 && memcmp(packet->payload, "GNUTELLA CONNECT/", 17) == 0) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_TRACE, "GNUTELLA DETECTED\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        if (packet->payload_packet_len > 50 && ((memcmp(packet->payload, "GET /get/", 9) == 0)
                || (memcmp(packet->payload, "GET /uri-res/", 13) == 0)
                )) {
            mmt_parse_packet_line_info(ipacket);
            for (c = 0; c < packet->parsed_lines; c++) {
                if ((packet->line[c].len > 19 && memcmp(packet->line[c].ptr, "User-Agent: Gnutella", 20) == 0)
                        || (packet->line[c].len > 10 && memcmp(packet->line[c].ptr, "X-Gnutella-", 11) == 0)
                        || (packet->line[c].len > 7 && memcmp(packet->line[c].ptr, "X-Queue:", 8) == 0)
                        || (packet->line[c].len > 36 && memcmp(packet->line[c].ptr,
                        "Content-Type: application/x-gnutella-", 37) == 0)) {
                    MMT_LOG(PROTO_GNUTELLA, MMT_LOG_DEBUG, "DETECTED GNUTELLA GET.\n");
                    mmt_int_gnutella_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
        }
        if (packet->payload_packet_len > 50 && ((memcmp(packet->payload, "GET / HTTP", 9) == 0))) {
            mmt_parse_packet_line_info(ipacket);
            if ((packet->user_agent_line.ptr != NULL && packet->user_agent_line.len > 15
                    && memcmp(packet->user_agent_line.ptr, "BearShare Lite ", 15) == 0)
                    || (packet->accept_line.ptr != NULL && packet->accept_line.len > 24
                    && memcmp(packet->accept_line.ptr, "application n/x-gnutella", 24) == 0)) {
                MMT_LOG(PROTO_GNUTELLA, MMT_LOG_DEBUG, "DETECTED GNUTELLA GET.\n");
                mmt_int_gnutella_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            }

        }
        /* haven't found this pattern in any trace. */
        if (packet->payload_packet_len > 50 && ((memcmp(packet->payload, "GET /get/", 9) == 0)
                || (memcmp(packet->payload, "GET /uri-res/", 13) == 0))) {
            c = 8;
            while (c < (packet->payload_packet_len - 9)) {
                if (packet->payload[c] == '?')
                    break;
                c++;
            }

            if (c < (packet->payload_packet_len - 9) && memcmp(&packet->payload[c], "urn:sha1:", 9) == 0) {
                MMT_LOG(PROTO_GNUTELLA, MMT_LOG_TRACE,
                        "detected GET /get/ or GET /uri-res/.\n");
                mmt_int_gnutella_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            }

        }

        /* answer to this packet is HTTP/1.1 ..... Content-Type: application/x-gnutella-packets,
         * it is searched in the upper paragraph. */
        if (packet->payload_packet_len > 30 && memcmp(packet->payload, "HEAD /gnutella/push-proxy?", 26) == 0) {
            MMT_LOG(PROTO_GNUTELLA, MMT_LOG_TRACE, "detected HEAD /gnutella/push-proxy?\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }
        /* haven't found any trace with this pattern */
        if (packet->payload_packet_len == 46
                && memcmp(packet->payload, "\x50\x55\x53\x48\x20\x67\x75\x69\x64\x3a", 10) == 0) {
            MMT_LOG(PROTO_GNUTELLA, MMT_LOG_TRACE,
                    "detected \x50\x55\x53\x48\x20\x67\x75\x69\x64\x3a\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        /* haven't found any trace with this pattern */
        if (packet->payload_packet_len > 250 && memcmp(packet->payload, "GET /gnutella/", 14) == 0)
            //PATTERN IS :: GET /gnutella/tigertree/v3?urn:tree:tiger/:
        {
            const uint16_t end = packet->payload_packet_len - 3;

            c = 13;
            while (c < end) {
                if ((memcmp(&packet->payload[14], "tigertree/", 10) == 0)
                        || (end - c > 18 && memcmp(&packet->payload[c], "\r\nUser-Agent: Foxy", 18) == 0)
                        || (end - c > 44
                        && memcmp(&packet->payload[c],
                        "\r\nAccept: application/tigertree-breadthfirst",
                        44) == 0) || (end - c > 10 && memcmp(&packet->payload[c], "\r\nX-Queue:", 10) == 0)
                        || (end - c > 13 && memcmp(&packet->payload[c], "\r\nX-Features:", 13) == 0)) {

                    MMT_LOG_GNUTELLA(PROTO_GNUTELLA,
                            MMT_LOG_TRACE, "FOXY :: GNUTELLA GET 2 DETECTED\n");
                    mmt_int_gnutella_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }

                c++;
            }
        }
        /* haven't found any trace with this pattern */
        if (packet->payload_packet_len > 1 && packet->payload[packet->payload_packet_len - 1] == 0x0a
                && packet->payload[packet->payload_packet_len - 2] == 0x0a) {
            if (packet->payload_packet_len > 3 && memcmp(packet->payload, "GIV", 3) == 0) {
                MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_TRACE, "MORPHEUS GIV DETECTED\n");
                /* Not Excludeing the flow now.. We shall Check the next Packet too for Gnutella Patterns */
                return;
            }
        }
        /* might be super tricky new ssl gnutella transmission, but the certificate is strange... */
        if (packet->payload_packet_len == 46 && get_u32(packet->payload, 0) == htonl(0x802c0103) &&
                get_u32(packet->payload, 4) == htonl(0x01000300) && get_u32(packet->payload, 8) == htonl(0x00002000) &&
                get_u16(packet->payload, 12) == htons(0x0034)) {
            MMT_LOG(PROTO_GNUTELLA, MMT_LOG_TRACE, "detected gnutella len == 46.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 49 &&
                memcmp(packet->payload, "\x80\x2f\x01\x03\x01\x00\x06\x00\x00\x00\x20\x00\x00\x34\x00\x00\xff\x4d\x6c",
                19) == 0) {
            MMT_LOG(PROTO_GNUTELLA, MMT_LOG_TRACE, "detected gnutella len == 49.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 89 && memcmp(&packet->payload[43], "\x20\x4d\x6c", 3) == 0 &&
                memcmp(packet->payload, "\x16\x03\x01\x00\x54\x01\x00\x00\x50\x03\x01\x4d\x6c", 13) == 0 &&
                memcmp(&packet->payload[76], "\x00\x02\x00\x34\x01\x00\x00\x05", 8) == 0) {
            MMT_LOG(PROTO_GNUTELLA, MMT_LOG_TRACE,
                    "detected gnutella asymmetrically len == 388.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        } else if (packet->payload_packet_len == 82) {
            if (get_u32(packet->payload, 0) == htonl(0x16030100)
                    && get_u32(packet->payload, 4) == htonl(0x4d010000)
                    && get_u16(packet->payload, 8) == htons(0x4903)
                    && get_u16(packet->payload, 76) == htons(0x0002)
                    && get_u32(packet->payload, 78) == htonl(0x00340100)) {
                MMT_LOG(PROTO_GNUTELLA, MMT_LOG_TRACE, "detected len == 82.\n");
                mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
    } else if (packet->udp != NULL) {
        if (src != NULL && (packet->udp->source == src->detected_gnutella_udp_port1 ||
                packet->udp->source == src->detected_gnutella_udp_port2) &&
                (packet->tick_timestamp - src->gnutella_ts) < gnutella_timeout) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_DEBUG, "port based detection\n\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
        }
        /* observations:
         * all the following patterns send out many packets which are the only ones of their flows,
         * often on the very beginning of the traces, or flows with many packets in one direction only.
         * but then suddenly, one gets an answer as you can see in netpeker-gnutella-rpc.pcap packet 11483.
         * Maybe gnutella tries to send out keys?
         */
        if (packet->payload_packet_len == 23 && packet->payload[15] == 0x00
                && packet->payload[16] == 0x41 && packet->payload[17] == 0x01
                && packet->payload[18] == 0x00 && packet->payload[19] == 0x00
                && packet->payload[20] == 0x00 && packet->payload[21] == 0x00 && packet->payload[22] == 0x00) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_DEBUG,
                    "detected gnutella udp, len = 23.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);

            return;
        }
        if (packet->payload_packet_len == 35 && packet->payload[25] == 0x49
                && packet->payload[26] == 0x50 && packet->payload[27] == 0x40
                && packet->payload[28] == 0x83 && packet->payload[29] == 0x53
                && packet->payload[30] == 0x43 && packet->payload[31] == 0x50 && packet->payload[32] == 0x41) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_DEBUG,
                    "detected gnutella udp, len = 35.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 32
                && (memcmp(&packet->payload[16], "\x31\x01\x00\x09\x00\x00\x00\x4c\x49\x4d\x45", 11) == 0)) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_DEBUG,
                    "detected gnutella udp, len = 32.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 34 && (memcmp(&packet->payload[25], "SCP@", 4) == 0)
                && (memcmp(&packet->payload[30], "DNA@", 4) == 0)) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_DEBUG,
                    "detected gnutella udp, len = 34.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if ((packet->payload_packet_len == 73 || packet->payload_packet_len == 96)
                && memcmp(&packet->payload[32], "urn:sha1:", 9) == 0) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_DEBUG,
                    "detected gnutella udp, len = 73,96.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        if (memcmp(packet->payload, "GND", 3) == 0) {
            if ((packet->payload_packet_len == 8 && (memcmp(&packet->payload[6], "\x01\x00", 2) == 0))
                    || (packet->payload_packet_len == 11 && (memcmp(&packet->payload[6], "\x01\x01\x08\x50\x49", 5)
                    == 0)) || (packet->payload_packet_len == 17
                    &&
                    (memcmp
                    (&packet->payload[6], "\x01\x01\x4c\x05\x50",
                    5) == 0))
                    || (packet->payload_packet_len == 28
                    && (memcmp(&packet->payload[6], "\x01\x01\x54\x0f\x51\x4b\x52\x50\x06\x52", 10) == 0))
                    || (packet->payload_packet_len == 41
                    && (memcmp(&packet->payload[6], "\x01\x01\x5c\x1b\x50\x55\x53\x48\x48\x10", 10) == 0))
                    || (packet->payload_packet_len > 200 && packet->payload_packet_len < 300 && packet->payload[3] == 0x03)
                    || (packet->payload_packet_len > 300 && (packet->payload[3] == 0x01 || packet->payload[3] == 0x03))) {
                MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_DEBUG,
                        "detected gnutella udp, GND.\n");
                mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }

        if ((packet->payload_packet_len == 32)
                && memcmp(&packet->payload[16], "\x31\x01\x00\x09\x00\x00\x00", 7) == 0) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_DEBUG,
                    "detected gnutella udp, len = 32 ii.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if ((packet->payload_packet_len == 23)
                && memcmp(&packet->payload[16], "\x00\x01\x00\x00\x00\x00\x00", 7) == 0) {
            MMT_LOG_GNUTELLA(PROTO_GNUTELLA, MMT_LOG_DEBUG,
                    "detected gnutella udp, len = 23 ii.\n");
            mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
    }
    //neonet detection follows

    /* haven't found any trace with this pattern */
    if (packet->tcp != NULL && ntohs(packet->tcp->source) >= 1024 && ntohs(packet->tcp->dest) >= 1024) {
        if (flow->l4.tcp.gnutella_stage == 0) {
            if (ipacket->session->data_packet_count == 1
                    && (packet->payload_packet_len == 11
                    || packet->payload_packet_len == 33 || packet->payload_packet_len == 37)) {
                flow->l4.tcp.gnutella_msg_id[0] = packet->payload[4];
                flow->l4.tcp.gnutella_msg_id[1] = packet->payload[6];
                flow->l4.tcp.gnutella_msg_id[2] = packet->payload[8];
                flow->l4.tcp.gnutella_stage = 1 + ipacket->session->last_packet_direction;
                return;
            }
        } else if (flow->l4.tcp.gnutella_stage == 1 + ipacket->session->last_packet_direction) {
            if (ipacket->session->data_packet_count == 2 && (packet->payload_packet_len == 33 || packet->payload_packet_len == 22)
                    && flow->l4.tcp.gnutella_msg_id[0] == packet->payload[0]
                    && flow->l4.tcp.gnutella_msg_id[1] == packet->payload[2]
                    && flow->l4.tcp.gnutella_msg_id[2] == packet->payload[4]
                    && MMT_SRC_OR_DST_HAS_PROTOCOL(src, dst, PROTO_GNUTELLA)) {
                MMT_LOG_GNUTELLA(PROTO_GNUTELLA, 
                        MMT_LOG_TRACE, "GNUTELLA DETECTED due to message ID match (NEONet protocol)\n");
                mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        } else if (flow->l4.tcp.gnutella_stage == 2 - ipacket->session->last_packet_direction) {
            if (ipacket->session->data_packet_count == 2 && (packet->payload_packet_len == 10 || packet->payload_packet_len == 75)
                    && flow->l4.tcp.gnutella_msg_id[0] == packet->payload[0]
                    && flow->l4.tcp.gnutella_msg_id[1] == packet->payload[2]
                    && flow->l4.tcp.gnutella_msg_id[2] == packet->payload[4]
                    && MMT_SRC_OR_DST_HAS_PROTOCOL(src, dst, PROTO_GNUTELLA)) {
                MMT_LOG_GNUTELLA(PROTO_GNUTELLA, 
                        MMT_LOG_TRACE, "GNUTELLA DETECTED due to message ID match (NEONet protocol)\n");
                mmt_int_gnutella_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_GNUTELLA);
}


int mmt_check_gnutella(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
        mmt_classify_me_gnutella(ipacket, index); //BW: TODO: this can be improved by splitting the classification into TCP and UDP
    }
    return 4;
}

void mmt_init_classify_me_gnutella() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_XBOX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WINUPDATE);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_GNUTELLA);
}


/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_gnutella_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_GNUTELLA, PROTO_GNUTELLA_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_gnutella();
        
        return register_protocol(protocol_struct, PROTO_GNUTELLA);
    } else {
        return 0;
    }
}


