#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_PPLIVE_TIMEOUT                  120

static uint32_t pplive_connection_timeout = MMT_PPLIVE_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_pplive_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_PPLIVE, protocol_type);
}

void mmt_classify_me_pplive(ipacket_t * ipacket, unsigned index)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;


    uint16_t a;

    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "search pplive.\n");


    if (packet->udp != NULL) {

        if (src != NULL && src->pplive_vod_cli_port == packet->udp->source
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_PPLIVE)) {
            if (src->pplive_last_packet_time_set == 1 && (MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->pplive_last_packet_time) < pplive_connection_timeout) {
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                src->pplive_last_packet_time_set = 1;
                src->pplive_last_packet_time = packet->tick_timestamp;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "timestamp src.\n");
                return;
            } else {
                src->pplive_vod_cli_port = 0;
                src->pplive_last_packet_time = 0;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
            }
        }

        if (dst != NULL && dst->pplive_vod_cli_port == packet->udp->dest
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_PPLIVE)) {
            if (dst->pplive_last_packet_time_set == 1 && (MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->pplive_last_packet_time) < pplive_connection_timeout) {
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                dst->pplive_last_packet_time_set = 1;
                dst->pplive_last_packet_time = packet->tick_timestamp;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "timestamp dst.\n");
                return;
            } else {
                dst->pplive_last_packet_time_set = 0;
                dst->pplive_vod_cli_port = 0;
                dst->pplive_last_packet_time = 0;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
            }
        }

        if ((packet->payload_packet_len >= 76) && ((packet->payload[0] == 0x01) || (packet->payload[0] == 0x18)
                || (packet->payload[0] == 0x05))
                && (packet->payload[1] == 0x00)
                && get_l32(packet->payload, 12) == 0 && (packet->payload[16] == 0 || packet->payload[16] == 1)
                && (packet->payload[17] == 0) && (packet->payload[24] == 0xac)) {
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        if (packet->payload_packet_len > 50 && packet->payload[0] == 0xe9
                && packet->payload[1] == 0x03 && (packet->payload[3] == 0x00 || packet->payload[3] == 0x01)
                && packet->payload[4] == 0x98 && packet->payload[5] == 0xab
                && packet->payload[6] == 0x01 && packet->payload[7] == 0x02) {
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        if (packet->payload_packet_len == 94 && packet->payload[8] == 0x00
                && ((get_u32(packet->payload, 9) == ntohl(0x03010000))
                || (get_u32(packet->payload, 9) == ntohl(0x02010000))
                || (get_u32(packet->payload, 9) == ntohl(0x01010000)))
                && ((get_u32(packet->payload, 58) == ntohl(0xb1130000))
                || ((packet->payload[60] == packet->payload[61])
                && (packet->payload[78] == 0x00 || packet->payload[78] == 0x01)
                && (packet->payload[79] == 0x00 || packet->payload[79] == 0x01))
                || ((get_u16(packet->payload, 58) == ntohs(0xb113))
                && (packet->payload[78] == 0x00 || packet->payload[78] == 0x01)
                && (packet->payload[79] == 0x00 || packet->payload[79] == 0x01)))) {
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        if ((packet->payload_packet_len >= 90 && packet->payload_packet_len <= 110)
                && (packet->payload[0] >= 0x0a && packet->payload[0] <= 0x0f)
                && get_u16(packet->payload, 86) == 0) {
            int i;
            for (i = 54; i < 68; i += 2) {
                if (((get_u32(packet->payload, i) == ntohl(0x4fde7e7f))
                        || (get_u32(packet->payload, i) == ntohl(0x7aa6090d)))
                        && (get_u16(packet->payload, i + 4) == 0)) {
                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive through "
                            "bitpatterns either 4f de 7e 7f 00 00 or 7a a6 09 0d 00 00.\n");
                    mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                    return;
                }
            }
        }
        if (ipacket->session->data_packet_count < 5 && !flow->pplive_stage) { /* With in 1st 4 packets */
            if (((packet->payload_packet_len >= 90 && packet->payload_packet_len <= 110)
                    && (!get_u32(packet->payload, packet->payload_packet_len - 16)
                    || !get_u32(packet->payload, packet->payload_packet_len - 4)))
                    ) {
                flow->pplive_stage = 2; /* Now start looking for size(28 | 30) */
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                        "Maybe found pplive packet. Now start looking for size(28 | 30).\n");
            }
            if (68 == packet->payload_packet_len
                    && get_l16(packet->payload, 0) == 0x21 && packet->payload[19] == packet->payload[20]
                    && packet->payload[20] == packet->payload[21]
                    && packet->payload[12] == packet->payload[13]
                    && packet->payload[14] == packet->payload[15]) {
                flow->pplive_stage = 3 + ipacket->session->last_packet_direction;
            }

            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet I.\n");
            return;
        }
        if (flow->pplive_stage == 3 + ipacket->session->last_packet_direction) {
            /* Because we are expecting packet in reverese direction.. */
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet II.\n");
            return;
        }
        if (flow->pplive_stage == (4 - ipacket->session->last_packet_direction)
                && packet->payload_packet_len > 67
                && (get_l16(packet->payload, 0) == 0x21
                || (get_l16(packet->payload, 0) == 0x22 && !get_l16(packet->payload, 28)))) {
            if (dst != NULL) {
                dst->pplive_vod_cli_port = packet->udp->dest;
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: VOD Port marked %u.\n", ntohs(packet->udp->dest));
                dst->pplive_last_packet_time = packet->tick_timestamp;
                dst->pplive_last_packet_time_set = 1;
            }
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        if (flow->pplive_stage == 2) {
            if ((packet->payload_packet_len == 30 && (packet->payload[0] == 0x02 || packet->payload[0] == 0x03)
                    && get_u32(packet->payload, 21) == ntohl(0x00000001))
                    || (packet->payload_packet_len == 28 && (packet->payload[0] == 0x01 || packet->payload[0] == 0x00)
                    && (get_u32(packet->payload, 19) == ntohl(0x00000001)))) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            if (ipacket->session->data_packet_count < 45) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet III.\n");
                return;
            }
        }
    } else if (packet->tcp != NULL) {

        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                "PPLIVE: TCP found, plen = %d, stage = %d, payload[0] = %x, payload[1] = %x, payload[2] = %x, payload[3] = %x \n",
                packet->payload_packet_len, flow->pplive_stage, packet->payload[0], packet->payload[1],
                packet->payload[2], packet->payload[3]);

        if (src != NULL && src->pplive_vod_cli_port == packet->tcp->source
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_PPLIVE)) {
            if (src->pplive_last_packet_time_set == 1 && (MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->pplive_last_packet_time) < pplive_connection_timeout) {
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                src->pplive_last_packet_time_set = 1;
                src->pplive_last_packet_time = packet->tick_timestamp;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "timestamp src.\n");
                return;
            } else {
                src->pplive_vod_cli_port = 0;
                src->pplive_last_packet_time = 0;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
            }
        }

        if (dst != NULL && dst->pplive_vod_cli_port == packet->tcp->dest
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_PPLIVE)) {
            if (dst->pplive_last_packet_time_set == 1 && (MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->pplive_last_packet_time) < pplive_connection_timeout) {
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                dst->pplive_last_packet_time_set = 1;
                dst->pplive_last_packet_time = packet->tick_timestamp;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "timestamp dst.\n");
                return;
            } else {
                dst->pplive_last_packet_time_set = 0;
                dst->pplive_vod_cli_port = 0;
                dst->pplive_last_packet_time = 0;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
            }
        }

        if (packet->payload_packet_len > 4 && mmt_memcmp(packet->payload, "GET /", 5) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if ((packet->parsed_lines == 8 || packet->parsed_lines == 9)
                    && packet->line[0].ptr != NULL && packet->line[0].len >= 8
                    && mmt_memcmp(&packet->payload[packet->line[0].len - 8], "HTTP/1.", 7) == 0
                    && packet->line[2].ptr != NULL && packet->line[2].len >= 16
                    && mmt_memcmp(packet->line[2].ptr, "x-flash-version:", 16) == 0
                    && packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= 11
                    && mmt_memcmp(packet->user_agent_line.ptr, "Mozilla/4.0", 11) == 0
                    && packet->line[6].ptr != NULL && packet->line[6].len >= 21
                    && mmt_memcmp(packet->line[6].ptr, "Pragma: Client=PPLive", 21) == 0) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found HTTP request.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            } else if ((packet->parsed_lines >= 6 && packet->parsed_lines <= 8)
                    && packet->line[0].ptr != NULL && packet->line[0].len >= 8
                    && mmt_memcmp(&packet->payload[packet->line[0].len - 8], "HTTP/1.", 7) == 0
                    && (((packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= 10)
                    && (mmt_memcmp(packet->user_agent_line.ptr, "PPLive DAC", 10) == 0))
                    || ((packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= 19)
                    && (mmt_memcmp(packet->user_agent_line.ptr, "PPLive-Media-Player", 19) == 0)))) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found HTTP request.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            } else if (packet->host_line.ptr != NULL && packet->host_line.len >= 13
                    && mmt_memcmp(packet->host_line.ptr, "player.pplive", 13) == 0) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found via Host header.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            } else if (packet->referer_line.ptr != NULL
                    && packet->referer_line.len >= 20
                    && mmt_memcmp(packet->referer_line.ptr, "http://player.pplive",
                    20) == 0) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found via Referer header.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            } else if (packet->parsed_lines >= 8 &&
                    packet->line[0].ptr != NULL && packet->line[0].len >= 8 &&
                    mmt_memcmp(&packet->payload[packet->line[0].len - 8], "HTTP/1.", 7) == 0) {

                uint8_t i, flag = 0;

                for (i = 0; i < packet->parsed_lines && i < 10 && flag < 2; i++) {
                    if (packet->line[i].ptr != NULL && packet->line[i].len >= 16
                            && mmt_memcmp(packet->line[i].ptr, "x-flash-version:",
                            16) == 0) {
                        flag++;
                    } else if (packet->line[i].ptr != NULL
                            && packet->line[i].len >= 21
                            && mmt_memcmp(packet->line[i].ptr, "Pragma: Client=PPLive",
                            21) == 0) {
                        flag++;
                    }
                }
                if (flag == 2) {
                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found HTTP request.\n");
                    mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
        }
        // searches for packets > 20 byte that begin with a hex number == packet->payload_packet_len - 4
        // and with the same number at position 16, 17, 18, 19
        if (packet->payload_packet_len > 20 && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len - 4) {
            if (packet->payload[4] == 0x21 && packet->payload[5] == 0x00) {
                if ((packet->payload[9] == packet->payload[10]) && (packet->payload[9] == packet->payload[11])) {
                    if ((packet->payload[16] == packet->payload[17]) &&
                            (packet->payload[16] == packet->payload[18]) && (packet->payload[16] == packet->payload[19])) {
                        MMT_LOG(PROTO_PPLIVE, 
                                MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                        mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return;
                    }
                }
            }
        }
        // stage > 0, packet begins with 21 00, bytes at positions 5, 6, 7 are equal, bytes at positions 12, 13, 14, 15 are equal,
        if (packet->payload_packet_len > 20 && flow->pplive_stage) {
            if (packet->payload[0] == 0x21 && packet->payload[1] == 0x00) {
                if (packet->payload[5] == packet->payload[6] && packet->payload[5] == packet->payload[7]) {
                    if (packet->payload[12] == packet->payload[13] && packet->payload[14] == packet->payload[15]
                            && packet->payload[12] == packet->payload[14]) {
                        MMT_LOG(PROTO_PPLIVE, 
                                MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                        mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return;
                    }
                }
            }
        }
        // packet (len>11) begins with a hex number == packet->payload_packet_len - 4 and matches certain bitmuster
        if (packet->payload_packet_len > 11 && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len - 4) {
            if (packet->payload[4] == 0xe9 && packet->payload[5] == 0x03 &&
                    ((packet->payload[7] == packet->payload[10]) || (packet->payload[7] == packet->payload[11]))) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
        // stage > 0, len>10, begins with e9 03, matches certain pattern
        if (packet->payload_packet_len > 10 && flow->pplive_stage) {
            if (packet->payload[0] == 0xe9 && packet->payload[1] == 0x03 &&
                    ((packet->payload[3] == packet->payload[6]) || (packet->payload[3] == packet->payload[7]))) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }

        /* Adware in the PPLive Client -> first TCP Packet has length of 4 Bytes -> 2nd TCP Packet has length of 96 Bytes */
        /* or */
        /* Peer-List Requests over TCP -> first Packet has length of 4 Bytes -> 2nd TCP Packet has length of 71 Bytes */
        /* there are different possibilities of the order of the packets */

        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                "PPLIVE: TCP found, plen = %d, stage = %d, payload[0] = %x, payload[1] = %x, payload[2] = %x, payload[3] = %x \n",
                packet->payload_packet_len, flow->pplive_stage,
                packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3]);

        /* generic pplive detection (independent of the stage) !!! */
        // len > 11, packet begins with a hex number == packet->payload_packet_len - 4, pattern: ?? ?? ?? ?? 21 00 ?? ?? 98 ab 01 02
        if (packet->payload_packet_len > 11 && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len - 4) {
            if (packet->payload[4] == 0x21 && packet->payload[5] == 0x00
                    && ((packet->payload[8] == 0x98 && packet->payload[9] == 0xab
                    && packet->payload[10] == 0x01 && packet->payload[11] == 0x02)
                    )) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            // packet 4 to 19 have a hex representation from 0x30 to 0x39
            if (packet->payload_packet_len > 20) {
                a = 4;
                while (a < 20) {
                    if (packet->payload[a] >= '0' && packet->payload[a] <= '9') {
                        if (a == 19) {
                            MMT_LOG(PROTO_PPLIVE, 
                                    MMT_LOG_DEBUG, "PPLIVE: direct new header format found\n");
                            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                            return;
                        } else {
                            a++;
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        /* 1st and 2nd (KD: ??????? )Packet of Client is 4 Byte  */
        // stage == 0, p_len == 4, pattern: 04 00 00 00 --> need next packet
        if (flow->pplive_stage == 0) {
            if (packet->payload_packet_len == 4 && packet->payload[0] > 0x04
                    && packet->payload[1] == 0x00 && packet->payload[2] == 0x00 && packet->payload[3] == 0x00) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: 4Byte TCP Packet Request found \n");

                /* go to the 2nd Client Packet */
                flow->pplive_stage = 1 + ipacket->session->last_packet_direction;
                flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction] = packet->payload[0];
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet i.\n");
                return;
            }
        } else if (flow->pplive_stage == 2 - ipacket->session->last_packet_direction) {
            if (packet->payload_packet_len == 4 && packet->payload[0] > 0x04
                    && packet->payload[1] == 0x00 && packet->payload[2] == 0x00 && packet->payload[3] == 0x00) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: 4Byte TCP Packet Response found \n");

                /* go to the 2nd Client Packet */
                flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction] = packet->payload[0];
            }
            flow->pplive_stage = 3;
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet ii.\n");
            return;
        } else if (flow->pplive_stage == 1 + ipacket->session->last_packet_direction || flow->pplive_stage == 3) {
            if (packet->payload_packet_len > 7 && flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction] >= 4) {
                if (packet->payload_packet_len == flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction]) {

                    if (packet->payload[0] == 0xe9 && packet->payload[1] == 0x03
                            && ((packet->payload[4] == 0x98
                            && packet->payload[5] == 0xab && packet->payload[6] == 0x01 && packet->payload[7] == 0x02)
                            )) {
                        MMT_LOG(PROTO_PPLIVE, 
                                MMT_LOG_DEBUG, "PPLIVE: two packet response found\n");

                        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                "found pplive over tcp with pattern iii.\n");
                        mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return;
                    }
                    // packet 4 to 19 have a hex representation from 0x30 to 0x39
                    if (packet->payload_packet_len > 16) {
                        a = 0;
                        while (a < 16) {
                            if (packet->payload[a] >= '0' && packet->payload[a] <= '9') {
                                if (a == 15) {
                                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                            "PPLIVE: new header format found\n");
                                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                            "found pplive over tcp with pattern v.\n");
                                    mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                                    return;
                                } else {
                                    a++;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    // p_len>79 and a lot of 00 in the end
                    if (packet->payload_packet_len > 79
                            && get_u32(packet->payload, packet->payload_packet_len - 9) == 0x00000000
                            && get_u32(packet->payload, packet->payload_packet_len - 5) == 0x00000000) {
                        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                "PPLIVE: Last 8 NULL bytes found.\n");
                        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                "found pplive over tcp with pattern vi.\n");
                        mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return;
                    }
                }
                if (packet->payload_packet_len > flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction]) {
                    if (packet->payload[0] == 0xe9 && packet->payload[1] == 0x03
                            && packet->payload[4] == 0x98 && packet->payload[5] == 0xab
                            && packet->payload[6] == 0x01 && packet->payload[7] == 0x02) {
                        a = flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction];
                        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "a=%u.\n", a);
                        if (packet->payload_packet_len > a + 4
                                && packet->payload[a + 2] == 0x00 && packet->payload[a + 3] == 0x00
                                && packet->payload[a] != 0) {
                            a += ((packet->payload[a + 1] << 8) + packet->payload[a] + 4);
                            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "a=%u.\n", a);
                            if (packet->payload_packet_len == a) {
                                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                        "found pplive over tcp with pattern vii.\n");
                                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                                return;
                            }
                            if (packet->payload_packet_len > a + 4
                                    && packet->payload[a + 2] == 0x00 && packet->payload[a + 3] == 0x00
                                    && packet->payload[a] != 0) {
                                a += ((packet->payload[a + 1] << 8) + packet->payload[a] + 4);
                                if (packet->payload_packet_len == a) {
                                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                            "found pplive over tcp with pattern viii.\n");
                                    mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                                    return;
                                }
                            }

                        }
                    }
                }
            }
        }
    }


    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "exclude pplive.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_PPLIVE);
}

int mmt_check_pplive_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        

        struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;


        uint16_t a;

        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "search pplive.\n");

        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                "PPLIVE: TCP found, plen = %d, stage = %d, payload[0] = %x, payload[1] = %x, payload[2] = %x, payload[3] = %x \n",
                packet->payload_packet_len, flow->pplive_stage, packet->payload[0], packet->payload[1],
                packet->payload[2], packet->payload[3]);

        if (src != NULL && src->pplive_vod_cli_port == packet->tcp->source
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_PPLIVE)) {
            if (src->pplive_last_packet_time_set == 1 && (MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->pplive_last_packet_time) < pplive_connection_timeout) {
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                src->pplive_last_packet_time_set = 1;
                src->pplive_last_packet_time = packet->tick_timestamp;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "timestamp src.\n");
                return 1;
            } else {
                src->pplive_vod_cli_port = 0;
                src->pplive_last_packet_time = 0;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
            }
        }

        if (dst != NULL && dst->pplive_vod_cli_port == packet->tcp->dest
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_PPLIVE)) {
            if (dst->pplive_last_packet_time_set == 1 && (MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->pplive_last_packet_time) < pplive_connection_timeout) {
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                dst->pplive_last_packet_time_set = 1;
                dst->pplive_last_packet_time = packet->tick_timestamp;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "timestamp dst.\n");
                return 1;
            } else {
                dst->pplive_last_packet_time_set = 0;
                dst->pplive_vod_cli_port = 0;
                dst->pplive_last_packet_time = 0;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
            }
        }

        if (packet->payload_packet_len > 4 && mmt_memcmp(packet->payload, "GET /", 5) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if ((packet->parsed_lines == 8 || packet->parsed_lines == 9)
                    && packet->line[0].ptr != NULL && packet->line[0].len >= 8
                    && mmt_memcmp(&packet->payload[packet->line[0].len - 8], "HTTP/1.", 7) == 0
                    && packet->line[2].ptr != NULL && packet->line[2].len >= 16
                    && mmt_memcmp(packet->line[2].ptr, "x-flash-version:", 16) == 0
                    && packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= 11
                    && mmt_memcmp(packet->user_agent_line.ptr, "Mozilla/4.0", 11) == 0
                    && packet->line[6].ptr != NULL && packet->line[6].len >= 21
                    && mmt_memcmp(packet->line[6].ptr, "Pragma: Client=PPLive", 21) == 0) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found HTTP request.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            } else if ((packet->parsed_lines >= 6 && packet->parsed_lines <= 8)
                    && packet->line[0].ptr != NULL && packet->line[0].len >= 8
                    && mmt_memcmp(&packet->payload[packet->line[0].len - 8], "HTTP/1.", 7) == 0
                    && (((packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= 10)
                    && (mmt_memcmp(packet->user_agent_line.ptr, "PPLive DAC", 10) == 0))
                    || ((packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= 19)
                    && (mmt_memcmp(packet->user_agent_line.ptr, "PPLive-Media-Player", 19) == 0)))) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found HTTP request.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            } else if (packet->host_line.ptr != NULL && packet->host_line.len >= 13
                    && mmt_memcmp(packet->host_line.ptr, "player.pplive", 13) == 0) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found via Host header.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            } else if (packet->referer_line.ptr != NULL
                    && packet->referer_line.len >= 20
                    && mmt_memcmp(packet->referer_line.ptr, "http://player.pplive",
                    20) == 0) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found via Referer header.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            } else if (packet->parsed_lines >= 8 &&
                    packet->line[0].ptr != NULL && packet->line[0].len >= 8 &&
                    mmt_memcmp(&packet->payload[packet->line[0].len - 8], "HTTP/1.", 7) == 0) {

                uint8_t i, flag = 0;

                for (i = 0; i < packet->parsed_lines && i < 10 && flag < 2; i++) {
                    if (packet->line[i].ptr != NULL && packet->line[i].len >= 16
                            && mmt_memcmp(packet->line[i].ptr, "x-flash-version:",
                            16) == 0) {
                        flag++;
                    } else if (packet->line[i].ptr != NULL
                            && packet->line[i].len >= 21
                            && mmt_memcmp(packet->line[i].ptr, "Pragma: Client=PPLive",
                            21) == 0) {
                        flag++;
                    }
                }
                if (flag == 2) {
                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: found HTTP request.\n");
                    mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return 1;
                }
            }
        }
        // searches for packets > 20 byte that begin with a hex number == packet->payload_packet_len - 4
        // and with the same number at position 16, 17, 18, 19
        if (packet->payload_packet_len > 20 && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len - 4) {
            if (packet->payload[4] == 0x21 && packet->payload[5] == 0x00) {
                if ((packet->payload[9] == packet->payload[10]) && (packet->payload[9] == packet->payload[11])) {
                    if ((packet->payload[16] == packet->payload[17]) &&
                            (packet->payload[16] == packet->payload[18]) && (packet->payload[16] == packet->payload[19])) {
                        MMT_LOG(PROTO_PPLIVE, 
                                MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                        mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return 1;
                    }
                }
            }
        }
        // stage > 0, packet begins with 21 00, bytes at positions 5, 6, 7 are equal, bytes at positions 12, 13, 14, 15 are equal,
        if (packet->payload_packet_len > 20 && flow->pplive_stage) {
            if (packet->payload[0] == 0x21 && packet->payload[1] == 0x00) {
                if (packet->payload[5] == packet->payload[6] && packet->payload[5] == packet->payload[7]) {
                    if (packet->payload[12] == packet->payload[13] && packet->payload[14] == packet->payload[15]
                            && packet->payload[12] == packet->payload[14]) {
                        MMT_LOG(PROTO_PPLIVE, 
                                MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                        mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return 1;
                    }
                }
            }
        }
        // packet (len>11) begins with a hex number == packet->payload_packet_len - 4 and matches certain bitmuster
        if (packet->payload_packet_len > 11 && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len - 4) {
            if (packet->payload[4] == 0xe9 && packet->payload[5] == 0x03 &&
                    ((packet->payload[7] == packet->payload[10]) || (packet->payload[7] == packet->payload[11]))) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
        }
        // stage > 0, len>10, begins with e9 03, matches certain pattern
        if (packet->payload_packet_len > 10 && flow->pplive_stage) {
            if (packet->payload[0] == 0xe9 && packet->payload[1] == 0x03 &&
                    ((packet->payload[3] == packet->payload[6]) || (packet->payload[3] == packet->payload[7]))) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
        }

        /* Adware in the PPLive Client -> first TCP Packet has length of 4 Bytes -> 2nd TCP Packet has length of 96 Bytes */
        /* or */
        /* Peer-List Requests over TCP -> first Packet has length of 4 Bytes -> 2nd TCP Packet has length of 71 Bytes */
        /* there are different possibilities of the order of the packets */

        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                "PPLIVE: TCP found, plen = %d, stage = %d, payload[0] = %x, payload[1] = %x, payload[2] = %x, payload[3] = %x \n",
                packet->payload_packet_len, flow->pplive_stage,
                packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3]);

        /* generic pplive detection (independent of the stage) !!! */
        // len > 11, packet begins with a hex number == packet->payload_packet_len - 4, pattern: ?? ?? ?? ?? 21 00 ?? ?? 98 ab 01 02
        if (packet->payload_packet_len > 11 && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len - 4) {
            if (packet->payload[4] == 0x21 && packet->payload[5] == 0x00
                    && ((packet->payload[8] == 0x98 && packet->payload[9] == 0xab
                    && packet->payload[10] == 0x01 && packet->payload[11] == 0x02)
                    )) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
            // packet 4 to 19 have a hex representation from 0x30 to 0x39
            if (packet->payload_packet_len > 20) {
                a = 4;
                while (a < 20) {
                    if (packet->payload[a] >= '0' && packet->payload[a] <= '9') {
                        if (a == 19) {
                            MMT_LOG(PROTO_PPLIVE, 
                                    MMT_LOG_DEBUG, "PPLIVE: direct new header format found\n");
                            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                            return 1;
                        } else {
                            a++;
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        /* 1st and 2nd (KD: ??????? )Packet of Client is 4 Byte  */
        // stage == 0, p_len == 4, pattern: 04 00 00 00 --> need next packet
        if (flow->pplive_stage == 0) {
            if (packet->payload_packet_len == 4 && packet->payload[0] > 0x04
                    && packet->payload[1] == 0x00 && packet->payload[2] == 0x00 && packet->payload[3] == 0x00) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: 4Byte TCP Packet Request found \n");

                /* go to the 2nd Client Packet */
                flow->pplive_stage = 1 + ipacket->session->last_packet_direction;
                flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction] = packet->payload[0];
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet i.\n");
                return 4;
            }
        } else if (flow->pplive_stage == 2 - ipacket->session->last_packet_direction) {
            if (packet->payload_packet_len == 4 && packet->payload[0] > 0x04
                    && packet->payload[1] == 0x00 && packet->payload[2] == 0x00 && packet->payload[3] == 0x00) {
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: 4Byte TCP Packet Response found \n");

                /* go to the 2nd Client Packet */
                flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction] = packet->payload[0];
            }
            flow->pplive_stage = 3;
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet ii.\n");
            return 4;
        } else if (flow->pplive_stage == 1 + ipacket->session->last_packet_direction || flow->pplive_stage == 3) {
            if (packet->payload_packet_len > 7 && flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction] >= 4) {
                if (packet->payload_packet_len == flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction]) {

                    if (packet->payload[0] == 0xe9 && packet->payload[1] == 0x03
                            && ((packet->payload[4] == 0x98
                            && packet->payload[5] == 0xab && packet->payload[6] == 0x01 && packet->payload[7] == 0x02)
                            )) {
                        MMT_LOG(PROTO_PPLIVE, 
                                MMT_LOG_DEBUG, "PPLIVE: two packet response found\n");

                        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                "found pplive over tcp with pattern iii.\n");
                        mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return 1;
                    }
                    // packet 4 to 19 have a hex representation from 0x30 to 0x39
                    if (packet->payload_packet_len > 16) {
                        a = 0;
                        while (a < 16) {
                            if (packet->payload[a] >= '0' && packet->payload[a] <= '9') {
                                if (a == 15) {
                                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                            "PPLIVE: new header format found\n");
                                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                            "found pplive over tcp with pattern v.\n");
                                    mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                                    return 1;
                                } else {
                                    a++;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    // p_len>79 and a lot of 00 in the end
                    if (packet->payload_packet_len > 79
                            && get_u32(packet->payload, packet->payload_packet_len - 9) == 0x00000000
                            && get_u32(packet->payload, packet->payload_packet_len - 5) == 0x00000000) {
                        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                "PPLIVE: Last 8 NULL bytes found.\n");
                        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                "found pplive over tcp with pattern vi.\n");
                        mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return 1;
                    }
                }
                if (packet->payload_packet_len > flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction]) {
                    if (packet->payload[0] == 0xe9 && packet->payload[1] == 0x03
                            && packet->payload[4] == 0x98 && packet->payload[5] == 0xab
                            && packet->payload[6] == 0x01 && packet->payload[7] == 0x02) {
                        a = flow->l4.tcp.pplive_next_packet_size[ipacket->session->last_packet_direction];
                        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "a=%u.\n", a);
                        if (packet->payload_packet_len > a + 4
                                && packet->payload[a + 2] == 0x00 && packet->payload[a + 3] == 0x00
                                && packet->payload[a] != 0) {
                            a += ((packet->payload[a + 1] << 8) + packet->payload[a] + 4);
                            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "a=%u.\n", a);
                            if (packet->payload_packet_len == a) {
                                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                        "found pplive over tcp with pattern vii.\n");
                                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                                return 1;
                            }
                            if (packet->payload_packet_len > a + 4
                                    && packet->payload[a + 2] == 0x00 && packet->payload[a + 3] == 0x00
                                    && packet->payload[a] != 0) {
                                a += ((packet->payload[a + 1] << 8) + packet->payload[a] + 4);
                                if (packet->payload_packet_len == a) {
                                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                                            "found pplive over tcp with pattern viii.\n");
                                    mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                                    return 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "exclude pplive.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_PPLIVE);
    }
    return 0;
}

int mmt_check_pplive_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "search pplive.\n");

        if (src != NULL && src->pplive_vod_cli_port == packet->udp->source
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_PPLIVE)) {
            if (src->pplive_last_packet_time_set == 1 && (MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->pplive_last_packet_time) < pplive_connection_timeout) {
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                src->pplive_last_packet_time_set = 1;
                src->pplive_last_packet_time = packet->tick_timestamp;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "timestamp src.\n");
                return 1;
            } else {
                src->pplive_vod_cli_port = 0;
                src->pplive_last_packet_time = 0;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
            }
        }

        if (dst != NULL && dst->pplive_vod_cli_port == packet->udp->dest
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_PPLIVE)) {
            if (dst->pplive_last_packet_time_set == 1 && (MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->pplive_last_packet_time) < pplive_connection_timeout) {
                mmt_int_pplive_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                dst->pplive_last_packet_time_set = 1;
                dst->pplive_last_packet_time = packet->tick_timestamp;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "timestamp dst.\n");
                return 1;
            } else {
                dst->pplive_last_packet_time_set = 0;
                dst->pplive_vod_cli_port = 0;
                dst->pplive_last_packet_time = 0;
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
            }
        }

        if ((packet->payload_packet_len >= 76) && ((packet->payload[0] == 0x01) || (packet->payload[0] == 0x18)
                || (packet->payload[0] == 0x05))
                && (packet->payload[1] == 0x00)
                && get_l32(packet->payload, 12) == 0 && (packet->payload[16] == 0 || packet->payload[16] == 1)
                && (packet->payload[17] == 0) && (packet->payload[24] == 0xac)) {
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        if (packet->payload_packet_len > 50 && packet->payload[0] == 0xe9
                && packet->payload[1] == 0x03 && (packet->payload[3] == 0x00 || packet->payload[3] == 0x01)
                && packet->payload[4] == 0x98 && packet->payload[5] == 0xab
                && packet->payload[6] == 0x01 && packet->payload[7] == 0x02) {
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        if (packet->payload_packet_len == 94 && packet->payload[8] == 0x00
                && ((get_u32(packet->payload, 9) == ntohl(0x03010000))
                || (get_u32(packet->payload, 9) == ntohl(0x02010000))
                || (get_u32(packet->payload, 9) == ntohl(0x01010000)))
                && ((get_u32(packet->payload, 58) == ntohl(0xb1130000))
                || ((packet->payload[60] == packet->payload[61])
                && (packet->payload[78] == 0x00 || packet->payload[78] == 0x01)
                && (packet->payload[79] == 0x00 || packet->payload[79] == 0x01))
                || ((get_u16(packet->payload, 58) == ntohs(0xb113))
                && (packet->payload[78] == 0x00 || packet->payload[78] == 0x01)
                && (packet->payload[79] == 0x00 || packet->payload[79] == 0x01)))) {
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        if ((packet->payload_packet_len >= 90 && packet->payload_packet_len <= 110)
                && (packet->payload[0] >= 0x0a && packet->payload[0] <= 0x0f)
                && get_u16(packet->payload, 86) == 0) {
            int i;
            for (i = 54; i < 68; i += 2) {
                if (((get_u32(packet->payload, i) == ntohl(0x4fde7e7f))
                        || (get_u32(packet->payload, i) == ntohl(0x7aa6090d)))
                        && (get_u16(packet->payload, i + 4) == 0)) {
                    MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive through "
                            "bitpatterns either 4f de 7e 7f 00 00 or 7a a6 09 0d 00 00.\n");
                    mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                    return 1;
                }
            }
        }
        if (ipacket->session->data_packet_count < 5 && !flow->pplive_stage) { /* With in 1st 4 packets */
            if (((packet->payload_packet_len >= 90 && packet->payload_packet_len <= 110)
                    && (!get_u32(packet->payload, packet->payload_packet_len - 16)
                    || !get_u32(packet->payload, packet->payload_packet_len - 4)))
                    ) {
                flow->pplive_stage = 2; /* Now start looking for size(28 | 30) */
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG,
                        "Maybe found pplive packet. Now start looking for size(28 | 30).\n");
            }
            if (68 == packet->payload_packet_len
                    && get_l16(packet->payload, 0) == 0x21 && packet->payload[19] == packet->payload[20]
                    && packet->payload[20] == packet->payload[21]
                    && packet->payload[12] == packet->payload[13]
                    && packet->payload[14] == packet->payload[15]) {
                flow->pplive_stage = 3 + ipacket->session->last_packet_direction;
            }

            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet I.\n");
            return 4;
        }
        if (flow->pplive_stage == 3 + ipacket->session->last_packet_direction) {
            /* Because we are expecting packet in reverese direction.. */
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet II.\n");
            return 4;
        }
        if (flow->pplive_stage == (4 - ipacket->session->last_packet_direction)
                && packet->payload_packet_len > 67
                && (get_l16(packet->payload, 0) == 0x21
                || (get_l16(packet->payload, 0) == 0x22 && !get_l16(packet->payload, 28)))) {
            if (dst != NULL) {
                dst->pplive_vod_cli_port = packet->udp->dest;
                MMT_LOG(PROTO_PPLIVE, 
                        MMT_LOG_DEBUG, "PPLIVE: VOD Port marked %u.\n", ntohs(packet->udp->dest));
                dst->pplive_last_packet_time = packet->tick_timestamp;
                dst->pplive_last_packet_time_set = 1;
            }
            MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
            mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        if (flow->pplive_stage == 2) {
            if ((packet->payload_packet_len == 30 && (packet->payload[0] == 0x02 || packet->payload[0] == 0x03)
                    && get_u32(packet->payload, 21) == ntohl(0x00000001))
                    || (packet->payload_packet_len == 28 && (packet->payload[0] == 0x01 || packet->payload[0] == 0x00)
                    && (get_u32(packet->payload, 19) == ntohl(0x00000001)))) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "found pplive.\n");
                mmt_int_pplive_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (ipacket->session->data_packet_count < 45) {
                MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "need next packet III.\n");
                return 4;
            }
        }

        MMT_LOG(PROTO_PPLIVE, MMT_LOG_DEBUG, "exclude pplive.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_PPLIVE);

    }
    return 0;
}

void mmt_init_classify_me_pplive() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PPLIVE); //BW: TODO: Check this out
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_PPLIVE);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_pplive_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_PPLIVE, PROTO_PPLIVE_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_pplive();

        return register_protocol(protocol_struct, PROTO_PPLIVE);
    } else {
        return 0;
    }
}


