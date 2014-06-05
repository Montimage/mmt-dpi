#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_PROTOCOL_UNSAFE_DETECTION 	0
#define MMT_PROTOCOL_SAFE_DETECTION 		1

#define MMT_PROTOCOL_PLAIN_DETECTION 	0
#define MMT_PROTOCOL_WEBSEED_DETECTION 	2

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_add_connection_as_bittorrent(ipacket_t * ipacket, const uint8_t save_detection, const uint8_t encrypted_connection,
        mmt_protocol_type_t protocol_type) {
    //ipacket->session->last_packet_direction == ipacket->session->setup_packet_direction;
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    if (save_detection != MMT_PROTOCOL_WEBSEED_DETECTION) {
        if (ipacket->session->setup_packet_direction == ipacket->session->last_packet_direction) {
            /*Packet direction from client to server*/
            if (packet->udp != NULL) {
                insert_to_local_protos(packet->udp->dest, PROTO_BITTORRENT, 17 /*UDP*/, &dst->local_protos);
            } else if (packet->tcp != NULL) {
                insert_to_local_protos(packet->tcp->dest, PROTO_BITTORRENT, 6 /*TCP*/, &dst->local_protos);
            }
        } else {
            /*Packet direction from server to client*/
            if (packet->udp != NULL) {
                insert_to_local_protos(packet->udp->source, PROTO_BITTORRENT, 17 /*UDP*/, &src->local_protos);
            } else if (packet->tcp != NULL) {
                insert_to_local_protos(packet->tcp->source, PROTO_BITTORRENT, 6 /*TCP*/, &src->local_protos);
            }
        }
    }
    mmt_change_internal_flow_packet_protocol(ipacket, PROTO_BITTORRENT, protocol_type);
}

static uint8_t mmt_int_search_bittorrent_tcp_zero(ipacket_t * ipacket) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint16_t a = 0;

    if (packet->payload_packet_len == 1 && packet->payload[0] == 0x13) {
        /* reset stage back to 0 so we will see the next packet here too */
        flow->bittorrent_stage = 0;
        return 0;
    }
    if (ipacket->session->data_packet_count == 2 && packet->payload_packet_len > 20) {

        if (memcmp(&packet->payload[0], "BitTorrent protocol", 19) == 0) {
            MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                    MMT_LOG_TRACE, "BT: plain BitTorrent protocol detected\n");
            mmt_add_connection_as_bittorrent(ipacket,
                    MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                    MMT_REAL_PROTOCOL);
            return 1;
        }
    }


    if (packet->payload_packet_len > 20) {
        /* test for match 0x13+"BitTorrent protocol" */
        if (packet->payload[0] == 0x13) {
            if (memcmp(&packet->payload[1], "BitTorrent protocol", 19) == 0) {
                MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                        MMT_LOG_TRACE, "BT: plain BitTorrent protocol detected\n");
                mmt_add_connection_as_bittorrent(ipacket,
                        MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                        MMT_REAL_PROTOCOL);
                return 1;
            }
        }
    }

    if (packet->payload_packet_len > 23 && memcmp(packet->payload, "GET /webseed?info_hash=", 23) == 0) {
        MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                MMT_LOG_TRACE, "BT: plain webseed BitTorrent protocol detected\n");
        mmt_add_connection_as_bittorrent(ipacket,
                MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_WEBSEED_DETECTION,
                MMT_CORRELATED_PROTOCOL);
        return 1;
    }
    /* seen Azureus as server for webseed, possibly other servers existing, to implement */
    /* is Server: hypertracker Bittorrent? */
    /* no asymmetric detection possible for answer of pattern "GET /data?fid=". */
    if (packet->payload_packet_len > 60
            && memcmp(packet->payload, "GET /data?fid=", 14) == 0 && memcmp(&packet->payload[54], "&size=", 6) == 0) {
        MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                MMT_LOG_TRACE, "BT: plain Bitcomet persistent seed protocol detected\n");
        mmt_add_connection_as_bittorrent(ipacket,
                MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_WEBSEED_DETECTION,
                MMT_CORRELATED_PROTOCOL);
        return 1;
    }


    if (packet->payload_packet_len > 90 && (memcmp(packet->payload, "GET ", 4) == 0
            || memcmp(packet->payload, "POST ", 5) == 0)) {
        const uint8_t *ptr = &packet->payload[4];
        uint16_t len = packet->payload_packet_len - 4;
        a = 0;


        /* parse complete get packet here into line structure elements */
        mmt_parse_packet_line_info(ipacket);
        /* answer to this pattern is HTTP....Server: hypertracker */
        if (packet->user_agent_line.ptr != NULL
                && ((packet->user_agent_line.len > 8 && memcmp(packet->user_agent_line.ptr, "Azureus ", 8) == 0)
                || (packet->user_agent_line.len >= 10 && memcmp(packet->user_agent_line.ptr, "BitTorrent", 10) == 0)
                || (packet->user_agent_line.len >= 11 && memcmp(packet->user_agent_line.ptr, "BTWebClient", 11) == 0))) {
            MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                    MMT_LOG_TRACE, "Azureus /Bittorrent user agent line detected\n");
            mmt_add_connection_as_bittorrent(ipacket,
                    MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_WEBSEED_DETECTION,
                    MMT_CORRELATED_PROTOCOL);
            return 1;
        }

        if (packet->user_agent_line.ptr != NULL
                && (packet->user_agent_line.len >= 9 && memcmp(packet->user_agent_line.ptr, "Shareaza ", 9) == 0)
                && (packet->parsed_lines > 8 && packet->line[8].ptr != 0
                && packet->line[8].len >= 9 && memcmp(packet->line[8].ptr, "X-Queue: ", 9) == 0)) {
            MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                    MMT_LOG_TRACE, "Bittorrent Shareaza detected.\n");
            mmt_add_connection_as_bittorrent(ipacket,
                    MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_WEBSEED_DETECTION,
                    MMT_CORRELATED_PROTOCOL);
            return 1;
        }

        /* this is a self built client, not possible to catch asymmetrically */
        if ((packet->parsed_lines == 10 || (packet->parsed_lines == 11 && packet->line[11].len == 0))
                && packet->user_agent_line.ptr != NULL
                && packet->user_agent_line.len > 12
                && mmt_mem_cmp(packet->user_agent_line.ptr, "Mozilla/4.0 ",
                12) == 0
                && packet->host_line.ptr != NULL
                && packet->host_line.len >= 7
                && packet->line[2].ptr != NULL
                && packet->line[2].len > 14
                && mmt_mem_cmp(packet->line[2].ptr, "Keep-Alive: 300", 15) == 0
                && packet->line[3].ptr != NULL
                && packet->line[3].len > 21
                && mmt_mem_cmp(packet->line[3].ptr, "Connection: Keep-alive", 22) == 0
                && packet->line[4].ptr != NULL
                && packet->line[4].len > 10
                && (mmt_mem_cmp(packet->line[4].ptr, "Accpet: */*", 11) == 0
                || mmt_mem_cmp(packet->line[4].ptr, "Accept: */*", 11) == 0)

                && packet->line[5].ptr != NULL
                && packet->line[5].len > 12
                && mmt_mem_cmp(packet->line[5].ptr, "Range: bytes=", 13) == 0
                && packet->line[7].ptr != NULL
                && packet->line[7].len > 15
                && mmt_mem_cmp(packet->line[7].ptr, "Pragma: no-cache", 16) == 0
                && packet->line[8].ptr != NULL
                && packet->line[8].len > 22 && mmt_mem_cmp(packet->line[8].ptr, "Cache-Control: no-cache", 23) == 0) {

            MMT_LOG_BITTORRENT(PROTO_BITTORRENT, MMT_LOG_TRACE, "Bitcomet LTS detected\n");
            mmt_add_connection_as_bittorrent(ipacket,
                    MMT_PROTOCOL_UNSAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                    MMT_CORRELATED_PROTOCOL);
            return 1;

        }

        /* FlashGet pattern */
        if (packet->parsed_lines == 8
                && packet->user_agent_line.ptr != NULL
                && packet->user_agent_line.len > (sizeof ("Mozilla/4.0 (compatible; MSIE 6.0;") - 1)
                && memcmp(packet->user_agent_line.ptr, "Mozilla/4.0 (compatible; MSIE 6.0;",
                sizeof ("Mozilla/4.0 (compatible; MSIE 6.0;") - 1) == 0
                && packet->host_line.ptr != NULL
                && packet->host_line.len >= 7
                && packet->line[2].ptr != NULL
                && packet->line[2].len == 11
                && memcmp(packet->line[2].ptr, "Accept: */*", 11) == 0
                && packet->line[3].ptr != NULL && packet->line[3].len >= (sizeof ("Referer: ") - 1)
                && mmt_mem_cmp(packet->line[3].ptr, "Referer: ", sizeof ("Referer: ") - 1) == 0
                && packet->line[5].ptr != NULL
                && packet->line[5].len > 13
                && mmt_mem_cmp(packet->line[5].ptr, "Range: bytes=", 13) == 0
                && packet->line[6].ptr != NULL
                && packet->line[6].len > 21 && mmt_mem_cmp(packet->line[6].ptr, "Connection: Keep-Alive", 22) == 0) {

            MMT_LOG_BITTORRENT(PROTO_BITTORRENT, MMT_LOG_TRACE, "FlashGet detected\n");
            mmt_add_connection_as_bittorrent(ipacket,
                    MMT_PROTOCOL_UNSAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                    MMT_CORRELATED_PROTOCOL);
            return 1;

        }
        if (packet->parsed_lines == 7
                && packet->user_agent_line.ptr != NULL
                && packet->user_agent_line.len > (sizeof ("Mozilla/4.0 (compatible; MSIE 6.0;") - 1)
                && memcmp(packet->user_agent_line.ptr, "Mozilla/4.0 (compatible; MSIE 6.0;",
                sizeof ("Mozilla/4.0 (compatible; MSIE 6.0;") - 1) == 0
                && packet->host_line.ptr != NULL
                && packet->host_line.len >= 7
                && packet->line[2].ptr != NULL
                && packet->line[2].len == 11
                && memcmp(packet->line[2].ptr, "Accept: */*", 11) == 0
                && packet->line[3].ptr != NULL && packet->line[3].len >= (sizeof ("Referer: ") - 1)
                && mmt_mem_cmp(packet->line[3].ptr, "Referer: ", sizeof ("Referer: ") - 1) == 0
                && packet->line[5].ptr != NULL
                && packet->line[5].len > 21 && mmt_mem_cmp(packet->line[5].ptr, "Connection: Keep-Alive", 22) == 0) {

            MMT_LOG_BITTORRENT(PROTO_BITTORRENT, MMT_LOG_TRACE, "FlashGet detected\n");
            mmt_add_connection_as_bittorrent(ipacket,
                    MMT_PROTOCOL_UNSAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                    MMT_CORRELATED_PROTOCOL);
            return 1;

        }

        /* answer to this pattern is not possible to implement asymmetrically */
        while (1) {
            if (len < 50 || ptr[0] == 0x0d) {
                goto mmt_end_bt_tracker_check;
            }
            if (memcmp(ptr, "info_hash=", 10) == 0) {
                break;
            }
            len--;
            ptr++;
        }

        MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                MMT_LOG_TRACE, " BT stat: tracker info hash found\n");

        /* len is > 50, so save operation here */
        len -= 10;
        ptr += 10;

        /* parse bt hash */
        for (a = 0; a < 20; a++) {
            if (len < 3) {
                goto mmt_end_bt_tracker_check;
            }
            if (*ptr == '%') {
                uint8_t x1 = 0xFF;
                uint8_t x2 = 0xFF;


                if (ptr[1] >= '0' && ptr[1] <= '9') {
                    x1 = ptr[1] - '0';
                }
                if (ptr[1] >= 'a' && ptr[1] <= 'f') {
                    x1 = 10 + ptr[1] - 'a';
                }
                if (ptr[1] >= 'A' && ptr[1] <= 'F') {
                    x1 = 10 + ptr[1] - 'A';
                }

                if (ptr[2] >= '0' && ptr[2] <= '9') {
                    x2 = ptr[2] - '0';
                }
                if (ptr[2] >= 'a' && ptr[2] <= 'f') {
                    x2 = 10 + ptr[2] - 'a';
                }
                if (ptr[2] >= 'A' && ptr[2] <= 'F') {
                    x2 = 10 + ptr[2] - 'A';
                }

                if (x1 == 0xFF || x2 == 0xFF) {
                    goto mmt_end_bt_tracker_check;
                }
                ptr += 3;
                len -= 3;
            } else if (*ptr >= 32 && *ptr < 127) {
                ptr++;
                len--;
            } else {
                goto mmt_end_bt_tracker_check;
            }
        }

        MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                MMT_LOG_TRACE, " BT stat: tracker info hash parsed\n");
        mmt_add_connection_as_bittorrent(ipacket,
                MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                MMT_CORRELATED_PROTOCOL);
        return 1;
    }

mmt_end_bt_tracker_check:

    if (packet->payload_packet_len == 80) {
        /* Warez 80 Bytes Packet
         * +----------------+---------------+-----------------+-----------------+
         * |20 BytesPattern | 32 Bytes Value| 12 BytesPattern | 16 Bytes Data   |
         * +----------------+---------------+-----------------+-----------------+
         * 20 BytesPattern : 4c 00 00 00 ff ff ff ff 57 00 00 00 00 00 00 00 20 00 00 00
         * 12 BytesPattern : 28 23 00 00 01 00 00 00 10 00 00 00
         * */
        static const char pattern_20_bytes[20] = {0x4c, 0x00, 0x00, 0x00, 0xff,
            0xff, 0xff, 0xff, 0x57, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00};
        static const char pattern_12_bytes[12] = {0x28, 0x23, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00};

        /* did not see this pattern anywhere */
        if ((memcmp(&packet->payload[0], pattern_20_bytes, 20) == 0)
                && (memcmp(&packet->payload[52], pattern_12_bytes, 12) == 0)) {
            MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                    MMT_LOG_TRACE, "BT: Warez - Plain BitTorrent protocol detected\n");
            mmt_add_connection_as_bittorrent(ipacket,
                    MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                    MMT_REAL_PROTOCOL);
            return 1;
        }
    } else if (packet->payload_packet_len > 50) {
        if (memcmp(packet->payload, "GET", 3) == 0) {

            mmt_parse_packet_line_info(ipacket);
            /* haven't fount this pattern anywhere */
            if (packet->host_line.ptr != NULL
                    && packet->host_line.len >= 9 && memcmp(packet->host_line.ptr, "ip2p.com:", 9) == 0) {
                MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                        MMT_LOG_TRACE,
                        "BT: Warez - Plain BitTorrent protocol detected due to Host: ip2p.com: pattern\n");
                mmt_add_connection_as_bittorrent(ipacket,
                        MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_WEBSEED_DETECTION,
                        MMT_CORRELATED_PROTOCOL);
                return 1;
            }
        }
    }
    return 0;
}

/*Search for BitTorrent commands*/
static void mmt_int_search_bittorrent_tcp(ipacket_t * ipacket) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    if (packet->payload_packet_len == 0) {
        return;
    }

    if (flow->bittorrent_stage < 10 && packet->payload_packet_len != 0) {
        /* exclude stage 0 detection from next run */
        flow->bittorrent_stage++;
        if (mmt_int_search_bittorrent_tcp_zero(ipacket) != 0) {
            MMT_LOG_BITTORRENT(PROTO_BITTORRENT, MMT_LOG_DEBUG,
                    "stage 0 has detected something, returning\n");
            return;
        }

        MMT_LOG_BITTORRENT(PROTO_BITTORRENT, MMT_LOG_DEBUG,
                "stage 0 has no direct detection, fall through\n");
    }
    return;
}

void mmt_classify_me_bittorrent(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    if (packet->detected_protocol_stack[0] != PROTO_BITTORRENT) {
        /* check for tcp retransmission here */

        if ((packet->tcp != NULL)
                && (packet->tcp_retransmission == 0 || packet->num_retried_bytes)) {
            mmt_int_search_bittorrent_tcp(ipacket);
        } else if (packet->udp != NULL) {

            flow->bittorrent_stage++;

            if (flow->bittorrent_stage < 10) {
                if (packet->payload_packet_len > 19 /* min size */) {
                    char *begin;

                    if (mmt_strncmp((const char*)packet->payload, ":target20:",   packet->payload_packet_len) == 0
                     || mmt_strncmp((const char*)packet->payload, ":find_node1:", packet->payload_packet_len) == 0
                     || mmt_strncmp((const char*)packet->payload, "d1:ad2:id20:", packet->payload_packet_len) == 0) {
bittorrent_found:
                        MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                                MMT_LOG_TRACE, "BT: plain BitTorrent protocol detected\n");
                        mmt_add_connection_as_bittorrent(ipacket,
                                MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                                MMT_REAL_PROTOCOL);
                        return;
                    } else if ((begin = memchr(packet->payload, 'B', packet->payload_packet_len - 19)) != NULL) {
                        u_long offset = (const unsigned char*)begin - packet->payload;

                        if ((packet->payload_packet_len - 19) > offset) {
                            if (memcmp(begin, "BitTorrent protocol", 19) == 0) {
                                goto bittorrent_found;
                            }
                        }
                    }
                }

                return;
            }

            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_BITTORRENT);
        }

    }
}

int mmt_check_bittorrent_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        if (packet->detected_protocol_stack[0] != PROTO_BITTORRENT) {
            /* check for tcp retransmission here */
            if (packet->tcp_retransmission == 0 || packet->num_retried_bytes) {
                //First check if the server already has Bittorrent as local application
                struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
                struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
                if (ipacket->session->setup_packet_direction == ipacket->session->last_packet_direction) {
                    /*Packet direction from client to server*/
                    uint32_t app = PROTO_UNKNOWN;
                    if (packet->tcp != NULL && packet->actual_payload_len > 0) {
                        app = check_local_proto_by_port_nb(packet->tcp->dest, &dst->local_protos);
                    }
                    if (app == PROTO_BITTORRENT) {
                        mmt_add_connection_as_bittorrent(ipacket,
                                MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                                MMT_REAL_PROTOCOL);
                    }
                } else {
                    /*Packet direction from server to client*/
                    uint32_t app = PROTO_UNKNOWN;
                    if (packet->tcp != NULL && packet->actual_payload_len > 0) {
                        app = check_local_proto_by_port_nb(packet->tcp->source, &src->local_protos);
                    }
                    if (app == PROTO_BITTORRENT) {
                        mmt_add_connection_as_bittorrent(ipacket,
                                MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                                MMT_REAL_PROTOCOL);
                    }
                }
                mmt_int_search_bittorrent_tcp(ipacket);
            }
        }
    }
    return 1;
}

int mmt_check_bittorrent_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->detected_protocol_stack[0] != PROTO_BITTORRENT) {
            //First check if the server already has Bittorrent as local application
            struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
            struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
            if (ipacket->session->setup_packet_direction == ipacket->session->last_packet_direction) {
                /*Packet direction from client to server*/
                uint32_t app = PROTO_UNKNOWN;
                if (packet->udp != NULL && packet->actual_payload_len > 0) {
                    app = check_local_proto_by_port_nb(packet->udp->dest, &dst->local_protos);
                }
                if (app == PROTO_BITTORRENT) {
                    goto bittorrent_found;
                }
            } else {
                /*Packet direction from server to client*/
                uint32_t app = PROTO_UNKNOWN;
                if (packet->udp != NULL && packet->actual_payload_len > 0) {
                    app = check_local_proto_by_port_nb(packet->udp->source, &src->local_protos);
                }
                if (app == PROTO_BITTORRENT) {
                    goto bittorrent_found;
                }
            }

            flow->bittorrent_stage++;

            if (flow->bittorrent_stage < 10) {
                if (packet->payload_packet_len > 19 /* min size */) {
                    char *begin;

                    if (mmt_strncmp((const char*)packet->payload, ":target20:",   packet->payload_packet_len) == 0
                     || mmt_strncmp((const char*)packet->payload, ":find_node1:", packet->payload_packet_len) == 0
                     || mmt_strncmp((const char*)packet->payload, "d1:ad2:id20:", packet->payload_packet_len) == 0
                     || mmt_strncmp((const char*)packet->payload, "d1:rd2:id20:", packet->payload_packet_len) == 0) {
bittorrent_found:
                        MMT_LOG_BITTORRENT(PROTO_BITTORRENT,
                                MMT_LOG_TRACE, "BT: plain BitTorrent protocol detected\n");
                        mmt_add_connection_as_bittorrent(ipacket,
                                MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION,
                                MMT_REAL_PROTOCOL);
                        return 1;
                    } else if ((begin = memchr(packet->payload, 'B', packet->payload_packet_len - 19)) != NULL) {
                        u_long offset = (const unsigned char*)begin - packet->payload;

                        if ((packet->payload_packet_len - 19) > offset) {
                            if (memcmp(begin, "BitTorrent protocol", 19) == 0) {
                                goto bittorrent_found;
                            }
                        }
                    }
                }
                return 1;
            }

            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_BITTORRENT);
        }
    }
    return 1;
}

void mmt_init_classify_me_bittorrent() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BITTORRENT);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_BITTORRENT);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_bittorrent_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_BITTORRENT, PROTO_BITTORRENT_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_bittorrent();

        return register_protocol(protocol_struct, PROTO_BITTORRENT);
    } else {
        return 0;
    }
}


