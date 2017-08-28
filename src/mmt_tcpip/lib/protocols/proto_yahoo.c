#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_YAHOO_DETECT_HTTP_CONNECTIONS   1
#define MMT_YAHOO_LAN_VIDEO_TIMEOUT         30

static uint8_t yahoo_detect_http_connections = MMT_YAHOO_DETECT_HTTP_CONNECTIONS;
static uint32_t yahoo_lan_video_timeout = MMT_YAHOO_LAN_VIDEO_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

struct mmt_yahoo_header {
    uint8_t YMSG_str[4];
    uint16_t version;
    uint16_t nothing0;
    uint16_t len;
    uint16_t service;
    uint32_t status;
    uint32_t session_id;
};

/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
static uint8_t mmt_check_for_YmsgCommand(uint16_t len, const uint8_t * ptr) {
    uint16_t i;

    for (i = 0; i < len - 12; i++) {
        if (ptr[i] == 'Y') {
            if (memcmp(&ptr[i + 1], "msg Command=", 12) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static void mmt_int_yahoo_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_YAHOO, protocol_type);
}



static uint8_t check_ymsg(const uint8_t * payload, uint16_t payload_packet_len) {

    const struct mmt_yahoo_header *yahoo = (struct mmt_yahoo_header *) payload;

    uint16_t yahoo_len_parsed = 0;
    do {
        uint16_t ylen = ntohs(yahoo->len);

        yahoo_len_parsed += 20 + ylen; /* possible overflow here: 20 + ylen = 0x10000 --> 0 --> infinite loop */

        if (ylen >= payload_packet_len || yahoo_len_parsed >= payload_packet_len)
            break;

        yahoo = (struct mmt_yahoo_header *) (payload + yahoo_len_parsed);
    } while (memcmp(yahoo->YMSG_str, "YMSG", 4) == 0);

    if (yahoo_len_parsed == payload_packet_len)
        return 1;
    return 0;
}

static void mmt_search_yahoo_tcp(ipacket_t * ipacket) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    const struct mmt_yahoo_header *yahoo = (struct mmt_yahoo_header *) packet->payload;
    if (packet->payload_packet_len == 0) {
        return;
    }

    /* packet must be at least 20 bytes long */
    if (packet->payload_packet_len >= 20
            && memcmp(yahoo->YMSG_str, "YMSG", 4) == 0 && ((packet->payload_packet_len - 20) == ntohs(yahoo->len)
            || check_ymsg(packet->payload, packet->payload_packet_len))) {
        MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE, "YAHOO FOUND\n");
        flow->yahoo_detection_finished = 2;
        if (ntohs(yahoo->service) == 24 || ntohs(yahoo->service) == 152 || ntohs(yahoo->service) == 74) {
            MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE, "YAHOO conference or chat invite  found");
            if (src != NULL) {
                src->yahoo_conf_logged_in = 1;
            }
            if (dst != NULL) {
                dst->yahoo_conf_logged_in = 1;
            }
        }
        if (ntohs(yahoo->service) == 27 || ntohs(yahoo->service) == 155 || ntohs(yahoo->service) == 160) {
            MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE, "YAHOO conference or chat logoff found");
            if (src != NULL) {
                src->yahoo_conf_logged_in = 0;
                src->yahoo_voice_conf_logged_in = 0;
            }
        }
        MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
        mmt_int_yahoo_add_connection(ipacket, MMT_REAL_PROTOCOL);
        return;
    } else if (flow->yahoo_detection_finished == 2 && packet->detected_protocol_stack[0] == PROTO_YAHOO) {
        return;
    } else if (packet->payload_packet_len == 4 && memcmp(yahoo->YMSG_str, "YMSG", 4) == 0) {
        flow->l4.tcp.yahoo_sip_comm = 1;
        return;
    } else if (flow->l4.tcp.yahoo_sip_comm && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
            && ipacket->session->data_packet_count < 3) {
        return;
    }

    /* now test for http login, at least 100 a bytes packet */
    if (yahoo_detect_http_connections != 0 && packet->payload_packet_len > 100) {
        if (memcmp(packet->payload, "POST /relay?token=", 18) == 0
                || memcmp(packet->payload, "GET /relay?token=", 17) == 0
                || memcmp(packet->payload, "GET /?token=", 12) == 0
                || memcmp(packet->payload, "HEAD /relay?token=", 18) == 0) {
            if ((src != NULL
                    && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_YAHOO)
                    != 0) || (dst != NULL
                    && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_YAHOO)
                    != 0)) {
                /* this is mostly a file transfer */
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
                mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }
        if (memcmp(packet->payload, "POST ", 5) == 0) {
            uint16_t a;
            mmt_parse_packet_line_info(ipacket);

            if ((packet->user_agent_line.len >= 21)
                    && (memcmp(packet->user_agent_line.ptr, "YahooMobileMessenger/", 21) == 0)) {
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO(Mobile)");
                mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }

            if (MMT_SRC_OR_DST_HAS_PROTOCOL(src, dst, PROTO_YAHOO)
                    && packet->parsed_lines > 5
                    && memcmp(&packet->payload[5], "/Messenger.", 11) == 0
                    && packet->line[1].len >= 17
                    && mmt_mem_cmp(packet->line[1].ptr, "Connection: Close",
                    17) == 0 && packet->line[2].len >= 6
                    && mmt_mem_cmp(packet->line[2].ptr, "Host: ", 6) == 0
                    && packet->line[3].len >= 16
                    && mmt_mem_cmp(packet->line[3].ptr, "Content-Length: ",
                    16) == 0 && packet->line[4].len >= 23
                    && mmt_mem_cmp(packet->line[4].ptr, "User-Agent: Mozilla/5.0",
                    23) == 0 && packet->line[5].len >= 23
                    && mmt_mem_cmp(packet->line[5].ptr, "Cache-Control: no-cache", 23) == 0) {
                MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE,
                        "YAHOO HTTP POST P2P FILETRANSFER FOUND\n");
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
                mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }

            if (packet->host_line.ptr != NULL && packet->host_line.len >= 26 &&
                    mmt_mem_cmp(packet->host_line.ptr, "filetransfer.msg.yahoo.com", 26) == 0) {
                MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE, "YAHOO HTTP POST FILETRANSFER FOUND\n");
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
                mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
            /* now check every line */
            for (a = 0; a < packet->parsed_lines; a++) {
                if (packet->line[a].len >= 4 && mmt_mem_cmp(packet->line[a].ptr, "YMSG", 4) == 0) {
                    MMT_LOG(PROTO_YAHOO,
                            MMT_LOG_TRACE,
                            "YAHOO HTTP POST FOUND, line is: %.*s\n", packet->line[a].len, packet->line[a].ptr);
                    MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
                    mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
            if (packet->parsed_lines > 8 && packet->line[8].len > 250 && packet->line[8].ptr != NULL) {
                if (memcmp(packet->line[8].ptr, "<Session ", 9) == 0) {
                    if (mmt_check_for_YmsgCommand(packet->line[8].len, packet->line[8].ptr)) {
                        MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG,
                                "found HTTP Proxy Yahoo Chat <Ymsg Command= pattern  \n");
                        mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return;
                    }
                }
            }
        }
        if (memcmp(packet->payload, "GET /Messenger.", 15) == 0) {
            if ((src != NULL
                    && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_YAHOO)
                    != 0) || (dst != NULL
                    && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_YAHOO)
                    != 0)) {
                MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE, "YAHOO HTTP GET /Messenger. match\n");
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
                mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }

        if ((memcmp(packet->payload, "GET /", 5) == 0)) {
            mmt_parse_packet_line_info(ipacket);
            if ((packet->user_agent_line.ptr != NULL
                    && packet->user_agent_line.len >= MMT_STATICSTRING_LEN("YahooMobileMessenger/")
                    && memcmp(packet->user_agent_line.ptr, "YahooMobileMessenger/",
                    MMT_STATICSTRING_LEN("YahooMobileMessenger/")) == 0)
                    || (packet->user_agent_line.len >= 15
                    && (memcmp(packet->user_agent_line.ptr, "Y!%20Messenger/", 15) == 0))) {
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO(Mobile)");
                mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
            if (packet->host_line.ptr != NULL && packet->host_line.len >= MMT_STATICSTRING_LEN("msg.yahoo.com") &&
                    memcmp(&packet->host_line.ptr[packet->host_line.len - MMT_STATICSTRING_LEN("msg.yahoo.com")],
                    "msg.yahoo.com", MMT_STATICSTRING_LEN("msg.yahoo.com")) == 0) {
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
                mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }

        }

    }
    /* found another http login command for yahoo, it is like OSCAR */
    /* detect http connections */

    if (packet->payload_packet_len > 50 && (memcmp(packet->payload, "content-length: ", 16) == 0)) {
        mmt_parse_packet_line_info(ipacket);
        if (packet->parsed_lines > 2 && packet->line[1].len == 0) {
            MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE, "first line is empty.\n");
            if (packet->line[2].len > 13 && memcmp(packet->line[2].ptr, "<Ymsg Command=", 14) == 0) {
                MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE, "YAHOO web chat found\n");
                mmt_int_yahoo_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
    }

    if (packet->payload_packet_len > 38 && memcmp(packet->payload, "CONNECT scs.msg.yahoo.com:5050 HTTP/1.", 38) == 0) {
        MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE, "YAHOO-HTTP FOUND\n");
        MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
        mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
        return;
    }

    if ((src != NULL && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_YAHOO) != 0)
            || (dst != NULL
            && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_YAHOO) != 0)) {
        if (packet->payload_packet_len == 6 && memcmp(packet->payload, "YAHOO!", 6) == 0) {
            MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
            mmt_int_yahoo_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        /* asymmetric detection for SNDIMG not done yet.
         * See ./Yahoo8.1-VideoCall-LAN.pcap and ./Yahoo-VideoCall-inPublicIP.pcap */


        if (packet->payload_packet_len == 8
                && (memcmp(packet->payload, "<SNDIMG>", 8) == 0 || memcmp(packet->payload, "<REQIMG>", 8) == 0
                || memcmp(packet->payload, "<RVWCFG>", 8) == 0 || memcmp(packet->payload, "<RUPCFG>", 8) == 0)) {
            MMT_LOG(PROTO_YAHOO, MMT_LOG_TRACE,
                    "YAHOO SNDIMG or REQIMG or RVWCFG or RUPCFG FOUND\n");
            if (src != NULL) {
                if (memcmp(packet->payload, "<SNDIMG>", 8) == 0) {
                    src->yahoo_video_lan_dir = 0;
                } else {
                    src->yahoo_video_lan_dir = 1;
                }
                src->yahoo_video_lan_timer = packet->tick_timestamp;
            }
            if (dst != NULL) {
                if (memcmp(packet->payload, "<SNDIMG>", 8) == 0) {
                    dst->yahoo_video_lan_dir = 0;
                } else {
                    dst->yahoo_video_lan_dir = 1;
                }
                dst->yahoo_video_lan_timer = packet->tick_timestamp;

            }
            MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO subtype VIDEO");
            mmt_int_yahoo_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (src != NULL && packet->tcp->dest == htons(5100)
                && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - src->yahoo_video_lan_timer) < yahoo_lan_video_timeout)) {
            if (src->yahoo_video_lan_dir == 1) {
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
                mmt_int_yahoo_add_connection(ipacket, MMT_REAL_PROTOCOL);
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "IMG MARKED");
                return;
            }

        }
        if (dst != NULL && packet->tcp->dest == htons(5100)
                && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - dst->yahoo_video_lan_timer) < yahoo_lan_video_timeout)) {
            if (dst->yahoo_video_lan_dir == 0) {
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO");
                mmt_int_yahoo_add_connection(ipacket, MMT_REAL_PROTOCOL);
                MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "IMG MARKED");
                return;
            }

        }
    }

    /* detect YAHOO over HTTP proxy */
#ifdef PROTO_HTTP
    if (packet->detected_protocol_stack[0] == PROTO_HTTP)
#endif
    {

        if (flow->l4.tcp.yahoo_http_proxy_stage == 0) {
            MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG,
                    "YAHOO maybe HTTP proxy packet 1 => need next packet\n");
            flow->l4.tcp.yahoo_http_proxy_stage = 1 + ipacket->session->last_packet_direction;
            return;
        }
        if (flow->l4.tcp.yahoo_http_proxy_stage == 1 + ipacket->session->last_packet_direction) {
            if ((packet->payload_packet_len > 250) && (memcmp(packet->payload, "<Session ", 9) == 0)) {
                if (mmt_check_for_YmsgCommand(packet->payload_packet_len, packet->payload)) {
                    MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG,
                            "found HTTP Proxy Yahoo Chat <Ymsg Command= pattern  \n");
                    mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
            MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG,
                    "YAHOO maybe HTTP proxy still initial direction => need next packet\n");
            return;
        }
        if (flow->l4.tcp.yahoo_http_proxy_stage == 2 - ipacket->session->last_packet_direction) {

            mmt_parse_packet_line_info_unix(ipacket);

            if (packet->parsed_unix_lines >= 9) {

                if (packet->unix_line[4].ptr != NULL && packet->unix_line[4].len >= 9 &&
                        packet->unix_line[8].ptr != NULL && packet->unix_line[8].len >= 6 &&
                        memcmp(packet->unix_line[4].ptr, "<Session ", 9) == 0 &&
                        memcmp(packet->unix_line[8].ptr, "<Ymsg ", 6) == 0) {

                    MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "found YAHOO over HTTP proxy");
                    mmt_int_yahoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
        }
    }
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_YAHOO);
}


static void mmt_search_yahoo_udp(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;

    if (src == NULL || MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_YAHOO) == 0) {
        goto excl_yahoo_udp;
    }
excl_yahoo_udp:

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_YAHOO);
}

void mmt_classify_me_yahoo(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "search yahoo\n");

    if (packet->payload_packet_len > 0 && flow->yahoo_detection_finished == 0) {
        if (packet->tcp != NULL && packet->tcp_retransmission == 0) {

            if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN
#ifdef PROTO_HTTP
                    || packet->detected_protocol_stack[0] == PROTO_HTTP
#endif
#ifdef PROTO_SSL
                    || packet->detected_protocol_stack[0] == PROTO_SSL
#endif
                    ) {
                mmt_search_yahoo_tcp(ipacket);
            }
        } else if (packet->udp != NULL) {
            mmt_search_yahoo_udp(ipacket);
        }
    }
    if (packet->payload_packet_len > 0 && flow->yahoo_detection_finished == 2) {
        if (packet->tcp != NULL && packet->tcp_retransmission == 0) {
            mmt_search_yahoo_tcp(ipacket);
        }
    }
}

int mmt_check_yahoo_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "search yahoo\n");

        if (packet->payload_packet_len > 0 && flow->yahoo_detection_finished == 0) {
            if (packet->tcp_retransmission == 0) {
                if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                        || packet->detected_protocol_stack[0] == PROTO_HTTP
                        || packet->detected_protocol_stack[0] == PROTO_SSL
                        ) {
                    mmt_search_yahoo_tcp(ipacket);
                }
            }
        }
        if (packet->payload_packet_len > 0 && flow->yahoo_detection_finished == 2) {
            if (packet->tcp_retransmission == 0) {
                mmt_search_yahoo_tcp(ipacket);
            }
        }
    }
    return 4;
}

int mmt_check_yahoo_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_YAHOO, MMT_LOG_DEBUG, "search yahoo\n");

        if (packet->payload_packet_len > 0 && flow->yahoo_detection_finished == 0) {
            mmt_search_yahoo_udp(ipacket);
        }
    }
    return 4;
}

void mmt_init_classify_me_yahoo() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_YAHOO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SSL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_YAHOO);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_yahoo_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_YAHOO, PROTO_YAHOO_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_yahoo();

        return register_protocol(protocol_struct, PROTO_YAHOO);
    } else {
        return 0;
    }
}


