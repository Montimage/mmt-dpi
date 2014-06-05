#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MAX_PACKETS_FOR_MSN 100

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_msn_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_MSN, protocol_type);
}

static uint8_t mmt_int_find_xmsn(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->parsed_lines > 3) {
        uint16_t i;
        for (i = 2; i < packet->parsed_lines; i++) {
            if (packet->line[i].ptr != NULL && packet->line[i].len > MMT_STATICSTRING_LEN("X-MSN") &&
                    memcmp(packet->line[i].ptr, "X-MSN", MMT_STATICSTRING_LEN("X-MSN")) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static void mmt_search_msn_tcp(ipacket_t * ipacket) {
    
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    uint16_t plen;
    uint16_t status = 0;

    MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "search msn tcp.\n");
#ifdef PROTO_SSL
    if (packet->detected_protocol_stack[0] == PROTO_SSL) {
        MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "msn ssl ft test\n");
        if (ipacket->session->data_packet_count < 10) {
        }

        if (ipacket->session->data_packet_count == 7 && packet->payload_packet_len > 300) {
            if (memcmp(packet->payload + 24, "MSNSLP", 6) == 0
                    || (get_u32(packet->payload, 0) == htonl(0x30000000) && get_u32(packet->payload, 4) == 0x00000000)) {
                MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "detected MSN File Transfer, ifdef ssl.\n");
                mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
        if (packet->payload_packet_len > 8 && ipacket->session->data_packet_count >= 5 && ipacket->session->data_packet_count <= 10 && (get_u32(packet->payload, 0) == htonl(0x18000000)
                && get_u32(packet->payload, 4) == 0x00000000)) {
            flow->l4.tcp.msn_ssl_ft++;
            MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                    "increased msn ft ssl stage to: %u at packet nr: %u\n", flow->l4.tcp.msn_ssl_ft,
                    flow->data_packet_count);
            if (flow->l4.tcp.msn_ssl_ft == 2) {
                MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                        "detected MSN File Transfer, ifdef ssl 2.\n");
                mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            }
            return;
        }
    }
#endif



    /* we detect the initial connection only ! */
    /* match: "VER " ..... "CVR" x 0x0d 0x0a
     * len should be small, lets say less than 100 bytes
     * x is now "0", but can be increased
     */
    /* now we have a look at the first packet only. */
    if (ipacket->session->data_packet_count == 1
#ifdef PROTO_SSL
            || ((packet->detected_protocol_stack[0] == PROTO_SSL) && ipacket->session->data_packet_count <= 3)
#endif
            ) {

        /* this part is working asymmetrically */
        if (packet->payload_packet_len > 32 && (packet->payload[0] == 0x02 || packet->payload[0] == 0x00)
                && (ntohl(get_u32(packet->payload, 8)) == 0x2112a442 || ntohl(get_u32(packet->payload, 4)) == 0x2112a442)
                && ((ntohl(get_u32(packet->payload, 24)) == 0x000f0004 && ntohl(get_u32(packet->payload, 28)) == 0x72c64bc6)
                || (ntohl(get_u32(packet->payload, 20)) == 0x000f0004
                && ntohl(get_u32(packet->payload, 24)) == 0x72c64bc6))) {
            MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                    "found MSN in packets that also contain voice.messenger.live.com.\n");

            /* TODO this is an alternative pattern for video detection */
            /*          if (packet->payload_packet_len > 100 &&
               get_u16(packet->payload, 86) == htons(0x05dc)) { */
            if (packet->payload_packet_len > 101 && packet->payload[101] == 0x02) {
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            } else {
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            }

            return;
        }

        /* this case works asymmetrically */
        if (packet->payload_packet_len > 10 && packet->payload_packet_len < 100) {
            if (get_u8(packet->payload, packet->payload_packet_len - 2) == 0x0d
                    && get_u8(packet->payload, packet->payload_packet_len - 1) == 0x0a) {
                /* The MSNP string is used in XBOX clients. */
                if (memcmp(packet->payload, "VER ", 4) == 0) {

                    if (memcmp(&packet->payload[packet->payload_packet_len - 6], "CVR",
                            3) == 0 || memcmp(&packet->payload[packet->payload_packet_len - 8], "MSNP", 4) == 0) {
                        MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                                "found MSN by pattern VER...CVR/MSNP ODOA.\n");
                        mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return;
                    }
                    if (memcmp(&packet->payload[4], "MSNFT", 5) == 0) {
                        MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                                "found MSN FT by pattern VER MSNFT...0d0a.\n");
                        mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return;
                    }
                }
            }
        }

        if (packet->payload_packet_len > 32 && (
#ifdef PROTO_HTTP
                packet->detected_protocol_stack[0] == PROTO_HTTP ||
#endif
                memcmp(packet->payload, "GET ", MMT_STATICSTRING_LEN("GET ")) == 0 ||
                memcmp(packet->payload, "POST ", MMT_STATICSTRING_LEN("POST ")) == 0)) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->user_agent_line.ptr != NULL &&
                    packet->user_agent_line.len > MMT_STATICSTRING_LEN("Messenger/") &&
                    memcmp(packet->user_agent_line.ptr, "Messenger/", MMT_STATICSTRING_LEN("Messenger/")) == 0) {
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }
#ifdef PROTO_HTTP
        /* we have to examine two http packets */
        if (packet->detected_protocol_stack[0] == PROTO_HTTP) {
        }
#endif
        /* not seen this pattern in any trace */
        /* now test for http login, at least 100 a bytes packet */
        if (packet->payload_packet_len > 100) {
            if (
#ifdef PROTO_HTTP
                    packet->detected_protocol_stack[0] == PROTO_HTTP ||
#endif
                    memcmp(packet->payload, "POST http://", 12) == 0) {
                /* scan packet if not already done... */
                mmt_parse_packet_line_info(ipacket);

                if (packet->content_line.ptr != NULL &&
                        ((packet->content_line.len == MMT_STATICSTRING_LEN("application/x-msn-messenger") &&
                        memcmp(packet->content_line.ptr, "application/x-msn-messenger",
                        MMT_STATICSTRING_LEN("application/x-msn-messenger")) == 0) ||
                        (packet->content_line.len >= MMT_STATICSTRING_LEN("text/x-msnmsgr") &&
                        memcmp(packet->content_line.ptr, "text/x-msnmsgr",
                        MMT_STATICSTRING_LEN("text/x-msnmsgr")) == 0))) {
                    MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                            "found MSN by pattern POST http:// .... application/x-msn-messenger.\n");
                    mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
        }

        /* now test for http login that uses a gateway, at least 400 a bytes packet */
        /* for this case the asymmetric detection is asym (1) */
        if (packet->payload_packet_len > 400) {
            if ((
#ifdef PROTO_HTTP
                    packet->detected_protocol_stack[0] == PROTO_HTTP ||
#endif
                    (memcmp(packet->payload, "POST ", 5) == 0))) {
                uint16_t c;
                if (memcmp(&packet->payload[5], "http://", 7) == 0) {
                    /*
                     * We are searching for a paten "POST http://gateway.messenger.hotmail.com/gateway/gateway.dll" or
                     * "POST http://<some ip addres here like 172.0.0.0>/gateway/gateway.dll"
                     * POST http:// is 12 byte so we are searching for 13 to 70 byte for this paten.
                     */
                    for (c = 13; c < 50; c++) {
                        if (memcmp(&packet->payload[c], "/", 1) == 0) {
                            if (memcmp(&packet->payload[c], "/gateway/gateway.dll", 20) == 0) {
                                MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                                        "found  pattern http://.../gateway/gateway.ddl.\n");
                                status = 1;
                                break;
                            }
                        }
                    }
                } else if ((memcmp(&packet->payload[5], "/gateway/gateway.dll", 20) == 0)) {
                    MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                            "found  pattern http://.../gateway/gateway.ddl.\n");
                    status = 1;
                }
            }
            if (status) {
                uint16_t a;

                mmt_parse_packet_line_info(ipacket);

                if (packet->content_line.ptr != NULL
                        &&
                        ((packet->content_line.len == 23
                        && memcmp(packet->content_line.ptr, "text/xml; charset=utf-8", 23) == 0)
                        ||
                        (packet->content_line.len == 24
                        && memcmp(packet->content_line.ptr, "text/html; charset=utf-8", 24) == 0)
                        ||
                        (packet->content_line.len == 33
                        && memcmp(packet->content_line.ptr, "application/x-www-form-urlencoded", 33) == 0)
                        )) {
                    if ((src != NULL
                            && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_MSN)
                            != 0) || (dst != NULL
                            && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask,
                            PROTO_MSN)
                            != 0)) {
                        MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                                "found MSN with pattern text/xml; charset=utf-8.\n");
                        mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return;
                    }
                    for (a = 0; a < packet->parsed_lines; a++) {
                        if (packet->line[a].len >= 4 &&
                                (memcmp(packet->line[a].ptr, "CVR ", 4) == 0
                                || memcmp(packet->line[a].ptr, "VER ",
                                4) == 0 || memcmp(packet->line[a].ptr, "ANS ", 4) == 0)) {
                            MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                                    "found MSN with pattern text/sml; charset0utf-8.\n");
                            MMT_LOG(PROTO_MSN, 
                                    MMT_LOG_TRACE, "MSN xml CVS / VER / ANS found\n");
                            mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                            return;
                        }
                    }
                }
            }
        }
        /* asym (1) ; possibly occurs in symmetric cases also. */
        if (ipacket->session->data_packet_count <= 10 &&
                (ipacket->session->data_packet_count_direction[0] <= 2 || ipacket->session->data_packet_count_direction[1] <= 2)
                && packet->payload_packet_len > 100) {
            /* not necessary to check the length, because this has been done : >400. */
            if (
#ifdef PROTO_HTTP
                    packet->detected_protocol_stack[0] == PROTO_HTTP ||
#endif
                    (memcmp(packet->payload, "HTTP/1.0 200 OK", 15) == 0) ||
                    (memcmp(packet->payload, "HTTP/1.1 200 OK", 15) == 0)
                    ) {

                mmt_parse_packet_line_info(ipacket);

                if (packet->content_line.ptr != NULL &&
                        ((packet->content_line.len == MMT_STATICSTRING_LEN("application/x-msn-messenger") &&
                        memcmp(packet->content_line.ptr, "application/x-msn-messenger",
                        MMT_STATICSTRING_LEN("application/x-msn-messenger")) == 0) ||
                        (packet->content_line.len >= MMT_STATICSTRING_LEN("text/x-msnmsgr") &&
                        memcmp(packet->content_line.ptr, "text/x-msnmsgr",
                        MMT_STATICSTRING_LEN("text/x-msnmsgr")) == 0))) {
                    MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                            "HTTP/1.0 200 OK .... application/x-msn-messenger.\n");
                    mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
                if (mmt_int_find_xmsn(ipacket) == 1) {
                    MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "HTTP/1.0 200 OK .... X-MSN.\n");
                    mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
        }


        /* did not find any trace with this pattern !!!!! */
        /* now block proxy connection */
        if (packet->payload_packet_len >= 42) {
            if (memcmp(packet->payload, "CONNECT messenger.hotmail.com:1863 HTTP/1.", 42) == 0) {
                MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                        "found MSN  with pattern CONNECT messenger.hotmail.com:1863 HTTP/1..\n");
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }

        if (packet->payload_packet_len >= 18) {

            if (memcmp(packet->payload, "USR ", 4) == 0 || memcmp(packet->payload, "ANS ", 4) == 0) {
                /* now we must see a number */
                const uint16_t endlen = packet->payload_packet_len - 12;
                plen = 4;
                while (1) {
                    if (packet->payload[plen] == ' ') {
                        break;
                    }
                    if (packet->payload[plen] < '0' || packet->payload[plen] > '9') {
                        goto ipq_msn_exclude;
                    }
                    plen++;
                    if (plen >= endlen) {
                        goto ipq_msn_exclude;
                    }
                }

                while (plen < endlen) {
                    if (mmt_check_for_email_address(ipacket, plen) != 0) {
                        MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "found mail address\n");
                        break;
                    }
                    if (packet->payload_packet_len > plen + 1
                            && (packet->payload[plen] < 20 || packet->payload[plen] > 128)) {
                        goto ipq_msn_exclude;
                    }
                    plen++;
                    if (plen >= endlen) {
                        goto ipq_msn_exclude;
                    }

                }
                MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                        "found MSN  with pattern USR/ANS ...mail_address.\n");
                mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
    }

    /* finished examining the first packet only. */


    /* asym (1) ; possibly occurs in symmetric cases also. */
    if (ipacket->session->data_packet_count <= 10 &&
            (ipacket->session->data_packet_count_direction[0] <= 2 || ipacket->session->data_packet_count_direction[1] <= 2) &&
            packet->payload_packet_len > 100) {
        /* not necessary to check the length, because this has been done : >400. */
        if (
#ifdef PROTO_HTTP
                packet->detected_protocol_stack[0] == PROTO_HTTP ||
#endif
                (memcmp(packet->payload, "HTTP/1.0 200 OK", 15) == 0) ||
                (memcmp(packet->payload, "HTTP/1.1 200 OK", 15) == 0)
                ) {

            mmt_parse_packet_line_info(ipacket);

            if (packet->content_line.ptr != NULL &&
                    ((packet->content_line.len == MMT_STATICSTRING_LEN("application/x-msn-messenger") &&
                    memcmp(packet->content_line.ptr, "application/x-msn-messenger",
                    MMT_STATICSTRING_LEN("application/x-msn-messenger")) == 0) ||
                    (packet->content_line.len >= MMT_STATICSTRING_LEN("text/x-msnmsgr") &&
                    memcmp(packet->content_line.ptr, "text/x-msnmsgr", MMT_STATICSTRING_LEN("text/x-msnmsgr")) == 0))) {
                MMT_LOG(PROTO_MSN, MMT_LOG_TRACE,
                        "HTTP/1.0 200 OK .... application/x-msn-messenger.\n");
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
            if (mmt_int_find_xmsn(ipacket) == 1) {
                MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "HTTP/1.0 200 OK .... X-MSN.\n");
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }
    }




    /* finished examining the secone packet only */
    /* direct user connection (file transfer,...) */

    if ((src != NULL && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_MSN) != 0)
            || (dst != NULL
            && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_MSN) != 0)) {
        if (ipacket->session->data_packet_count == 1 &&
                packet->payload_packet_len > 12 && memcmp(packet->payload, "recipientid=", 12) == 0) {
            MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "detected file transfer.\n");
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
    }

    /* MSN File Transfer of MSN 8.1 and 8.5
     * first packet with length 4 and pattern 0x04000000
     * second packet (in the same direction), with length 56 and pattern 0x00000000 from payload[16]
     * third packet (in the opposite direction to 1 & 2), with length 4 and pattern 0x30000000
     */
    if (flow->l4.tcp.msn_stage == 0) {
        /* asymmetric detection to this pattern is asym (2) */
        if ((packet->payload_packet_len == 4 || packet->payload_packet_len == 8)
                && get_u32(packet->payload, 0) == htonl(0x04000000)) {
            MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "maybe first TCP MSN detected\n");

            if (packet->payload_packet_len == 8 && get_u32(packet->payload, 4) == htonl(0x666f6f00)) {
                flow->l4.tcp.msn_stage = 5 + ipacket->session->last_packet_direction;
                return;
            }

            flow->l4.tcp.msn_stage = 1 + ipacket->session->last_packet_direction;
            return;
        }
        /* asymmetric detection to this pattern is asym (2) */
    } else if (flow->l4.tcp.msn_stage == 1 + ipacket->session->last_packet_direction) {
        if (packet->payload_packet_len > 10 && get_u32(packet->payload, 0) == htonl(0x666f6f00)) {
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "MSN File Transfer detected 1\n");
            return;
        }
        /* did not see this pattern in any trace */
        if (packet->payload_packet_len == 56 && get_u32(packet->payload, 16) == 0) {
            MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "maybe Second TCP MSN detected\n");
            flow->l4.tcp.msn_stage = 3 + ipacket->session->last_packet_direction;
            return;
        }


    } else if (flow->l4.tcp.msn_stage == 2 - ipacket->session->last_packet_direction
            && packet->payload_packet_len == 4 && get_u32(packet->payload, 0) == htonl(0x30000000)) {
        mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
        MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "MSN File Transfer detected 2\n");
        return;
    } else if ((flow->l4.tcp.msn_stage == 3 + ipacket->session->last_packet_direction)
            || (flow->l4.tcp.msn_stage == 4 - ipacket->session->last_packet_direction)) {
        if (packet->payload_packet_len == 4 && get_u32(packet->payload, 0) == htonl(0x30000000)) {
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "MSN File Transfer detected 2\n");
            return;
        }
    } else if (flow->l4.tcp.msn_stage == 6 - ipacket->session->last_packet_direction) {
        if ((packet->payload_packet_len == 4) &&
                (get_u32(packet->payload, 0) == htonl(0x10000000) || get_u32(packet->payload, 0) == htonl(0x30000000))) {
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "MSN File Transfer detected 3\n");
            return;
        }
    } else if (flow->l4.tcp.msn_stage == 5 + ipacket->session->last_packet_direction) {
        if ((packet->payload_packet_len == 20) && get_u32(packet->payload, 0) == htonl(0x10000000)) {
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "MSN File Transfer detected 3\n");
            return;
        }
    }
    MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "msn 7.\n");
    if (ipacket->session->data_packet_count <= MAX_PACKETS_FOR_MSN) {
        if (packet->tcp->source == htons(443)
                || packet->tcp->dest == htons(443)) {
            if (packet->payload_packet_len > 300) {
                if (memcmp(&packet->payload[40], "INVITE MSNMSGR", 14) == 0
                        || memcmp(&packet->payload[56], "INVITE MSNMSGR", 14) == 0
                        || memcmp(&packet->payload[172], "INVITE MSNMSGR", 14) == 0) {
                    mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);

                    MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "MSN File Transfer detected 3\n");
                    return;
                }
            }
            return;
        }
        /* For no
           n port 443 flows exclude flow bitmask after first packet itself */
    }
    MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "exclude msn.\n");
ipq_msn_exclude:
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MSN);
}

static void mmt_search_udp_msn_misc(ipacket_t * ipacket) {
    
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;


    /* do we have an msn login ? */
    if ((src == NULL || MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_MSN) == 0)
            && (dst == NULL
            || MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_MSN) == 0)) {
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MSN);
        return;
    }

    /* asymmetric ft detection works */
    if (packet->payload_packet_len == 20
            && get_u32(packet->payload, 4) == 0 && packet->payload[9] == 0
            && get_u16(packet->payload, 10) == htons(0x0100)) {
        MMT_LOG(PROTO_MSN, MMT_LOG_TRACE, "msn udp misc data connection detected\n");
        mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
    }

    /* asymmetric detection working. */
    return;
    //}
}

void mmt_classify_me_msn(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    /* this if request should always be true */
    if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MSN) == 0) {
        /* we deal with tcp now */
        if (packet->tcp != NULL) {
            /* msn can use http or ssl for connection. That's why every http, ssl and ukn packet must enter in the msn detection */
            /* the detection can swich out the http or the ssl detection. In this case we need not check those protocols */
            // need to do the ceck when protocol == http too (POST /gateway ...)
            if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN
#if defined(PROTO_HTTP)
                    || packet->detected_protocol_stack[0] == PROTO_HTTP
#endif
#if defined(PROTO_SSL)
                    || packet->detected_protocol_stack[0] == PROTO_SSL
#endif
#if defined(PROTO_STUN)
                    || packet->detected_protocol_stack[0] == PROTO_STUN
#endif
                    ) {
                mmt_search_msn_tcp(ipacket);
            }
        } else if (packet->udp != NULL) {
            mmt_search_udp_msn_misc(ipacket);
        }
    }
}

int mmt_check_msn_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        /* this if request should always be true */
        if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MSN) == 0) {
            /* we deal with tcp now */
            /* msn can use http or ssl for connection. That's why every http, ssl and ukn packet must enter in the msn detection */
            /* the detection can swich out the http or the ssl detection. In this case we need not check those protocols */
            // need to do the ceck when protocol == http too (POST /gateway ...)
            if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                    || packet->detected_protocol_stack[0] == PROTO_HTTP
                    || packet->detected_protocol_stack[0] == PROTO_SSL
                    || packet->detected_protocol_stack[0] == PROTO_STUN
                    ) {
                mmt_search_msn_tcp(ipacket);
            }
        }
    }
    return 1;
}

int mmt_check_msn_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        /* this if request should always be true */
        if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MSN) == 0) {
            mmt_search_udp_msn_misc(ipacket);
        }
    }
    return 1;
}

void mmt_init_classify_me_msn() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MSN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SSL);
    MMT_BITMASK_RESET(excluded_protocol_bitmask);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_MSN);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_msn_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MSN, PROTO_MSN_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_msn();

        return register_protocol(protocol_struct, PROTO_MSN);
    } else {
        return 0;
    }
}


