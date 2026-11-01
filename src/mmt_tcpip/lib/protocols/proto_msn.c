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
            if (packet->line[i].ptr != NULL && packet->line[i].len > 5 &&
                    mmt_memcmp(packet->line[i].ptr, "X-MSN", 5) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* Result of a mmt_search_msn_tcp() stage: MSN_STAGE_CONTINUE falls through
 * to the next stage, MSN_STAGE_DONE is the original `return;` and
 * MSN_STAGE_EXCLUDE is the original `goto mmt_msn_exclude;`. */
enum msn_stage_result {
    MSN_STAGE_CONTINUE,
    MSN_STAGE_DONE,
    MSN_STAGE_EXCLUDE
};

/* First packet: STUN-like video pattern, "VER " handshake, Messenger agent. */
static enum msn_stage_result mmt_msn_first_packet_signatures(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    /* this part is working asymmetrically */
    if (packet->payload_packet_len > 32 && (packet->payload[0] == 0x02 || packet->payload[0] == 0x00)
            && (ntohl(get_u32(packet->payload, 8)) == 0x2112a442 || ntohl(get_u32(packet->payload, 4)) == 0x2112a442)
            && ((ntohl(get_u32(packet->payload, 24)) == 0x000f0004 && ntohl(get_u32(packet->payload, 28)) == 0x72c64bc6)
            || (ntohl(get_u32(packet->payload, 20)) == 0x000f0004
            && ntohl(get_u32(packet->payload, 24)) == 0x72c64bc6))) {

        /* The unverified alternative video pattern (payload[86..87] ==
         * 0x05dc) was never enabled and has been dropped. */
        mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
        /**
         * @brief V523 The 'then' statement is equivalent to the 'else' statement.
         * 
         */
        return MSN_STAGE_DONE;
    }

    /* this case works asymmetrically */
    if (packet->payload_packet_len > 10 && packet->payload_packet_len < 100) {
        if (get_u8(packet->payload, packet->payload_packet_len - 2) == 0x0d
                && get_u8(packet->payload, packet->payload_packet_len - 1) == 0x0a) {
            /* The MSNP string is used in XBOX clients. */
            if (mmt_memcmp(packet->payload, "VER ", 4) == 0) {

                if (mmt_memcmp(&packet->payload[packet->payload_packet_len - 6], "CVR",
                        3) == 0 || mmt_memcmp(&packet->payload[packet->payload_packet_len - 8], "MSNP", 4) == 0) {
                    mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
                    return MSN_STAGE_DONE;
                }
                if (mmt_memcmp(&packet->payload[4], "MSNFT", 5) == 0) {
                    mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
                    return MSN_STAGE_DONE;
                }
            }
        }
    }

    if (packet->payload_packet_len > 32 && (
#ifdef PROTO_HTTP
            packet->detected_protocol_stack[0] == PROTO_HTTP ||
#endif
            mmt_memcmp(packet->payload, "GET ", 4) == 0 ||
            mmt_memcmp(packet->payload, "POST ", 5) == 0)) {
        mmt_parse_packet_line_info(ipacket);
        if (packet->user_agent_line.ptr != NULL &&
                packet->user_agent_line.len > 10 &&
                mmt_memcmp(packet->user_agent_line.ptr, "Messenger/", 10) == 0) {
            mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return MSN_STAGE_DONE;
        }
    }
    return MSN_STAGE_CONTINUE;
}

/* First packet: HTTP login (Content-Type of the messenger). */
static enum msn_stage_result mmt_msn_first_packet_http_login(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

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
                mmt_memcmp(packet->payload, "POST http://", 12) == 0) {
            /* scan packet if not already done... */
            mmt_parse_packet_line_info(ipacket);

            if (packet->content_line.ptr != NULL &&
                    ((packet->content_line.len == 27 &&
                    mmt_memcmp(packet->content_line.ptr, "application/x-msn-messenger",
                    27) == 0) ||
                    (packet->content_line.len >= 14 &&
                    mmt_memcmp(packet->content_line.ptr, "text/x-msnmsgr",
                    14) == 0))) {
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return MSN_STAGE_DONE;
            }
        }
    }
    return MSN_STAGE_CONTINUE;
}

/* First packet: HTTP login through the messenger gateway. */
static enum msn_stage_result mmt_msn_first_packet_gateway(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    uint16_t status = 0;

    /* now test for http login that uses a gateway, at least 400 a bytes packet */
    /* for this case the asymmetric detection is asym (1) */
    if (packet->payload_packet_len > 400) {
        if ((
#ifdef PROTO_HTTP
                packet->detected_protocol_stack[0] == PROTO_HTTP ||
#endif
                (mmt_memcmp(packet->payload, "POST ", 5) == 0))) {
            uint16_t c;
            if (mmt_memcmp(&packet->payload[5], "http://", 7) == 0) {
                /*
                 * We are searching for a paten "POST http://gateway.messenger.hotmail.com/gateway/gateway.dll" or
                 * "POST http://<some ip addres here like 172.0.0.0>/gateway/gateway.dll"
                 * POST http:// is 12 byte so we are searching for 13 to 70 byte for this paten.
                 */
                for (c = 13; c < 50; c++) {
                    if (mmt_memcmp(&packet->payload[c], "/", 1) == 0) {
                        if (mmt_memcmp(&packet->payload[c], "/gateway/gateway.dll", 20) == 0) {
                            status = 1;
                            break;
                        }
                    }
                }
            } else if ((mmt_memcmp(&packet->payload[5], "/gateway/gateway.dll", 20) == 0)) {
                status = 1;
            }
        }
        if (status) {
            uint16_t a;

            mmt_parse_packet_line_info(ipacket);

            if (packet->content_line.ptr != NULL
                    &&
                    ((packet->content_line.len == 23
                    && mmt_memcmp(packet->content_line.ptr, "text/xml; charset=utf-8", 23) == 0)
                    ||
                    (packet->content_line.len == 24
                    && mmt_memcmp(packet->content_line.ptr, "text/html; charset=utf-8", 24) == 0)
                    ||
                    (packet->content_line.len == 33
                    && mmt_memcmp(packet->content_line.ptr, "application/x-www-form-urlencoded", 33) == 0)
                    )) {
                if ((src != NULL
                        && MMT_HOST_HAS_PROTOCOL(src, PROTO_MSN)
                        != 0) || (dst != NULL
                        && MMT_HOST_HAS_PROTOCOL(dst, PROTO_MSN)
                        != 0)) {
                    mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return MSN_STAGE_DONE;
                }
                for (a = 0; a < packet->parsed_lines; a++) {
                    if (packet->line[a].len >= 4 &&
                            (mmt_memcmp(packet->line[a].ptr, "CVR ", 4) == 0
                            || mmt_memcmp(packet->line[a].ptr, "VER ",
                            4) == 0 || mmt_memcmp(packet->line[a].ptr, "ANS ", 4) == 0)) {
                        mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                        return MSN_STAGE_DONE;
                    }
                }
            }
        }
    }
    return MSN_STAGE_CONTINUE;
}

/* First packet: proxy CONNECT and the "USR "/"ANS " login commands. */
static enum msn_stage_result mmt_msn_first_packet_proxy_login(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint16_t plen;

    /* did not find any trace with this pattern !!!!! */
    /* now block proxy connection */
    if (packet->payload_packet_len >= 42) {
        if (mmt_memcmp(packet->payload, "CONNECT messenger.hotmail.com:1863 HTTP/1.", 42) == 0) {
            mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return MSN_STAGE_DONE;
        }
    }

    if (packet->payload_packet_len >= 18) {

        if (mmt_memcmp(packet->payload, "USR ", 4) == 0 || mmt_memcmp(packet->payload, "ANS ", 4) == 0) {
            /* now we must see a number */
            const uint16_t endlen = packet->payload_packet_len - 12;
            plen = 4;
            while (1) {
                if (packet->payload[plen] == ' ') {
                    break;
                }
                if (packet->payload[plen] < '0' || packet->payload[plen] > '9') {
                    return MSN_STAGE_EXCLUDE;
                }
                plen++;
                if (plen >= endlen) {
                    return MSN_STAGE_EXCLUDE;
                }
            }

            while (plen < endlen) {
                if (mmt_check_for_email_address(ipacket, plen) != 0) {
                    break;
                }
                if (packet->payload_packet_len > plen + 1
                        && (packet->payload[plen] < 20 || packet->payload[plen] > 128)) {
                    return MSN_STAGE_EXCLUDE;
                }
                plen++;
                if (plen >= endlen) {
                    return MSN_STAGE_EXCLUDE;
                }

            }
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return MSN_STAGE_DONE;
        }
    }
    return MSN_STAGE_CONTINUE;
}

/* The checks run on the first packet of the flow only. */
static enum msn_stage_result mmt_msn_first_packet(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    enum msn_stage_result result;

    result = mmt_msn_first_packet_signatures(ipacket);
    if (result != MSN_STAGE_CONTINUE) {
        return result;
    }
    result = mmt_msn_first_packet_http_login(ipacket);
    if (result != MSN_STAGE_CONTINUE) {
        return result;
    }
    result = mmt_msn_first_packet_gateway(ipacket);
    if (result != MSN_STAGE_CONTINUE) {
        return result;
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
                (mmt_memcmp(packet->payload, "HTTP/1.0 200 OK", 15) == 0) ||
                (mmt_memcmp(packet->payload, "HTTP/1.1 200 OK", 15) == 0)
                ) {

            mmt_parse_packet_line_info(ipacket);

            if (packet->content_line.ptr != NULL &&
                    ((packet->content_line.len == 27 &&
                    mmt_memcmp(packet->content_line.ptr, "application/x-msn-messenger",
                    27) == 0) ||
                    (packet->content_line.len >= 14 &&
                    mmt_memcmp(packet->content_line.ptr, "text/x-msnmsgr",
                    14) == 0))) {
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return MSN_STAGE_DONE;
            }
            if (mmt_int_find_xmsn(ipacket) == 1) {
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return MSN_STAGE_DONE;
            }
        }
    }

    return mmt_msn_first_packet_proxy_login(ipacket);
}

/* Direct user connection: the MSN file transfer handshake. */
static enum msn_stage_result mmt_msn_file_transfer(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* MSN File Transfer of MSN 8.1 and 8.5
     * first packet with length 4 and pattern 0x04000000
     * second packet (in the same direction), with length 56 and pattern 0x00000000 from payload[16]
     * third packet (in the opposite direction to 1 & 2), with length 4 and pattern 0x30000000
     */
    if (flow->l4.tcp.msn_stage == 0) {
        /* asymmetric detection to this pattern is asym (2) */
        if ((packet->payload_packet_len == 4 || packet->payload_packet_len == 8)
                && get_u32(packet->payload, 0) == htonl(0x04000000)) {

            if (packet->payload_packet_len == 8 && get_u32(packet->payload, 4) == htonl(0x666f6f00)) {
                flow->l4.tcp.msn_stage = 5 + ipacket->session->last_packet_direction;
                return MSN_STAGE_DONE;
            }

            flow->l4.tcp.msn_stage = 1 + ipacket->session->last_packet_direction;
            return MSN_STAGE_DONE;
        }
        /* asymmetric detection to this pattern is asym (2) */
    } else if (flow->l4.tcp.msn_stage == 1 + ipacket->session->last_packet_direction) {
        if (packet->payload_packet_len > 10 && get_u32(packet->payload, 0) == htonl(0x666f6f00)) {
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return MSN_STAGE_DONE;
        }
        /* did not see this pattern in any trace */
        if (packet->payload_packet_len == 56 && get_u32(packet->payload, 16) == 0) {
            flow->l4.tcp.msn_stage = 3 + ipacket->session->last_packet_direction;
            return MSN_STAGE_DONE;
        }

    } else if (flow->l4.tcp.msn_stage == 2 - ipacket->session->last_packet_direction
            && packet->payload_packet_len == 4 && get_u32(packet->payload, 0) == htonl(0x30000000)) {
        mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
        return MSN_STAGE_DONE;
    } else if ((flow->l4.tcp.msn_stage == 3 + ipacket->session->last_packet_direction)
            || (flow->l4.tcp.msn_stage == 4 - ipacket->session->last_packet_direction)) {
        if (packet->payload_packet_len == 4 && get_u32(packet->payload, 0) == htonl(0x30000000)) {
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return MSN_STAGE_DONE;
        }
    } else if (flow->l4.tcp.msn_stage == 6 - ipacket->session->last_packet_direction) {
        if ((packet->payload_packet_len == 4) &&
                (get_u32(packet->payload, 0) == htonl(0x10000000) || get_u32(packet->payload, 0) == htonl(0x30000000))) {
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return MSN_STAGE_DONE;
        }
    } else if (flow->l4.tcp.msn_stage == 5 + ipacket->session->last_packet_direction) {
        if ((packet->payload_packet_len == 20) && get_u32(packet->payload, 0) == htonl(0x10000000)) {
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return MSN_STAGE_DONE;
        }
    }
    return MSN_STAGE_CONTINUE;
}

static void mmt_search_msn_tcp(ipacket_t * ipacket) {
    
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    /* we detect the initial connection only ! */
    /* match: "VER " ..... "CVR" x 0x0d 0x0a
     * len should be small, lets say less than 100 bytes
     * x is now "0", but can be increased
     */
    /* now we have a look at the first packet only. */
    if (ipacket->session->data_packet_count == 1) {
        enum msn_stage_result result = mmt_msn_first_packet(ipacket);

        if (result == MSN_STAGE_DONE) {
            return;
        }
        if (result == MSN_STAGE_EXCLUDE) {
            goto mmt_msn_exclude;
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
                (mmt_memcmp(packet->payload, "HTTP/1.0 200 OK", 15) == 0) ||
                (mmt_memcmp(packet->payload, "HTTP/1.1 200 OK", 15) == 0)
                ) {

            mmt_parse_packet_line_info(ipacket);

            if (packet->content_line.ptr != NULL &&
                    ((packet->content_line.len == 27 &&
                    mmt_memcmp(packet->content_line.ptr, "application/x-msn-messenger",
                    27) == 0) ||
                    (packet->content_line.len >= 14 &&
                    mmt_memcmp(packet->content_line.ptr, "text/x-msnmsgr", 14) == 0))) {
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
            if (mmt_int_find_xmsn(ipacket) == 1) {
                mmt_int_msn_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }
    }

    /* finished examining the secone packet only */
    /* direct user connection (file transfer,...) */

    if ((src != NULL && MMT_HOST_HAS_PROTOCOL(src, PROTO_MSN) != 0)
            || (dst != NULL
            && MMT_HOST_HAS_PROTOCOL(dst, PROTO_MSN) != 0)) {
        if (ipacket->session->data_packet_count == 1 &&
                packet->payload_packet_len > 12 && mmt_memcmp(packet->payload, "recipientid=", 12) == 0) {
            mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
    }

    if (mmt_msn_file_transfer(ipacket) == MSN_STAGE_DONE) {
        return;
    }
    if (ipacket->session->data_packet_count <= MAX_PACKETS_FOR_MSN) {
        if (packet->tcp->source == htons(443)
                || packet->tcp->dest == htons(443)) {
            if (packet->payload_packet_len > 300) {
                if (mmt_memcmp(&packet->payload[40], "INVITE MSNMSGR", 14) == 0
                        || mmt_memcmp(&packet->payload[56], "INVITE MSNMSGR", 14) == 0
                        || mmt_memcmp(&packet->payload[172], "INVITE MSNMSGR", 14) == 0) {
                    mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);

                    return;
                }
            }
            return;
        }
        /* For no
           n port 443 flows exclude flow bitmask after first packet itself */
    }
mmt_msn_exclude:
    MMT_EXCLUDE_PROTOCOL(flow, PROTO_MSN);
}

static void mmt_search_udp_msn_misc(ipacket_t * ipacket) {
    
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    /* do we have an msn login ? */
    if ((src == NULL || MMT_HOST_HAS_PROTOCOL(src, PROTO_MSN) == 0)
            && (dst == NULL
            || MMT_HOST_HAS_PROTOCOL(dst, PROTO_MSN) == 0)) {
        MMT_EXCLUDE_PROTOCOL(flow, PROTO_MSN);
        return;
    }

    /* asymmetric ft detection works */
    if (packet->payload_packet_len == 20
            && get_u32(packet->payload, 4) == 0 && packet->payload[9] == 0
            && get_u16(packet->payload, 10) == htons(0x0100)) {
        mmt_int_msn_add_connection(ipacket, MMT_REAL_PROTOCOL);
    }

    /* asymmetric detection working. */
    return;
    //}
}

int mmt_check_msn_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        /* this if request should always be true */
        if (MMT_FLOW_EXCLUDES(flow, PROTO_MSN) == 0) {
            /* we deal with tcp now */
            /* msn can use http for connection, so http and unknown packets
             * enter the msn detection (POST /gateway ...). Issue #540
             * (F-BUG-311): a flow already classified SSL is no longer
             * re-inspected for up to MAX_PACKETS_FOR_MSN packets — the
             * MSN-over-TLS signatures matched a service shut down in 2013. */
            if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                    || packet->detected_protocol_stack[0] == PROTO_HTTP
                    || packet->detected_protocol_stack[0] == PROTO_STUN
                    ) {
                mmt_search_msn_tcp(ipacket);
            }
        }
    }
    return 4;
}

int mmt_check_msn_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        /* this if request should always be true */
        if (MMT_FLOW_EXCLUDES(flow, PROTO_MSN) == 0) {
            mmt_search_udp_msn_misc(ipacket);
        }
    }
    return 4;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_msn_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MSN, PROTO_MSN_ALIAS);
    if (protocol_struct != NULL) {

        /* two detection adds (HTTP on top of MSN; SSL dropped by issue
         * #540) — beyond the single-add shape of mmt_init_classify_bitmasks().
         * The old wrapper's explicit MMT_BITMASK_RESET of the excluded mask
         * was redundant: MMT_SAVE_AS_BITMASK already zeroes every word. */
        mmt_init_classify_bitmasks_multi(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask,
                MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                (const uint32_t[]){PROTO_MSN, PROTO_HTTP}, 2,
                PROTO_MSN);

        return register_protocol(protocol_struct, PROTO_MSN);
    } else {
        return 0;
    }
}
