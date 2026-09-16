#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_IRC_TIMEOUT                     120

static uint32_t irc_timeout = MMT_IRC_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

#define MMT_IRC_FIND_LESS(time_err,less) {int t1 = 0;\
                                            MMT_INTERNAL_TIMESTAMP_TYPE timestamp = time_err[0];\
                                            for(t1=0;t1 < 16;t1++) {\
                                              if(timestamp > time_err[t1]) {\
                                                timestamp = time_err[t1];\
                                                less = t1;}}}

static void mmt_int_irc_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_IRC, MMT_REAL_PROTOCOL);
}


static uint8_t mmt_is_duplicate(struct mmt_internal_tcpip_id_struct *id_t, uint16_t port) {
    unsigned index = 0;
    while (index < id_t->irc_number_of_port) {
        if (port == id_t->irc_port[index])
            return 1;
        index++;
    }
    return 0;
}

static uint8_t mmt_check_for_NOTICE_or_PRIVMSG(ipacket_t * ipacket) {

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    uint16_t i;
    uint8_t number_of_lines_to_be_searched_for = 0;
    for (i = 0; i < packet->payload_packet_len - 7; i++) {
        if (packet->payload[i] == 'N' || packet->payload[i] == 'P') {
            if (mmt_memcmp(&packet->payload[i + 1], "OTICE ", 6) == 0 || mmt_memcmp(&packet->payload[i + 1], "RIVMSG ", 7) == 0) {
                MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "found NOTICE or PRIVMSG\n");
                return 1;
            }
        }
        if (packet->payload[i] == 0x0a) {
            number_of_lines_to_be_searched_for++;
            if (number_of_lines_to_be_searched_for == 2) {
                return 0;
            }
        }
    }
    return 0;

}

static uint8_t mmt_check_for_Nickname(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint16_t i, packetl = packet->payload_packet_len;

    if (packetl < 4) {
        return 0;
    }

    for (i = 0; i < (packetl - 4); i++) {
        if (packet->payload[i] == 'N' || packet->payload[i] == 'n') {
            if ((((packetl - (i + 1)) >= 4) && mmt_memcmp(&packet->payload[i + 1], "ick=", 4) == 0)
                    || (((packetl - (i + 1)) >= 8) && (mmt_memcmp(&packet->payload[i + 1], "ickname=", 8) == 0))
                    || (((packetl - (i + 1)) >= 8) && (mmt_memcmp(&packet->payload[i + 1], "ickName=", 8) == 0))) {
                MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "found HTTP IRC Nickname pattern\n");
                return 1;
            }
        }
    }
    return 0;
}

static uint8_t mmt_check_for_cmd(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint16_t i;

    if (packet->payload_packet_len < 4) {
        return 0;
    }

    for (i = 0; i < packet->payload_packet_len - 4; i++) {
        if (packet->payload[i] == 'c') {
            if (mmt_memcmp(&packet->payload[i + 1], "md=", 3) == 0) {
                MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "found HTTP IRC cmd pattern  \n");
                return 1;
            }
        }
    }
    return 0;
}

static uint8_t mmt_check_for_IRC_traces(const uint8_t * ptr, uint16_t len) {
    uint16_t i;

    if (len < 4) {
        return 0;
    }

    for (i = 0; i < len - 4; i++) {
        if (ptr[i] == 'i') {
            if (mmt_memcmp(&ptr[i + 1], "rc.", 3) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* IRC-over-SSL detection watches packet-length handshake signatures. Each
 * helper owns one signature family and returns 1 when it matched (the state
 * machine advanced or the flow was marked IRC), which stops the scan. */

/* case 1: len 1460, len 1460, len 1176 several times in one direction, than len = 4, 4096, 8192 in the other direction
 * case 2: len 1448, len 1448, len 1200 several times in one direction, than len = 4, 4096, 8192 in the other direction */
static uint8_t mmt_irc_ssl_detect_1460_1448(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* case 1: len 1460, len 1460, len 1176 several times in one direction, than len = 4, 4096, 8192 in the other direction */
    if (packet->payload_packet_len == 1460
            && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0) || (flow->l4.tcp.irc_stage2 == 3
            && flow->l4.tcp.irc_direction ==
            1 + ipacket->session->last_packet_direction))) {
        flow->l4.tcp.irc_stage2 = 1;
        flow->l4.tcp.irc_direction = 1 + ipacket->session->last_packet_direction;
        return 1;
    }
    if (packet->payload_packet_len == 1460 && flow->l4.tcp.irc_stage2 == 1
            && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction) {
        flow->l4.tcp.irc_stage2 = 2;
        return 1;
    }
    if (packet->payload_packet_len == 1176 && flow->l4.tcp.irc_stage2 == 2
            && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction) {
        flow->l4.tcp.irc_stage2 = 3;
        flow->l4.tcp.irc_0x1000_full = 1;
        return 1;
    }
    if (packet->payload_packet_len == 4 && (flow->l4.tcp.irc_stage2 == 3 || flow->l4.tcp.irc_0x1000_full == 1)
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && (ntohs(get_u16(packet->payload, 2)) == 0x1000
            || ntohs(get_u16(packet->payload, 2)) ==
            0x2000)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "IRC SSL detected: ->1460,1460,1176,<-4096||8192");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    /* case 2: len 1448, len 1448, len 1200 several times in one direction, than len = 4, 4096, 8192 in the other direction */
    if (packet->payload_packet_len == 1448
            && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0) || (flow->l4.tcp.irc_stage2 == 6
            && flow->l4.tcp.irc_direction ==
            1 + ipacket->session->last_packet_direction))) {
        flow->l4.tcp.irc_stage2 = 4;
        flow->l4.tcp.irc_direction = 1 + ipacket->session->last_packet_direction;
        MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "len = 1448 first\n");
        return 1;
    }
    if (packet->payload_packet_len == 1448 && flow->l4.tcp.irc_stage2 == 4
            && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction) {
        flow->l4.tcp.irc_stage2 = 5;
        MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "len = 1448 second \n");
        return 1;
    }
    if (packet->payload_packet_len == 1200 && flow->l4.tcp.irc_stage2 == 5
            && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction) {
        flow->l4.tcp.irc_stage2 = 6;
        flow->l4.tcp.irc_0x1000_full = 1;
        MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "len = 1200  \n");
        return 1;
    }
    if (packet->payload_packet_len == 4 && (flow->l4.tcp.irc_stage2 == 6 || flow->l4.tcp.irc_0x1000_full == 1)
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && (ntohs(get_u16(packet->payload, 2)) == 0x1000
            || ntohs(get_u16(packet->payload, 2)) ==
            0x2000)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "IRC SSL detected: ->1448,1448,1200,<-4096||8192");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    return 0;
}

/* case 3: several packets with len 1380, 1200, 1024, 1448, 1248,
 * than one packet in the other direction with the len or two times the len. */
static uint8_t mmt_irc_ssl_detect_echo_reply(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len == 1380 && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0)
            || (flow->l4.tcp.irc_stage2 == 7
            && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction))) {
        flow->l4.tcp.irc_stage2 = 7;
        flow->l4.tcp.irc_direction = 1 + ipacket->session->last_packet_direction;
        return 1;
    }
    if (packet->payload_packet_len == 4 && flow->l4.tcp.irc_stage2 == 7
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && (ntohs(get_u16(packet->payload, 2)) == 1380
            || ntohs(get_u16(packet->payload, 2)) ==
            2760)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "IRC SSL detected: ->1380,<-1380||2760");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    if (packet->payload_packet_len == 1200 && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0)
            || (flow->l4.tcp.irc_stage2 == 8
            && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction))) {
        flow->l4.tcp.irc_stage2 = 8;
        flow->l4.tcp.irc_direction = 1 + ipacket->session->last_packet_direction;
        return 1;
    }
    if (packet->payload_packet_len == 4 && flow->l4.tcp.irc_stage2 == 8
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && (ntohs(get_u16(packet->payload, 2)) == 1200
            || ntohs(get_u16(packet->payload, 2)) ==
            2400)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "IRC SSL detected: ->1200,<-1200||2400");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    if (packet->payload_packet_len == 1024 && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0)
            || (flow->l4.tcp.irc_stage2 == 9
            && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction))) {
        flow->l4.tcp.irc_stage2 = 9;
        flow->l4.tcp.irc_direction = 1 + ipacket->session->last_packet_direction;
        return 1;
    }
    if (packet->payload_packet_len == 4 && (flow->l4.tcp.irc_stage2 == 9 || flow->l4.tcp.irc_stage2 == 15)
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && (ntohs(get_u16(packet->payload, 2)) == 1024
            || ntohs(get_u16(packet->payload, 2)) ==
            2048)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "IRC SSL detected: ->1024,<-1024||2048");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    if (packet->payload_packet_len == 1248 && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0)
            || (flow->l4.tcp.irc_stage2 == 10
            && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction))) {
        flow->l4.tcp.irc_stage2 = 10;
        flow->l4.tcp.irc_direction = 1 + ipacket->session->last_packet_direction;
        return 1;
    }
    if (packet->payload_packet_len == 4 && flow->l4.tcp.irc_stage2 == 10
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && (ntohs(get_u16(packet->payload, 2)) == 1248
            || ntohs(get_u16(packet->payload, 2)) ==
            2496)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "IRC SSL detected: ->1248,<-1248||2496");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    if (packet->payload_packet_len == 1448
            && (flow->l4.tcp.irc_stage2 == 5 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 11;
        return 1;
    }
    if (packet->payload_packet_len == 4
            && (flow->l4.tcp.irc_stage2 == 4 || flow->l4.tcp.irc_stage2 == 5 || flow->l4.tcp.irc_stage2 == 11
            || flow->l4.tcp.irc_stage2 == 13)
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && (ntohs(get_u16(packet->payload, 2)) == 1448
            || ntohs(get_u16(packet->payload, 2)) ==
            2896)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "IRC SSL detected: ->1448,<-1448||2896");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    return 0;
}

/* case 4: five packets with len = 1448, one with len 952, than one packet from other direction len = 8192
 * case 5: len 1024, len 1448, len 1448, len 1200, len 1448, len 600 */
static uint8_t mmt_irc_ssl_detect_long_chain(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* case 4 : five packets with len = 1448, one with len 952, than one packet from other direction len = 8192 */
    if (packet->payload_packet_len == 1448
            && (flow->l4.tcp.irc_stage2 == 11 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 12;
        return 1;
    }
    if (packet->payload_packet_len == 1448
            && (flow->l4.tcp.irc_stage2 == 12 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 13;
        return 1;
    }
    if (packet->payload_packet_len == 952
            && (flow->l4.tcp.irc_stage2 == 13 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 14;
        return 1;
    }
    if (packet->payload_packet_len == 4
            && flow->l4.tcp.irc_stage2 == 14
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && ntohs(get_u16(packet->payload, 2)) == 8192) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                "IRC SSL detected: ->1448,1448,1448,1448,1448,952,<-8192");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    /* case 5: len 1024, len 1448, len 1448, len 1200, len 1448, len 600 */
    if (packet->payload_packet_len == 1448
            && (flow->l4.tcp.irc_stage2 == 9 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 15;
        return 1;
    }
    if (packet->payload_packet_len == 1448
            && (flow->l4.tcp.irc_stage2 == 15 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 16;
        return 1;
    }
    if (packet->payload_packet_len == 1200
            && (flow->l4.tcp.irc_stage2 == 16 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 17;
        return 1;
    }
    if (packet->payload_packet_len == 1448
            && (flow->l4.tcp.irc_stage2 == 17 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 18;
        return 1;
    }
    if (packet->payload_packet_len == 600
            && (flow->l4.tcp.irc_stage2 == 18 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 19;
        return 1;
    }
    if (packet->payload_packet_len == 4
            && flow->l4.tcp.irc_stage2 == 19
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && ntohs(get_u16(packet->payload, 2)) == 7168) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                "IRC SSL detected: ->1024,1448,1448,1200,1448,600,<-7168");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    /* -> 1024, 1380, -> 2404    */
    if (packet->payload_packet_len == 1380
            && (flow->l4.tcp.irc_stage2 == 9 && flow->l4.tcp.irc_direction == 1 + ipacket->session->last_packet_direction)) {
        flow->l4.tcp.irc_stage2 = 20;
        return 1;
    }
    if (packet->payload_packet_len == 4
            && flow->l4.tcp.irc_stage2 == 20
            && flow->l4.tcp.irc_direction == 2 - ipacket->session->last_packet_direction && ntohs(get_u16(packet->payload, 2)) == 2404) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "IRC SSL detected: ->1024,1380 <-2404");
        mmt_int_irc_add_connection(ipacket);
        return 1;

    }
    return 0;
}

uint8_t mmt_search_irc_ssl_detect(ipacket_t * ipacket) {

    MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "called mmt_search_irc_ssl_detect\n");

    if (mmt_irc_ssl_detect_1460_1448(ipacket)) {
        return 1;
    }
    if (mmt_irc_ssl_detect_echo_reply(ipacket)) {
        return 1;
    }
    if (mmt_irc_ssl_detect_long_chain(ipacket)) {
        return 1;
    }
    return 0;
}

/* Backward-compatible alias for the misspelled exported name ("ninty" and an
 * unverifiable accuracy claim). Kept for ABI stability; the canonical entry
 * point is mmt_search_irc_ssl_detect(). Removal release: 2.0.0. */
uint8_t mmt_search_irc_ssl_detect_ninty_percent_but_very_fast(ipacket_t * ipacket)
        __attribute__((deprecated("use mmt_search_irc_ssl_detect; removal in 2.0.0")));

uint8_t mmt_search_irc_ssl_detect_ninty_percent_but_very_fast(ipacket_t * ipacket) {
    return mmt_search_irc_ssl_detect(ipacket);
}

/* Refresh the per-host IRC timestamp when the flow is already detected. */
static void mmt_irc_touch_detected_peer(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = packet->src;
    struct mmt_internal_tcpip_id_struct *dst = packet->dst;

    if (packet->detected_protocol_stack[0] != PROTO_IRC) {
        return;
    }
    if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
            (packet->tick_timestamp - src->irc_ts) < irc_timeout)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "irc : save src connection packet detected\n");
        src->irc_ts = packet->tick_timestamp;
    } else if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
            (packet->tick_timestamp - dst->irc_ts) < irc_timeout)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "irc : save dst connection packet detected\n");
        dst->irc_ts = packet->tick_timestamp;
    }
}

/* Match the packet ports against the DCC ports remembered on a host that was
 * recently seen as IRC. Returns 1 when the flow was marked IRC (the caller
 * returns), 0 to keep detecting. */
static uint8_t mmt_irc_match_dcc_port(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = packet->src;
    struct mmt_internal_tcpip_id_struct *dst = packet->dst;
    uint16_t sport = 0;
    uint16_t dport = 0;
    uint16_t counter = 0;

    if (!(dst != NULL && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_IRC)
            && ((MMT_INTERNAL_TIMESTAMP_TYPE)
            (packet->tick_timestamp - dst->irc_ts)) <
            irc_timeout)
            && !(src != NULL
            &&
            MMT_COMPARE_PROTOCOL_TO_BITMASK
            (src->detected_protocol_bitmask, PROTO_IRC)
            && ((MMT_INTERNAL_TIMESTAMP_TYPE)
            (packet->tick_timestamp - src->irc_ts)) < irc_timeout)) {
        return 0;
    }
    if (packet->tcp != NULL) {
        sport = packet->tcp->source;
        dport = packet->tcp->dest;
    }
    if (dst != NULL) {
        for (counter = 0; counter < dst->irc_number_of_port; counter++) {
            if (dst->irc_port[counter] == sport || dst->irc_port[counter] == dport) {
                dst->last_time_port_used[counter] = packet->tick_timestamp;
                MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                        "dest port matched with the DCC port and the flow is marked as IRC");
                mmt_int_irc_add_connection(ipacket);
                return 1;
            }
        }
    }
    if (src != NULL) {
        for (counter = 0; counter < src->irc_number_of_port; counter++) {
            if (src->irc_port[counter] == sport || src->irc_port[counter] == dport) {
                src->last_time_port_used[counter] = packet->tick_timestamp;
                mmt_int_irc_add_connection(ipacket);
                MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                        "Source port matched with the DCC port and the flow is marked as IRC");
                return 1;
            }
        }
    }
    return 0;
}

/* Second packet of a session: scan the payload for one of the hard-coded
 * IRC server name traces (HTTP-proxied IRC landing pages). */
static void mmt_irc_scan_server_names(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    uint16_t c1 = 0;

    if (flow->detected_protocol_stack[0] == PROTO_IRC
            || ipacket->session->data_packet_count != 2
            || !(packet->payload_packet_len > 400 && packet->payload_packet_len < 1381)) {
        return;
    }
    for (c1 = 50; c1 < packet->payload_packet_len - 23; c1++) {
        if (packet->payload[c1] == 'i' || packet->payload[c1] == 'd') {
            if ((mmt_memcmp(&packet->payload[c1], "irc.hackthissite.org0", 21)
                    == 0)
                    || (mmt_memcmp(&packet->payload[c1], "irc.gamepad.ca1", 15) == 0)
                    || (mmt_memcmp(&packet->payload[c1], "dungeon.axenet.org0", 19)
                    == 0)
                    || (mmt_memcmp(&packet->payload[c1], "dazed.nuggethaus.net", 20)
                    == 0)
                    || (mmt_memcmp(&packet->payload[c1], "irc.indymedia.org", 17)
                    == 0)
                    || (mmt_memcmp(&packet->payload[c1], "irc.cccp-project.net", 20)
                    == 0)
                    || (mmt_memcmp(&packet->payload[c1], "dirc.followell.net0", 19)
                    == 0)
                    || (mmt_memcmp(&packet->payload[c1], "irc.discostars.de1", 18)
                    == 0)
                    || (mmt_memcmp(&packet->payload[c1], "irc.rizon.net", 13) == 0)) {
                MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                        "IRC SSL detected with :- irc.hackthissite.org0 | irc.gamepad.ca1 | dungeon.axenet.org0 "
                        "| dazed.nuggethaus.net | irc.indymedia.org | irc.discostars.de1 ");
                mmt_int_irc_add_connection(ipacket);
                break;
            }
        }
    }
}

/* Second-signal-word scan: a packet whose later lines still carry NICK or
 * USER is IRC. Single implementation for both line arrays — the caller
 * passes whichever one it just parsed (F-CLEAN-004). */
static uint8_t mmt_irc_line_has_second_signal(const struct mmt_int_one_line_struct *lines,
        uint16_t parsed) {
    uint16_t c = 0;
    for (c = 1; c < parsed; c++) {
        if (lines[c].len > 4 && (mmt_memcmp(lines[c].ptr, "NICK ", 5) == 0
                || mmt_memcmp(lines[c].ptr, "USER ", 5) == 0)) {
            return 1;
        }
    }
    return 0;
}

/* Remember a DCC port on the host struct: append while fewer than 16 are
 * stored, else evict the least-recently-used slot; a nonzero port refreshes
 * irc_ts either way. done_log is the side-specific debug tag (kept verbatim
 * so DEBUG builds print the same strings as before). */
static void mmt_irc_save_dcc_port(struct mmt_internal_tcpip_id_struct *host,
        uint16_t port, MMT_INTERNAL_TIMESTAMP_TYPE ts, const char *done_log) {
    (void) done_log;
    if (host->irc_number_of_port < 16 && port != 0) {
        if (!mmt_is_duplicate(host, port)) {
            host->irc_port[host->irc_number_of_port]
                    = port;
            host->irc_number_of_port++;
            MMT_LOG
                    (PROTO_IRC,

                    MMT_LOG_DEBUG, "found port=%d",
                    ntohs(get_u16(host->irc_port, 0)));
            MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "%s", done_log);
        }
        host->irc_ts = ts;
    } else if (port != 0 && host->irc_number_of_port == 16) {
        if (!mmt_is_duplicate(host, port)) {
            int less = 0;
            MMT_IRC_FIND_LESS(host->last_time_port_used, less);
            host->irc_port[less] = port;
            MMT_LOG
                    (PROTO_IRC,

                    MMT_LOG_DEBUG, "found port=%d",
                    ntohs(get_u16(host->irc_port, 0)));
        }
        host->irc_ts = ts;
    }
}

/* Read the decimal port token at pos in the line and remember it on src
 * and/or dst. Returns 1 when the caller stops scanning the line (a host
 * handled the port), 0 when both hosts are NULL. */
static uint8_t mmt_irc_read_dcc_ports(ipacket_t * ipacket, uint16_t line_idx, uint16_t pos) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = packet->src;
    struct mmt_internal_tcpip_id_struct *dst = packet->dst;
    uint16_t j = pos;
    uint16_t k = 0;
    uint16_t port = 0;

    if (src != NULL) {
        k = j;
        port =
                ntohs_mmt_bytestream_to_number
                (&packet->line[line_idx].ptr[j], packet->payload_packet_len - j, &j);
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "port %u.",
                port);
        j = k;
        // hier jetztberlegen, wie die ports abgespeichert werden sollen
        if (src->irc_number_of_port < 16)
            MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                "src->irc_number_of_port < 16.");
        mmt_irc_save_dcc_port(src, port, packet->tick_timestamp,
                "jjeeeeeeeeeeeeeeeeeeeeeeeee");
        if (dst == NULL) {
            return 1;
        }
    }
    if (dst != NULL) {
        port = ntohs_mmt_bytestream_to_number
                (&packet->line[line_idx].ptr[j], packet->payload_packet_len - j, &j);
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "port %u.",
                port);
        // hier das gleiche wie oben.
        /* hier werden 16 ports pro irc flows mitgespeichert. knnte man denn nicht ein-
         * fach an die dst oder src einen flag setzten, dass dieser port fr eine bestimmte
         * zeit ein irc-port bleibt?
         */
        mmt_irc_save_dcc_port(dst, port, packet->tick_timestamp,
                "juuuuuuuuuuuuuuuu");
        return 1;
    }
    return 0;
}

/* Scan one PRIVMSG line for ": ... DCC SEND|CHAT <args>" and harvest the
 * advertised port after the third space. *space is the running space count —
 * legacy behavior keeps it across lines and matches within a packet. */
static void mmt_irc_scan_dcc_args(ipacket_t * ipacket, uint16_t line_idx, uint16_t start,
        uint8_t * space) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint16_t j = 0;

    for (j = start; j < packet->line[line_idx].len - 9; j++) {
        if (packet->line[line_idx].ptr[j] != ':') {
            continue;
        }
        if (mmt_memcmp(&packet->line[line_idx].ptr[j + 1], "xdcc ", 5) == 0) {
            MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "xdcc should match.");
        }
        j += 2;
        if (mmt_memcmp(&packet->line[line_idx].ptr[j], "DCC ", 4) != 0) {
            continue;
        }
        j += 4;
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "found DCC.");
        if (!(mmt_memcmp(&packet->line[line_idx].ptr[j], "SEND ", 5) == 0
                || (mmt_memcmp(&packet->line[line_idx].ptr[j], "CHAT", 4) == 0)
                || (mmt_memcmp(&packet->line[line_idx].ptr[j], "chat", 4) == 0)
                || (mmt_memcmp(&packet->line[line_idx].ptr[j], "sslchat", 7) == 0)
                || (mmt_memcmp(&packet->line[line_idx].ptr[j], "TSEND", 5) == 0))) {
            continue;
        }
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                "found CHAT,chat,sslchat,TSEND.");
        j += 4;

        while (packet->line[line_idx].len > j &&
                ((packet->line[line_idx].ptr[j] >= 'a' && packet->line[line_idx].ptr[j] <= 'z')
                || (packet->line[line_idx].ptr[j] >= 'A' && packet->line[line_idx].ptr[j] <= 'Z')
                || (packet->line[line_idx].ptr[j] >= '0' && packet->line[line_idx].ptr[j] <= '9')
                || (packet->line[line_idx].ptr[j] == ' ')
                || (packet->line[line_idx].ptr[j] == '.')
                || (packet->line[line_idx].ptr[j] == '-'))) {

            if (packet->line[line_idx].ptr[j] == ' ') {
                (*space)++;
                MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "space %u.", *space);
            }
            if (*space == 3) {
                j++;
                MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "read port.");
                if (mmt_irc_read_dcc_ports(ipacket, line_idx, j)) {
                    break;
                }
            }
            j++;
        }
    }
}

/* detected_irc tail: the flow is already IRC — re-parse the lines and harvest
 * DCC SEND/CHAT ports. The inverted guard replaces the old wrapper `if`. */
static void mmt_irc_process_detected(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    uint16_t i = 0;
    uint16_t j = 0;
    uint16_t h = 0;
    uint8_t space = 0;
    uint8_t have_privmsg = 0;

    MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "detected_irc:");

    if (flow->detected_protocol_stack[0] != PROTO_IRC) {
        return;
    }
    if (packet->payload[packet->payload_packet_len - 2] != 0x0d
            && packet->payload[packet->payload_packet_len - 1] == 0x0a) {
        mmt_parse_packet_line_info_unix(ipacket);
        packet->parsed_lines = packet->parsed_unix_lines;
        for (i = 0; i < packet->parsed_lines; i++) {
            packet->line[i] = packet->unix_line[i];
            packet->line[i].ptr = packet->unix_line[i].ptr;
            packet->line[i].len = packet->unix_line[i].len;
        }
    } else if (packet->payload[packet->payload_packet_len - 2] == 0x0d) {
        mmt_parse_packet_line_info(ipacket);
    } else {
        return;
    }
    for (i = 0; i < packet->parsed_lines; i++) {
        if (packet->line[i].len > 6 && mmt_memcmp(packet->line[i].ptr, "NOTICE ", 7) == 0) {
            MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "NOTICE");
            for (j = 7; j < packet->line[i].len - 8; j++) {
                if (packet->line[i].ptr[j] == ':') {
                    if (mmt_memcmp(&packet->line[i].ptr[j + 1], "DCC SEND ", 9) == 0
                            || mmt_memcmp(&packet->line[i].ptr[j + 1], "DCC CHAT ", 9) == 0) {
                        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                                "found NOTICE and DCC CHAT or DCC SEND.");
                    }
                }
            }
        }
        have_privmsg = 0;
        if (packet->payload_packet_len > 0 && packet->payload[0] == 0x3a /* 0x3a = ':' */) {
            MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "3a");
            for (j = 1; j < packet->line[i].len - 9; j++) {
                if (packet->line[i].ptr[j] == ' ') {
                    j++;
                    if (packet->line[i].ptr[j] == 'P') {
                        MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "P");
                        j++;
                        if (mmt_memcmp(&packet->line[i].ptr[j], "RIVMSG ", 7) == 0)
                            MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "RIVMSG");
                        h = j + 7;
                        have_privmsg = 1;
                        break;
                    }
                }
            }
        }
        if (have_privmsg
                || (packet->line[i].len > 7 && (mmt_memcmp(packet->line[i].ptr, "PRIVMSG ", 8) == 0))) {
            if (!have_privmsg) {
                MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "PRIVMSG	");
                h = 7;
            }
            mmt_irc_scan_dcc_args(ipacket, i, h, &space);
        }
    }
}

/* Command-stage detection for not-yet-detected flows: count ':'-opened lines
 * (seven of them mean IRC) and spot the first USER/NICK/PASS/... command.
 * Returns 1 when classification must stop — the flow was just marked IRC
 * (the detected scan already ran from the 0x3a path, replacing the old
 * `goto detected_irc`) or a second signal word completed detection — and
 * 0 to keep going with the HTTP checks. */
static uint8_t mmt_irc_scan_command_stage(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    uint16_t i = 0;

    if (flow->detected_protocol_stack[0] == PROTO_IRC
            || ipacket->session->data_packet_count >= 20
            || packet->payload_packet_len < 8) {
        return 0;
    }
    if (get_u8(packet->payload, packet->payload_packet_len - 1) != 0x0a
            && (ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) != 0x0a00)) {
        return 0;
    }
    if (mmt_memcmp(packet->payload, ":", 1) == 0) {
        if (packet->payload[packet->payload_packet_len - 2] != 0x0d
                && packet->payload[packet->payload_packet_len - 1] == 0x0a) {
            mmt_parse_packet_line_info_unix(ipacket);
            packet->parsed_lines = packet->parsed_unix_lines;
            for (i = 0; i < packet->parsed_lines; i++) {
                packet->line[i] = packet->unix_line[i];
                packet->line[i].ptr = packet->unix_line[i].ptr;
                packet->line[i].len = packet->unix_line[i].len;
            }
        } else if (packet->payload[packet->payload_packet_len - 2] == 0x0d) {
            mmt_parse_packet_line_info(ipacket);
        } else {
            flow->l4.tcp.irc_3a_counter++;
        }
        for (i = 0; i < packet->parsed_lines; i++) {
            if (packet->line[i].ptr[0] == ':') {
                flow->l4.tcp.irc_3a_counter++;
                if (flow->l4.tcp.irc_3a_counter == 7) { /* ':' == 0x3a */
                    MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "0x3a. seven times. found irc.");
                    mmt_int_irc_add_connection(ipacket);
                    mmt_irc_process_detected(ipacket);
                    return 1;
                }
            }
        }
        if (flow->l4.tcp.irc_3a_counter == 7) { /* ':' == 0x3a */
            MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "0x3a. seven times. found irc.");
            mmt_int_irc_add_connection(ipacket);
            mmt_irc_process_detected(ipacket);
            return 1;
        }
    }
    if ((mmt_memcmp(packet->payload, "USER ", 5) == 0)
            || (mmt_memcmp(packet->payload, "NICK ", 5) == 0)
            || (mmt_memcmp(packet->payload, "PASS ", 5) == 0)
            || (mmt_memcmp(packet->payload, ":", 1) == 0 && mmt_check_for_NOTICE_or_PRIVMSG(ipacket) != 0)
            || (mmt_memcmp(packet->payload, "PONG ", 5) == 0)
            || (mmt_memcmp(packet->payload, "PING ", 5) == 0)
            || (mmt_memcmp(packet->payload, "JOIN ", 5) == 0)
            || (mmt_memcmp(packet->payload, "NOTICE ", 7) == 0)
            || (mmt_memcmp(packet->payload, "PRIVMSG ", 8) == 0)
            || (mmt_memcmp(packet->payload, "VERSION ", 8) == 0)) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                "USER, NICK, PASS, NOTICE, PRIVMSG one time");
        if (flow->l4.tcp.irc_stage == 2) {
            MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "found irc");
            mmt_int_irc_add_connection(ipacket);
            flow->l4.tcp.irc_stage = 3;
        }
        if (flow->l4.tcp.irc_stage == 1) {
            MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "second time, stage=2");
            flow->l4.tcp.irc_stage = 2;
        }
        if (flow->l4.tcp.irc_stage == 0) {
            MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "first time, stage=1");
            flow->l4.tcp.irc_stage = 1;
        }
        /* irc packets can have either windows line breaks (0d0a) or unix line breaks (0a) */
        if (packet->payload[packet->payload_packet_len - 2] == 0x0d
                && packet->payload[packet->payload_packet_len - 1] == 0x0a) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->parsed_lines > 1) {
                MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                        "packet contains more than one line");
                if (mmt_irc_line_has_second_signal(packet->line, packet->parsed_lines)) {
                    MMT_LOG(PROTO_IRC,
                            MMT_LOG_TRACE, "two icq signal words in the same packet");
                    mmt_int_irc_add_connection(ipacket);
                    flow->l4.tcp.irc_stage = 3;
                    return 1;
                }
            }
        } else if (packet->payload[packet->payload_packet_len - 1] == 0x0a) {
            mmt_parse_packet_line_info_unix(ipacket);
            if (packet->parsed_unix_lines > 1) {
                MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                        "packet contains more than one line");
                if (mmt_irc_line_has_second_signal(packet->unix_line, packet->parsed_unix_lines)) {
                    MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                            "two icq signal words in the same packet");
                    mmt_int_irc_add_connection(ipacket);
                    flow->l4.tcp.irc_stage = 3;
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* Web-IRC login over HTTP: a POST whose request line, URL or referer carries
 * an "irc." trace arms irc_stage and reports the POST-body offset through
 * *http_content_ptr_len. Returns 1 when the caller must return — the POST
 * body is not in this packet. */
static uint8_t mmt_irc_check_http_post(ipacket_t * ipacket, uint16_t * http_content_ptr_len) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    uint16_t http_header_len = 0;

    if (flow->detected_protocol_stack[0] == PROTO_IRC
            || flow->l4.tcp.irc_stage != 0
            || packet->payload_packet_len <= 5) {
        return 0;
    }
    //HTTP POST Method being employed
    if (mmt_memcmp(packet->payload, "POST ", 5) != 0) {
        return 0;
    }
    mmt_parse_packet_line_info(ipacket);
    if (!packet->parsed_lines) {
        return 0;
    }
    http_header_len = (packet->line[packet->parsed_lines - 1].ptr - packet->payload) + 2;
    if (packet->payload_packet_len > http_header_len) {
        *http_content_ptr_len = packet->payload_packet_len - http_header_len;
    }
    if ((mmt_check_for_IRC_traces(packet->line[0].ptr, packet->line[0].len))
            || ((packet->http_url_name.ptr)
            && (mmt_check_for_IRC_traces(packet->http_url_name.ptr, packet->http_url_name.len)))
            || ((packet->referer_line.ptr)
            && (mmt_check_for_IRC_traces(packet->referer_line.ptr, packet->referer_line.len)))) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE,
                "IRC detected from the Http URL/ Referer header ");
        flow->l4.tcp.irc_stage = 1;
        // HTTP POST Request body is not in the same packet.
        if (!*http_content_ptr_len) {
            return 1;
        }
    }
    return 0;
}

/* irc_stage == 1: a POST body carrying interface=/nickname or item=/cmd
 * completes the web-IRC login signature. Returns 1 when marked IRC. */
static uint8_t mmt_irc_check_http_login(ipacket_t * ipacket, uint16_t http_content_ptr_len) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (flow->detected_protocol_stack[0] == PROTO_IRC || flow->l4.tcp.irc_stage != 1) {
        return 0;
    }
    if ((((packet->payload_packet_len - http_content_ptr_len) > 10)
            && (mmt_memcmp(packet->payload + http_content_ptr_len, "interface=", 10) == 0)
            && (mmt_check_for_Nickname(ipacket) != 0))
            || (((packet->payload_packet_len - http_content_ptr_len) > 5)
            && (mmt_memcmp(packet->payload + http_content_ptr_len, "item=", 5) == 0)
            && (mmt_check_for_cmd(ipacket) != 0))) {
        MMT_LOG(PROTO_IRC, MMT_LOG_TRACE, "IRC Nickname, cmd,  one time");
        mmt_int_irc_add_connection(ipacket);
        return 1;
    }
    return 0;
}

void mmt_classify_irc_tcp(ipacket_t * ipacket, unsigned index) {

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    uint16_t http_content_ptr_len = 0;

    MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "irc : search irc\n");
    if (flow->detected_protocol_stack[0] != PROTO_IRC && ipacket->session->data_packet_count > 70) {
        MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "exclude irc, packet_counter > 70\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_IRC);
        return;
    }
    if (flow->detected_protocol_stack[0] != PROTO_IRC && ipacket->session->data_packet_count > 30 &&
            flow->l4.tcp.irc_stage2 == 0) {
        MMT_LOG(PROTO_IRC, MMT_LOG_DEBUG, "packet_counter > 30, exclude irc.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_IRC);
        return;
    }
    mmt_irc_touch_detected_peer(ipacket);

    if (mmt_irc_match_dcc_port(ipacket)) {
        return;
    }

    mmt_irc_scan_server_names(ipacket);

    if (flow->detected_protocol_stack[0] != PROTO_IRC &&
            mmt_search_irc_ssl_detect(ipacket) != 0) {
        return;
    }

    if (mmt_irc_scan_command_stage(ipacket)) {
        return;
    }

    /**
     * Trying to primarily detect the HTTP Web based IRC chat patterns based on the HTTP headers
     * during the User login time.When the HTTP data gets posted using the POST method ,patterns
     * will be searched in the HTTP content.
     */
    if (mmt_irc_check_http_post(ipacket, &http_content_ptr_len)) {
        return;
    }

    if (mmt_irc_check_http_login(ipacket, http_content_ptr_len)) {
        return;
    }

    mmt_irc_process_detected(ipacket);
}

int mmt_check_irc(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_irc_tcp(ipacket, index);
    }
    return 4;
}

void mmt_init_classify_me_irc() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_IRC);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_IRC);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_irc_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_IRC, PROTO_IRC_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_irc();

        return register_protocol(protocol_struct, PROTO_IRC);
    } else {
        return 0;
    }
}

