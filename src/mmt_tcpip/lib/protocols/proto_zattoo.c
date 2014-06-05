#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_ZATTOO_TIMEOUT                  120

static uint32_t zattoo_connection_timeout = MMT_ZATTOO_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_zattoo_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    mmt_internal_add_connection(ipacket, PROTO_ZATTOO, protocol_type);

    if (src != NULL) {
        src->zattoo_ts = packet->tick_timestamp;
    }
    if (dst != NULL) {
        dst->zattoo_ts = packet->tick_timestamp;
    }
}


static uint8_t mmt_int_zattoo_user_agent_set(ipacket_t * ipacket) {
    if (ipacket->internal_packet->user_agent_line.ptr != NULL && ((mmt_tcpip_internal_packet_t *) ipacket->internal_packet)->user_agent_line.len == 111) {
        if (memcmp(ipacket->internal_packet->user_agent_line.ptr +
                ipacket->internal_packet->user_agent_line.len - 25, "Zattoo/4", sizeof ("Zattoo/4") - 1) == 0) {
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "found zattoo useragent\n");
            return 1;
        }
    }
    return 0;
}

void mmt_classify_me_zattoo(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    uint16_t i;

    if (packet->detected_protocol_stack[0] == PROTO_ZATTOO) {
        if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - src->zattoo_ts) < zattoo_connection_timeout)) {
            src->zattoo_ts = packet->tick_timestamp;
        }
        if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - dst->zattoo_ts) < zattoo_connection_timeout)) {
            dst->zattoo_ts = packet->tick_timestamp;
        }
        return;
    }

    if (packet->tcp != NULL) {
        if (packet->payload_packet_len > 50 && memcmp(packet->payload, "GET /frontdoor/fd?brand=Zattoo&v=", 33) == 0) {
            MMT_LOG(PROTO_ZATTOO,
                    MMT_LOG_DEBUG, "add connection over tcp with pattern GET /frontdoor/fd?brand=Zattoo&v=\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len > 50
                && memcmp(packet->payload, "GET /ZattooAdRedirect/redirect.jsp?user=", 40) == 0) {
            MMT_LOG(PROTO_ZATTOO,
                    MMT_LOG_DEBUG, "add connection over tcp with pattern GET /ZattooAdRedirect/redirect.jsp?user=\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len > 50
                && (memcmp(packet->payload, "POST /channelserver/player/channel/update HTTP/1.1", 50) == 0
                || memcmp(packet->payload, "GET /epg/query", 14) == 0)) {
            mmt_parse_packet_line_info(ipacket);
            for (i = 0; i < packet->parsed_lines; i++) {
                if (packet->line[i].len >= 18 && (mmt_mem_cmp(packet->line[i].ptr, "User-Agent: Zattoo", 18) == 0)) {
                    MMT_LOG(PROTO_ZATTOO,
                            MMT_LOG_DEBUG,
                            "add connection over tcp with pattern POST /channelserver/player/channel/update HTTP/1.1\n");
                    mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
        } else if (packet->payload_packet_len > 50
                && (memcmp(packet->payload, "GET /", 5) == 0
                || memcmp(packet->payload, "POST /", MMT_STATICSTRING_LEN("POST /")) == 0)) {
            /* TODO to avoid searching currently only a specific length and offset is used
             * that might be changed later */
            mmt_parse_packet_line_info(ipacket);
            if (mmt_int_zattoo_user_agent_set(ipacket)) {
                mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        } else if (packet->payload_packet_len > 50 && memcmp(packet->payload, "POST http://", 12) == 0) {
            mmt_parse_packet_line_info(ipacket);
            // test for unique character of the zattoo header
            if (packet->parsed_lines == 4 && packet->host_line.ptr != NULL) {
                uint32_t ip;
                uint16_t bytes_read = 0;

                ip = mmt_bytestream_to_ipv4(&packet->payload[12], packet->payload_packet_len, &bytes_read);

                // and now test the firt 5 bytes of the payload for zattoo pattern
                if (ip == packet->iph->daddr
                        && packet->empty_line_position_set != 0
                        && ((packet->payload_packet_len - packet->empty_line_position) > 10)
                        && packet->payload[packet->empty_line_position + 2] ==
                        0x03
                        && packet->payload[packet->empty_line_position + 3] ==
                        0x04
                        && packet->payload[packet->empty_line_position + 4] ==
                        0x00
                        && packet->payload[packet->empty_line_position + 5] ==
                        0x04
                        && packet->payload[packet->empty_line_position + 6] ==
                        0x0a && packet->payload[packet->empty_line_position + 7] == 0x00) {
                    MMT_LOG(PROTO_ZATTOO,
                            MMT_LOG_DEBUG, "add connection over tcp with pattern POST http://\n");
                    mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return;
                }
            }
        } else if (flow->zattoo_stage == 0) {

            if (packet->payload_packet_len > 50
                    && packet->payload[0] == 0x03
                    && packet->payload[1] == 0x04
                    && packet->payload[2] == 0x00
                    && packet->payload[3] == 0x04 && packet->payload[4] == 0x0a && packet->payload[5] == 0x00) {
                flow->zattoo_stage = 1 + ipacket->session->last_packet_direction;
                MMT_LOG(PROTO_ZATTOO,
                        MMT_LOG_DEBUG, "need next packet, seen pattern 0x030400040a00\n");
                return;
            }
            /* the following is is searching for flash, not for zattoo. cust1 wants to do so. */
        } else if (flow->zattoo_stage == 2 - ipacket->session->last_packet_direction
                && packet->payload_packet_len > 50 && packet->payload[0] == 0x03 && packet->payload[1] == 0x04) {
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "add connection over tcp with 0x0304.\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        } else if (flow->zattoo_stage == 1 + ipacket->session->last_packet_direction) {
            if (packet->payload_packet_len > 500 && packet->payload[0] == 0x00 && packet->payload[1] == 0x00) {
                flow->zattoo_stage = 3 + ipacket->session->last_packet_direction;
                MMT_LOG(PROTO_ZATTOO,
                        MMT_LOG_DEBUG, "need next packet, seen pattern 0x0000\n");
                return;
            }
            if (packet->payload_packet_len > 50
                    && packet->payload[0] == 0x03
                    && packet->payload[1] == 0x04
                    && packet->payload[2] == 0x00
                    && packet->payload[3] == 0x04 && packet->payload[4] == 0x0a && packet->payload[5] == 0x00) {
            }
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG,
                    "need next packet, seen pattern 0x030400040a00\n");
            return;
        } else if (flow->zattoo_stage == 4 - ipacket->session->last_packet_direction
                && packet->payload_packet_len > 50 && packet->payload[0] == 0x03 && packet->payload[1] == 0x04) {
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "add connection over tcp with 0x0304.\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        } else if (flow->zattoo_stage == 5 + ipacket->session->last_packet_direction && (packet->payload_packet_len == 125)) {
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "detected zattoo.\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        } else if (flow->zattoo_stage == 6 - ipacket->session->last_packet_direction && packet->payload_packet_len == 1412) {
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "found zattoo.\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }
        MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG,
                "ZATTOO: discarted the flow (TCP): packet_size: %u; Flowstage: %u\n",
                packet->payload_packet_len, flow->zattoo_stage);

    } else if (packet->udp != NULL) {

        if (packet->payload_packet_len > 20 && (packet->udp->dest == htons(5003)
                || packet->udp->source == htons(5003))
                && (get_u16(packet->payload, 0) == htons(0x037a)
                || get_u16(packet->payload, 0) == htons(0x0378)
                || get_u16(packet->payload, 0) == htons(0x0305)
                || get_u32(packet->payload, 0) == htonl(0x03040004)
                || get_u32(packet->payload, 0) == htonl(0x03010005))) {
            if (++flow->zattoo_stage == 2) {
                MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "add connection over udp.\n");
                mmt_int_zattoo_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "need next packet udp.\n");
            return;
        }

        MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG,
                "ZATTOO: discarded the flow (UDP): packet_size: %u; Flowstage: %u\n",
                packet->payload_packet_len, flow->zattoo_stage);

    }

    MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "exclude zattoo.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_ZATTOO);
}

int mmt_check_zattoo_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

        uint16_t i;

        if (packet->detected_protocol_stack[0] == PROTO_ZATTOO) {
            if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->zattoo_ts) < zattoo_connection_timeout)) {
                src->zattoo_ts = packet->tick_timestamp;
            }
            if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->zattoo_ts) < zattoo_connection_timeout)) {
                dst->zattoo_ts = packet->tick_timestamp;
            }
            return 1;
        }

        if (packet->payload_packet_len > 50 && memcmp(packet->payload, "GET /frontdoor/fd?brand=Zattoo&v=", 33) == 0) {
            MMT_LOG(PROTO_ZATTOO,
                    MMT_LOG_DEBUG, "add connection over tcp with pattern GET /frontdoor/fd?brand=Zattoo&v=\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len > 50
                && memcmp(packet->payload, "GET /ZattooAdRedirect/redirect.jsp?user=", 40) == 0) {
            MMT_LOG(PROTO_ZATTOO,
                    MMT_LOG_DEBUG, "add connection over tcp with pattern GET /ZattooAdRedirect/redirect.jsp?user=\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len > 50
                && (memcmp(packet->payload, "POST /channelserver/player/channel/update HTTP/1.1", 50) == 0
                || memcmp(packet->payload, "GET /epg/query", 14) == 0)) {
            mmt_parse_packet_line_info(ipacket);
            for (i = 0; i < packet->parsed_lines; i++) {
                if (packet->line[i].len >= 18 && (mmt_mem_cmp(packet->line[i].ptr, "User-Agent: Zattoo", 18) == 0)) {
                    MMT_LOG(PROTO_ZATTOO,
                            MMT_LOG_DEBUG,
                            "add connection over tcp with pattern POST /channelserver/player/channel/update HTTP/1.1\n");
                    mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return 1;
                }
            }
        } else if (packet->payload_packet_len > 50
                && (memcmp(packet->payload, "GET /", 5) == 0
                || memcmp(packet->payload, "POST /", MMT_STATICSTRING_LEN("POST /")) == 0)) {
            /* TODO to avoid searching currently only a specific length and offset is used
             * that might be changed later */
            mmt_parse_packet_line_info(ipacket);
            if (mmt_int_zattoo_user_agent_set(ipacket)) {
                mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            }
        } else if (packet->payload_packet_len > 50 && memcmp(packet->payload, "POST http://", 12) == 0) {
            mmt_parse_packet_line_info(ipacket);
            // test for unique character of the zattoo header
            if (packet->parsed_lines == 4 && packet->host_line.ptr != NULL) {
                uint32_t ip;
                uint16_t bytes_read = 0;

                ip = mmt_bytestream_to_ipv4(&packet->payload[12], packet->payload_packet_len, &bytes_read);

                // and now test the firt 5 bytes of the payload for zattoo pattern
                if (ip == packet->iph->daddr
                        && packet->empty_line_position_set != 0
                        && ((packet->payload_packet_len - packet->empty_line_position) > 10)
                        && packet->payload[packet->empty_line_position + 2] ==
                        0x03
                        && packet->payload[packet->empty_line_position + 3] ==
                        0x04
                        && packet->payload[packet->empty_line_position + 4] ==
                        0x00
                        && packet->payload[packet->empty_line_position + 5] ==
                        0x04
                        && packet->payload[packet->empty_line_position + 6] ==
                        0x0a && packet->payload[packet->empty_line_position + 7] == 0x00) {
                    MMT_LOG(PROTO_ZATTOO,
                            MMT_LOG_DEBUG, "add connection over tcp with pattern POST http://\n");
                    mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return 1;
                }
            }
        } else if (flow->zattoo_stage == 0) {

            if (packet->payload_packet_len > 50
                    && packet->payload[0] == 0x03
                    && packet->payload[1] == 0x04
                    && packet->payload[2] == 0x00
                    && packet->payload[3] == 0x04 && packet->payload[4] == 0x0a && packet->payload[5] == 0x00) {
                flow->zattoo_stage = 1 + ipacket->session->last_packet_direction;
                MMT_LOG(PROTO_ZATTOO,
                        MMT_LOG_DEBUG, "need next packet, seen pattern 0x030400040a00\n");
                return 1;
            }
            /* the following is is searching for flash, not for zattoo. cust1 wants to do so. */
        } else if (flow->zattoo_stage == 2 - ipacket->session->last_packet_direction
                && packet->payload_packet_len > 50 && packet->payload[0] == 0x03 && packet->payload[1] == 0x04) {
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "add connection over tcp with 0x0304.\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return 1;
        } else if (flow->zattoo_stage == 1 + ipacket->session->last_packet_direction) {
            if (packet->payload_packet_len > 500 && packet->payload[0] == 0x00 && packet->payload[1] == 0x00) {
                flow->zattoo_stage = 3 + ipacket->session->last_packet_direction;
                MMT_LOG(PROTO_ZATTOO,
                        MMT_LOG_DEBUG, "need next packet, seen pattern 0x0000\n");
                return 1;
            }
            if (packet->payload_packet_len > 50
                    && packet->payload[0] == 0x03
                    && packet->payload[1] == 0x04
                    && packet->payload[2] == 0x00
                    && packet->payload[3] == 0x04 && packet->payload[4] == 0x0a && packet->payload[5] == 0x00) {
            }
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG,
                    "need next packet, seen pattern 0x030400040a00\n");
            return 1;
        } else if (flow->zattoo_stage == 4 - ipacket->session->last_packet_direction
                && packet->payload_packet_len > 50 && packet->payload[0] == 0x03 && packet->payload[1] == 0x04) {
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "add connection over tcp with 0x0304.\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return 1;
        } else if (flow->zattoo_stage == 5 + ipacket->session->last_packet_direction && (packet->payload_packet_len == 125)) {
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "detected zattoo.\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return 1;
        } else if (flow->zattoo_stage == 6 - ipacket->session->last_packet_direction && packet->payload_packet_len == 1412) {
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "found zattoo.\n");
            mmt_int_zattoo_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return 1;
        }
        MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG,
                "ZATTOO: discarted the flow (TCP): packet_size: %u; Flowstage: %u\n",
                packet->payload_packet_len, flow->zattoo_stage);

        MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "exclude zattoo.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_ZATTOO);
    }
    return 1;
}

int mmt_check_zattoo_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

        if (packet->detected_protocol_stack[0] == PROTO_ZATTOO) {
            if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->zattoo_ts) < zattoo_connection_timeout)) {
                src->zattoo_ts = packet->tick_timestamp;
            }
            if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->zattoo_ts) < zattoo_connection_timeout)) {
                dst->zattoo_ts = packet->tick_timestamp;
            }
            return 1;
        }

        if (packet->payload_packet_len > 20 && (packet->udp->dest == htons(5003)
                || packet->udp->source == htons(5003))
                && (get_u16(packet->payload, 0) == htons(0x037a)
                || get_u16(packet->payload, 0) == htons(0x0378)
                || get_u16(packet->payload, 0) == htons(0x0305)
                || get_u32(packet->payload, 0) == htonl(0x03040004)
                || get_u32(packet->payload, 0) == htonl(0x03010005))) {
            if (++flow->zattoo_stage == 2) {
                MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "add connection over udp.\n");
                mmt_int_zattoo_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
            MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "need next packet udp.\n");
            return 1;
        }

        MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG,
                "ZATTOO: discarded the flow (UDP): packet_size: %u; Flowstage: %u\n",
                packet->payload_packet_len, flow->zattoo_stage);

        MMT_LOG(PROTO_ZATTOO, MMT_LOG_DEBUG, "exclude zattoo.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_ZATTOO);

    }
    return 1;
}

void mmt_init_classify_me_zattoo() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ZATTOO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FLASH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_ZATTOO);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_zattoo_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_ZATTOO, PROTO_ZATTOO_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_zattoo();

        return register_protocol(protocol_struct, PROTO_ZATTOO);
    } else {
        return 0;
    }
}


