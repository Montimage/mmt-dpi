#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_MANOLITO_TIMEOUT                120

static uint32_t manolito_subscriber_timeout = MMT_MANOLITO_TIMEOUT; //Is this right or should this be multiplied by Micros in a sec???

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_manolito_add_connection(ipacket_t * ipacket) {

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    mmt_internal_add_connection(ipacket, PROTO_MANOLITO, MMT_REAL_PROTOCOL);


    if (src != NULL) {
        if (packet->udp != NULL) {
            src->manolito_last_pkt_arrival_time = packet->tick_timestamp;
        }
    }
    if (dst != NULL) {
        if (packet->udp != NULL) {
            dst->manolito_last_pkt_arrival_time = packet->tick_timestamp;
        }
    }
}

/*
  return 0 if nothing has been detected
  return 1 if it is a megaupload packet
 */
uint8_t search_manolito_tcp(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO TCP DETECTION\n");

    if (flow->l4.tcp.manolito_stage == 0 && packet->payload_packet_len > 6) {
        if (mmt_mem_cmp(packet->payload, "SIZ ", 4) != 0)
            goto end_manolito_nothing_found;

        flow->l4.tcp.manolito_stage = 1 + ipacket->session->last_packet_direction;
        MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO Stage 1.\n");
        goto end_manolito_maybe_hit;

    } else if ((flow->l4.tcp.manolito_stage == 2 - ipacket->session->last_packet_direction)
            && packet->payload_packet_len > 4) {
        if (mmt_mem_cmp(packet->payload, "STR ", 4) != 0)
            goto end_manolito_nothing_found;
        MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO Stage 2.\n");
        flow->l4.tcp.manolito_stage = 3 + ipacket->session->last_packet_direction;
        goto end_manolito_maybe_hit;

    } else if ((flow->l4.tcp.manolito_stage == 4 - ipacket->session->last_packet_direction) && packet->payload_packet_len > 5) {
        if (mmt_mem_cmp(packet->payload, "MD5 ", 4) != 0)
            goto end_manolito_nothing_found;
        MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO Stage 3.\n");
        flow->l4.tcp.manolito_stage = 5 + ipacket->session->last_packet_direction;
        goto end_manolito_maybe_hit;

    } else if ((flow->l4.tcp.manolito_stage == 6 - ipacket->session->last_packet_direction) && packet->payload_packet_len == 4) {

        if (mmt_mem_cmp(packet->payload, "GO!!", 4) != 0)
            goto end_manolito_nothing_found;
        MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO Stage 4.\n");
        goto end_manolito_found;
    }
    goto end_manolito_nothing_found;

end_manolito_found:
    MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO FOUND\n");
    mmt_int_manolito_add_connection(ipacket);
    return 1;

end_manolito_maybe_hit:
    MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO maybe hit.\n");
    return 4;

end_manolito_nothing_found:
    MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO NOTHING FOUND\n");
    return 0;
}

void mmt_classify_me_manolito(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;


    if (packet->tcp != NULL) {
        if (search_manolito_tcp(ipacket) != 0)
            return;
    } else if (packet->udp != NULL) {
        if (flow->detected_protocol_stack[0] == PROTO_MANOLITO) {
            if (src != NULL) {
                src->manolito_last_pkt_arrival_time = packet->tick_timestamp;
            }
            if (dst != NULL) {
                dst->manolito_last_pkt_arrival_time = packet->tick_timestamp;
            }
            return;
        } else if (packet->udp->source == htons(41170)
                || packet->udp->dest == htons(41170)) {
            if (src != NULL && src->manolito_last_pkt_arrival_time != 0
                    && (packet->tick_timestamp - src->manolito_last_pkt_arrival_time <
                    manolito_subscriber_timeout)) {
                MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO: UDP detected \n");
                mmt_int_manolito_add_connection(ipacket);
                return;
            } else if (src != NULL
                    && (packet->tick_timestamp - src->manolito_last_pkt_arrival_time) >=
                    manolito_subscriber_timeout) {
                src->manolito_last_pkt_arrival_time = 0;
            }

            if (dst != NULL && dst->manolito_last_pkt_arrival_time != 0
                    && (packet->tick_timestamp - dst->manolito_last_pkt_arrival_time <
                    manolito_subscriber_timeout)) {
                MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO: UDP detected \n");
                mmt_int_manolito_add_connection(ipacket);
                return;
            } else if (dst != NULL
                    && (packet->tick_timestamp - dst->manolito_last_pkt_arrival_time) >=
                    manolito_subscriber_timeout) {
                dst->manolito_last_pkt_arrival_time = 0;
            }

            if ((packet->payload_packet_len == 20 && htons(0x3d4b) == get_u16(packet->payload, 0)
                    && packet->payload[2] == 0xd9 && htons(0xedbb) == get_u16(packet->payload, 16))
                    || (packet->payload_packet_len == 25 && htons(0x3e4a) == get_u16(packet->payload, 0)
                    && htons(0x092f) == get_u16(packet->payload, 20) && packet->payload[22] == 0x20)
                    || (packet->payload_packet_len == 20 && !get_u16(packet->payload, 2) && !get_u32(packet->payload, 8)
                    && !get_u16(packet->payload, 18) && get_u16(packet->payload, 0))
                    ) { //20B pkt is For PING
                MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO: UDP detected \n");
                mmt_int_manolito_add_connection(ipacket);
                return;
            } else if (ipacket->session->data_packet_count < 7) {
                return;
            }
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MANOLITO);
}

int mmt_check_manolito_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (search_manolito_tcp(ipacket) != 0) {
            return 4;
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MANOLITO);
    }
    return 0;
}

int mmt_check_manolito_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

        if (flow->detected_protocol_stack[0] == PROTO_MANOLITO) {
            if (src != NULL) {
                src->manolito_last_pkt_arrival_time = packet->tick_timestamp;
            }
            if (dst != NULL) {
                dst->manolito_last_pkt_arrival_time = packet->tick_timestamp;
            }
            return 1;
        } else if (packet->udp->source == htons(41170)
                || packet->udp->dest == htons(41170)) {
            if (src != NULL && src->manolito_last_pkt_arrival_time != 0
                    && (packet->tick_timestamp - src->manolito_last_pkt_arrival_time <
                    manolito_subscriber_timeout)) {
                MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO: UDP detected \n");
                mmt_int_manolito_add_connection(ipacket);
                return 1;
            } else if (src != NULL
                    && (packet->tick_timestamp - src->manolito_last_pkt_arrival_time) >=
                    manolito_subscriber_timeout) {
                src->manolito_last_pkt_arrival_time = 0;
            }

            if (dst != NULL && dst->manolito_last_pkt_arrival_time != 0
                    && (packet->tick_timestamp - dst->manolito_last_pkt_arrival_time <
                    manolito_subscriber_timeout)) {
                MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO: UDP detected \n");
                mmt_int_manolito_add_connection(ipacket);
                return 1;
            } else if (dst != NULL
                    && (packet->tick_timestamp - dst->manolito_last_pkt_arrival_time) >=
                    manolito_subscriber_timeout) {
                dst->manolito_last_pkt_arrival_time = 0;
            }

            if ((packet->payload_packet_len == 20 && htons(0x3d4b) == get_u16(packet->payload, 0)
                    && packet->payload[2] == 0xd9 && htons(0xedbb) == get_u16(packet->payload, 16))
                    || (packet->payload_packet_len == 25 && htons(0x3e4a) == get_u16(packet->payload, 0)
                    && htons(0x092f) == get_u16(packet->payload, 20) && packet->payload[22] == 0x20)
                    || (packet->payload_packet_len == 20 && !get_u16(packet->payload, 2) && !get_u32(packet->payload, 8)
                    && !get_u16(packet->payload, 18) && get_u16(packet->payload, 0))
                    ) { //20B pkt is For PING
                MMT_LOG(PROTO_MANOLITO, MMT_LOG_DEBUG, "MANOLITO: UDP detected \n");
                mmt_int_manolito_add_connection(ipacket);
                return 1;
            } else if (ipacket->session->data_packet_count < 7) {
                return 4;
            }
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MANOLITO);
    }
    return 0;
}

void mmt_init_classify_me_manolito() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_MANOLITO);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_manolito_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MANOLITO, PROTO_MANOLITO_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_manolito();

        return register_protocol(protocol_struct, PROTO_MANOLITO);
    } else {
        return 0;
    }
}


