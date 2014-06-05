#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_THUNDER_TIMEOUT                 30

static uint32_t thunder_timeout = MMT_THUNDER_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_thunder_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    mmt_internal_add_connection(ipacket, PROTO_THUNDER, protocol_type);

    if (src != NULL) {
        src->thunder_ts = packet->tick_timestamp;
    }
    if (dst != NULL) {
        dst->thunder_ts = packet->tick_timestamp;
    }
}



static void mmt_int_search_thunder_udp(ipacket_t * ipacket)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len > 8 && packet->payload[0] >= 0x30
            && packet->payload[0] < 0x40 && packet->payload[1] == 0 && packet->payload[2] == 0 && packet->payload[3] == 0) {
        if (flow->thunder_stage == 3) {
            MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG, "THUNDER udp detected\n");
            mmt_int_thunder_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        flow->thunder_stage++;
        MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG,
                "maybe thunder udp packet detected, stage increased to %u\n", flow->thunder_stage);
        return;
    }

    MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG,
            "excluding thunder udp at stage %u\n", flow->thunder_stage);

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_THUNDER);
}


static void mmt_int_search_thunder_tcp(ipacket_t * ipacket)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len > 8 && packet->payload[0] >= 0x30
            && packet->payload[0] < 0x40 && packet->payload[1] == 0 && packet->payload[2] == 0 && packet->payload[3] == 0) {
        if (flow->thunder_stage == 3) {
            MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG, "THUNDER tcp detected\n");
            mmt_int_thunder_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        flow->thunder_stage++;
        MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG,
                "maybe thunder tcp packet detected, stage increased to %u\n", flow->thunder_stage);
        return;
    }

    if (flow->thunder_stage == 0 && packet->payload_packet_len > 17
            && mmt_mem_cmp(packet->payload, "POST / HTTP/1.1\r\n", 17) == 0) {
        mmt_parse_packet_line_info(ipacket);

        MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG,
                "maybe thunder http POST packet detected, parsed packet lines: %u, empty line set %u (at: %u)\n",
                packet->parsed_lines, packet->empty_line_position_set, packet->empty_line_position);

        if (packet->empty_line_position_set != 0 &&
                packet->content_line.ptr != NULL &&
                packet->content_line.len == 24 &&
                mmt_mem_cmp(packet->content_line.ptr, "application/octet-stream",
                24) == 0 && packet->empty_line_position < (packet->payload_packet_len - 8)
                && packet->payload[packet->empty_line_position + 2] >= 0x30
                && packet->payload[packet->empty_line_position + 2] < 0x40
                && packet->payload[packet->empty_line_position + 3] == 0x00
                && packet->payload[packet->empty_line_position + 4] == 0x00
                && packet->payload[packet->empty_line_position + 5] == 0x00) {
            MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG,
                    "maybe thunder http POST packet application does match\n");
            mmt_int_thunder_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }
    }
    MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG,
            "excluding thunder tcp at stage %u\n", flow->thunder_stage);

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_THUNDER);
}


static void mmt_int_search_thunder_http(ipacket_t * ipacket)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    /* unused
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    */
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;


    if (packet->detected_protocol_stack[0] == PROTO_THUNDER) {
        if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - src->thunder_ts) < thunder_timeout)) {
            MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG,
                    "thunder : save src connection packet detected\n");
            src->thunder_ts = packet->tick_timestamp;
        } else if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - dst->thunder_ts) < thunder_timeout)) {
            MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG,
                    "thunder : save dst connection packet detected\n");
            dst->thunder_ts = packet->tick_timestamp;
        }
        return;
    }

    if (packet->payload_packet_len > 5
            && memcmp(packet->payload, "GET /", 5) == 0 && MMT_SRC_OR_DST_HAS_PROTOCOL(src, dst, PROTO_THUNDER)) {
        MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG, "HTTP packet detected.\n");
        mmt_parse_packet_line_info(ipacket);

        if (packet->parsed_lines > 7
                && packet->parsed_lines < 11
                && packet->line[1].len > 10
                && mmt_mem_cmp(packet->line[1].ptr, "Accept: */*", 11) == 0
                && packet->line[2].len > 22
                && mmt_mem_cmp(packet->line[2].ptr, "Cache-Control: no-cache",
                23) == 0 && packet->line[3].len > 16
                && mmt_mem_cmp(packet->line[3].ptr, "Connection: close", 17) == 0
                && packet->line[4].len > 6
                && mmt_mem_cmp(packet->line[4].ptr, "Host: ", 6) == 0
                && packet->line[5].len > 15
                && mmt_mem_cmp(packet->line[5].ptr, "Pragma: no-cache", 16) == 0
                && packet->user_agent_line.ptr != NULL
                && packet->user_agent_line.len > 49
                && mmt_mem_cmp(packet->user_agent_line.ptr,
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)", 50) == 0) {
            MMT_LOG(PROTO_THUNDER, MMT_LOG_DEBUG,
                    "Thunder HTTP download detected, adding flow.\n");
            mmt_int_thunder_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
        }
    }
}

void mmt_classify_me_thunder(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->tcp != NULL) {
        mmt_int_search_thunder_http(ipacket);
        mmt_int_search_thunder_tcp(ipacket);
    } else if (packet->udp != NULL) {
        mmt_int_search_thunder_udp(ipacket);
    }
}

int mmt_check_thunder_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_int_search_thunder_http(ipacket); //BW: TODO: avoid this double classification, if Thunder is detected in HTTP avoid checking in tcp
        mmt_int_search_thunder_tcp(ipacket);
    }
    return 1;
}

int mmt_check_thunder_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_int_search_thunder_udp(ipacket);

    }
    return 1;
}

void mmt_init_classify_me_thunder() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_THUNDER);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_thunder_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_THUNDER, PROTO_THUNDER_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_thunder();

        return register_protocol(protocol_struct, PROTO_THUNDER);
    } else {
        return 0;
    }
}


