#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_BATTLEFIELD_TIMEOUT             60

static uint32_t battlefield_timeout = MMT_BATTLEFIELD_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_battlefield_add_connection(ipacket_t * ipacket)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    /* unused
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    */
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    mmt_internal_add_connection(ipacket, PROTO_BATTLEFIELD, MMT_REAL_PROTOCOL);

    if (src != NULL) {
        src->battlefield_ts = packet->tick_timestamp;
    }
    if (dst != NULL) {
        dst->battlefield_ts = packet->tick_timestamp;
    }
}

int mmt_check_battlefield(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

        if (packet->detected_protocol_stack[0] == PROTO_BATTLEFIELD) {
            if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->battlefield_ts) < battlefield_timeout)) {
                src->battlefield_ts = packet->tick_timestamp;
            } else if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->battlefield_ts) < battlefield_timeout)) {
                dst->battlefield_ts = packet->tick_timestamp;
            }
            return 4;
        }

        if (MMT_SRC_OR_DST_HAS_PROTOCOL(src, dst, PROTO_BATTLEFIELD)) {
            if (flow->l4.udp.battlefield_stage == 0 || flow->l4.udp.battlefield_stage == 1 + ipacket->session->last_packet_direction) {
                if (packet->payload_packet_len > 8 && get_u16(packet->payload, 0) == htons(0xfefd)) {
                    flow->l4.udp.battlefield_msg_id = get_u32(packet->payload, 2);
                    flow->l4.udp.battlefield_stage = 1 + ipacket->session->last_packet_direction;
                    return 4;
                }
            } else if (flow->l4.udp.battlefield_stage == 2 - ipacket->session->last_packet_direction) {
                if (packet->payload_packet_len > 8 && get_u32(packet->payload, 0) == flow->l4.udp.battlefield_msg_id) {
                    mmt_int_battlefield_add_connection(ipacket);
                    return 1;
                }
            }
        }

        if (flow->l4.udp.battlefield_stage == 0) {
            if (packet->payload_packet_len == 46 && packet->payload[2] == 0 && packet->payload[4] == 0
                    && get_u32(packet->payload, 7) == htonl(0x98001100)) {
                flow->l4.udp.battlefield_stage = 3 + ipacket->session->last_packet_direction;
                return 4;
            }
        } else if (flow->l4.udp.battlefield_stage == 4 - ipacket->session->last_packet_direction) {
            if (packet->payload_packet_len == 7
                    && (packet->payload[0] == 0x02 || packet->payload[packet->payload_packet_len - 1] == 0xe0)) {
                mmt_int_battlefield_add_connection(ipacket);
                return 1;
            }
        }

        if (packet->payload_packet_len == 18 && mmt_mem_cmp(&packet->payload[5], "battlefield2\x00", 13) == 0) {
            mmt_int_battlefield_add_connection(ipacket);
            return 1;
        } else if (packet->payload_packet_len > 10 &&
                (mmt_mem_cmp(packet->payload, "\x11\x20\x00\x01\x00\x00\x50\xb9\x10\x11", 10) == 0
                || mmt_mem_cmp(packet->payload, "\x11\x20\x00\x01\x00\x00\x30\xb9\x10\x11", 10) == 0
                || mmt_mem_cmp(packet->payload, "\x11\x20\x00\x01\x00\x00\xa0\x98\x00\x11", 10) == 0)) {
            mmt_int_battlefield_add_connection(ipacket);
            return 1;
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_BATTLEFIELD);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_battlefield_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_BATTLEFIELD, PROTO_BATTLEFIELD_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_BATTLEFIELD);

        return register_protocol(protocol_struct, PROTO_BATTLEFIELD);
    } else {
        return 0;
    }
}
