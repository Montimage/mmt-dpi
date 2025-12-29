#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_armagetron_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_ARMAGETRON, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_armagetron(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "search armagetron.\n");


    if (packet->payload_packet_len > 10) {
        /* login request */
        if (get_u32(packet->payload, 0) == htonl(0x000b0000)) {
            const uint16_t dataLength = ntohs(get_u16(packet->payload, 4));
            if (dataLength == 0 || dataLength * 2 + 8 != packet->payload_packet_len)
                goto exclude;
            if (get_u16(packet->payload, 6) == htons(0x0008)
                    && get_u16(packet->payload, packet->payload_packet_len - 2) == 0) {
                MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "detected armagetron.\n");
                mmt_int_armagetron_add_connection(ipacket);
                return;
            }
        }
        /* sync_msg */
        if (packet->payload_packet_len == 16 && get_u16(packet->payload, 0) == htons(0x001c)
                && get_u16(packet->payload, 2) != 0) {
            const uint16_t dataLength = ntohs(get_u16(packet->payload, 4));
            if (dataLength != 4)
                goto exclude;
            if (get_u32(packet->payload, 6) == htonl(0x00000500) && get_u32(packet->payload, 6 + 4) == htonl(0x00010000)
                    && get_u16(packet->payload, packet->payload_packet_len - 2) == 0) {
                MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "detected armagetron.\n");
                mmt_int_armagetron_add_connection(ipacket);
                return;
            }
        }

        /* net_sync combination */
        if (packet->payload_packet_len > 50 && get_u16(packet->payload, 0) == htons(0x0018)
                && get_u16(packet->payload, 2) != 0) {
            uint16_t val;
            const uint16_t dataLength = ntohs(get_u16(packet->payload, 4));
            if (dataLength == 0 || dataLength * 2 + 8 > packet->payload_packet_len)
                goto exclude;
            val = get_u16(packet->payload, 6 + 2);
            if (val == get_u16(packet->payload, 6 + 6)) {
                val = ntohs(get_u16(packet->payload, 6 + 8));
                if ((6 + 10 + val + 4) < packet->payload_packet_len
                        && (get_u32(packet->payload, 6 + 10 + val) == htonl(0x00010000)
                        || get_u32(packet->payload, 6 + 10 + val) == htonl(0x00000001))
                        && get_u16(packet->payload, packet->payload_packet_len - 2) == 0) {
                    MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "detected armagetron.\n");
                    mmt_int_armagetron_add_connection(ipacket);
                    return;
                }
            }
        }
    }

exclude:
    MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "exclude armagetron.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_ARMAGETRON);
}

int mmt_check_armagetron(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "search armagetron.\n");

        if (packet->payload_packet_len > 10) {
            /* login request */
            if (get_u32(packet->payload, 0) == htonl(0x000b0000)) {
                const uint16_t dataLength = ntohs(get_u16(packet->payload, 4));
                if (dataLength == 0 || dataLength * 2 + 8 != packet->payload_packet_len)
                    goto exclude;
                if (get_u16(packet->payload, 6) == htons(0x0008)
                        && get_u16(packet->payload, packet->payload_packet_len - 2) == 0) {
                    MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "detected armagetron.\n");
                    mmt_int_armagetron_add_connection(ipacket);
                    return 1;
                }
            }
            /* sync_msg */
            if (packet->payload_packet_len == 16 && get_u16(packet->payload, 0) == htons(0x001c)
                    && get_u16(packet->payload, 2) != 0) {
                const uint16_t dataLength = ntohs(get_u16(packet->payload, 4));
                if (dataLength != 4)
                    goto exclude;
                if (get_u32(packet->payload, 6) == htonl(0x00000500) && get_u32(packet->payload, 6 + 4) == htonl(0x00010000)
                        && get_u16(packet->payload, packet->payload_packet_len - 2) == 0) {
                    MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "detected armagetron.\n");
                    mmt_int_armagetron_add_connection(ipacket);
                    return 1;
                }
            }

            /* net_sync combination */
            if (packet->payload_packet_len > 50 && get_u16(packet->payload, 0) == htons(0x0018)
                    && get_u16(packet->payload, 2) != 0) {
                uint16_t val;
                const uint16_t dataLength = ntohs(get_u16(packet->payload, 4));
                if (dataLength == 0 || dataLength * 2 + 8 > packet->payload_packet_len)
                    goto exclude;
                val = get_u16(packet->payload, 6 + 2);
                if (val == get_u16(packet->payload, 6 + 6)) {
                    val = ntohs(get_u16(packet->payload, 6 + 8));
                    if ((6 + 10 + val + 4) < packet->payload_packet_len
                            && (get_u32(packet->payload, 6 + 10 + val) == htonl(0x00010000)
                            || get_u32(packet->payload, 6 + 10 + val) == htonl(0x00000001))
                            && get_u16(packet->payload, packet->payload_packet_len - 2) == 0) {
                        MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "detected armagetron.\n");
                        mmt_int_armagetron_add_connection(ipacket);
                        return 1;
                    }
                }
            }
        }

exclude:
        MMT_LOG(PROTO_ARMAGETRON, MMT_LOG_DEBUG, "exclude armagetron.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_ARMAGETRON);
    }
    return 0;
}

void mmt_init_classify_me_armagetron() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_ARMAGETRON);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_armagetron_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_ARMAGETRON, PROTO_ARMAGETRON_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_armagetron();

        return register_protocol(protocol_struct, PROTO_ARMAGETRON);
    } else {
        return 0;
    }
}
