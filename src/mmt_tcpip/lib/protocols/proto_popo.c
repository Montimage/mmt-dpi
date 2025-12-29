#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_popo_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_POPO, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_popo(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    if (packet->tcp != NULL) {
        if ((packet->payload_packet_len == 20)
                && get_u32(packet->payload, 0) == htonl(0x0c000000)
                && get_u32(packet->payload, 4) == htonl(0x01010000)
                && get_u32(packet->payload, 8) == htonl(0x06000000)
                && get_u32(packet->payload, 12) == 0 && get_u32(packet->payload, 16) == 0) {
            MMT_LOG(PROTO_POPO, MMT_LOG_DEBUG, "POPO detected\n");
            mmt_int_popo_add_connection(ipacket);
            return;
        }

        if (MMT_SRC_OR_DST_HAS_PROTOCOL(src, dst, PROTO_POPO) != 0) {
#define MMT_POPO_IP_SUBNET_START ( (220 << 24) + (181 << 16) + (28 << 8) + 220)
#define MMT_POPO_IP_SUBNET_END ( (220 << 24) + (181 << 16) + (28 << 8) + 238)

            /* may match the first payload ip packet only ... */

            if (ntohl(packet->iph->daddr) >= MMT_POPO_IP_SUBNET_START
                    && ntohl(packet->iph->daddr) <= MMT_POPO_IP_SUBNET_END) {
                MMT_LOG(PROTO_POPO, MMT_LOG_DEBUG, "POPO ip subnet detected\n");
                mmt_int_popo_add_connection(ipacket);
                return;
            }
        }
    }

    if (packet->payload_packet_len > 13 && packet->payload_packet_len == get_l32(packet->payload, 0)
            && !get_l16(packet->payload, 12)) {
        register uint16_t ii;
        for (ii = 14; ii < 50 && ii < packet->payload_packet_len - 8; ++ii) {
            if (packet->payload[ii] == '@')
                if (!mmt_memcmp(&packet->payload[ii + 1], "163.com", 7)
                        || (ii <= packet->payload_packet_len - 13 && !mmt_memcmp(&packet->payload[ii + 1], "popo.163.com", 12))) {
                    MMT_LOG(PROTO_POPO, MMT_LOG_DEBUG, "POPO  detected.\n");
                    mmt_int_popo_add_connection(ipacket);
                    return;
                }
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_POPO);
}

int mmt_check_popo(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_popo(ipacket, index);
    }
    return 4;
}

void mmt_init_classify_me_popo() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_POPO);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_popo_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_POPO, PROTO_POPO_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_popo();

        return register_protocol(protocol_struct, PROTO_POPO);
    } else {
        return 0;
    }
}
