#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void ntop_check_citrix(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = (struct mmt_tcpip_internal_packet_struct *) ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    /* unused
    const uint8_t *packet_payload = packet->payload;
    */
    uint32_t payload_len = packet->payload_packet_len;

#if 0
    printf("[len=%u][%02X %02X %02X %02X]\n", payload_len,
            packet->payload[0] & 0xFF,
            packet->payload[1] & 0xFF,
            packet->payload[2] & 0xFF,
            packet->payload[3] & 0xFF);
#endif

    if (packet->tcp != NULL) {
        flow->l4.tcp.citrix_packet_id++;

        if ((flow->l4.tcp.citrix_packet_id == 3)
                /* We have seen the 3-way handshake */
                && flow->l4.tcp.seen_syn
                && flow->l4.tcp.seen_syn_ack
                && flow->l4.tcp.seen_ack) {
            if (payload_len == 6) {
                char citrix_header[] = {0x07, 0x07, 0x49, 0x43, 0x41, 0x00};

                if (memcmp(packet->payload, citrix_header, sizeof (citrix_header)) == 0) {
                    MMT_LOG(PROTO_CITRIX, MMT_LOG_DEBUG, "Found citrix.\n");
                    mmt_internal_add_connection(ipacket, PROTO_CITRIX, MMT_REAL_PROTOCOL);
                }

                return;
            } else if (payload_len > 4) {
                char citrix_header[] = {0x1a, 0x43, 0x47, 0x50, 0x2f, 0x30, 0x31};

                if ((memcmp(packet->payload, citrix_header, sizeof (citrix_header)) == 0)
                 || (mmt_strncmp((const char*)packet->payload, "Citrix.TcpProxyService", payload_len) == 0)) {
                    MMT_LOG(PROTO_CITRIX, MMT_LOG_DEBUG, "Found citrix.\n");
                    mmt_internal_add_connection(ipacket, PROTO_CITRIX, MMT_REAL_PROTOCOL);
                }

                return;
            }


            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_CITRIX);
        } else if (flow->l4.tcp.citrix_packet_id > 3)
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_CITRIX);

        return;
    }
}

void mmt_classify_me_citrix(ipacket_t * ipacket, unsigned index) {
    MMT_LOG(PROTO_CITRIX, MMT_LOG_DEBUG, "citrix detection...\n");

    /* skip marked packets */
    if (((mmt_tcpip_internal_packet_t *) ipacket->internal_packet)->detected_protocol_stack[0] != PROTO_CITRIX)
        ntop_check_citrix(ipacket);
}

int mmt_check_citrix(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = (mmt_tcpip_internal_packet_t *) ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        uint32_t payload_len = packet->payload_packet_len;

        flow->l4.tcp.citrix_packet_id++;

        if ((flow->l4.tcp.citrix_packet_id == 3)
                /* We have seen the 3-way handshake */
                && flow->l4.tcp.seen_syn
                && flow->l4.tcp.seen_syn_ack
                && flow->l4.tcp.seen_ack) {
            if (payload_len == 6) {
                char citrix_header[] = {0x07, 0x07, 0x49, 0x43, 0x41, 0x00};

                if (memcmp(packet->payload, citrix_header, sizeof (citrix_header)) == 0) {
                    MMT_LOG(PROTO_CITRIX, MMT_LOG_DEBUG, "Found citrix.\n");
                    mmt_internal_add_connection(ipacket, PROTO_CITRIX, MMT_REAL_PROTOCOL);
                    return 1;
                }

                
            } else if (payload_len > 4) {
                char citrix_header[] = {0x1a, 0x43, 0x47, 0x50, 0x2f, 0x30, 0x31};

                if ((memcmp(packet->payload, citrix_header, sizeof (citrix_header)) == 0)
                 || (mmt_strncmp((const char*)packet->payload, "Citrix.TcpProxyService", payload_len) == 0)) {
                    MMT_LOG(PROTO_CITRIX, MMT_LOG_DEBUG, "Found citrix.\n");
                    mmt_internal_add_connection(ipacket, PROTO_CITRIX, MMT_REAL_PROTOCOL);
                    return 1;
                }

                
            }

            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_CITRIX);
        } else if (flow->l4.tcp.citrix_packet_id > 3) {
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_CITRIX);
        }

    }
    return 0;
}

void mmt_init_classify_me_citrix() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_CITRIX);
}


/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_citrix_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_CITRIX, PROTO_CITRIX_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_citrix();

        return register_protocol(protocol_struct, PROTO_CITRIX);
    } else {
        return 0;
    }
}


