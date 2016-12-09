#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_feidian_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_FEIDIAN, protocol_type);
}

void mmt_classify_me_feidian(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    if (packet->tcp != NULL) {
        if (packet->tcp->dest == htons(8080) && packet->payload_packet_len == 4
                && packet->payload[0] == 0x29 && packet->payload[1] == 0x1c
                && packet->payload[2] == 0x32 && packet->payload[3] == 0x01) {
            MMT_LOG(PROTO_FEIDIAN, MMT_LOG_DEBUG,
                    "Feidian: found the flow (TCP): packet_size: %u; Flowstage: %u\n",
                    packet->payload_packet_len, flow->l4.udp.feidian_stage);
            mmt_int_feidian_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        } else if (packet->payload_packet_len > 50 && memcmp(packet->payload, "GET /", 5) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->host_line.ptr != NULL && packet->host_line.len == 18
                    && memcmp(packet->host_line.ptr, "config.feidian.com", 18) == 0) {
                mmt_int_feidian_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }
        MMT_LOG(PROTO_FEIDIAN, MMT_LOG_DEBUG,
                "Feidian: discarted the flow (TCP): packet_size: %u; Flowstage: %u\n",
                packet->payload_packet_len, flow->l4.udp.feidian_stage);
    } else if (packet->udp != NULL) {
        if (ntohs(packet->udp->source) == 53124 || ntohs(packet->udp->dest) == 53124) {
            if (flow->l4.udp.feidian_stage == 0 && (packet->payload_packet_len == 112)
                    && packet->payload[0] == 0x1c && packet->payload[1] == 0x1c
                    && packet->payload[2] == 0x32 && packet->payload[3] == 0x01) {
                flow->l4.udp.feidian_stage = 1;
                return;
            } else if (flow->l4.udp.feidian_stage == 1
                    && (packet->payload_packet_len == 116 || packet->payload_packet_len == 112)
                    && packet->payload[0] == 0x1c
                    && packet->payload[1] == 0x1c && packet->payload[2] == 0x32 && packet->payload[3] == 0x01) {
                mmt_int_feidian_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
        MMT_LOG(PROTO_FEIDIAN, MMT_LOG_DEBUG,
                "Feidian: discarted the flow (UDP): packet_size: %u; Flowstage: %u\n",
                packet->payload_packet_len, flow->l4.udp.feidian_stage);
    }
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FEIDIAN);
}

int mmt_check_feidian_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->tcp->dest == htons(8080) && packet->payload_packet_len == 4
                && packet->payload[0] == 0x29 && packet->payload[1] == 0x1c
                && packet->payload[2] == 0x32 && packet->payload[3] == 0x01) {
            MMT_LOG(PROTO_FEIDIAN, MMT_LOG_DEBUG,
                    "Feidian: found the flow (TCP): packet_size: %u; Flowstage: %u\n",
                    packet->payload_packet_len, flow->l4.udp.feidian_stage);
            mmt_int_feidian_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        } else if (packet->payload_packet_len > 50 && memcmp(packet->payload, "GET /", 5) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->host_line.ptr != NULL && packet->host_line.len == 18
                    && memcmp(packet->host_line.ptr, "config.feidian.com", 18) == 0) {
                mmt_int_feidian_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            }
        }
        MMT_LOG(PROTO_FEIDIAN, MMT_LOG_DEBUG,
                "Feidian: discarted the flow (TCP): packet_size: %u; Flowstage: %u\n",
                packet->payload_packet_len, flow->l4.udp.feidian_stage);

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FEIDIAN);

    }
    return 0;
}

int mmt_check_feidian_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (ntohs(packet->udp->source) == 53124 || ntohs(packet->udp->dest) == 53124) {
            if (flow->l4.udp.feidian_stage == 0 && (packet->payload_packet_len == 112)
                    && packet->payload[0] == 0x1c && packet->payload[1] == 0x1c
                    && packet->payload[2] == 0x32 && packet->payload[3] == 0x01) {
                flow->l4.udp.feidian_stage = 1;
                return 4;
            } else if (flow->l4.udp.feidian_stage == 1
                    && (packet->payload_packet_len == 116 || packet->payload_packet_len == 112)
                    && packet->payload[0] == 0x1c
                    && packet->payload[1] == 0x1c && packet->payload[2] == 0x32 && packet->payload[3] == 0x01) {
                mmt_int_feidian_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
        }
        MMT_LOG(PROTO_FEIDIAN, MMT_LOG_DEBUG,
                "Feidian: discarted the flow (UDP): packet_size: %u; Flowstage: %u\n",
                packet->payload_packet_len, flow->l4.udp.feidian_stage);

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FEIDIAN);
    }
    return 0;
}

void mmt_init_classify_me_feidian() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FEIDIAN);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_feidian_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FEIDIAN, PROTO_FEIDIAN_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_feidian();

        return register_protocol(protocol_struct, PROTO_FEIDIAN);
    } else {
        return 0;
    }
}


