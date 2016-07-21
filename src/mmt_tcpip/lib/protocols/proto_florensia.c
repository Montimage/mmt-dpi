#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_florensia_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_FLORENSIA, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_florensia(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "search florensia.\n");

    if (packet->tcp != NULL) {
        if (packet->payload_packet_len == 5 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && packet->payload[2] == 0x65 && packet->payload[4] == 0xff) {
            if (flow->florensia_stage == 1) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia.\n");
                mmt_florensia_add_connection(ipacket);
                return;
            }
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return;
        }
        if (packet->payload_packet_len > 8 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && get_u16(packet->payload, 2) == htons(0x0201) && get_u32(packet->payload, 4) == htonl(0xFFFFFFFF)) {
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return;
        }
        if (packet->payload_packet_len == 406 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && packet->payload[2] == 0x63) {
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return;
        }
        if (packet->payload_packet_len == 12 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && get_u16(packet->payload, 2) == htons(0x0301)) {
            if (flow->florensia_stage == 1) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia.\n");
                mmt_florensia_add_connection(ipacket);
                return;
            }
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return;
        }

        if (flow->florensia_stage == 1) {
            if (packet->payload_packet_len == 8 && get_l16(packet->payload, 0) == packet->payload_packet_len
                    && get_u16(packet->payload, 2) == htons(0x0302) && get_u32(packet->payload, 4) == htonl(0xFFFFFFFF)) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia asymmetrically.\n");
                mmt_florensia_add_connection(ipacket);
                return;
            }
            if (packet->payload_packet_len == 24 && get_l16(packet->payload, 0) == packet->payload_packet_len
                    && get_u16(packet->payload, 2) == htons(0x0202)
                    && get_u32(packet->payload, packet->payload_packet_len - 4) == htonl(0xFFFFFFFF)) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia.\n");
                mmt_florensia_add_connection(ipacket);
                return;
            }
            if (ipacket->session->data_packet_count < 10 && get_l16(packet->payload, 0) == packet->payload_packet_len) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia.\n");
                return;
            }
        }
    }

    if (packet->udp != NULL) {
        if (flow->florensia_stage == 0 && packet->payload_packet_len == 6
                && get_u16(packet->payload, 0) == ntohs(0x0503) && get_u32(packet->payload, 2) == htonl(0xFFFF0000)) {
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return;
        }
        if (flow->florensia_stage == 1 && packet->payload_packet_len == 8
                && get_u16(packet->payload, 0) == ntohs(0x0500) && get_u16(packet->payload, 4) == htons(0x4191)) {
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia.\n");
            mmt_florensia_add_connection(ipacket);
            return;
        }
    }

    MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "exclude florensia.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FLORENSIA);
}

int mmt_check_florensia_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "search florensia.\n");

        if (packet->payload_packet_len == 5 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && packet->payload[2] == 0x65 && packet->payload[4] == 0xff) {
            if (flow->florensia_stage == 1) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia.\n");
                mmt_florensia_add_connection(ipacket);
                return 1;
            }
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return 1;
        }
        if (packet->payload_packet_len > 8 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && get_u16(packet->payload, 2) == htons(0x0201) && get_u32(packet->payload, 4) == htonl(0xFFFFFFFF)) {
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return 1;
        }
        if (packet->payload_packet_len == 406 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && packet->payload[2] == 0x63) {
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return 1;
        }
        if (packet->payload_packet_len == 12 && get_l16(packet->payload, 0) == packet->payload_packet_len
                && get_u16(packet->payload, 2) == htons(0x0301)) {
            if (flow->florensia_stage == 1) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia.\n");
                mmt_florensia_add_connection(ipacket);
                return 1;
            }
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return 1;
        }

        if (flow->florensia_stage == 1) {
            if (packet->payload_packet_len == 8 && get_l16(packet->payload, 0) == packet->payload_packet_len
                    && get_u16(packet->payload, 2) == htons(0x0302) && get_u32(packet->payload, 4) == htonl(0xFFFFFFFF)) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia asymmetrically.\n");
                mmt_florensia_add_connection(ipacket);
                return 1;
            }
            if (packet->payload_packet_len == 24 && get_l16(packet->payload, 0) == packet->payload_packet_len
                    && get_u16(packet->payload, 2) == htons(0x0202)
                    && get_u32(packet->payload, packet->payload_packet_len - 4) == htonl(0xFFFFFFFF)) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia.\n");
                mmt_florensia_add_connection(ipacket);
                return 1;
            }
            if (ipacket->session->data_packet_count < 10 && get_l16(packet->payload, 0) == packet->payload_packet_len) {
                MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia.\n");
                return 1;
            }
        }

        MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "exclude florensia.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FLORENSIA);
    }
    return 0;
}

int mmt_check_florensia_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "search florensia.\n");

        if (flow->florensia_stage == 0 && packet->payload_packet_len == 6
                && get_u16(packet->payload, 0) == ntohs(0x0503) && get_u32(packet->payload, 2) == htonl(0xFFFF0000)) {
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
            flow->florensia_stage = 1;
            return 1;
        }
        if (flow->florensia_stage == 1 && packet->payload_packet_len == 8
                && get_u16(packet->payload, 0) == ntohs(0x0500) && get_u16(packet->payload, 4) == htons(0x4191)) {
            MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "found florensia.\n");
            mmt_florensia_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_FLORENSIA, MMT_LOG_DEBUG, "exclude florensia.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FLORENSIA);
    }
    return 0;
}

void mmt_init_classify_me_florensia() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FLORENSIA);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_florensia_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FLORENSIA, PROTO_FLORENSIA_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_florensia();

        return register_protocol(protocol_struct, PROTO_FLORENSIA);
    } else {
        return 0;
    }
}


