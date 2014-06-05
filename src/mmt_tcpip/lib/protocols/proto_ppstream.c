#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ppstream_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_PPSTREAM, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_ppstream(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    // struct mmt_id_struct *src=mmt_struct->src;
    // struct mmt_id_struct *dst=mmt_struct->dst;



    /* check TCP Connections -> Videodata */
    if (packet->tcp != NULL) {
        if (packet->payload_packet_len >= 60 && get_u32(packet->payload, 52) == 0
                && memcmp(packet->payload, "PSProtocol\x0", 11) == 0) {
            MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG, "found ppstream over tcp.\n");
            mmt_int_ppstream_add_connection(ipacket);
            return;
        }
    }

    if (packet->udp != NULL) {
        if (packet->payload_packet_len > 2 && packet->payload[2] == 0x43
                && ((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
                || (packet->payload_packet_len == get_l16(packet->payload, 0))
                || (packet->payload_packet_len >= 6 && packet->payload_packet_len - 6 == get_l16(packet->payload, 0)))) {
            flow->l4.udp.ppstream_stage++;
            if (flow->l4.udp.ppstream_stage == 5) {
                MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG,
                        "found ppstream over udp pattern len, 43.\n");
                mmt_int_ppstream_add_connection(ipacket);
                return;
            }
            return;
        }

        if (flow->l4.udp.ppstream_stage == 0
                && packet->payload_packet_len > 4 && ((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
                || (packet->payload_packet_len == get_l16(packet->payload, 0))
                || (packet->payload_packet_len >= 6
                && packet->payload_packet_len - 6 == get_l16(packet->payload,
                0)))) {

            if (packet->payload[2] == 0x00 && packet->payload[3] == 0x00 && packet->payload[4] == 0x03) {
                flow->l4.udp.ppstream_stage = 7;
                MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG, "need next packet I.\n");
                return;
            }
        }

        if (flow->l4.udp.ppstream_stage == 7
                && packet->payload_packet_len > 4 && packet->payload[3] == 0x00
                && ((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
                || (packet->payload_packet_len == get_l16(packet->payload, 0))
                || (packet->payload_packet_len >= 6 && packet->payload_packet_len - 6 == get_l16(packet->payload, 0)))
                && (packet->payload[2] == 0x00 && packet->payload[4] == 0x03)) {
            MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG,
                    "found ppstream over udp with pattern Vb.\n");
            mmt_int_ppstream_add_connection(ipacket);
            return;
        }




    }

    MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG, "exclude ppstream.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_PPSTREAM);
}

int mmt_check_ppstream_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* check TCP Connections -> Videodata */
        if (packet->payload_packet_len >= 60 && get_u32(packet->payload, 52) == 0
                && memcmp(packet->payload, "PSProtocol\x0", 11) == 0) {
            MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG, "found ppstream over tcp.\n");
            mmt_int_ppstream_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG, "exclude ppstream.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_PPSTREAM);

    }
    return 1;
}

int mmt_check_ppstream_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 2 && packet->payload[2] == 0x43
                && ((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
                || (packet->payload_packet_len == get_l16(packet->payload, 0))
                || (packet->payload_packet_len >= 6 && packet->payload_packet_len - 6 == get_l16(packet->payload, 0)))) {
            flow->l4.udp.ppstream_stage++;
            if (flow->l4.udp.ppstream_stage == 5) {
                MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG,
                        "found ppstream over udp pattern len, 43.\n");
                mmt_int_ppstream_add_connection(ipacket);
                return 1;
            }
            return 1;
        }

        if (flow->l4.udp.ppstream_stage == 0
                && packet->payload_packet_len > 4 && ((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
                || (packet->payload_packet_len == get_l16(packet->payload, 0))
                || (packet->payload_packet_len >= 6
                && packet->payload_packet_len - 6 == get_l16(packet->payload,
                0)))) {

            if (packet->payload[2] == 0x00 && packet->payload[3] == 0x00 && packet->payload[4] == 0x03) {
                flow->l4.udp.ppstream_stage = 7;
                MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG, "need next packet I.\n");
                return 1;
            }
        }

        if (flow->l4.udp.ppstream_stage == 7
                && packet->payload_packet_len > 4 && packet->payload[3] == 0x00
                && ((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
                || (packet->payload_packet_len == get_l16(packet->payload, 0))
                || (packet->payload_packet_len >= 6 && packet->payload_packet_len - 6 == get_l16(packet->payload, 0)))
                && (packet->payload[2] == 0x00 && packet->payload[4] == 0x03)) {
            MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG,
                    "found ppstream over udp with pattern Vb.\n");
            mmt_int_ppstream_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_PPSTREAM, MMT_LOG_DEBUG, "exclude ppstream.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_PPSTREAM);

    }
    return 1;
}

void mmt_init_classify_me_ppstream() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_PPSTREAM);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ppstream_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_PPSTREAM, PROTO_PPSTREAM_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_ppstream();

        return register_protocol(protocol_struct, PROTO_PPSTREAM);
    } else {
        return 0;
    }
}


