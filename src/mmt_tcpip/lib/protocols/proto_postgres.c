#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_postgres_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_POSTGRES, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_postgres(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    //      struct mmt_id_struct         *src=mmt_struct->src;
    //      struct mmt_id_struct         *dst=mmt_struct->dst;

    uint16_t size;

    if (flow->l4.tcp.postgres_stage == 0) {
        //SSL
        if (packet->payload_packet_len > 7 &&
                packet->payload[4] == 0x04 &&
                packet->payload[5] == 0xd2 &&
                packet->payload[6] == 0x16 &&
                packet->payload[7] == 0x2f && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len) {
            flow->l4.tcp.postgres_stage = 1 + ipacket->session->last_packet_direction;
            return;
        }
        //no SSL
        if (packet->payload_packet_len > 7 &&
                //protocol version number - to be updated
                ntohl(get_u32(packet->payload, 4)) < 0x00040000 &&
                ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len) {
            flow->l4.tcp.postgres_stage = 3 + ipacket->session->last_packet_direction;
            return;
        }
    } else {
        if (flow->l4.tcp.postgres_stage == 2 - ipacket->session->last_packet_direction) {
            //SSL accepted
            if (packet->payload_packet_len == 1 && packet->payload[0] == 'S') {
                MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "PostgreSQL detected, SSL accepted.\n");
                mmt_int_postgres_add_connection(ipacket);
                return;
            }
            //SSL denied
            if (packet->payload_packet_len == 1 && packet->payload[0] == 'N') {
                MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "PostgreSQL detected, SSL denied.\n");
                mmt_int_postgres_add_connection(ipacket);
                return;
            }
        }
        //no SSL
        if (flow->l4.tcp.postgres_stage == 4 - ipacket->session->last_packet_direction)
            if (packet->payload_packet_len > 8 &&
                    ntohl(get_u32(packet->payload, 5)) < 10 &&
                    ntohl(get_u32(packet->payload, 1)) == packet->payload_packet_len - 1 && packet->payload[0] == 0x52) {
                MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "PostgreSQL detected, no SSL.\n");
                mmt_int_postgres_add_connection(ipacket);
                return;
            }
        if (flow->l4.tcp.postgres_stage == 6
                && ntohl(get_u32(packet->payload, 1)) == packet->payload_packet_len - 1 && packet->payload[0] == 'p') {
            MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "found postgres asymmetrically.\n");
            mmt_int_postgres_add_connection(ipacket);
            return;
        }
        if (flow->l4.tcp.postgres_stage == 5 && packet->payload[0] == 'R') {
            if (ntohl(get_u32(packet->payload, 1)) == packet->payload_packet_len - 1) {
                MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "found postgres asymmetrically.\n");
                mmt_int_postgres_add_connection(ipacket);
                return;
            }
            size = ntohl(get_u32(packet->payload, 1)) + 1;
            if (packet->payload[size - 1] == 'S') {
                if ((size + get_u32(packet->payload, (size + 1))) == packet->payload_packet_len) {
                    MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "found postgres asymmetrically.\n");
                    mmt_int_postgres_add_connection(ipacket);
                    return;
                }
            }
            size += get_u32(packet->payload, (size + 1)) + 1;
            if (packet->payload[size - 1] == 'S') {
                MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "found postgres asymmetrically.\n");
                mmt_int_postgres_add_connection(ipacket);
                return;
            }
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_POSTGRES);
}

int mmt_check_postgres(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint16_t size;

        if (flow->l4.tcp.postgres_stage == 0) {
            //SSL
            if (packet->payload_packet_len > 7 &&
                    packet->payload[4] == 0x04 &&
                    packet->payload[5] == 0xd2 &&
                    packet->payload[6] == 0x16 &&
                    packet->payload[7] == 0x2f && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len) {
                flow->l4.tcp.postgres_stage = 1 + ipacket->session->last_packet_direction;
                return 1;
            }
            //no SSL
            if (packet->payload_packet_len > 7 &&
                    //protocol version number - to be updated
                    ntohl(get_u32(packet->payload, 4)) < 0x00040000 &&
                    ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len) {
                flow->l4.tcp.postgres_stage = 3 + ipacket->session->last_packet_direction;
                return 1;
            }
        } else {
            if (flow->l4.tcp.postgres_stage == 2 - ipacket->session->last_packet_direction) {
                //SSL accepted
                if (packet->payload_packet_len == 1 && packet->payload[0] == 'S') {
                    MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "PostgreSQL detected, SSL accepted.\n");
                    mmt_int_postgres_add_connection(ipacket);
                    return 1;
                }
                //SSL denied
                if (packet->payload_packet_len == 1 && packet->payload[0] == 'N') {
                    MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "PostgreSQL detected, SSL denied.\n");
                    mmt_int_postgres_add_connection(ipacket);
                    return 1;
                }
            }
            //no SSL
            if (flow->l4.tcp.postgres_stage == 4 - ipacket->session->last_packet_direction)
                if (packet->payload_packet_len > 8 &&
                        ntohl(get_u32(packet->payload, 5)) < 10 &&
                        ntohl(get_u32(packet->payload, 1)) == packet->payload_packet_len - 1 && packet->payload[0] == 0x52) {
                    MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "PostgreSQL detected, no SSL.\n");
                    mmt_int_postgres_add_connection(ipacket);
                    return 1;
                }
            if (flow->l4.tcp.postgres_stage == 6
                    && ntohl(get_u32(packet->payload, 1)) == packet->payload_packet_len - 1 && packet->payload[0] == 'p') {
                MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "found postgres asymmetrically.\n");
                mmt_int_postgres_add_connection(ipacket);
                return 1;
            }
            if (flow->l4.tcp.postgres_stage == 5 && packet->payload[0] == 'R') {
                if (ntohl(get_u32(packet->payload, 1)) == packet->payload_packet_len - 1) {
                    MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "found postgres asymmetrically.\n");
                    mmt_int_postgres_add_connection(ipacket);
                    return 1;
                }
                size = ntohl(get_u32(packet->payload, 1)) + 1;
                if (packet->payload[size - 1] == 'S') {
                    if ((size + get_u32(packet->payload, (size + 1))) == packet->payload_packet_len) {
                        MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "found postgres asymmetrically.\n");
                        mmt_int_postgres_add_connection(ipacket);
                        return 1;
                    }
                }
                size += get_u32(packet->payload, (size + 1)) + 1;
                if (packet->payload[size - 1] == 'S') {
                    MMT_LOG(PROTO_POSTGRES, MMT_LOG_DEBUG, "found postgres asymmetrically.\n");
                    mmt_int_postgres_add_connection(ipacket);
                    return 1;
                }
            }
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_POSTGRES);
    }
    return 1;
}

void mmt_init_classify_me_postgres() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_POSTGRES);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_postgres_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_POSTGRES, PROTO_POSTGRES_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_postgres();

        return register_protocol(protocol_struct, PROTO_POSTGRES);
    } else {
        return 0;
    }
}


