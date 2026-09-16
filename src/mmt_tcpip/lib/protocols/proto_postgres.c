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
                return 4;
            }
            //no SSL
            if (packet->payload_packet_len > 7 &&
                    //protocol version number - to be updated
                    ntohl(get_u32(packet->payload, 4)) < 0x00040000 &&
                    ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len) {
                flow->l4.tcp.postgres_stage = 3 + ipacket->session->last_packet_direction;
                return 4;
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
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_postgres_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_POSTGRES, PROTO_POSTGRES_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_POSTGRES);

        return register_protocol(protocol_struct, PROTO_POSTGRES);
    } else {
        return 0;
    }
}
