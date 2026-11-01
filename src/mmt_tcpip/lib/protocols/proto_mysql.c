#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_mysql_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_MYSQL, MMT_REAL_PROTOCOL);
}

int mmt_check_mysql(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 37 //min length
                && get_u16(packet->payload, 0) == packet->payload_packet_len - 4 //first 3 bytes are length
                && get_u8(packet->payload, 2) == 0x00 //3rd byte of packet length
                && get_u8(packet->payload, 3) == 0x00 //packet sequence number is 0 for startup packet
                && get_u8(packet->payload, 5) > 0x30 //server version > 0
                && get_u8(packet->payload, 5) < 0x37 //server version < 7
                && get_u8(packet->payload, 6) == 0x2e //dot
                ) {
            uint32_t a;
            for (a = 7; a + 31 < packet->payload_packet_len; a++) {
                if (packet->payload[a] == 0x00) {
                    if (get_u8(packet->payload, a + 13) == 0x00 //filler byte
                            && get_u64(packet->payload, a + 19) == 0x0ULL //13 more
                            && get_u32(packet->payload, a + 27) == 0x0 //filler bytes
                            && get_u8(packet->payload, a + 31) == 0x0) {
                        mmt_int_mysql_add_connection(ipacket);
                        return 1;
                    }
                    break;
                }
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_MYSQL);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_mysql_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MYSQL, PROTO_MYSQL_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_MYSQL);

        return register_protocol(protocol_struct, PROTO_MYSQL);
    } else {
        return 0;
    }
}
