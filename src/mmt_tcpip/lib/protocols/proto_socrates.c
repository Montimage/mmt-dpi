#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_socrates_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SOCRATES, MMT_REAL_PROTOCOL);
}

int mmt_check_socrates_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if (packet->payload_packet_len > 13 && packet->payload[0] == 0xfe
                && packet->payload[packet->payload_packet_len - 1] == 0x05) {
            if (packet->payload_packet_len == ntohl(get_u32(packet->payload, 2))) {
                if (mmt_memcmp(&packet->payload[6], "socrates", 8) == 0) {
                    mmt_socrates_add_connection(ipacket);
                    return 1;
                }
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_SOCRATES);
    }
    return 0;
}

int mmt_check_socrates_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if (packet->payload_packet_len > 9 && packet->payload[0] == 0xfe
                && packet->payload[packet->payload_packet_len - 1] == 0x05) {
            if (mmt_memcmp(&packet->payload[2], "socrates", 8) == 0) {
                mmt_socrates_add_connection(ipacket);
                return 1;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_SOCRATES);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_socrates_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SOCRATES, PROTO_SOCRATES_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_SOCRATES);

        return register_protocol(protocol_struct, PROTO_SOCRATES);
    } else {
        return 0;
    }
}
