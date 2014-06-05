#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_i23v5_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_I23V5, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_i23v5(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint32_t i;
    uint32_t sum;

    MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "search i23v5.\n");

    /*
     * encryption of i23v5 is tricky:  the 7th bit of the first byte and the sescond bit of the second byte must be set.
     * Three lengths are written in three packets after 0x0d58, 0x0e58 and 0x0f58 but without a certain order.
     * The sum of the three packets is in another packet at any place.
     */

    if (packet->payload_packet_len > 7 && ((packet->payload[0] & 0x04) == 0x04 && (packet->payload[2] & 0x80) == 0x80)) {
        MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "found i23v5 handshake bits.\n");

        for (i = 3; i < packet->payload_packet_len - 5; i++) {
            if (packet->payload[i] == 0x0d && packet->payload[i + 1] == 0x58) {
                MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "found first i23v5 key len.\n");
                flow->i23v5_len1 = get_u32(packet->payload, i + 2);
                return;
            }
        }
        for (i = 3; i < packet->payload_packet_len - 5; i++) {
            if (packet->payload[i] == 0x0e && packet->payload[i + 1] == 0x58) {
                MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "found second i23v5 key len.\n");
                flow->i23v5_len2 = get_u32(packet->payload, i + 2);
                return;
            }
        }
        for (i = 3; i < packet->payload_packet_len - 5; i++) {
            if (packet->payload[i] == 0x0f && packet->payload[i + 1] == 0x58) {
                MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "found third i23v5 key len.\n");
                flow->i23v5_len3 = get_u32(packet->payload, i + 2);
                return;
            }
        }
        if (flow->i23v5_len1 != 0 && flow->i23v5_len2 != 0 && flow->i23v5_len3 != 0) {
            for (i = 3; i < packet->payload_packet_len - 5; i++) {
                sum = flow->i23v5_len1 + flow->i23v5_len2 + flow->i23v5_len3;
                if (get_u32(packet->payload, i) == sum) {
                    MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "key sum matches.\n");
                    mmt_i23v5_add_connection(ipacket);
                }

            }
        }
    }

    MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "exclude i23v5.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_I23V5);
}

int mmt_check_i23v5(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint32_t i;
        uint32_t sum;
        MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "search i23v5.\n");

        /*
         * encryption of i23v5 is tricky:  the 7th bit of the first byte and the sescond bit of the second byte must be set.
         * Three lengths are written in three packets after 0x0d58, 0x0e58 and 0x0f58 but without a certain order.
         * The sum of the three packets is in another packet at any place.
         */
        if (packet->payload_packet_len > 7 && ((packet->payload[0] & 0x04) == 0x04 && (packet->payload[2] & 0x80) == 0x80)) {
            MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "found i23v5 handshake bits.\n");

            for (i = 3; i < packet->payload_packet_len - 5; i++) {
                if (packet->payload[i] == 0x0d && packet->payload[i + 1] == 0x58) {
                    MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "found first i23v5 key len.\n");
                    flow->i23v5_len1 = get_u32(packet->payload, i + 2);
                    return 1;
                }
            }
            for (i = 3; i < packet->payload_packet_len - 5; i++) {
                if (packet->payload[i] == 0x0e && packet->payload[i + 1] == 0x58) {
                    MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "found second i23v5 key len.\n");
                    flow->i23v5_len2 = get_u32(packet->payload, i + 2);
                    return 1;
                }
            }
            for (i = 3; i < packet->payload_packet_len - 5; i++) {
                if (packet->payload[i] == 0x0f && packet->payload[i + 1] == 0x58) {
                    MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "found third i23v5 key len.\n");
                    flow->i23v5_len3 = get_u32(packet->payload, i + 2);
                    return 1;
                }
            }
            if (flow->i23v5_len1 != 0 && flow->i23v5_len2 != 0 && flow->i23v5_len3 != 0) {
                for (i = 3; i < packet->payload_packet_len - 5; i++) {
                    sum = flow->i23v5_len1 + flow->i23v5_len2 + flow->i23v5_len3;
                    if (get_u32(packet->payload, i) == sum) {
                        MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "key sum matches.\n");
                        mmt_i23v5_add_connection(ipacket);
                        return 1;
                    }

                }
            }
        }

        MMT_LOG(PROTO_I23V5, MMT_LOG_DEBUG, "exclude i23v5.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_I23V5);

    }
    return 1;
}

void mmt_init_classify_me_i23v5() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_I23V5);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_i23v5_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_I23V5, PROTO_I23V5_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_i23v5();

        return register_protocol(protocol_struct, PROTO_I23V5);
    } else {
        return 0;
    }
}


