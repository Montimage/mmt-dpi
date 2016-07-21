#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_mgcp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_MGCP, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_mgcp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* information about MGCP taken from http://en.wikipedia.org/wiki/MGCP */

    uint16_t pos = 4;

    if (packet->payload_packet_len < 8) {
        goto mgcp_excluded;
    }

    /* packet must end with 0x0d0a or with 0x0a */
    /* BW: If the packet is truncated, we must not access beyond the available portion.
     * Check only if the packet is not truncated */
    if (packet->l3_packet_len == packet->l3_captured_packet_len) {
        if (packet->payload[packet->payload_packet_len - 1] != 0x0a
                && get_u16(packet->payload, packet->payload_packet_len - 2) != htons(0x0d0a)) {
            goto mgcp_excluded;
        }
    }



    if (packet->payload[0] != 'A' && packet->payload[0] != 'C' && packet->payload[0] != 'D' &&
            packet->payload[0] != 'E' && packet->payload[0] != 'M' && packet->payload[0] != 'N' &&
            packet->payload[0] != 'R') {
        goto mgcp_excluded;
    }
    if (memcmp(packet->payload, "AUEP ", 5) != 0 && memcmp(packet->payload, "AUCX ", 5) != 0 &&
            memcmp(packet->payload, "CRCX ", 5) != 0 && memcmp(packet->payload, "DLCX ", 5) != 0 &&
            memcmp(packet->payload, "EPCF ", 5) != 0 && memcmp(packet->payload, "MDCX ", 5) != 0 &&
            memcmp(packet->payload, "NTFY ", 5) != 0 && memcmp(packet->payload, "RQNT ", 5) != 0 &&
            memcmp(packet->payload, "RSIP ", 5) != 0) {
        goto mgcp_excluded;
    }
    // now search for string "MGCP " in the rest of the message
    while ((pos + 5) < packet->payload_packet_len) {
        if (memcmp(&packet->payload[pos], "MGCP ", 5) == 0) {
            MMT_LOG(PROTO_MGCP, MMT_LOG_DEBUG, "MGCP match.\n");
            mmt_int_mgcp_add_connection(ipacket);
            return;
        }
        pos++;
    }

mgcp_excluded:
    MMT_LOG(PROTO_MGCP, MMT_LOG_DEBUG, "exclude MGCP.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MGCP);
}

int mmt_check_mgcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* information about MGCP taken from http://en.wikipedia.org/wiki/MGCP */
        uint16_t pos = 4;

        if (packet->payload_packet_len < 8) {
            goto mgcp_excluded;
        }

        /* packet must end with 0x0d0a or with 0x0a */
        /* BW: If the packet is truncated, we must not access beyond the available portion.
         * Check only if the packet is not truncated */
        if (packet->l3_packet_len == packet->l3_captured_packet_len) {
            if (packet->payload[packet->payload_packet_len - 1] != 0x0a
                    && get_u16(packet->payload, packet->payload_packet_len - 2) != htons(0x0d0a)) {
                goto mgcp_excluded;
            }
        }

        if (packet->payload[0] != 'A' && packet->payload[0] != 'C' && packet->payload[0] != 'D' &&
                packet->payload[0] != 'E' && packet->payload[0] != 'M' && packet->payload[0] != 'N' &&
                packet->payload[0] != 'R') {
            goto mgcp_excluded;
        }
        if (memcmp(packet->payload, "AUEP ", 5) != 0 && memcmp(packet->payload, "AUCX ", 5) != 0 &&
                memcmp(packet->payload, "CRCX ", 5) != 0 && memcmp(packet->payload, "DLCX ", 5) != 0 &&
                memcmp(packet->payload, "EPCF ", 5) != 0 && memcmp(packet->payload, "MDCX ", 5) != 0 &&
                memcmp(packet->payload, "NTFY ", 5) != 0 && memcmp(packet->payload, "RQNT ", 5) != 0 &&
                memcmp(packet->payload, "RSIP ", 5) != 0) {
            goto mgcp_excluded;
        }
        // now search for string "MGCP " in the rest of the message
        while ((pos + 5) < packet->payload_packet_len) {
            if (memcmp(&packet->payload[pos], "MGCP ", 5) == 0) {
                MMT_LOG(PROTO_MGCP, MMT_LOG_DEBUG, "MGCP match.\n");
                mmt_int_mgcp_add_connection(ipacket);
                return 1;
            }
            pos++;
        }

mgcp_excluded:
        MMT_LOG(PROTO_MGCP, MMT_LOG_DEBUG, "exclude MGCP.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MGCP);

    }
    return 0;
}

void mmt_init_classify_me_mgcp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_MGCP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_mgcp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MGCP, PROTO_MGCP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_mgcp();

        return register_protocol(protocol_struct, PROTO_MGCP);
    } else {
        return 0;
    }
}


