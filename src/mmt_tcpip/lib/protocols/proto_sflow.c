#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

int mmt_check_sflow(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        MMT_LOG(PROTO_SFLOW, MMT_LOG_DEBUG, "sflow detection...\n");
        uint32_t payload_len = packet->payload_packet_len;

        /* sFlow v2/v5 datagram header: version(4) agent_address_type(4)
         * agent_address(4 for IPv4, 16 for IPv6) sub_agent_id(4, v5 only)
         * sequence(4) uptime(4) num_samples(4). Besides the version, the
         * address type must be 1 (IPv4) or 2 (IPv6) and the payload must
         * hold the header it implies (24/28 bytes for IPv4, 36/40 for IPv6):
         * a bare 00 00 00 02/05 prefix is common in other UDP payloads. */
        uint32_t addr_type = 0, min_len = 0;
        if (payload_len >= 24) {
            addr_type = ntohl(get_u32(packet->payload, 4));
            min_len = (addr_type == 2 ? 36 : 24) + (packet->payload[3] == 5 ? 4 : 0);
        }
        if ((payload_len >= 24)
                /* Version */
                && (packet->payload[0] == 0) && (packet->payload[1] == 0) && (packet->payload[2] == 0)
                && ((packet->payload[3] == 2) || (packet->payload[3] == 5))
                && (addr_type == 1 || addr_type == 2)
                && (payload_len >= min_len)) {
            MMT_LOG(PROTO_SFLOW, MMT_LOG_DEBUG, "Found sflow.\n");
            mmt_internal_add_connection(ipacket, PROTO_SFLOW, MMT_REAL_PROTOCOL);
            return 1;
        }
    }
    return 4;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_sflow_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SFLOW, PROTO_SFLOW_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
                PROTO_SFLOW, PROTO_SFLOW);

        return register_protocol(protocol_struct, PROTO_SFLOW);
    } else {
        return 0;
    }
}
