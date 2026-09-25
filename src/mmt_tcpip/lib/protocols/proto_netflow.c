#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

int mmt_check_netflow(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        MMT_LOG(PROTO_NETFLOW, MMT_LOG_DEBUG, "netflow detection...\n");
        uint32_t payload_len = packet->payload_packet_len;

        /* NetFlow v5/v9: version(2) count(2) sys_uptime(4) unix_secs(4) ...
         * the export time is the unix_secs field at offset 8. */
        if ((payload_len >= 24)
                && (packet->payload[0] == 0)
                && ((packet->payload[1] == 5)
                || (packet->payload[1] == 9))
                && (packet->payload[3] <= 48 /* Flow count */)) {
            uint32_t when = ntohl(get_u32(packet->payload, 8)); /* unix_secs */

            if (when >= 946684800 /* 1/1/2000 */) {
                MMT_LOG(PROTO_NETFLOW, MMT_LOG_DEBUG, "Found netflow.\n");
                mmt_internal_add_connection(ipacket, PROTO_NETFLOW, MMT_REAL_PROTOCOL);
                return 1;
            }
        }
        /* IPFIX (RFC 7011, version 10) has a different header: version(2)
         * length(2) export_time(4) ... — the length covers the whole message
         * (one per datagram) and the export time sits at offset 4. */
        if ((payload_len >= 16)
                && (packet->payload[0] == 0)
                && (packet->payload[1] == 10)
                && (ntohs(get_u16(packet->payload, 2)) == payload_len)
                && (ntohl(get_u32(packet->payload, 4)) >= 946684800 /* 1/1/2000 */)) {
            MMT_LOG(PROTO_NETFLOW, MMT_LOG_DEBUG, "Found IPFIX.\n");
            mmt_internal_add_connection(ipacket, PROTO_NETFLOW, MMT_REAL_PROTOCOL);
            return 1;
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(packet->flow->excluded_protocol_bitmask, PROTO_NETFLOW);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_netflow_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NETFLOW, PROTO_NETFLOW_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
                PROTO_NETFLOW, PROTO_NETFLOW);

        return register_protocol(protocol_struct, PROTO_NETFLOW);
    } else {
        return 0;
    }
}
