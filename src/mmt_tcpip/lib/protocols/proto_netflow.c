#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

void mmt_classify_me_netflow(ipacket_t * ipacket, unsigned index)
{
    MMT_LOG(PROTO_NETFLOW, MMT_LOG_DEBUG, "netflow detection...\n");
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    /* unused
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    const uint8_t *packet_payload = packet->payload;
    */
    uint32_t payload_len = packet->payload_packet_len;

    if ((packet->udp != NULL)
            && (payload_len >= 24)
            && (packet->payload[0] == 0)
            && ((packet->payload[1] == 5)
            || (packet->payload[1] == 9)
            || (packet->payload[1] == 10 /* IPFIX */))
            && (packet->payload[3] <= 48 /* Flow count */)) {
        uint32_t when, *_when;

        _when = (uint32_t*) & packet->payload[8]; /* Sysuptime */

        when = ntohl(*_when);

        if (when >= 946684800 /* 1/1/2000 */) {
            MMT_LOG(PROTO_NETFLOW, MMT_LOG_DEBUG, "Found netflow.\n");
            mmt_internal_add_connection(ipacket, PROTO_NETFLOW, MMT_REAL_PROTOCOL);
            return;
        }
    }
}

int mmt_check_netflow(ipacket_t * ipacket, unsigned index) {//BW: TODO: check this out
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        MMT_LOG(PROTO_NETFLOW, MMT_LOG_DEBUG, "netflow detection...\n");
        uint32_t payload_len = packet->payload_packet_len;

        if ((payload_len >= 24)
                && (packet->payload[0] == 0)
                && ((packet->payload[1] == 5)
                || (packet->payload[1] == 9)
                || (packet->payload[1] == 10 /* IPFIX */))
                && (packet->payload[3] <= 48 /* Flow count */)) {
            uint32_t when, *_when;

            _when = (uint32_t*) & packet->payload[8]; /* Sysuptime */

            when = ntohl(*_when);

            if (when >= 946684800 /* 1/1/2000 */) {
                MMT_LOG(PROTO_NETFLOW, MMT_LOG_DEBUG, "Found netflow.\n");
                mmt_internal_add_connection(ipacket, PROTO_NETFLOW, MMT_REAL_PROTOCOL);
                return 1;
            }
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(packet->flow->excluded_protocol_bitmask, PROTO_NETFLOW);
    }
    return 0;
}

void mmt_init_classify_me_netflow() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NETFLOW); //BW: TODO: check this out
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_NETFLOW);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_netflow_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NETFLOW, PROTO_NETFLOW_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_netflow();

        return register_protocol(protocol_struct, PROTO_NETFLOW);
    } else {
        return 0;
    }
}
