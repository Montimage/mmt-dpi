#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_applejuice_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_APPLEJUICE, MMT_REAL_PROTOCOL);
}

int mmt_check_applejuice(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_APPLEJUICE, MMT_LOG_DEBUG, "search applejuice.\n");

        if ((packet->payload_packet_len > 7) && (packet->payload[6] == 0x0d)
                && (packet->payload[7] == 0x0a)
                && (mmt_mem_cmp(packet->payload, "ajprot", 6) == 0)) {
            MMT_LOG(PROTO_APPLEJUICE, MMT_LOG_DEBUG, "detected applejuice.\n");
            mmt_int_applejuice_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_APPLEJUICE, MMT_LOG_DEBUG, "exclude applejuice.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_APPLEJUICE);
    }
    return 0;
}

void mmt_classify_me_applejuice_tcp(ipacket_t * ipacket, unsigned index)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_APPLEJUICE, MMT_LOG_DEBUG, "search applejuice.\n");

    if ((packet->payload_packet_len > 7) && (packet->payload[6] == 0x0d)
            && (packet->payload[7] == 0x0a)
            && (mmt_mem_cmp(packet->payload, "ajprot", 6) == 0)) {
        MMT_LOG(PROTO_APPLEJUICE, MMT_LOG_DEBUG, "detected applejuice.\n");
        mmt_int_applejuice_add_connection(ipacket);
        return;
    }

    MMT_LOG(PROTO_APPLEJUICE, MMT_LOG_DEBUG, "exclude applejuice.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_APPLEJUICE);
}

void mmt_init_classify_me_applejuice() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_APPLEJUICE);
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_applejuice_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_APPLEJUICE, PROTO_APPLEJUICE_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_applejuice();

        return register_protocol(protocol_struct, PROTO_APPLEJUICE);
    } else {
        return 0;
    }
}


