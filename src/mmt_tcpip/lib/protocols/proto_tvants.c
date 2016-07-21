#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_TVANTS_TIMEOUT                  5

/* unused
static uint32_t tvants_connection_timeout = MMT_TVANTS_TIMEOUT * MMT_MICRO_IN_SEC; //Not used
*/

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_tvants_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_TVANTS, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_tvants(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "search tvants.  \n");

    if (packet->udp != NULL && packet->payload_packet_len > 57
            && packet->payload[0] == 0x04 && packet->payload[1] == 0x00
            && (packet->payload[2] == 0x05 || packet->payload[2] == 0x06
            || packet->payload[2] == 0x07) && packet->payload[3] == 0x00
            && packet->payload_packet_len == (packet->payload[5] << 8) + packet->payload[4]
            && packet->payload[6] == 0x00 && packet->payload[7] == 0x00
            && (memcmp(&packet->payload[48], "TVANTS", 6) == 0
            || memcmp(&packet->payload[49], "TVANTS", 6) == 0 || memcmp(&packet->payload[51], "TVANTS", 6) == 0)) {

        MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "found tvants over udp.  \n");
        mmt_int_tvants_add_connection(ipacket);

    } else if (packet->tcp != NULL && packet->payload_packet_len > 15
            && packet->payload[0] == 0x04 && packet->payload[1] == 0x00
            && packet->payload[2] == 0x07 && packet->payload[3] == 0x00
            && packet->payload_packet_len == (packet->payload[5] << 8) + packet->payload[4]
            && packet->payload[6] == 0x00 && packet->payload[7] == 0x00
            && memcmp(&packet->payload[8], "TVANTS", 6) == 0) {

        MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "found tvants over tcp.  \n");
        mmt_int_tvants_add_connection(ipacket);

    }
    MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "exclude tvants.  \n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TVANTS);

}

int mmt_check_tvants_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "search tvants.  \n");

        if (packet->payload_packet_len > 15
                && packet->payload[0] == 0x04 && packet->payload[1] == 0x00
                && packet->payload[2] == 0x07 && packet->payload[3] == 0x00
                && packet->payload_packet_len == (packet->payload[5] << 8) + packet->payload[4]
                && packet->payload[6] == 0x00 && packet->payload[7] == 0x00
                && memcmp(&packet->payload[8], "TVANTS", 6) == 0) {

            MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "found tvants over tcp.  \n");
            mmt_int_tvants_add_connection(ipacket);
            return 1;
        }
        MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "exclude tvants.  \n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TVANTS);

    }
    return 0;
}

int mmt_check_tvants_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "search tvants.  \n");

        if (packet->payload_packet_len > 57
                && packet->payload[0] == 0x04 && packet->payload[1] == 0x00
                && (packet->payload[2] == 0x05 || packet->payload[2] == 0x06
                || packet->payload[2] == 0x07) && packet->payload[3] == 0x00
                && packet->payload_packet_len == (packet->payload[5] << 8) + packet->payload[4]
                && packet->payload[6] == 0x00 && packet->payload[7] == 0x00
                && (memcmp(&packet->payload[48], "TVANTS", 6) == 0
                || memcmp(&packet->payload[49], "TVANTS", 6) == 0 || memcmp(&packet->payload[51], "TVANTS", 6) == 0)) {

            MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "found tvants over udp.  \n");
            mmt_int_tvants_add_connection(ipacket);
            return 1;
        }
        MMT_LOG(PROTO_TVANTS, MMT_LOG_DEBUG, "exclude tvants.  \n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TVANTS);
    }
    return 0;
}

void mmt_init_classify_me_tvants() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_TVANTS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_tvants_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TVANTS, PROTO_TVANTS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_tvants();

        return register_protocol(protocol_struct, PROTO_TVANTS);
    } else {
        return 0;
    }
}


