#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_activesync_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_HTTP_APPLICATION_ACTIVESYNC, MMT_CORRELATED_PROTOCOL);
}

void mmt_classify_me_activesync(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    if (packet->tcp != NULL) {

        if (packet->payload_packet_len > 150
                && ((memcmp(packet->payload, "OPTIONS /Microsoft-Server-ActiveSync?", 37) == 0)
                || (memcmp(packet->payload, "POST /Microsoft-Server-ActiveSync?", 34) == 0))) {
            mmt_int_activesync_add_connection(ipacket);
            MMT_LOG(PROTO_HTTP_APPLICATION_ACTIVESYNC, MMT_LOG_DEBUG,
                    " flow marked as ActiveSync \n");
            return;
        }
    }

    MMT_LOG(PROTO_HTTP_APPLICATION_ACTIVESYNC, MMT_LOG_DEBUG, "exclude activesync\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP_APPLICATION_ACTIVESYNC);

}

int mmt_check_http_application_activesync(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        if (packet->payload_packet_len > 150
                && ((memcmp(packet->payload, "OPTIONS /Microsoft-Server-ActiveSync?", 37) == 0)
                || (memcmp(packet->payload, "POST /Microsoft-Server-ActiveSync?", 34) == 0))) {
            mmt_int_activesync_add_connection(ipacket);
            MMT_LOG(PROTO_HTTP_APPLICATION_ACTIVESYNC, MMT_LOG_DEBUG,
                    " flow marked as ActiveSync \n");
            return 1;
        }

        MMT_LOG(PROTO_HTTP_APPLICATION_ACTIVESYNC, MMT_LOG_DEBUG, "exclude activesync\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP_APPLICATION_ACTIVESYNC);


    }
    return 0;
}

void mmt_init_classify_me_http_application_activesync() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_HTTP_APPLICATION_ACTIVESYNC);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_http_application_activesync_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_HTTP_APPLICATION_ACTIVESYNC, PROTO_HTTP_APPLICATION_ACTIVESYNC_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_http_application_activesync();

        return register_protocol(protocol_struct, PROTO_HTTP_APPLICATION_ACTIVESYNC);
    } else {
        return 0;
    }
}


