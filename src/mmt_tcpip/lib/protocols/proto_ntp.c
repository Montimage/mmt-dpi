#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ntp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_NTP, MMT_REAL_PROTOCOL);
}

/* detection also works asymmetrically */

void mmt_classify_me_ntp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;



    if (!(packet->udp->dest == htons(123) || packet->udp->source == htons(123)))
        goto exclude_ntp;

    MMT_LOG(PROTO_NTP, MMT_LOG_DEBUG, "NTP port detected\n");

    if (packet->payload_packet_len != 48)
        goto exclude_ntp;

    MMT_LOG(PROTO_NTP, MMT_LOG_DEBUG, "NTP length detected\n");


    if ((((packet->payload[0] & 0x38) >> 3) <= 4)) {
        MMT_LOG(PROTO_NTP, MMT_LOG_DEBUG, "detected NTP.");
        mmt_int_ntp_add_connection(ipacket);
        return;
    }



exclude_ntp:
    MMT_LOG(PROTO_NTP, MMT_LOG_DEBUG, "NTP excluded.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_NTP);
}

int mmt_check_ntp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        if (!(packet->udp->dest == htons(123) || packet->udp->source == htons(123)))
            goto exclude_ntp;

        MMT_LOG(PROTO_NTP, MMT_LOG_DEBUG, "NTP port detected\n");

        if (packet->payload_packet_len != 48)
            goto exclude_ntp;

        MMT_LOG(PROTO_NTP, MMT_LOG_DEBUG, "NTP length detected\n");
        if ((((packet->payload[0] & 0x38) >> 3) <= 4)) {
            MMT_LOG(PROTO_NTP, MMT_LOG_DEBUG, "detected NTP.");
            mmt_int_ntp_add_connection(ipacket);
            return 1;
        }
exclude_ntp:
        MMT_LOG(PROTO_NTP, MMT_LOG_DEBUG, "NTP excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_NTP);
    }
    return 0;
}

void mmt_init_classify_me_ntp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_NTP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ntp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NTP, PROTO_NTP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_ntp();

        return register_protocol(protocol_struct, PROTO_NTP);
    } else {
        return 0;
    }
}
