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

int mmt_check_ntp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        
        if (!(packet->udp->dest == htons(123) || packet->udp->source == htons(123)))
            goto exclude_ntp;


        if (packet->payload_packet_len != 48)
            goto exclude_ntp;

        if ((((packet->payload[0] & 0x38) >> 3) <= 4)) {
            mmt_int_ntp_add_connection(ipacket);
            return 1;
        }
exclude_ntp:
        MMT_EXCLUDE_PROTOCOL(flow, PROTO_NTP);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ntp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NTP, PROTO_NTP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_NTP);

        return register_protocol(protocol_struct, PROTO_NTP);
    } else {
        return 0;
    }
}
