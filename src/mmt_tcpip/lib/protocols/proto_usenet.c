#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_usenet_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_USENET, MMT_REAL_PROTOCOL);
}

int mmt_check_usenet(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;


        // check for the first server replay
        /*
           200    Service available, posting allowed
           201    Service available, posting prohibited
         */
        if (flow->l4.tcp.usenet_stage == 0 && packet->payload_packet_len > 10
                && ((mmt_mem_cmp(packet->payload, "200 ", 4) == 0)
                || (mmt_mem_cmp(packet->payload, "201 ", 4) == 0))) {

            flow->l4.tcp.usenet_stage = 1 + ipacket->session->last_packet_direction;

            return 4;
        }

        /*
           [C] AUTHINFO USER fred
           [S] 381 Enter passphrase
           [C] AUTHINFO PASS flintstone
           [S] 281 Authentication accepted
         */
        // check for client username
        if (flow->l4.tcp.usenet_stage == 2 - ipacket->session->last_packet_direction) {
            if (packet->payload_packet_len > 20 && (mmt_mem_cmp(packet->payload, "AUTHINFO USER ", 14) == 0)) {
                flow->l4.tcp.usenet_stage = 3 + ipacket->session->last_packet_direction;

                mmt_int_usenet_add_connection(ipacket);
                return 1;
            } else if (packet->payload_packet_len == 13 && (mmt_mem_cmp(packet->payload, "MODE READER\r\n", 13) == 0)) {

                mmt_int_usenet_add_connection(ipacket);
                return 1;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_USENET);

    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_usenet_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_USENET, PROTO_USENET_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_USENET);
        
        return register_protocol(protocol_struct, PROTO_USENET);
    } else {
        return 0;
    }
}
