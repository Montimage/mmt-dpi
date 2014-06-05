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

void mmt_classify_me_usenet(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: search usenet.\n");
    MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: STAGE IS %u.\n", flow->l4.tcp.usenet_stage);

    // check for the first server replay
    /*
       200    Service available, posting allowed
       201    Service available, posting prohibited
     */
    if (flow->l4.tcp.usenet_stage == 0 && packet->payload_packet_len > 10
            && ((mmt_mem_cmp(packet->payload, "200 ", 4) == 0)
            || (mmt_mem_cmp(packet->payload, "201 ", 4) == 0))) {

        MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: found 200 or 201.\n");
        flow->l4.tcp.usenet_stage = 1 + ipacket->session->last_packet_direction;

        MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: maybe hit.\n");
        return;
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
            MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: username found\n");
            flow->l4.tcp.usenet_stage = 3 + ipacket->session->last_packet_direction;

            MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: found usenet.\n");
            mmt_int_usenet_add_connection(ipacket);
            return;
        } else if (packet->payload_packet_len == 13 && (mmt_mem_cmp(packet->payload, "MODE READER\r\n", 13) == 0)) {
            MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG,
                    "USENET: no login necessary but we are a client.\n");

            MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: found usenet.\n");
            mmt_int_usenet_add_connection(ipacket);
            return;
        }
    }

    MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: exclude usenet.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_USENET);
}

int mmt_check_usenet(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: search usenet.\n");
        MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: STAGE IS %u.\n", flow->l4.tcp.usenet_stage);

        // check for the first server replay
        /*
           200    Service available, posting allowed
           201    Service available, posting prohibited
         */
        if (flow->l4.tcp.usenet_stage == 0 && packet->payload_packet_len > 10
                && ((mmt_mem_cmp(packet->payload, "200 ", 4) == 0)
                || (mmt_mem_cmp(packet->payload, "201 ", 4) == 0))) {

            MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: found 200 or 201.\n");
            flow->l4.tcp.usenet_stage = 1 + ipacket->session->last_packet_direction;

            MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: maybe hit.\n");
            return 1;
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
                MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: username found\n");
                flow->l4.tcp.usenet_stage = 3 + ipacket->session->last_packet_direction;

                MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: found usenet.\n");
                mmt_int_usenet_add_connection(ipacket);
                return 1;
            } else if (packet->payload_packet_len == 13 && (mmt_mem_cmp(packet->payload, "MODE READER\r\n", 13) == 0)) {
                MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG,
                        "USENET: no login necessary but we are a client.\n");

                MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: found usenet.\n");
                mmt_int_usenet_add_connection(ipacket);
                return 1;
            }
        }

        MMT_LOG(PROTO_USENET, MMT_LOG_DEBUG, "USENET: exclude usenet.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_USENET);

    }
    return 1;
}

void mmt_init_classify_me_usenet() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_RDP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_usenet_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_USENET, PROTO_USENET_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_usenet();
        
        return register_protocol(protocol_struct, PROTO_USENET);
    } else {
        return 0;
    }
}


