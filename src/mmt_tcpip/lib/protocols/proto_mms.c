#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_mms_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_MMS, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_mms(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    /* search MSMMS packets */
    if (packet->payload_packet_len >= 20) {

        if (flow->l4.tcp.mms_stage == 0 && packet->payload[4] == 0xce
                && packet->payload[5] == 0xfa && packet->payload[6] == 0x0b
                && packet->payload[7] == 0xb0 && packet->payload[12] == 0x4d
                && packet->payload[13] == 0x4d && packet->payload[14] == 0x53 && packet->payload[15] == 0x20) {
            MMT_LOG(PROTO_MMS, MMT_LOG_DEBUG, "MMS: MSMMS Request found \n");
            flow->l4.tcp.mms_stage = 1 + ipacket->session->last_packet_direction;
            return;
        }

        if (flow->l4.tcp.mms_stage == 2 - ipacket->session->last_packet_direction
                && packet->payload[4] == 0xce && packet->payload[5] == 0xfa
                && packet->payload[6] == 0x0b && packet->payload[7] == 0xb0
                && packet->payload[12] == 0x4d && packet->payload[13] == 0x4d
                && packet->payload[14] == 0x53 && packet->payload[15] == 0x20) {
            MMT_LOG(PROTO_MMS, MMT_LOG_DEBUG, "MMS: MSMMS Response found \n");
            mmt_int_mms_add_connection(ipacket);
            return;
        }
    }
#ifdef PROTO_HTTP
    if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP) != 0) {
#endif							/* PROTOCOL_HTTP */
        MMT_LOG(PROTO_MMS, MMT_LOG_DEBUG, "MMS: exclude\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MMS);

#ifdef PROTO_HTTP
    } else {
        MMT_LOG(PROTO_MMS, MMT_LOG_DEBUG, "MMS avoid early exclude from http\n");
    }
#endif							/* PROTOCOL_HTTP */

}

int mmt_check_mms(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* search MSMMS packets */
        if (packet->payload_packet_len >= 20) {
            if (flow->l4.tcp.mms_stage == 0 && packet->payload[4] == 0xce
                    && packet->payload[5] == 0xfa && packet->payload[6] == 0x0b
                    && packet->payload[7] == 0xb0 && packet->payload[12] == 0x4d
                    && packet->payload[13] == 0x4d && packet->payload[14] == 0x53 && packet->payload[15] == 0x20) {
                MMT_LOG(PROTO_MMS, MMT_LOG_DEBUG, "MMS: MSMMS Request found \n");
                flow->l4.tcp.mms_stage = 1 + ipacket->session->last_packet_direction;
                return 1;
            }

            if (flow->l4.tcp.mms_stage == 2 - ipacket->session->last_packet_direction
                    && packet->payload[4] == 0xce && packet->payload[5] == 0xfa
                    && packet->payload[6] == 0x0b && packet->payload[7] == 0xb0
                    && packet->payload[12] == 0x4d && packet->payload[13] == 0x4d
                    && packet->payload[14] == 0x53 && packet->payload[15] == 0x20) {
                MMT_LOG(PROTO_MMS, MMT_LOG_DEBUG, "MMS: MSMMS Response found \n");
                mmt_int_mms_add_connection(ipacket);
                return 1;
            }
        }
        if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP) != 0) {
            MMT_LOG(PROTO_MMS, MMT_LOG_DEBUG, "MMS: exclude\n");
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MMS);
        } else {
            MMT_LOG(PROTO_MMS, MMT_LOG_DEBUG, "MMS avoid early exclude from http\n");
        }
    }
    return 0;
}

void mmt_init_classify_me_mms() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_MMS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_mms_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MMS, PROTO_MMS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_mms();

        return register_protocol(protocol_struct, PROTO_MMS);
    } else {
        return 0;
    }
}
