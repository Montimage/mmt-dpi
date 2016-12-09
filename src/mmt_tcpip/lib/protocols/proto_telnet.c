#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_telnet_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_TELNET, MMT_REAL_PROTOCOL);
}


static uint8_t search_iac(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    uint16_t a;

    if (packet->payload_packet_len < 3) {
        return 0;
    }

    if (!(packet->payload[0] == 0xff
            && packet->payload[1] > 0xf9 && packet->payload[1] != 0xff && packet->payload[2] < 0x28)) {
        return 0;
    }

    a = 3;

    while (a < packet->payload_packet_len - 2) {
        // commands start with a 0xff byte followed by a command byte >= 0xf0 and < 0xff
        // command bytes 0xfb to 0xfe are followed by an option byte <= 0x28
        if (!(packet->payload[a] != 0xff ||
                (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xf0) && (packet->payload[a + 1] <= 0xfa)) ||
                (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xfb) && (packet->payload[a + 1] != 0xff)
                && (packet->payload[a + 2] <= 0x28)))) {
            return 0;
        }
        a++;
    }

    return 1;
}

/* this detection also works asymmetrically */
void mmt_classify_me_telnet(ipacket_t * ipacket, unsigned index) {


    struct mmt_internal_tcpip_session_struct *flow = ipacket->internal_packet->flow;
    //      struct mmt_id_struct         *src=mmt_struct->src;
    //      struct mmt_id_struct         *dst=mmt_struct->dst;

    MMT_LOG(PROTO_TELNET, MMT_LOG_DEBUG, "search telnet.\n");

    if (search_iac(ipacket) == 1) {

        if (flow->l4.tcp.telnet_stage == 2) {
            MMT_LOG(PROTO_TELNET, MMT_LOG_DEBUG, "telnet identified.\n");
            mmt_int_telnet_add_connection(ipacket);
            return;
        }
        flow->l4.tcp.telnet_stage++;
        MMT_LOG(PROTO_TELNET, MMT_LOG_DEBUG, "telnet stage %u.\n", flow->l4.tcp.telnet_stage);
        return;
    }

    if ((ipacket->session->data_packet_count < 12 && flow->l4.tcp.telnet_stage > 0) || ipacket->session->data_packet_count < 6) {
        return;
    } else {
        MMT_LOG(PROTO_TELNET, MMT_LOG_DEBUG, "telnet excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TELNET);
    }
    return;
}

int mmt_check_telnet(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = ipacket->internal_packet->flow;

        MMT_LOG(PROTO_TELNET, MMT_LOG_DEBUG, "search telnet.\n");

        if (search_iac(ipacket) == 1) {
            if (flow->l4.tcp.telnet_stage == 2) {
                MMT_LOG(PROTO_TELNET, MMT_LOG_DEBUG, "telnet identified.\n");
                mmt_int_telnet_add_connection(ipacket);
                return 1;
            }
            flow->l4.tcp.telnet_stage++;
            MMT_LOG(PROTO_TELNET, MMT_LOG_DEBUG, "telnet stage %u.\n", flow->l4.tcp.telnet_stage);
            return 4;
        }

        if ((ipacket->session->data_packet_count < 12 && flow->l4.tcp.telnet_stage > 0) || ipacket->session->data_packet_count < 6) {
            return 4;
        }

        MMT_LOG(PROTO_TELNET, MMT_LOG_DEBUG, "telnet excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TELNET);
    }
    return 0;
}

void mmt_init_classify_me_telnet() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_TELNET);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_telnet_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TELNET, PROTO_TELNET_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_telnet();

        return register_protocol(protocol_struct, PROTO_TELNET);
    } else {
        return 0;
    }
}


