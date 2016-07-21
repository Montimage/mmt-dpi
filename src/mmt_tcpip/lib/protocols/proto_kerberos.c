#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_kerberos_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_KERBEROS, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_kerberos(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    /* I have observed 0a,0c,0d,0e at packet->payload[19/21], maybe there are other possibilities */
    if (packet->payload_packet_len >= 4 && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len - 4) {
        if (packet->payload_packet_len > 19 &&
                packet->payload[14] == 0x05 &&
                (packet->payload[19] == 0x0a ||
                packet->payload[19] == 0x0c || packet->payload[19] == 0x0d || packet->payload[19] == 0x0e)) {
            MMT_LOG(PROTO_KERBEROS, MMT_LOG_DEBUG, "found KERBEROS\n");
            mmt_int_kerberos_add_connection(ipacket);
            return;

        }
        if (packet->payload_packet_len > 21 &&
                packet->payload[16] == 0x05 &&
                (packet->payload[21] == 0x0a ||
                packet->payload[21] == 0x0c || packet->payload[21] == 0x0d || packet->payload[21] == 0x0e)) {
            MMT_LOG(PROTO_KERBEROS, MMT_LOG_DEBUG, "found KERBEROS\n");
            mmt_int_kerberos_add_connection(ipacket);
            return;

        }



    }

    MMT_LOG(PROTO_KERBEROS, MMT_LOG_DEBUG, "no KERBEROS detected.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_KERBEROS);
}

int mmt_check_kerberos(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* I have observed 0a,0c,0d,0e at packet->payload[19/21], maybe there are other possibilities */
        if (packet->payload_packet_len >= 4 && ntohl(get_u32(packet->payload, 0)) == packet->payload_packet_len - 4) {
            if (packet->payload_packet_len > 19 &&
                    packet->payload[14] == 0x05 &&
                    (packet->payload[19] == 0x0a ||
                    packet->payload[19] == 0x0c || packet->payload[19] == 0x0d || packet->payload[19] == 0x0e)) {
                MMT_LOG(PROTO_KERBEROS, MMT_LOG_DEBUG, "found KERBEROS\n");
                mmt_int_kerberos_add_connection(ipacket);
                return 1;
            }
            if (packet->payload_packet_len > 21 &&
                    packet->payload[16] == 0x05 &&
                    (packet->payload[21] == 0x0a ||
                    packet->payload[21] == 0x0c || packet->payload[21] == 0x0d || packet->payload[21] == 0x0e)) {
                MMT_LOG(PROTO_KERBEROS, MMT_LOG_DEBUG, "found KERBEROS\n");
                mmt_int_kerberos_add_connection(ipacket);
                return 1;
            }
        }

        MMT_LOG(PROTO_KERBEROS, MMT_LOG_DEBUG, "no KERBEROS detected.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_KERBEROS);
    }
    return 0;
}

void mmt_init_classify_me_kerberos() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_KERBEROS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_kerberos_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_KERBEROS, PROTO_KERBEROS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_kerberos();

        return register_protocol(protocol_struct, PROTO_KERBEROS);
    } else {
        return 0;
    }
}


