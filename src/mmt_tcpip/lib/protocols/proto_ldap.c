#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ldap_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_LDAP, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_ldap(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    //  u16 dport;



    MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "search ldap\n");


    if (packet->payload_packet_len >= 14 && packet->payload[0] == 0x30) {

        // simple type
        if (packet->payload[1] == 0x0c && packet->payload_packet_len == 14 &&
                packet->payload[packet->payload_packet_len - 1] == 0x00 && packet->payload[2] == 0x02) {

            if (packet->payload[3] == 0x01 &&
                    (packet->payload[5] == 0x60 || packet->payload[5] == 0x61) && packet->payload[6] == 0x07) {
                MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "found ldap simple type 1\n");
                mmt_int_ldap_add_connection(ipacket);
                return;
            }

            if (packet->payload[3] == 0x02 &&
                    (packet->payload[6] == 0x60 || packet->payload[6] == 0x61) && packet->payload[7] == 0x07) {
                MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "found ldap simple type 2\n");
                mmt_int_ldap_add_connection(ipacket);
                return;
            }
        }
        // normal type
        if (packet->payload[1] == 0x84 && packet->payload_packet_len >= 0x84 &&
                packet->payload[2] == 0x00 && packet->payload[3] == 0x00 && packet->payload[6] == 0x02) {

            if (packet->payload[7] == 0x01 &&
                    (packet->payload[9] == 0x60 || packet->payload[9] == 0x61 || packet->payload[9] == 0x63 ||
                    packet->payload[9] == 0x64) && packet->payload[10] == 0x84) {

                MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "found ldap type 1\n");
                mmt_int_ldap_add_connection(ipacket);
                return;
            }

            if (packet->payload[7] == 0x02 &&
                    (packet->payload[10] == 0x60 || packet->payload[10] == 0x61 || packet->payload[10] == 0x63 ||
                    packet->payload[10] == 0x64) && packet->payload[11] == 0x84) {

                MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "found ldap type 2\n");
                mmt_int_ldap_add_connection(ipacket);
                return;
            }
        }
    }


    MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "ldap excluded.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_LDAP);
}

int mmt_check_ldap(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct * flow = packet->flow;

        MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "search ldap\n");

        if (packet->payload_packet_len >= 14 && packet->payload[0] == 0x30) {
            // simple type
            if (packet->payload[1] == 0x0c && packet->payload_packet_len == 14 &&
                    packet->payload[packet->payload_packet_len - 1] == 0x00 && packet->payload[2] == 0x02) {

                if (packet->payload[3] == 0x01 &&
                        (packet->payload[5] == 0x60 || packet->payload[5] == 0x61) && packet->payload[6] == 0x07) {
                    MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "found ldap simple type 1\n");
                    mmt_int_ldap_add_connection(ipacket);
                    return 1;
                }

                if (packet->payload[3] == 0x02 &&
                        (packet->payload[6] == 0x60 || packet->payload[6] == 0x61) && packet->payload[7] == 0x07) {
                    MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "found ldap simple type 2\n");
                    mmt_int_ldap_add_connection(ipacket);
                    return 1;
                }
            }
            // normal type
            if (packet->payload[1] == 0x84 && packet->payload_packet_len >= 0x84 &&
                    packet->payload[2] == 0x00 && packet->payload[3] == 0x00 && packet->payload[6] == 0x02) {

                if (packet->payload[7] == 0x01 &&
                        (packet->payload[9] == 0x60 || packet->payload[9] == 0x61 || packet->payload[9] == 0x63 ||
                        packet->payload[9] == 0x64) && packet->payload[10] == 0x84) {

                    MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "found ldap type 1\n");
                    mmt_int_ldap_add_connection(ipacket);
                    return 1;
                }

                if (packet->payload[7] == 0x02 &&
                        (packet->payload[10] == 0x60 || packet->payload[10] == 0x61 || packet->payload[10] == 0x63 ||
                        packet->payload[10] == 0x64) && packet->payload[11] == 0x84) {

                    MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "found ldap type 2\n");
                    mmt_int_ldap_add_connection(ipacket);
                    return 1;
                }
            }
        }

        MMT_LOG(PROTO_LDAP, MMT_LOG_DEBUG, "ldap excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_LDAP);
    }
    return 1;
}

void mmt_init_classify_me_ldap() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_LDAP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ldap_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_LDAP, PROTO_LDAP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_ldap();

        return register_protocol(protocol_struct, PROTO_LDAP);
    } else {
        return 0;
    }
}


