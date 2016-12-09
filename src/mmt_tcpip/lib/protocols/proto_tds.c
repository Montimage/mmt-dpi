#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_tds_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_TDS, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_tds(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len > 8
            && packet->payload_packet_len < 512
            && packet->payload[1] < 0x02
            && ntohs(get_u16(packet->payload, 2)) == packet->payload_packet_len && get_u16(packet->payload, 4) == 0x0000) {

        if (flow->l4.tcp.tds_stage == 0) {
            if (packet->payload[0] != 0x02 && packet->payload[0] != 0x07 && packet->payload[0] != 0x12) {
                goto exclude_tds;
            } else {
                flow->l4.tcp.tds_stage = 1 + ipacket->session->last_packet_direction;
                flow->l4.tcp.tds_login_version = packet->payload[0];
                return;
            }
        } else if (flow->l4.tcp.tds_stage == 2 - ipacket->session->last_packet_direction) {
            switch (flow->l4.tcp.tds_login_version) {
                case 0x12:
                    if (packet->payload[0] == 0x04) {
                        flow->l4.tcp.tds_stage = 3 + ipacket->session->last_packet_direction;
                        return;
                    } else {
                        goto exclude_tds;
                    }
                    //TODO: add more cases for other versions
                default:
                    goto exclude_tds;
            }
        } else if (flow->l4.tcp.tds_stage == 4 - ipacket->session->last_packet_direction) {
            switch (flow->l4.tcp.tds_login_version) {
                case 0x12:
                    if (packet->payload[0] == 0x12) {
                        MMT_LOG(PROTO_TDS, MMT_LOG_DEBUG, "TDS detected\n");
                        mmt_int_tds_add_connection(ipacket);
                        return;
                    } else {
                        goto exclude_tds;
                    }
                    //TODO: add more cases for other versions
                default:
                    goto exclude_tds;
            }
        }
    }

exclude_tds:

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TDS);
}

int mmt_check_tds(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct * flow = packet->flow;

        if (packet->payload_packet_len > 8
                && packet->payload_packet_len < 512
                && packet->payload[1] < 0x02
                && ntohs(get_u16(packet->payload, 2)) == packet->payload_packet_len && get_u16(packet->payload, 4) == 0x0000) {

            if (flow->l4.tcp.tds_stage == 0) {
                if (packet->payload[0] != 0x02 && packet->payload[0] != 0x07 && packet->payload[0] != 0x12) {
                    goto exclude_tds;
                } else {
                    flow->l4.tcp.tds_stage = 1 + ipacket->session->last_packet_direction;
                    flow->l4.tcp.tds_login_version = packet->payload[0];
                    return 4;
                }
            } else if (flow->l4.tcp.tds_stage == 2 - ipacket->session->last_packet_direction) {
                switch (flow->l4.tcp.tds_login_version) {
                    case 0x12:
                        if (packet->payload[0] == 0x04) {
                            flow->l4.tcp.tds_stage = 3 + ipacket->session->last_packet_direction;
                            return 4;
                        } else {
                            goto exclude_tds;
                        }
                        //BW: TODO: add more cases for other versions
                    default:
                        goto exclude_tds;
                }
            } else if (flow->l4.tcp.tds_stage == 4 - ipacket->session->last_packet_direction) {
                switch (flow->l4.tcp.tds_login_version) {
                    case 0x12:
                        if (packet->payload[0] == 0x12) {
                            MMT_LOG(PROTO_TDS, MMT_LOG_DEBUG, "TDS detected\n");
                            mmt_int_tds_add_connection(ipacket);
                            return 1;
                        } else {
                            goto exclude_tds;
                        }
                        //BW: TODO: add more cases for other versions
                    default:
                        goto exclude_tds;
                }
            }
        }

exclude_tds:
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TDS);
    }
    return 0;
}

void mmt_init_classify_me_tds() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_TDS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_tds_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TDS, PROTO_TDS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_tds();

        return register_protocol(protocol_struct, PROTO_TDS);
    } else {
        return 0;
    }
}


