#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_snmp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SNMP, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_snmp(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->payload_packet_len > 32 && packet->payload[0] == 0x30) {
        int offset;
        switch (packet->payload[1]) {
            case 0x81:
                offset = 3;
                break;
            case 0x82:
                offset = 4;
                break;
            default:
                if (packet->payload[1] > 0x82) {
                    MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP excluded, second byte is > 0x82\n");
                    goto excl;
                }
                offset = 2;
        }

        if (get_u16(packet->payload, offset) != htons(0x0201)) {
            MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP excluded, 0x0201 pattern not found\n");
            goto excl;
        }

        if (packet->payload[offset + 2] >= 0x04) {
            MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP excluded, version > 3\n");
            goto excl;
        }

        if (flow->l4.udp.snmp_stage == 0) {
            if (packet->udp->dest == htons(161) || packet->udp->dest == htons(162)) {
                MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP detected due to port.\n");
                mmt_int_snmp_add_connection(ipacket);
                return;
            }
            MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP stage 0.\n");
            if (packet->payload[offset + 2] == 3) {
                flow->l4.udp.snmp_msg_id = ntohs(get_u32(packet->payload, offset + 8));
            } else if (packet->payload[offset + 2] == 0) {
                flow->l4.udp.snmp_msg_id = get_u8(packet->payload, offset + 15);
            } else {
                flow->l4.udp.snmp_msg_id = ntohs(get_u16(packet->payload, offset + 15));
            }
            flow->l4.udp.snmp_stage = 1 + ipacket->session->last_packet_direction;
            return;
        } else if (flow->l4.udp.snmp_stage == 1 + ipacket->session->last_packet_direction) {
            if (packet->payload[offset + 2] == 0) {
                if (flow->l4.udp.snmp_msg_id != get_u8(packet->payload, offset + 15) - 1) {
                    MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG,
                            "SNMP v1 excluded, message ID doesn't match\n");
                    goto excl;
                }
            }
        } else if (flow->l4.udp.snmp_stage == 2 - ipacket->session->last_packet_direction) {
            MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP stage 1-2.\n");
            if (packet->payload[offset + 2] == 3) {
                if (flow->l4.udp.snmp_msg_id != ntohs(get_u32(packet->payload, offset + 8))) {
                    MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG,
                            "SNMP v3 excluded, message ID doesn't match\n");
                    goto excl;
                }
            } else if (packet->payload[offset + 2] == 0) {
                if (flow->l4.udp.snmp_msg_id != get_u8(packet->payload, offset + 15)) {
                    MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG,
                            "SNMP v1 excluded, message ID doesn't match\n");
                    goto excl;
                }
            } else {
                if (flow->l4.udp.snmp_msg_id != ntohs(get_u16(packet->payload, offset + 15))) {
                    MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG,
                            "SNMP v2 excluded, message ID doesn't match\n");
                    goto excl;
                }
            }
            MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP detected.\n");
            mmt_int_snmp_add_connection(ipacket);
            return;
        }
    } else {
        MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP excluded.\n");
    }
excl:
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SNMP);

}

int mmt_check_snmp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len > 32 && packet->payload[0] == 0x30) {
            int offset;
            switch (packet->payload[1]) {
                case 0x81:
                    offset = 3;
                    break;
                case 0x82:
                    offset = 4;
                    break;
                default:
                    if (packet->payload[1] > 0x82) {
                        MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP excluded, second byte is > 0x82\n");
                        goto excl;
                    }
                    offset = 2;
            }

            if (get_u16(packet->payload, offset) != htons(0x0201)) {
                MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP excluded, 0x0201 pattern not found\n");
                goto excl;
            }

            if (packet->payload[offset + 2] >= 0x04) {
                MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP excluded, version > 3\n");
                goto excl;
            }

            if (flow->l4.udp.snmp_stage == 0) {
                if (packet->udp->dest == htons(161) || packet->udp->dest == htons(162)) {
                    MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP detected due to port.\n");
                    mmt_int_snmp_add_connection(ipacket);
                    return 1;
                }
                MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP stage 0.\n");
                if (packet->payload[offset + 2] == 3) {
                    flow->l4.udp.snmp_msg_id = ntohs(get_u32(packet->payload, offset + 8));
                } else if (packet->payload[offset + 2] == 0) {
                    flow->l4.udp.snmp_msg_id = get_u8(packet->payload, offset + 15);
                } else {
                    flow->l4.udp.snmp_msg_id = ntohs(get_u16(packet->payload, offset + 15));
                }
                flow->l4.udp.snmp_stage = 1 + ipacket->session->last_packet_direction;
                return 4;
            } else if (flow->l4.udp.snmp_stage == 1 + ipacket->session->last_packet_direction) {
                if (packet->payload[offset + 2] == 0) {
                    if (flow->l4.udp.snmp_msg_id != get_u8(packet->payload, offset + 15) - 1) {
                        MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG,
                                "SNMP v1 excluded, message ID doesn't match\n");
                        goto excl;
                    }
                }
            } else if (flow->l4.udp.snmp_stage == 2 - ipacket->session->last_packet_direction) {
                MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP stage 1-2.\n");
                if (packet->payload[offset + 2] == 3) {
                    if (flow->l4.udp.snmp_msg_id != ntohs(get_u32(packet->payload, offset + 8))) {
                        MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG,
                                "SNMP v3 excluded, message ID doesn't match\n");
                        goto excl;
                    }
                } else if (packet->payload[offset + 2] == 0) {
                    if (flow->l4.udp.snmp_msg_id != get_u8(packet->payload, offset + 15)) {
                        MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG,
                                "SNMP v1 excluded, message ID doesn't match\n");
                        goto excl;
                    }
                } else {
                    if (flow->l4.udp.snmp_msg_id != ntohs(get_u16(packet->payload, offset + 15))) {
                        MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG,
                                "SNMP v2 excluded, message ID doesn't match\n");
                        goto excl;
                    }
                }
                MMT_LOG(PROTO_SNMP, MMT_LOG_DEBUG, "SNMP detected.\n");
                mmt_int_snmp_add_connection(ipacket);
                return 1;
            }
        }
excl:
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SNMP);
    }
    return 0;
}

void mmt_init_classify_me_snmp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SNMP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_snmp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SNMP, PROTO_SNMP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_snmp();

        return register_protocol(protocol_struct, PROTO_SNMP);
    } else {
        return 0;
    }
}
