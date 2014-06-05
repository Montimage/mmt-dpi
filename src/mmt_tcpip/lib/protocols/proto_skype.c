#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

#if 0 /* unused */
static u_int is_private_addr(uint32_t addr) {
    addr = ntohl(addr);

    if (((addr & 0xFF000000) == 0x0A000000) /* 10.0.0.0/8  */
            || ((addr & 0xFFF00000) == 0xAC100000) /* 172.16/12   */
            || ((addr & 0xFFFF0000) == 0xC0A80000) /* 192.168/16  */
            || ((addr & 0xFF000000) == 0x7F000000) /* 127.0.0.0/8 */
            )
        return (1);
    else
        return (0);
}
#endif

static void ntop_check_skype(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    /* unused
    const uint8_t *packet_payload = packet->payload;
    */
    uint32_t payload_len = packet->payload_packet_len;

    if (packet->udp != NULL) {
        flow->l4.udp.skype_packet_id++;

        if (flow->l4.udp.skype_packet_id < 5) {
            /* skype-to-skype */
            if (((payload_len == 3) && ((packet->payload[2] & 0x0F) == 0x0d))
                    || ((payload_len >= 16)
                    && (packet->payload[0] != 0x30) /* Avoid invalid SNMP detection */
                    && (packet->payload[2] == 0x02))) {
                MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
                mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
                return;
            }

            /* Third payload octet is always 0x*d (something - d); interpret it as skype */
            if ((payload_len >= 16) && ((packet->payload[2] & 0x0F) == 0x0d)) {
                flow->l4.udp.skype_like_packet++;
            }

            return;
        } else if (flow->l4.udp.skype_like_packet == 4) {
            MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
            mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
            return;
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SKYPE);
        return;
    } else if (packet->tcp != NULL) {
        flow->l4.tcp.skype_packet_id++;

        if ((flow->l4.tcp.skype_packet_id <= 8)) {
            if (payload_len <= 32) {
                flow->l4.tcp.skype_like_packet++;
            }
            if ((payload_len == 6) && (packet->payload[0] == 0x00) &&
                    (packet->payload[1] == 0x00) && (packet->payload[2] == 0x00) &&
                    (packet->payload[3] == 0x00) && (packet->payload[4] == 0x00) &&
                    (packet->payload[5] == 0x00)) {
                //This is a skype packet
                MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
                mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
                return;
            }

            if ((flow->l4.tcp.skype_packet_id == 3)
                    /* We have seen the 3-way handshake */
                    && flow->l4.tcp.seen_syn
                    && flow->l4.tcp.seen_syn_ack
                    && flow->l4.tcp.seen_ack) {
                if ((payload_len == 8) || (payload_len == 3)) {
                    MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
                    mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
                    return;
                }
                /* printf("[SKYPE] [id: %u][len: %d]\n", flow->l4.tcp.skype_packet_id, payload_len);  */
            }
        } else if (flow->l4.tcp.skype_like_packet == 8) {
            MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
            mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
            return;
        } else {
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SKYPE);
        }

        return;
    }
}

void mmt_classify_me_skype(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "skype detection...\n");

    /* skip marked packets */
    if (packet->detected_protocol_stack[0] != PROTO_SKYPE)
        ntop_check_skype(ipacket);
}

int mmt_check_skype_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        uint32_t payload_len = packet->payload_packet_len;

        /* skip marked packets */
        if (packet->detected_protocol_stack[0] != PROTO_UNKNOWN)
            return 0;

        flow->l4.tcp.skype_packet_id++;

        if ((flow->l4.tcp.skype_packet_id <= 8)) {
            if (payload_len <= 32) {
                flow->l4.tcp.skype_like_packet++;
            }

            if ((flow->l4.tcp.skype_packet_id == 3)
                    /* We have seen the 3-way handshake */
                    && flow->l4.tcp.seen_syn
                    && flow->l4.tcp.seen_syn_ack
                    && flow->l4.tcp.seen_ack) {
                if (((payload_len == 8) || (payload_len == 3)) && flow->l4.tcp.skype_like_packet == 0) {
                    MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
                    mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
                    return 1;
                }
                /* printf("[SKYPE] [id: %u][len: %d]\n", flow->l4.tcp.skype_packet_id, payload_len);  */
            }
        } else if (flow->l4.tcp.skype_like_packet == 8) {
            MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
            mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
            return 1;
        } else {
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SKYPE);
        }
    }
    return 1;
}

int mmt_check_skype_udp(ipacket_t * ipacket, unsigned index) { //BW: TODO: Check this out
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        uint32_t payload_len = packet->payload_packet_len;

        /* skip marked packets */
        if (packet->detected_protocol_stack[0] != PROTO_UNKNOWN)
            return 0;

        flow->l4.udp.skype_packet_id++;

        if (flow->l4.udp.skype_packet_id < 5) {
            /* skype-to-skype */
            if (((payload_len == 3) && ((packet->payload[2] & 0x0F) == 0x0d))
                    || ((payload_len >= 16)
                    && (packet->payload[0] != 0x30) /* Avoid invalid SNMP detection */
                    && (packet->payload[2] == 0x02))) {
                MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
                //mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
                flow->l4.udp.skype_like_packet++;
                return 1;
            }

            /* Third payload octet is always 0x*d (something - d); interpret it as skype */
            if ((payload_len >= 16) && ((packet->payload[2] & 0x0F) == 0x0d)) {
                flow->l4.udp.skype_like_packet++;
            }

            return 1;
        } else if (flow->l4.udp.skype_like_packet == 4) {
            MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
            mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
            return 1;
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SKYPE);

    }
    return 1;
}

void mmt_init_classify_me_skype() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    //IPOQUE_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SKYPE);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SKYPE);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_skype_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SKYPE, PROTO_SKYPE_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_skype();

        return register_protocol(protocol_struct, PROTO_SKYPE);
    } else {
        return 0;
    }
}


