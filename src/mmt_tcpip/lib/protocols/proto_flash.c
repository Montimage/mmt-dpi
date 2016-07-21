#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

void check_by_ip_address(ipacket_t * ipacket)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    /* unused
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    */

    if (packet->iph /* IPv4 only */) {
        /*
         * Ustream.tv 199.66.236.0/22
         */
        if (((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC742EC00 /* 199.66.236.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC742EC00 /* 199.66.236.0 */)) {
            mmt_internal_add_connection(ipacket, PROTO_USTREAM, MMT_REAL_PROTOCOL);
            return;
        }
    }
}

static void mmt_int_flash_add_connection(ipacket_t * ipacket)
{
    mmt_internal_add_connection(ipacket, PROTO_FLASH, MMT_REAL_PROTOCOL);
    check_by_ip_address(ipacket);
}

void mmt_classify_me_flash(ipacket_t * ipacket, unsigned index)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (flow->l4.tcp.flash_stage == 0 && packet->payload_packet_len > 0
            && (packet->payload[0] == 0x03 || packet->payload[0] == 0x06)) {
        flow->l4.tcp.flash_bytes = packet->payload_packet_len;
        if (packet->tcp->psh == 0) {
            MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG, "FLASH pass 1: \n");
            flow->l4.tcp.flash_stage = ipacket->session->last_packet_direction + 1;

            MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
                    "FLASH pass 1: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
                    flow->l4.tcp.flash_bytes);
            return;
        } else if (packet->tcp->psh != 0 && flow->l4.tcp.flash_bytes == 1537) {
            MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
                    "FLASH hit: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
                    flow->l4.tcp.flash_bytes);
            flow->l4.tcp.flash_stage = 3;
            mmt_int_flash_add_connection(ipacket);
            return;
        }
    } else if (flow->l4.tcp.flash_stage == 1 + ipacket->session->last_packet_direction) {
        flow->l4.tcp.flash_bytes += packet->payload_packet_len;
        if (packet->tcp->psh != 0 && flow->l4.tcp.flash_bytes == 1537) {
            MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
                    "FLASH hit: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
                    flow->l4.tcp.flash_bytes);
            flow->l4.tcp.flash_stage = 3;
            mmt_int_flash_add_connection(ipacket);
            return;
        } else if (packet->tcp->psh == 0 && flow->l4.tcp.flash_bytes < 1537) {
            MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
                    "FLASH pass 2: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
                    flow->l4.tcp.flash_bytes);
            return;
        }
    }

    MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
            "FLASH might be excluded: flash_stage: %u, flash_bytes: %u, packet_direction: %u\n",
            flow->l4.tcp.flash_stage, flow->l4.tcp.flash_bytes, packet->last_packet_direction);

#ifdef PROTO_HTTP
    if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP) != 0) {
#endif							/* IPOQUE_PROTOCOL_HTTP */
        MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG, "FLASH: exclude\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FLASH);
#ifdef PROTO_HTTP
    } else {
        MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG, "FLASH avoid early exclude from http\n");
    }
#endif							/* IPOQUE_PROTOCOL_HTTP */

}

int mmt_check_flash(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->l4.tcp.flash_stage == 0 && packet->payload_packet_len > 0
                && (packet->payload[0] == 0x03 || packet->payload[0] == 0x06)) {
            flow->l4.tcp.flash_bytes = packet->payload_packet_len;
            if (packet->tcp->psh == 0) {
                MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG, "FLASH pass 1: \n");
                flow->l4.tcp.flash_stage = ipacket->session->last_packet_direction + 1;

                MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
                        "FLASH pass 1: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
                        flow->l4.tcp.flash_bytes);
                return 1;
            } else if (packet->tcp->psh != 0 && flow->l4.tcp.flash_bytes == 1537) {
                MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
                        "FLASH hit: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
                        flow->l4.tcp.flash_bytes);
                flow->l4.tcp.flash_stage = 3;
                mmt_int_flash_add_connection(ipacket);
                return 1;
            }
        } else if (flow->l4.tcp.flash_stage == 1 + ipacket->session->last_packet_direction) {
            flow->l4.tcp.flash_bytes += packet->payload_packet_len;
            if (packet->tcp->psh != 0 && flow->l4.tcp.flash_bytes == 1537) {
                MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
                        "FLASH hit: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
                        flow->l4.tcp.flash_bytes);
                flow->l4.tcp.flash_stage = 3;
                mmt_int_flash_add_connection(ipacket);
                return 1;
            } else if (packet->tcp->psh == 0 && flow->l4.tcp.flash_bytes < 1537) {
                MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
                        "FLASH pass 2: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
                        flow->l4.tcp.flash_bytes);
                return 1;
            }
        }

        MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG,
                "FLASH might be excluded: flash_stage: %u, flash_bytes: %u, packet_direction: %u\n",
                flow->l4.tcp.flash_stage, flow->l4.tcp.flash_bytes, packet->last_packet_direction);

        if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP) != 0) {
            MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG, "FLASH: exclude\n");
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FLASH);
            return 0;
        } else {
            MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG, "FLASH avoid early exclude from http\n");
        }

    }
    return 0;
}

void mmt_init_classify_me_flash() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FLASH);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FLASH);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_flash_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FLASH, PROTO_FLASH_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_flash();

        return register_protocol(protocol_struct, PROTO_FLASH);
    } else {
        return 0;
    }
}


