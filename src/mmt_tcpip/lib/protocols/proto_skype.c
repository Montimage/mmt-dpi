#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

int mmt_check_skype_dns(ipacket_t * ipacket, unsigned index) {
    debug("[DNS.SKYPE] Checking skype in DNS");
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
            debug("[DNS.SKYPE] Checking skype in DNS (2)");

    }
    MMT_ADD_PROTOCOL_TO_BITMASK(packet->flow->excluded_protocol_bitmask, PROTO_SKYPE);
    return 0;
}

int mmt_check_skype_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        uint32_t payload_len = packet->payload_packet_len;
        // int l4_offset = get_packet_offset_at_index(ipacket, index);
        
        /* skip marked packets */
        if (packet->detected_protocol_stack[0] != PROTO_UNKNOWN)
            return 0;
        if(packet->tcp == NULL) return 0;

        flow->l4.tcp.skype_packet_id++;

        if(flow->l4.tcp.skype_packet_id < 3) {
            ; /* Too early */
        } else if ((flow->l4.tcp.skype_packet_id == 3)
                    /* We have seen the 3-way handshake */
                    && flow->l4.tcp.seen_syn
                    && flow->l4.tcp.seen_syn_ack
                    && flow->l4.tcp.seen_ack) {
                if (((payload_len == 8) || (payload_len == 3))) {
                    MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
                    debug("[TCP.SKYPE]");
                    mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
                    return 1;
                }
                /* printf("[SKYPE] [id: %u][len: %d]\n", flow->l4.tcp.skype_packet_id, payload_len);  */
            }
            else{
                MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SKYPE);
                return 0;
            }
    }
    return 0;
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
        
        if(packet->udp == NULL) return 0;

        flow->l4.udp.skype_packet_id++;

        if (flow->l4.udp.skype_packet_id < 5) {
            uint16_t dport = ntohs(packet->udp->dest);
            
            /* skype-to-skype */
            if(dport!=1119){
                if (((payload_len == 3) && ((packet->payload[2] & 0x0F) == 0x0d))
                    || ((payload_len >= 16)
                    && (packet->payload[0] != 0x30) /* Avoid invalid SNMP detection */
                    && (packet->payload[2] == 0x02))) {
                    MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
                    // debug("[UDP.SKYPE]");
                    mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
                    // flow->l4.udp.skype_like_packet++;
                    return 1;
                }
            }
            

            // /* Third payload octet is always 0x*d (something - d); interpret it as skype */
            // if ((payload_len >= 16) && ((packet->payload[2] & 0x0F) == 0x0d)) {
            //     flow->l4.udp.skype_like_packet++;
            // }

            // return 1;
        }
        //  else if (flow->l4.udp.skype_like_packet == 4) {
        //     MMT_LOG(PROTO_SKYPE, MMT_LOG_DEBUG, "Found skype.\n");
        //     mmt_internal_add_connection(ipacket, PROTO_SKYPE, MMT_REAL_PROTOCOL);
        //     return 1;
        // }
        
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SKYPE);

    }
    return 0;
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


