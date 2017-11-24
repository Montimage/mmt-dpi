#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_sip_add_connection(ipacket_t * ipacket, uint32_t protocol) {
    if (protocol == PROTO_SIP) {
        mmt_internal_add_connection(ipacket, protocol, MMT_REAL_PROTOCOL);
    } else {
        mmt_internal_add_connection(ipacket, protocol, MMT_CORRELATED_PROTOCOL);
    }
}

uint32_t check_sip_internal(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    /* unused
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    */
    uint32_t proto;
    if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= 11 && mmt_memcmp(packet->user_agent_line.ptr, "Yahoo Voice", 11) == 0) {
        mmt_int_sip_add_connection(ipacket, PROTO_YAHOOMSG);
        //printf("Test from sip\n");
        set_local_conv_proto(ipacket, PROTO_YAHOOMSG, packet);
        return PROTO_YAHOO;
    }

    /* Check the protocol by the IP addresses!!!*/
    proto = get_proto_id_from_address(ipacket);
    if (proto != PROTO_UNKNOWN) {
        switch(proto) {
            case PROTO_YAHOO:
                mmt_int_sip_add_connection(ipacket, PROTO_YAHOOMSG);
                //printf("Test from sip\n");
                set_local_conv_proto(ipacket, PROTO_YAHOOMSG, packet);
                return PROTO_YAHOOMSG;
            default:
                mmt_int_sip_add_connection(ipacket, proto);
                return proto;
        }
    }

    return PROTO_UNKNOWN;
}

static void mmt_search_sip_handshake(ipacket_t * ipacket)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    const uint8_t *packet_payload = packet->payload;
    uint32_t payload_len = packet->payload_packet_len;


    if (payload_len > 4) {
        /* search for STUN Turn ChannelData Prefix */
        uint16_t message_len = ntohs(get_u16(packet->payload, 2));
        if (payload_len - 4 == message_len) {
            MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found STUN TURN ChannelData prefix.\n");
            payload_len -= 4;
            packet_payload += 4;
        }
    }
#ifndef PROTO_YAHOO
    if (payload_len >= 14 && packet_payload[payload_len - 2] == 0x0d && packet_payload[payload_len - 1] == 0x0a)
#endif
#ifdef PROTO_YAHOO
        if (payload_len >= 14)
#endif
        {
            mmt_parse_packet_line_info(ipacket);

            switch(packet_payload[0]){
                case 'N':
                    if ((mmt_memcmp(packet_payload + 1, "OTIFY ", 6) == 0)
                        && (mmt_memcmp(&packet_payload[7], "SIP:", 4) == 0 || mmt_memcmp(&packet_payload[7], "sip:", 4) == 0)) {
                        
                        MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip NOTIFY.\n");
                        mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                        check_sip_internal(ipacket);
                        return;
                    }
                    break;
                case 'n':
                if ((mmt_memcmp(packet_payload + 1, "otify ", 6) == 0)
                    && (mmt_memcmp(&packet_payload[7], "SIP:", 4) == 0 || mmt_memcmp(&packet_payload[7], "sip:", 4) == 0)) {

                    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip NOTIFY.\n");
                    mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                    check_sip_internal(ipacket);
                    return;
                }
                break;

                case 'R':
                if ((mmt_memcmp(packet_payload + 1, "EGISTER ", 8) == 0)
                    && (mmt_memcmp(&packet_payload[9], "SIP:", 4) == 0 || mmt_memcmp(&packet_payload[9], "sip:", 4) == 0)) {

                    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip REGISTER.\n");
                    mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                    check_sip_internal(ipacket);
                    return;
                }
                break;

                case 'r':
                if ((mmt_memcmp(packet_payload + 1, "egister ", 8) == 0)
                    && (mmt_memcmp(&packet_payload[9], "SIP:", 4) == 0 || mmt_memcmp(&packet_payload[9], "sip:", 4) == 0)) {

                    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip REGISTER.\n");
                    mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                    check_sip_internal(ipacket);
                    return;
                }
                break;

                case 'I':
                if ((mmt_memcmp(packet_payload + 1, "NVITE ", 6) == 0)
                    && (mmt_memcmp(&packet_payload[7], "SIP:", 4) == 0 || mmt_memcmp(&packet_payload[7], "sip:", 4) == 0)) {
                    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip INVITE.\n");
                    mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                    check_sip_internal(ipacket);
                    return;
                }
                break;

                case 'i':
                if ((mmt_memcmp(packet_payload + 1, "invite ", 7) == 0)
                    && (mmt_memcmp(&packet_payload[7], "SIP:", 4) == 0 || mmt_memcmp(&packet_payload[7], "sip:", 4) == 0)) {
                    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip INVITE.\n");
                    mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                    check_sip_internal(ipacket);
                    return;
                }
                break;

                case 'S':
                /* seen this in second direction on the third position,
                 * maybe it could be deleted, if somebody sees it in the first direction,
                 * please delete this comment.
                 */
                if (mmt_memcmp(packet_payload + 1, "IP/2.0 200 OK", 13) == 0) {
                    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip SIP/2.0 0K.\n");
                    mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                    check_sip_internal(ipacket);
                    return;
                }
                break;

                case 's':
                /* seen this in second direction on the third position,
                 * maybe it could be deleted, if somebody sees it in the first direction,
                 * please delete this comment.
                 */
                if (mmt_memcmp(packet_payload + 1, "sip/2.0 200 OK", 14) == 0) {
                    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip SIP/2.0 0K.\n");
                    mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                    check_sip_internal(ipacket);
                    return;
                }
                break;

                case 'O':
                /* Courtesy of Miguel Quesada <mquesadab@gmail.com> */
                if ((mmt_memcmp(packet_payload + 1, "PTIONS ", 7) == 0)
                        && (mmt_memcmp(&packet_payload[8], "SIP:", 4) == 0
                        || mmt_memcmp(&packet_payload[8], "sip:", 4) == 0)) {
                    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip OPTIONS.\n");
                    mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                    check_sip_internal(ipacket);
                    return;
                }
                break;

                case 'o':
                /* Courtesy of Miguel Quesada <mquesadab@gmail.com> */
                if ((mmt_memcmp(packet_payload + 1, "ptions ", 7) == 0)
                        && (mmt_memcmp(&packet_payload[8], "SIP:", 4) == 0
                        || mmt_memcmp(&packet_payload[8], "sip:", 4) == 0)) {
                    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "found sip OPTIONS.\n");
                    mmt_int_sip_add_connection(ipacket, PROTO_SIP);
                    check_sip_internal(ipacket);
                    return;
                }
                break;
                default:
                break;
            }
        }

    /* add bitmask for tcp only, some stupid udp programs
     * send a very few (< 10 ) packets before invite (mostly a 0x0a0x0d, but just search the first 3 payload_packets here */
    if (packet->udp != NULL && ipacket->session->data_packet_count < 20) {
        MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "need next packet.\n");
        return;
    }
#ifdef PROTO_STUN
    /* for STUN flows we need some more packets */
    if (packet->udp != NULL && flow->detected_protocol_stack[0] == PROTO_STUN && ipacket->session->data_packet_count < 40) {
        MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "need next STUN packet.\n");
        return;
    }
#endif

    if (payload_len == 4 && get_u32(packet_payload, 0) == 0) {
        MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "maybe sip. need next packet.\n");
        return;
    }
#ifdef PROTO_YAHOO
    if (payload_len > 30 && packet_payload[0] == 0x90
            && packet_payload[3] == payload_len - 20 && get_u32(packet_payload, 4) == 0
            && get_u32(packet_payload, 8) == 0) {
        flow->sip_yahoo_voice = 1;
        MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "maybe sip yahoo. need next packet.\n");
    }
    if (flow->sip_yahoo_voice && ipacket->session->data_packet_count < 10) {
        return;
    }
#endif
    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "exclude sip.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SIP);
    return;


}

void mmt_classify_me_sip(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "sip detection...\n");

    /* skip marked packets */
    if (packet->detected_protocol_stack[0] != PROTO_SIP) {
        if (packet->tcp_retransmission == 0) {
            mmt_search_sip_handshake(ipacket);
        }
    }
}

int mmt_check_sip(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        MMT_LOG(PROTO_SIP, MMT_LOG_DEBUG, "sip detection...\n");

        /* skip marked packets */
        if (packet->detected_protocol_stack[0] != PROTO_SIP) {
            if (packet->tcp_retransmission == 0) { //BW: TODO: shouldn't we change the bitmask to indicate no retransmissions?
                mmt_search_sip_handshake(ipacket);
            }
        }
    }
    return 4;
}

void mmt_init_classify_me_sip() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SIP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_STUN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SIP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_sip_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SIP, PROTO_SIP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_sip();

        return register_protocol(protocol_struct, PROTO_SIP);
    } else {
        return 0;
    }
}


