#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

void mmt_classify_me_spotify(ipacket_t * ipacket, unsigned index) {


    MMT_LOG(PROTO_SPOTIFY, MMT_LOG_DEBUG, "spotify detection...\n");
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    //struct mmt_id_struct *dst = mmt_struct->dst;
    uint32_t payload_len = packet->payload_packet_len;

    if (packet->iph /* IPv4 only */) {
        /*
           SPOTIFY NETWORK (NET-78.31.8.0/22) 78.31.8.0 - 78.31.15.255
           199.59.148.0/22
         */
        if (((ntohl(packet->iph->saddr) & 0xFFFFFC00) == 0x4E1F0800)
                || ((ntohl(packet->iph->daddr) & 0xFFFFFC00) == 0x4E1F0800)) {
            MMT_LOG(PROTO_SPOTIFY, MMT_LOG_DEBUG, "Found spotify.\n");
            mmt_internal_add_connection(ipacket, PROTO_SPOTIFY, MMT_REAL_PROTOCOL);
            return;
        }

        if (packet->tcp != NULL) {
            flow->l4.tcp.spotify_like_packet++;
            if (flow->l4.tcp.spotify_like_packet == 1) {
                /* first three octets are 010000 */
                if ((payload_len >= 16) && (packet->payload[0] == 0x01) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x00)) {
                    flow->l4.tcp.spotify_stage = 1;
                    //Need to check the packet on the return path
                    return;
                }
            }
            if ((flow->l4.tcp.spotify_like_packet == 2) && (flow->l4.tcp.spotify_stage == 1)) {
                /* first octet is 00 */
                if ((payload_len >= 16) && (packet->payload[0] == 0x00)) {
                    //Now check if SPOTIFY was already detected for the source address
                    if (MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_SPOTIFY)) {
                        flow->l4.tcp.spotify_stage = 2;
                        MMT_LOG(PROTO_SPOTIFY, MMT_LOG_DEBUG, "Found spotify.\n");
                        mmt_internal_add_connection(ipacket, PROTO_SPOTIFY, MMT_REAL_PROTOCOL);
                        return;
                    }
                }
            }
        }
    }
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SPOTIFY);
}

int mmt_check_spotify(ipacket_t * ipacket, unsigned index) { //BW: TODO: check this out
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {



        MMT_LOG(PROTO_SPOTIFY, MMT_LOG_DEBUG, "spotify detection...\n");
        struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        //struct mmt_id_struct *dst = mmt_struct->dst;
        uint32_t payload_len = packet->payload_packet_len;

        if (packet->iph /* IPv4 only */) { //This is an extra check! the bitmask include IPV4 only
            /*
               SPOTIFY NETWORK (NET-78.31.8.0/22) 78.31.8.0 - 78.31.15.255
               199.59.148.0/22
             */
            if (((ntohl(packet->iph->saddr) & 0xFFFFFC00) == 0x4E1F0800)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFC00) == 0x4E1F0800)) {
                MMT_LOG(PROTO_SPOTIFY, MMT_LOG_DEBUG, "Found spotify.\n");
                mmt_internal_add_connection(ipacket, PROTO_SPOTIFY, MMT_REAL_PROTOCOL);
                return 1;
            }

            flow->l4.tcp.spotify_like_packet++;
            if (flow->l4.tcp.spotify_like_packet == 1) {
                /* first three octets are 010000 */
                if ((payload_len >= 16) && (packet->payload[0] == 0x01) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x00)) {
                    flow->l4.tcp.spotify_stage = 1;
                    //Need to check more packets
                    return 4;
                }
            }
            if ((flow->l4.tcp.spotify_like_packet == 2) && (flow->l4.tcp.spotify_stage == 1)) {
                /* first octet is 00 */
                if ((payload_len >= 16) && (packet->payload[0] == 0x00)) {
                    //Now check if SPOTIFY was already detected for the source address
                    if (MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_SPOTIFY)) {
                        flow->l4.tcp.spotify_stage = 2;
                        MMT_LOG(PROTO_SPOTIFY, MMT_LOG_DEBUG, "Found spotify.\n");
                        mmt_internal_add_connection(ipacket, PROTO_SPOTIFY, MMT_REAL_PROTOCOL);
                        return 1;
                    }
                }
            }
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SPOTIFY);

    }
    return 0;
}

void mmt_init_classify_me_spotify() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SPOTIFY);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SPOTIFY);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_spotify_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SPOTIFY, PROTO_SPOTIFY_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_spotify();

        return register_protocol(protocol_struct, PROTO_SPOTIFY);
    } else {
        return 0;
    }
}
