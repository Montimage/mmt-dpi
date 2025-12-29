#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_xbox_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_XBOX, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_xbox(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /*
     * THIS IS TH XBOX UDP DETCTION ONLY !!!
     * the xbox tcp detection is done by http code
     */


    /* this detection also works for asymmetric xbox udp traffic */
    if (packet->udp != NULL) {

        uint16_t dport = ntohs(packet->udp->dest);
        uint16_t sport = ntohs(packet->udp->source);

        MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "search xbox\n");

        if (packet->payload_packet_len > 12 &&
                get_u32(packet->payload, 0) == 0 && packet->payload[5] == 0x58 &&
                mmt_memcmp(&packet->payload[7], "\x00\x00\x00", 3) == 0) {

            if ((packet->payload[4] == 0x0c && packet->payload[6] == 0x76) ||
                    (packet->payload[4] == 0x02 && packet->payload[6] == 0x18) ||
                    (packet->payload[4] == 0x0b && packet->payload[6] == 0x80) ||
                    (packet->payload[4] == 0x03 && packet->payload[6] == 0x40) ||
                    (packet->payload[4] == 0x06 && packet->payload[6] == 0x4e)) {

                mmt_int_xbox_add_connection(ipacket);
                MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "xbox udp connection detected\n");
                return;
            }
        }
        if ((dport == 3074 || sport == 3074)
                && ((packet->payload_packet_len == 24 && packet->payload[0] == 0x00)
                || (packet->payload_packet_len == 42 && packet->payload[0] == 0x4f && packet->payload[2] == 0x0a)
                || (packet->payload_packet_len == 80 && ntohs(get_u16(packet->payload, 0)) == 0x50bc
                && packet->payload[2] == 0x45)
                || (packet->payload_packet_len == 40 && ntohl(get_u32(packet->payload, 0)) == 0xcf5f3202)
                || (packet->payload_packet_len == 38 && ntohl(get_u32(packet->payload, 0)) == 0xc1457f03)
                || (packet->payload_packet_len == 28 && ntohl(get_u32(packet->payload, 0)) == 0x015f2c00))) {
            if (flow->l4.udp.xbox_stage == 1) {
                mmt_int_xbox_add_connection(ipacket);
                MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "xbox udp connection detected\n");
                return;
            }
            MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "maybe xbox.\n");
            flow->l4.udp.xbox_stage++;
            return;
        }

        /* exclude here all non matched udp traffic, exclude here tcp only if http has been excluded, because xbox could use http */
        if (packet->tcp == NULL
#ifdef PROTO_HTTP
                || MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP) != 0
#endif
                ) {
            MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "xbox udp excluded.\n");
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_XBOX);
        }
    }
    /* to not exclude tcp traffic here, done by http code... */
}

int mmt_check_xbox(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /*
         * THIS IS TH XBOX UDP DETCTION ONLY !!!
         * the xbox tcp detection is done by http code
         */
        /* this detection also works for asymmetric xbox udp traffic */
        if (packet->udp != NULL) {

            uint16_t dport = ntohs(packet->udp->dest);
            uint16_t sport = ntohs(packet->udp->source);

            MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "search xbox\n");

            if (packet->payload_packet_len > 12 &&
                    get_u32(packet->payload, 0) == 0 && packet->payload[5] == 0x58 &&
                    mmt_memcmp(&packet->payload[7], "\x00\x00\x00", 3) == 0) {

                if ((packet->payload[4] == 0x0c && packet->payload[6] == 0x76) ||
                        (packet->payload[4] == 0x02 && packet->payload[6] == 0x18) ||
                        (packet->payload[4] == 0x0b && packet->payload[6] == 0x80) ||
                        (packet->payload[4] == 0x03 && packet->payload[6] == 0x40) ||
                        (packet->payload[4] == 0x06 && packet->payload[6] == 0x4e)) {

                    mmt_int_xbox_add_connection(ipacket);
                    MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "xbox udp connection detected\n");
                    return 1;
                }
            }
            if ((dport == 3074 || sport == 3074)
                    && ((packet->payload_packet_len == 24 && packet->payload[0] == 0x00)
                    || (packet->payload_packet_len == 42 && packet->payload[0] == 0x4f && packet->payload[2] == 0x0a)
                    || (packet->payload_packet_len == 80 && ntohs(get_u16(packet->payload, 0)) == 0x50bc
                    && packet->payload[2] == 0x45)
                    || (packet->payload_packet_len == 40 && ntohl(get_u32(packet->payload, 0)) == 0xcf5f3202)
                    || (packet->payload_packet_len == 38 && ntohl(get_u32(packet->payload, 0)) == 0xc1457f03)
                    || (packet->payload_packet_len == 28 && ntohl(get_u32(packet->payload, 0)) == 0x015f2c00))) {
                if (flow->l4.udp.xbox_stage == 1) {
                    mmt_int_xbox_add_connection(ipacket);
                    MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "xbox udp connection detected\n");
                    return 1;
                }
                MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "maybe xbox.\n");
                flow->l4.udp.xbox_stage++;
                return 4;
            }

            /* exclude here all non matched udp traffic, exclude here tcp only if http has been excluded, because xbox could use http */
            if (packet->tcp == NULL || MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP) != 0) {
                MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "xbox udp excluded.\n");
                MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_XBOX);
                return 0;
            }
        }
        /* to not exclude tcp traffic here, done by http code... */
    }
    return 0;
}

void mmt_init_classify_me_xbox() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_XBOX);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_xbox_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_XBOX, PROTO_XBOX_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_xbox();

        return register_protocol(protocol_struct, PROTO_XBOX);
    } else {
        return 0;
    }
}
