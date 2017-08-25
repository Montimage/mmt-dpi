#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_stun_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_STUN, MMT_REAL_PROTOCOL);
    ipacket->session->content_flags = ipacket->session->content_flags | MMT_CONTENT_CONVERSATIONAL;
}

typedef enum {
    IPOQUE_IS_STUN,
    IPOQUE_IS_NOT_STUN
} mmt_int_stun_result_t;

static mmt_int_stun_result_t mmt_int_check_stun(ipacket_t * ipacket, const uint8_t * payload, const uint16_t payload_length) {
    uint16_t a;

    /*
     * token list of message types and attribute types from
     * http://wwwbs1.informatik.htw-dresden.de/svortrag/i02/Schoene/stun/stun.html
     * the same list you can find in
     * https://summersoft.fay.ar.us/repos/ethereal/branches/redhat-9/ethereal-0.10.3-1/ethereal-0.10.3/packet-stun.c
     * token further message types and attributes from
     * http://www.freeswitch.org/docs/group__stun1.html
     * added further attributes observed
     * message types: 0x0001, 0x0101, 0x0111, 0x0002, 0x0102, 0x0112, 0x0003, 0x0103, 0x0004, 0x0104, 0x0114, 0x0115
     * attribute types: 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009,
     * 0x000a, 0x000b, 0c000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0020,
     * 0x0022, 0x0024, 0x8001, 0x8006, 0x8008, 0x8015, 0x8020, 0x8028, 0x802a, 0x8029, 0x8050, 0x8054, 0x8055
     *
     * 0x8003, 0x8004 used by facetime
     */

    if (payload_length >= 20 && ntohs(get_u16(payload, 2)) + 20 == payload_length &&
            ((payload[0] == 0x00 && (payload[1] >= 0x01 && payload[1] <= 0x04)) ||
            (payload[0] == 0x01 &&
            ((payload[1] >= 0x01 && payload[1] <= 0x04) || (payload[1] >= 0x11 && payload[1] <= 0x15))))) {
        uint8_t mod;
        uint8_t old = 1;
        uint8_t padding = 0;
        MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "len and type match.\n");

        if (payload_length == 20) {
            MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "found stun.\n");
            return IPOQUE_IS_STUN;
        }

        a = 20;

        while (a < payload_length) {

            if (old && payload_length >= a + 4
                    &&
                    ((payload[a] == 0x00
                    && ((payload[a + 1] >= 0x01 && payload[a + 1] <= 0x16) || payload[a + 1] == 0x19
                    || payload[a + 1] == 0x20 || payload[a + 1] == 0x22 || payload[a + 1] == 0x24
                    || payload[a + 1] == 0x25))
                    || (payload[a] == 0x80
                    && (payload[a + 1] == 0x01 || payload[a + 1] == 0x03 || payload[a + 1] == 0x04
                    || payload[a + 1] == 0x06 || payload[a + 1] == 0x08 || payload[a + 1] == 0x15
                    || payload[a + 1] == 0x20 || payload[a + 1] == 0x22 || payload[a + 1] == 0x28
                    || payload[a + 1] == 0x2a || payload[a + 1] == 0x29 || payload[a + 1] == 0x50
                    || payload[a + 1] == 0x54 || payload[a + 1] == 0x55)))) {

                MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "attribute match.\n");

                a += ((payload[a + 2] << 8) + payload[a + 3] + 4);
                mod = a % 4;
                if (mod) {
                    padding = 4 - mod;
                }
                if (a == payload_length || (padding && (a + padding) == payload_length)) {
                    MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "found stun.\n");
                    return IPOQUE_IS_STUN;
                }

            } else if (payload_length >= a + padding + 4
                    &&
                    ((payload[a + padding] == 0x00
                    && ((payload[a + 1 + padding] >= 0x01 && payload[a + 1 + padding] <= 0x16)
                    || payload[a + 1 + padding] == 0x19 || payload[a + 1 + padding] == 0x20
                    || payload[a + 1 + padding] == 0x22 || payload[a + 1 + padding] == 0x24
                    || payload[a + 1 + padding] == 0x25))
                    || (payload[a + padding] == 0x80
                    && (payload[a + 1 + padding] == 0x01 || payload[a + 1 + padding] == 0x03
                    || payload[a + 1 + padding] == 0x04 || payload[a + 1 + padding] == 0x06
                    || payload[a + 1 + padding] == 0x08 || payload[a + 1 + padding] == 0x15
                    || payload[a + 1 + padding] == 0x20 || payload[a + 1 + padding] == 0x22
                    || payload[a + 1 + padding] == 0x28 || payload[a + 1 + padding] == 0x2a
                    || payload[a + 1 + padding] == 0x29 || payload[a + 1 + padding] == 0x50
                    || payload[a + 1 + padding] == 0x54 || payload[a + 1 + padding] == 0x55)))) {

                MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "New STUN - attribute match.\n");

                old = 0;
                a += ((payload[a + 2 + padding] << 8) + payload[a + 3 + padding] + 4);
                padding = 0;
                mod = a % 4;
                if (mod) {
                    a += 4 - mod;
                }
                if (a == payload_length) {
                    MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "found stun.\n");
                    return IPOQUE_IS_STUN;
                }
            } else {
                break;
            }
        }
    }

    return IPOQUE_IS_NOT_STUN;
}

void mmt_classify_me_stun(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "search stun.\n");


    if (packet->tcp) {

        /* STUN may be encapsulated in TCP packets */

        if (packet->payload_packet_len >= 2 + 20 &&
                ntohs(get_u16(packet->payload, 0)) + 2 == packet->payload_packet_len) {

            /* TODO there could be several STUN packets in a single TCP packet so maybe the detection could be
             * improved by checking only the STUN packet of given length */

            if (mmt_int_check_stun(ipacket, packet->payload + 2, packet->payload_packet_len - 2) ==
                    IPOQUE_IS_STUN) {
                MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "found TCP stun.\n");
                mmt_int_stun_add_connection(ipacket);
                return;
            }
        }
    }
    if (mmt_int_check_stun(ipacket, packet->payload, packet->payload_packet_len) == IPOQUE_IS_STUN) {
        MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "found UDP stun.\n");
        mmt_int_stun_add_connection(ipacket);
        return;
    }

    MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "exclude stun.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_STUN);
}

int mmt_check_stun_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "search stun.\n");

        /* STUN may be encapsulated in TCP packets */
        if (packet->payload_packet_len >= 2 + 20 &&
                ntohs(get_u16(packet->payload, 0)) + 2 == packet->payload_packet_len) {

            /* TODO there could be several STUN packets in a single TCP packet so maybe the detection could be
             * improved by checking only the STUN packet of given length */
            if (mmt_int_check_stun(ipacket, packet->payload + 2, packet->payload_packet_len - 2) ==
                    IPOQUE_IS_STUN) {
                MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "found TCP stun.\n");
                mmt_int_stun_add_connection(ipacket);
                return 1;
            }
        }
        MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "exclude stun.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_STUN);
    }
    return 0;
}

int check_viber_udp(ipacket_t * ipacket) {
    //Viber signatures are all orthogonal with SSL signature! If we detect any valid vider signature return a positive value
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    /* viber runs over tcp port 5243 or 7985 */
    if (packet->udp->source == htons(5243) || packet->udp->dest == htons(5243) || packet->udp->source == htons(7985) || packet->udp->dest == htons(7985)) {
        if (packet->iph /* IPv4 only */) {
            /*
             * Viber is hosted over Amazon cloud
             * Check if this is the case
             * 50.16.0.0/14
             * 107.20.0.0/14
             * 23.20.0.0/14
             * 54.224.0.0/11
             * 46.51.0.0/16
             * 46.137.0.0/16
             * 176.34.0.0/16
             * These are not the only ranges but the most consequent ones
             */
            
            if (((ntohl(packet->iph->saddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x36A93FA0 /* 54.169.63.160 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x36A93FA0 /* 54.169.63.160 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }

            if (((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x3400FC00 /* 52.0.252.0 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x3400FC00 /* 52.0.252.0 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }

            if (((ntohl(packet->iph->saddr) & 0xFFFFFFC0 /* 255.255.255.192 */) == 0x365DFF40 /* 54.93.255.64 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFFC0 /* 255.255.255.192 */) == 0x365DFF40 /* 54.93.255.64 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }

            if (((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x32100000 /* 50.16.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x32100000 /* 50.16.0.0/14 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x6B140000 /* 107.20.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x6B140000 /* 107.20.0.0/14 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x17140000 /* 23.20.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x17140000 /* 23.20.0.0/14 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFE00000 /* 255.224.0.0 */) == 0x36E00000 /* 54.224.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFE00000 /* 255.224.0.0 */) == 0x36E00000 /* 54.224.0.0/14 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E330000 /* 46.51.0.0/16 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E330000 /* 46.51.0.0/16 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E890000 /* 46.137.0.0/16 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E890000 /* 46.137.0.0/16 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0xB0220000 /* 176.34.0.0/16 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0xB0220000 /* 176.34.0.0/16 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
        }
    }
    return 0;
}

int check_tango_udp(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    const char tango_pattern[] = {0x09, 0x54, 0x41, 0x4e, 0x47, 0x4f};

    if (packet->payload_packet_len > 32 && packet->payload[0] == 0x03 &&
            (mmt_memcmp(&packet->payload[6], tango_pattern, sizeof (tango_pattern)) == 0)) {
        flow->l4.udp.tango_like_packet++;
    }
    if (flow->l4.udp.tango_like_packet >= 1) {
        insert_to_local_protos(packet->udp->dest, PROTO_TANGO, 17 /*UDP*/, &dst->local_protos);
        insert_to_local_protos(packet->udp->source, PROTO_TANGO, 17 /*UDP*/, &src->local_protos);
        mmt_internal_add_connection(ipacket, PROTO_TANGO, MMT_REAL_PROTOCOL);
        //fprintf(stdout, "Test from tango pattern\n");
        return 1;
    }

    if (packet->iph /* IPv4 only */) {
        /*
         * 72.251.243.112/29
         * 199.83.168.0/21
         */
        if (((ntohl(packet->iph->saddr) & 0xFFFFF800 /* 255.255.248.0 */) == 0xC753A800 /* 199.83.168.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFF800 /* 255.255.248.0 */) == 0xC753A800 /* 199.83.168.0 */)) {
            mmt_internal_add_connection(ipacket, PROTO_TANGO, MMT_REAL_PROTOCOL);
            insert_to_local_protos(packet->udp->dest, PROTO_TANGO, 17 /*UDP*/, &dst->local_protos);
            insert_to_local_protos(packet->udp->source, PROTO_TANGO, 17 /*UDP*/, &src->local_protos);
            return 1;
        }
        if (((ntohl(packet->iph->saddr) & 0xFFFFFFF8 /* 255.255.255.248 */) == 0x48FBF370 /* 72.251.243.112/29 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFFFF8 /* 255.255.255.248 */) == 0x48FBF370 /* 72.251.243.112/29 */)) {
            mmt_internal_add_connection(ipacket, PROTO_TANGO, MMT_REAL_PROTOCOL);
            insert_to_local_protos(packet->udp->dest, PROTO_TANGO, 17 /*UDP*/, &dst->local_protos);
            insert_to_local_protos(packet->udp->source, PROTO_TANGO, 17 /*UDP*/, &src->local_protos);
            return 1;
        }
    }

    uint32_t proto; 
    proto = check_local_proto_by_port_nb(packet->udp->dest, &dst->local_protos);
    if (proto == PROTO_TANGO) {
        mmt_internal_add_connection(ipacket, PROTO_TANGO, MMT_CORRELATED_PROTOCOL);
        return 1;
    }
    proto = check_local_proto_by_port_nb(packet->udp->source, &src->local_protos);
    if (proto == PROTO_TANGO) {
        mmt_internal_add_connection(ipacket, PROTO_TANGO, MMT_CORRELATED_PROTOCOL);
        return 1;
    }

    return 0;
}

uint32_t check_apple_facetime_signaling_udp(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    if (packet->iph /* IPv4 only */) {
        /*
         * 103.2.28.0/22
         */
        if ((((ntohl(packet->iph->saddr) & 0xFF000000 /* 255.0.0.0 */) == 0x11000000 /* 17.0.0.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFF000000 /* 255.0.0.0 */) == 0x11000000 /* 17.0.0.0 */)) && (packet->payload_packet_len == 16)) {
            insert_to_local_protos(packet->udp->dest, PROTO_FACETIME, 17 /*UDP*/, &dst->local_protos);
            insert_to_local_protos(packet->udp->source, PROTO_FACETIME, 17 /*UDP*/, &src->local_protos);
            mmt_internal_add_connection(ipacket, PROTO_FACETIME, MMT_REAL_PROTOCOL);
            return 1;
        }
    }

    return 0;
}

uint32_t check_stun_internal(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    uint32_t proto;

    if (packet->iph /* IPv4 only */) {
        /*
         * 103.2.28.0/22
         */
        if (((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x67021C00 /* 103.2.28.0/22 */)) {
            mmt_internal_add_connection(ipacket, PROTO_LINE, MMT_REAL_PROTOCOL);
            //In addition, report the port number of the source address
            insert_to_local_protos(packet->udp->dest, PROTO_LINE, 17 /*UDP*/, &dst->local_protos);
            insert_to_local_protos(packet->udp->source, PROTO_LINE, 17 /*UDP*/, &src->local_protos);
            return PROTO_LINE;
        }
    }

    /* Check the protocol by the IP addresses!!!*/
    proto = get_proto_id_from_address(ipacket);
    if (proto != PROTO_UNKNOWN) {
        switch (proto) {
            case PROTO_YAHOO:
                mmt_internal_add_connection(ipacket, PROTO_YAHOOMSG, MMT_CORRELATED_PROTOCOL);
                insert_to_local_protos(packet->udp->dest, PROTO_YAHOOMSG, 17 /*UDP*/, &dst->local_protos);
                insert_to_local_protos(packet->udp->source, PROTO_YAHOOMSG, 17 /*UDP*/, &src->local_protos);
                return PROTO_YAHOOMSG;
            case PROTO_GOOGLE:
                mmt_internal_add_connection(ipacket, PROTO_GTALK, MMT_CORRELATED_PROTOCOL);
                insert_to_local_protos(packet->udp->dest, PROTO_GTALK, 17 /*UDP*/, &dst->local_protos);
                insert_to_local_protos(packet->udp->source, PROTO_GTALK, 17 /*UDP*/, &src->local_protos);
                return PROTO_GTALK;
            default:
                mmt_internal_add_connection(ipacket, proto, MMT_CORRELATED_PROTOCOL);
                insert_to_local_protos(packet->udp->dest, proto, 17 /*UDP*/, &dst->local_protos);
                insert_to_local_protos(packet->udp->source, proto, 17 /*UDP*/, &src->local_protos);
                return proto;
        }
    }

    return PROTO_UNKNOWN;
}

int mmt_check_stun_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "search stun.\n");

        if (mmt_int_check_stun(ipacket, packet->payload, packet->payload_packet_len) == IPOQUE_IS_STUN) {
            MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "found UDP stun.\n");
            mmt_int_stun_add_connection(ipacket);
            check_stun_internal(ipacket);
            return 4;
        } else {
            if (check_viber_udp(ipacket) || check_tango_udp(ipacket) || check_apple_facetime_signaling_udp(ipacket)) {
                MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_STUN);
                return 4;
            }
        }

        MMT_LOG(PROTO_STUN, MMT_LOG_DEBUG, "exclude stun.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_STUN);
    }
    return 0;
}

void mmt_init_classify_me_stun() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_STUN);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_stun_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_STUN, PROTO_STUN_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_stun();

        return register_protocol(protocol_struct, PROTO_STUN);
    } else {
        return 0;
    }
}


