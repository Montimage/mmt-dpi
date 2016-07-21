#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define IPOQUE_MAX_MDNS_REQUESTS                        128

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

/*
This module should detect MDNS
 */
static void mmt_int_mdns_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_MDNS, MMT_REAL_PROTOCOL);
}

static int mmt_int_check_mdns_payload(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = (struct mmt_tcpip_internal_packet_struct *) ipacket->internal_packet;

    if ((packet->payload[2] & 0x80) == 0 &&
            ntohs(get_u16(packet->payload, 4)) <= IPOQUE_MAX_MDNS_REQUESTS &&
            ntohs(get_u16(packet->payload, 6)) <= IPOQUE_MAX_MDNS_REQUESTS) {

        MMT_LOG(PROTO_MDNS, MMT_LOG_DEBUG, "found MDNS with question query.\n");

        return 1;
    } else if ((packet->payload[2] & 0x80) != 0 &&
            ntohs(get_u16(packet->payload, 4)) == 0 &&
            ntohs(get_u16(packet->payload, 6)) <= IPOQUE_MAX_MDNS_REQUESTS &&
            ntohs(get_u16(packet->payload, 6)) != 0) {
        MMT_LOG(PROTO_MDNS, MMT_LOG_DEBUG, "found MDNS with answer query.\n");

        return 1;
    }

    return 0;
}

void mmt_classify_me_mdns(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint16_t dport;
    //      const u16 sport=ntohs(packet->udp->source);

    /* check if UDP and */
    if (packet->udp != NULL) {
        /*read destination port */
        dport = ntohs(packet->udp->dest);

        MMT_LOG(PROTO_MDNS, MMT_LOG_DEBUG, "MDNS udp start \n");



        /*check standard MDNS to port 5353 */
        /*took this information from http://www.it-administrator.de/lexikon/multicast-dns.html */

        if (dport == 5353 && packet->payload_packet_len >= 12) {

            MMT_LOG(PROTO_MDNS, MMT_LOG_DEBUG, "found MDNS with destination port 5353\n");

            /* MDNS header is similar to dns header */
            /* dns header
               0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                      ID                       |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                    QDCOUNT                    |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                    ANCOUNT                    |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                    NSCOUNT                    |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                    ARCOUNT                    |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             *
             * dns query check: query: QR set, ancount = 0, nscount = 0, QDCOUNT < MAX_MDNS, ARCOUNT < MAX_MDNS
             *
             */

            /* mdns protocol must have destination address  224.0.0.251 */
            /* took this information from http://www.it-administrator.de/lexikon/multicast-dns.html */

            if (packet->iph != NULL && ntohl(packet->iph->daddr) == 0xe00000fb) {

                MMT_LOG(PROTO_MDNS, 
                        MMT_LOG_DEBUG, "found MDNS with destination address 224.0.0.251 (=0xe00000fb)\n");

                if (mmt_int_check_mdns_payload(ipacket) == 1) {
                    mmt_int_mdns_add_connection(ipacket);
                    return;
                }
            }
#ifdef MMT_SUPPORT_IPV6
            if (packet->iphv6 != NULL) {
                const uint32_t *daddr = packet->iphv6->daddr.mmt_v6_u.u6_addr32;
                if (daddr[0] == htonl(0xff020000) && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == htonl(0xfb)) {

                    MMT_LOG(PROTO_MDNS, 
                            MMT_LOG_DEBUG, "found MDNS with destination address ff02::fb\n");

                    if (mmt_int_check_mdns_payload(ipacket) == 1) {
                        mmt_int_mdns_add_connection(ipacket);
                        return;
                    }
                }
            }
#endif

        }
    }
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MDNS);
}

int mmt_check_mdns(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct * flow = packet->flow;

        uint16_t dport;

        /*read destination port */
        dport = ntohs(packet->udp->dest);

        MMT_LOG(PROTO_MDNS, MMT_LOG_DEBUG, "MDNS udp start \n");

        /*check standard MDNS to port 5353 */
        /*took this information from http://www.it-administrator.de/lexikon/multicast-dns.html */
        if (dport == 5353 && packet->payload_packet_len >= 12) {
            MMT_LOG(PROTO_MDNS, MMT_LOG_DEBUG, "found MDNS with destination port 5353\n");

            /* MDNS header is similar to dns header */
            /* dns header
               0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                      ID                       |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                    QDCOUNT                    |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                    ANCOUNT                    |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                    NSCOUNT                    |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               |                    ARCOUNT                    |
               +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             *
             * dns query check: query: QR set, ancount = 0, nscount = 0, QDCOUNT < MAX_MDNS, ARCOUNT < MAX_MDNS
             *
             */

            /* mdns protocol must have destination address  224.0.0.251 */
            /* took this information from http://www.it-administrator.de/lexikon/multicast-dns.html */

            if (packet->iph != NULL && ntohl(packet->iph->daddr) == 0xe00000fb) {

                MMT_LOG(PROTO_MDNS, 
                        MMT_LOG_DEBUG, "found MDNS with destination address 224.0.0.251 (=0xe00000fb)\n");

                if (mmt_int_check_mdns_payload(ipacket) == 1) {
                    mmt_int_mdns_add_connection(ipacket);
                    return 1;
                }
            }
            if (packet->iphv6 != NULL) {
                const uint32_t *daddr = packet->iphv6->daddr.mmt_v6_u.u6_addr32;
                if (daddr[0] == htonl(0xff020000) && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == htonl(0xfb)) {

                    MMT_LOG(PROTO_MDNS, 
                            MMT_LOG_DEBUG, "found MDNS with destination address ff02::fb\n");

                    if (mmt_int_check_mdns_payload(ipacket) == 1) {
                        mmt_int_mdns_add_connection(ipacket);
                        return 1;
                    }
                }
            }
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MDNS);
    }
    return 0;
}

void mmt_init_classify_me_mdns() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_MDNS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_mdns_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MDNS, PROTO_MDNS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_mdns();

        return register_protocol(protocol_struct, PROTO_MDNS);
    } else {
        return 0;
    }
}


