/*
 * proto_geneve.c — GENEVE (RFC 8926 §3), issue #572 (F-BUG-308).
 *
 * mmt_check_geneve claims a UDP flow on the IANA port 6081 whose datagrams
 * carry a version-0 GENEVE header with its options inside the datagram;
 * geneve_classify_next_proto steps over the 8-byte base header and the
 * Opt Len * 4 bytes of options and hands the payload, by its Protocol Type,
 * to Ethernet (0x6558, transparent Ethernet bridging), IPv4 or IPv6. A
 * control packet (O bit) carries a tunnel-endpoint message, not a user flow,
 * so its path ends here. Nesting is bounded by the protocol path.
 */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "tunnel_walk.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

#define GENEVE_UDP_PORT   6081
#define GENEVE_HDR_LEN    8u
#define GENEVE_FLAG_O     0x80u    /* control packet */
#define GENEVE_PT_TEB     0x6558u  /* transparent Ethernet bridging */

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

/* Length of the base header plus options, or 0 when the version is not 0. */
static uint32_t geneve_header_len(const uint8_t *h) {
    if ((h[0] >> 6) != 0)
        return 0;
    return GENEVE_HDR_LEN + 4u * (uint32_t) (h[0] & 0x3f);
}

int mmt_check_geneve(ipacket_t * ipacket, unsigned index) {
    (void) index;
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* guard evaluated by the classifier walk (issue #561) */
    if (packet->udp != NULL
            && (packet->udp->dest == htons(GENEVE_UDP_PORT)
                || packet->udp->source == htons(GENEVE_UDP_PORT))
            && packet->payload_packet_len >= GENEVE_HDR_LEN) {
        uint32_t hlen = geneve_header_len(packet->payload);
        uint16_t ptype = (uint16_t) ((packet->payload[2] << 8) | packet->payload[3]);
        /* the Protocol Type is an EtherType (RFC 8926 §3.4) */
        if (hlen != 0 && hlen <= packet->payload_packet_len && ptype >= 0x0600) {
            mmt_internal_add_connection(ipacket, PROTO_GENEVE, MMT_REAL_PROTOCOL);
            return 1;
        }
    }
    MMT_EXCLUDE_PROTOCOL(flow, PROTO_GENEVE);
    return 0;
}

static int geneve_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);
    /* Issue #502 caplen prologue: the base header, then the options it
     * announces, must be captured before the payload is handed on. */
    if (offset < 0 || (uint64_t) offset + GENEVE_HDR_LEN > ipacket->p_hdr->caplen)
        return mmt_tunnel_end_path(ipacket, index);
    const uint8_t *h = &ipacket->data[offset];
    uint32_t hlen = geneve_header_len(h);
    if (hlen == 0 || (uint64_t) offset + hlen > ipacket->p_hdr->caplen)
        return mmt_tunnel_end_path(ipacket, index);
    if (h[1] & GENEVE_FLAG_O)
        return mmt_tunnel_end_path(ipacket, index);

    classified_proto_t retval;
    switch (((uint16_t) h[2] << 8) | h[3]) {
    case GENEVE_PT_TEB:
        retval.proto_id = PROTO_ETHERNET;
        break;
    case ETH_P_IP:
        retval.proto_id = PROTO_IP;
        break;
    case ETH_P_IPV6:
        retval.proto_id = PROTO_IPV6;
        break;
    default:
        retval.proto_id = PROTO_UNKNOWN;
        break;
    }
    retval.offset = (uint16_t) hlen;
    retval.status = Classified;
    return set_classified_proto(ipacket, index + 1, retval);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_geneve_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_GENEVE, PROTO_GENEVE_ALIAS);
    if (protocol_struct != NULL) {
        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_GENEVE);
        register_classification_function(protocol_struct, geneve_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_GENEVE);
    }
    return 0;
}
