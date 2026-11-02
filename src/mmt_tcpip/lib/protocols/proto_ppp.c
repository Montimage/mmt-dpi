/*
 * proto_ppp.c — PPP encapsulation (RFC 1661 §2), issue #572 (F-BUG-308).
 *
 * PPPoE sessions and GRE (PPTP) hand a PPP frame to this layer:
 * an optional Address/Control pair (0xFF 0x03, absent under ACFC and in
 * PPPoE), then the Protocol field — one byte under PFC, recognised by its
 * odd value, else two bytes whose low octet is odd (RFC 1661 §2). IPv4,
 * IPv6 and MPLS are handed on; a control protocol (LCP, the NCPs,
 * authentication: values 0x4000 and above) carries no user flow and ends
 * the path, and another network-layer protocol is reported unknown.
 *
 * Ethernet also maps the LCP and IPCP EtherTypes to PPP; that payload is
 * the control packet itself, with no Protocol field, so the path ends here.
 */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "tunnel_walk.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

#define PPP_PROTO_IP        0x0021u
#define PPP_PROTO_IPV6      0x0057u
#define PPP_PROTO_MPLS_UC   0x0281u
#define PPP_PROTO_MPLS_MC   0x0283u
#define PPP_PROTO_CONTROL   0x4000u   /* 0x4000-0xffff: control protocols */

static int ppp_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    if (index > 0 && ipacket->proto_hierarchy->proto_path[index - 1] == PROTO_ETHERNET)
        return mmt_tunnel_end_path(ipacket, index);
    int offset = get_packet_offset_at_index(ipacket, index);
    if (offset < 0)
        return mmt_tunnel_end_path(ipacket, index);
    const uint64_t caplen = ipacket->p_hdr->caplen;
    uint32_t len = 0;
    /* Issue #502 caplen prologue: each field is read only once captured. */
    if ((uint64_t) offset + 2 <= caplen
            && ipacket->data[offset] == 0xFF && ipacket->data[offset + 1] == 0x03)
        len = 2;                                       /* Address, Control */
    if ((uint64_t) offset + len + 1 > caplen)
        return mmt_tunnel_end_path(ipacket, index);
    uint32_t proto = ipacket->data[offset + len];
    if (proto & 0x01) {
        len += 1;                                      /* PFC: one byte */
    } else {
        if ((uint64_t) offset + len + 2 > caplen)
            return mmt_tunnel_end_path(ipacket, index);
        proto = (proto << 8) | ipacket->data[offset + len + 1];
        if ((proto & 0x01) == 0)
            return mmt_tunnel_end_path(ipacket, index);   /* malformed field */
        len += 2;
    }

    classified_proto_t retval;
    switch (proto) {
    case PPP_PROTO_IP:
        retval.proto_id = PROTO_IP;
        break;
    case PPP_PROTO_IPV6:
        retval.proto_id = PROTO_IPV6;
        break;
    case PPP_PROTO_MPLS_UC:
    case PPP_PROTO_MPLS_MC:
        retval.proto_id = PROTO_MPLS;
        break;
    default:
        if (proto >= PPP_PROTO_CONTROL)
            return mmt_tunnel_end_path(ipacket, index);
        retval.proto_id = PROTO_UNKNOWN;
        break;
    }
    retval.offset = (uint16_t) len;
    retval.status = Classified;
    return set_classified_proto(ipacket, index + 1, retval);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ppp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_PPP, PROTO_PPP_ALIAS);
    if (protocol_struct != NULL) {
        register_classification_function(protocol_struct, ppp_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_PPP);
    }
    return 0;
}
