/*
 * proto_mpls.c — MPLS label stack (RFC 3032), issue #572 (F-BUG-308).
 *
 * Ethernet, 802.1Q and PPP hand an MPLS label stack to this layer. The whole
 * stack is one protocol layer: the walker steps over 4-byte label stack
 * entries until the bottom-of-stack (S) bit, then hands the payload to IPv4,
 * IPv6 or — behind a pseudowire control word — Ethernet. MPLS carries no
 * next-protocol field, so the payload is told by the explicit-null label of
 * the bottom entry or else by its first nibble, the heuristic RFC 4385 §3
 * makes safe by reserving the 0000 nibble for the control word.
 *
 * The walk is bounded: a stack deeper than MPLS_MAX_LABEL_ENTRIES entries,
 * or one whose bottom entry lies beyond the capture, ends the path here
 * (no next layer). Every entry is read only after the caplen prologue proves
 * it captured (issue #502).
 */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "tunnel_walk.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

#define MPLS_ENTRY_LEN          4u
/* Deeper than any deployed segment-routing stack; a longer run without an
 * S bit is malformed or crafted, and the path ends at this layer. */
#define MPLS_MAX_LABEL_ENTRIES  16u
#define MPLS_LABEL_IPV4_NULL    0u   /* RFC 3032 §2.1 IPv4 Explicit NULL */
#define MPLS_LABEL_IPV6_NULL    2u   /* RFC 3032 §2.1 IPv6 Explicit NULL */
#define MPLS_LABEL_GAL         13u   /* RFC 5586 G-ACh Label: no user payload */
#define MPLS_PW_CW_LEN          4u   /* RFC 4385 pseudowire control word */
#define MPLS_ETH_HDR_LEN       14u

/* Classify the layer beneath an MPLS label stack starting at `offset`.
 * Returns the next protocol (PROTO_UNKNOWN for an unrecognised payload) and
 * its offset relative to the stack, or 0 when the path must end here. */
static int mpls_walk(const ipacket_t *ipacket, int offset, uint32_t *proto, uint32_t *next) {
    const uint64_t caplen = ipacket->p_hdr->caplen;
    uint32_t label = 0;
    uint32_t len = 0;
    unsigned i;

    if (offset < 0)
        return 0;
    for (i = 0; i < MPLS_MAX_LABEL_ENTRIES; i++) {
        if ((uint64_t) offset + len + MPLS_ENTRY_LEN > caplen)
            return 0;
        const uint8_t *e = &ipacket->data[offset + len];
        label = ((uint32_t) e[0] << 12) | ((uint32_t) e[1] << 4) | (e[2] >> 4);
        len += MPLS_ENTRY_LEN;
        if (e[2] & 0x01)
            break;                     /* bottom of stack */
    }
    if (i == MPLS_MAX_LABEL_ENTRIES)
        return 0;                      /* no S bit within the bound */

    *next = len;
    if (label == MPLS_LABEL_IPV4_NULL) {
        *proto = PROTO_IP;
        return 1;
    }
    if (label == MPLS_LABEL_IPV6_NULL) {
        *proto = PROTO_IPV6;
        return 1;
    }
    if (label == MPLS_LABEL_GAL)
        return 0;                      /* OAM on the G-ACh, not a user flow */
    if ((uint64_t) offset + len + 1 > caplen)
        return 0;
    switch (ipacket->data[offset + len] >> 4) {
    case 4:
        *proto = PROTO_IP;
        return 1;
    case 6:
        *proto = PROTO_IPV6;
        return 1;
    case 0:
        /* Ethernet pseudowire behind a control word (RFC 4448 §3): the
         * inner frame must be captured up to its EtherType. */
        if ((uint64_t) offset + len + MPLS_PW_CW_LEN + MPLS_ETH_HDR_LEN > caplen)
            return 0;
        *proto = PROTO_ETHERNET;
        *next = len + MPLS_PW_CW_LEN;
        return 1;
    default:
        *proto = PROTO_UNKNOWN;
        return 1;
    }
}

static int mpls_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    uint32_t proto = PROTO_UNKNOWN, next = 0;
    if (!mpls_walk(ipacket, get_packet_offset_at_index(ipacket, index), &proto, &next))
        return mmt_tunnel_end_path(ipacket, index);
    classified_proto_t retval;
    retval.proto_id = proto;
    retval.offset = (uint16_t) next;
    retval.status = Classified;
    return set_classified_proto(ipacket, index + 1, retval);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_mpls_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MPLS, PROTO_MPLS_ALIAS);
    if (protocol_struct != NULL) {
        register_classification_function(protocol_struct, mpls_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_MPLS);
    }
    return 0;
}
