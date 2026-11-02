/*
 * proto_vxlan.c — VXLAN (RFC 7348 §5), issue #572 (F-BUG-308).
 *
 * mmt_check_vxlan claims a UDP flow on the IANA port 4789 whose datagrams
 * carry the 8-byte VXLAN header with the I flag (valid VNI) set and room for
 * an inner Ethernet header; vxlan_classify_next_proto then re-enters
 * Ethernet beneath the header, so the inner flow is sessionized and
 * classified like any other (its session's parent is the outer UDP flow).
 * Nesting is bounded by the protocol path (PROTO_PATH_SIZE layers).
 */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "tunnel_walk.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

#define VXLAN_UDP_PORT    4789
#define VXLAN_HDR_LEN     8u
#define VXLAN_FLAG_I      0x08u   /* RFC 7348 §5: the VNI is valid */
#define VXLAN_ETH_HDR_LEN 14u

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

int mmt_check_vxlan(ipacket_t * ipacket, unsigned index) {
    (void) index;
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* guard evaluated by the classifier walk (issue #561) */
    if (packet->udp != NULL
            && (packet->udp->dest == htons(VXLAN_UDP_PORT)
                || packet->udp->source == htons(VXLAN_UDP_PORT))
            && packet->payload_packet_len >= VXLAN_HDR_LEN + VXLAN_ETH_HDR_LEN
            && (packet->payload[0] & VXLAN_FLAG_I) != 0) {
        mmt_internal_add_connection(ipacket, PROTO_VXLAN, MMT_REAL_PROTOCOL);
        return 1;
    }
    MMT_EXCLUDE_PROTOCOL(flow, PROTO_VXLAN);
    return 0;
}

static int vxlan_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);
    /* Issue #502 caplen prologue: the header and the inner Ethernet header
     * must be captured before the flags are read or Ethernet re-entered. */
    if (offset < 0
            || (uint64_t) offset + VXLAN_HDR_LEN + VXLAN_ETH_HDR_LEN > ipacket->p_hdr->caplen)
        return mmt_tunnel_end_path(ipacket, index);
    if ((ipacket->data[offset] & VXLAN_FLAG_I) == 0)
        return mmt_tunnel_end_path(ipacket, index);
    classified_proto_t retval;
    retval.proto_id = PROTO_ETHERNET;
    retval.offset = VXLAN_HDR_LEN;
    retval.status = Classified;
    return set_classified_proto(ipacket, index + 1, retval);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_vxlan_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_VXLAN, PROTO_VXLAN_ALIAS);
    if (protocol_struct != NULL) {
        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_VXLAN);
        register_classification_function(protocol_struct, vxlan_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_VXLAN);
    }
    return 0;
}
