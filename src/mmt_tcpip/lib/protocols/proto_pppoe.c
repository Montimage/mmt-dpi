/*
 * proto_pppoe.c — PPPoE (RFC 2516 §4), issue #572 (F-BUG-308).
 *
 * Ethernet, 802.1Q and Linux SLL hand both PPPoE stages to this layer. A
 * session-stage packet (VER 1, TYPE 1, CODE 0x00) carries a PPP frame after
 * the 6-byte header and is handed to PPP; a discovery packet (PADI, PADO,
 * PADR, PADS, PADT — non-zero CODE) carries tags, not a user flow, so its
 * path ends here, as does a header that is not fully captured (issue #502).
 */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "tunnel_walk.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

#define PPPOE_HDR_LEN        6u
#define PPPOE_VER_TYPE       0x11u   /* VER 1, TYPE 1 */
#define PPPOE_CODE_SESSION   0x00u

static int pppoe_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);
    if (offset < 0 || (uint64_t) offset + PPPOE_HDR_LEN > ipacket->p_hdr->caplen)
        return mmt_tunnel_end_path(ipacket, index);
    const uint8_t *h = &ipacket->data[offset];
    if (h[0] != PPPOE_VER_TYPE || h[1] != PPPOE_CODE_SESSION)
        return mmt_tunnel_end_path(ipacket, index);
    classified_proto_t retval;
    retval.proto_id = PROTO_PPP;
    retval.offset = PPPOE_HDR_LEN;
    retval.status = Classified;
    return set_classified_proto(ipacket, index + 1, retval);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_pppoe_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_PPPOE, PROTO_PPPOE_ALIAS);
    if (protocol_struct != NULL) {
        register_classification_function(protocol_struct, pppoe_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_PPPOE);
    }
    return 0;
}
