#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "udp.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

static attribute_metadata_t udp_attributes_metadata[UDP_ATTRIBUTES_NB] = {
    {UDP_SRC_PORT, UDP_SRC_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 0, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {UDP_DEST_PORT, UDP_DEST_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {UDP_LEN, UDP_LEN_ALIAS, MMT_U16_DATA, sizeof (short), 4, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {UDP_CHECKSUM, UDP_CHECKSUM_ALIAS, MMT_U16_DATA, sizeof (short), 6, SCOPE_PACKET, general_short_extraction_with_ordering_change},
};

int udp_pre_classification_function(ipacket_t * ipacket, unsigned index) {
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    int l4_offset = get_packet_offset_at_index(ipacket, index);
    int ip6_jumbo = 0;

    if (packet->iphv6) {
        packet->l4_packet_len = (ipacket->p_hdr->caplen - l4_offset);
        /* F-BUG-002 (#375): the enclosing IPv6 payload_len bounds the L4
         * segment too — it counts every byte after the 40-byte base header
         * (extension headers + upper-layer data), so bytes captured beyond
         * it are not L4 data. A zero payload_len marks a jumbogram
         * (RFC 2675): the real length sits in the Jumbo Payload hop-by-hop
         * option, so the captured bound is the only one available. */
        const uint8_t * ip6_hdr = (const uint8_t *) packet->iphv6;
        uintptr_t ip6_off = (uintptr_t) ip6_hdr - (uintptr_t) ipacket->data;
        uint32_t ip6_plen = ((uint32_t) ip6_hdr[4] << 8) | ip6_hdr[5];
        if (ip6_plen == 0) {
            ip6_jumbo = 1;
        } else if (l4_offset >= 0
                && (uint64_t) l4_offset >= (uint64_t) ip6_off + sizeof(struct mmt_ipv6hdr)) {
            uint32_t ext_len = (uint32_t) l4_offset - (uint32_t) ip6_off
                - (uint32_t) sizeof(struct mmt_ipv6hdr);
            uint32_t declared = (ip6_plen > ext_len) ? ip6_plen - ext_len : 0;
            if (declared < packet->l4_packet_len)
                packet->l4_packet_len = declared;
        }
    } else {
        //Do nothing! this is done in ip.c
    }

    ////////////////////////////////////////////////
    packet->udp = (struct udphdr *) & ipacket->data[l4_offset];
    packet->tcp = NULL;

    if (packet->flow) {
        mmt_set_flow_protocol_to_packet(packet->flow, packet);
    } else {
        mmt_reset_internal_packet_protocol(ipacket->internal_packet);
    }

    // This is a UDP flow, offset is 8
    packet->l4_protocol = 17; /* UDP for sure ;) */

    if( packet->l4_packet_len < sizeof( struct udphdr )) {
        MMT_LOG( PROTO_UDP, MMT_LOG_DEBUG, "*** Warning: malformed packet (udp length mismatch)\n" );
        return MMT_CLASSIFY_SKIP;
    }

    packet->payload = ((uint8_t *) packet->udp) + sizeof( struct udphdr );
    /* F-BUG-002 (#375): the UDP header's own length field bounds the
     * datagram inside the enclosing IP payload — bytes captured beyond it
     * (padding, over-capture, encapsulation trailers) are not payload, and a
     * forged udp->len larger than the IP payload still clamps to the
     * enclosing bound (l4_packet_len). udp->len == 0 keeps the enclosing
     * bound — it means "rest of the datagram" over IPv4 and is mandatory in
     * IPv6 jumbograms (RFC 2675) — but a non-jumbo IPv6 packet declaring it
     * is malformed and exposes no payload. */
    {
        uint32_t udp_datagram_len = packet->l4_packet_len;
        /* The header field is read only when the capture holds it — a
         * corrupt l4_offset past caplen must not be dereferenced; keeping
         * the enclosing bound lets the caplen clamp below expose zero
         * payload, the same outcome the pre-#375 code reached. */
        if ((uint64_t) l4_offset + sizeof(struct udphdr) <= ipacket->p_hdr->caplen) {
            uint32_t udp_len = ntohs(((const mmt_una_udphdr_t *) packet->udp)->len);
            if (udp_len != 0) {
                if (udp_len < udp_datagram_len)
                    udp_datagram_len = udp_len;
            } else if (packet->iphv6 != NULL && ! ip6_jumbo) {
                udp_datagram_len = sizeof(struct udphdr);
            }
        }
        packet->payload_packet_len = (udp_datagram_len > sizeof(struct udphdr))
            ? (uint16_t) (udp_datagram_len - sizeof(struct udphdr)) : 0;
    }
    /* F-BUG-107/#195: l4_packet_len derives from the IP total length and can
     * exceed the captured bytes on truncated pcaps — clamp payload_packet_len
     * to what data[] actually holds so every payload[] read stays in bounds. */
    {
        /* uintptr subtraction wraps huge when payload < data -> fails check */
        uintptr_t poff = (uintptr_t)packet->payload - (uintptr_t)ipacket->data;
        uint32_t avail = ( poff < ipacket->p_hdr->caplen )
            ? (uint32_t)(ipacket->p_hdr->caplen - (uint32_t)poff) : 0;
        if( packet->payload_packet_len > avail )
            packet->payload_packet_len = avail;
    }

    mmt_connection_tracking(ipacket, index);

    if (packet->flow == NULL && packet->udp != NULL) {
        return MMT_CLASSIFY_SKIP; // was PROTO_UNKNOWN (0): a protocol id used as a verdict
    }

    //Set the offset for the next proto anyway! we might not get there
    ipacket->proto_headers_offset->proto_path[index + 1] = sizeof( struct udphdr );
    invalidate_packet_offset_cache(ipacket); // Issue #19: direct offset write

    MMT_SAVE_AS_BITMASK(packet->detection_bitmask, packet->detected_protocol_stack[0]);

    /* build mmt_selction packet bitmask */
    packet->mmt_selection_packet |= (MMT_SELECTION_BITMASK_PROTOCOL_INT_UDP | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

    if (packet->payload_packet_len != 0) {
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;
    }

    if (packet->tcp_retransmission == 0) {
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;
    }

    if (ipacket->session->packet_count > (CFG_CLASSIFICATION_THRESHOLD * 2)) {
        return MMT_CLASSIFY_SKIP;
    }

    return MMT_CLASSIFY_CONTINUE;
}

int udp_post_classification_function(ipacket_t * ipacket, unsigned index) {
    int a;
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    classified_proto_t retval;
    // retval.offset = -1;
    // retval.proto_id = -1;
    retval.status = NonClassified;
    retval.offset = 8; //UDP header is 8 bytes long

    a = packet->detected_protocol_stack[0];
    ////////////////////////////////////////////////
    retval.proto_id = a;

    int new_retval = 0;
    if (retval.proto_id == PROTO_UNKNOWN && ipacket->session->packet_count <= (CFG_CLASSIFICATION_THRESHOLD * 2)) {
        // LN: Check if the protocol id in the last index of protocol hierarchy is not PROTO_UDP -> do not try to classify more - external classification
        if(ipacket->proto_hierarchy->proto_path[ipacket->proto_hierarchy->len - 1]!=PROTO_UDP){
            return new_retval;
        }
        // Issue #87: the "different strategies" this fallback asked for are
        // the DPI profiles — each of the heuristic levers below (IP-range,
        // then port) is gated by its own profile toggle on the handler.
        /* The protocol is unkown and we reached the classification threshold! Try with IP addresses and port numbers before setting it as unkown */
        if (ipacket->mmt_handler->ip_address_classify == 1)
        {
            retval.proto_id = get_proto_id_from_address(ipacket);
        }
        
        if (retval.proto_id == PROTO_UNKNOWN && ipacket->mmt_handler->port_classify != 0) {
            retval.proto_id = mmt_guess_protocol_by_port_number(ipacket);
        }

        if (retval.proto_id != PROTO_UNKNOWN){
            retval.status = Classified;
            new_retval = set_classified_proto(ipacket, index + 1, retval);}
        else{
            // retval.status = NonClassified;
            // //LN: Add protocol unknown after UDP
            retval.status = Classified;
            return set_classified_proto(ipacket, index + 1, retval);
        }

    } else {
        /* now shift and insert */
        int stack_size = packet->flow->protocol_stack_info.current_stack_size_minus_one;

        for (a = stack_size; a >= 0; a--) {
            if (packet->flow->detected_protocol_stack[a] != PROTO_UNKNOWN) {
                if ((a > 0 && packet->flow->detected_protocol_stack[a] != packet->flow->detected_protocol_stack[a - 1]) || (a == 0)) {
                    index++;
                    retval.proto_id = packet->flow->detected_protocol_stack[a];
                    retval.status = Classified;
                    new_retval = set_classified_proto(ipacket, index, retval);
                    retval.offset = 0; // verified: stacked application ids share the payload, so offset 0 past the first
                }
            }
        }
    }
    return new_retval;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_udp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_UDP, PROTO_UDP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < UDP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &udp_attributes_metadata[i]);
        }
        register_pre_post_classification_functions(protocol_struct, udp_pre_classification_function, udp_post_classification_function);
        return register_protocol(protocol_struct, PROTO_UDP);
    } else {
        return 0;
    }
}


