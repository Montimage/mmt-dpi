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

    if (packet->iphv6) {
        packet->l4_packet_len = (ipacket->p_hdr->caplen - l4_offset);
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
        return 0;
    }

    packet->payload_packet_len = packet->l4_packet_len - sizeof( struct udphdr );
    packet->payload = ((uint8_t *) packet->udp) + sizeof( struct udphdr );

    mmt_connection_tracking(ipacket, index);

    if (packet->flow == NULL && packet->udp != NULL) {
        return (PROTO_UNKNOWN); //TODO: check this out
    }

    //Set the offset for the next proto anyway! we might not get there
    ipacket->proto_headers_offset->proto_path[index + 1] = sizeof( struct udphdr );

    MMT_SAVE_AS_BITMASK(packet->detection_bitmask, packet->detected_protocol_stack[0]);

    /* build mmt_selction packet bitmask */
    packet->mmt_selection_packet |= (MMT_SELECTION_BITMASK_PROTOCOL_INT_UDP | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

    if (packet->payload_packet_len != 0) {
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;
    }

    if (packet->tcp_retransmission == 0) { //TODO: do we need to keep this???
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;
    }

    if (ipacket->session->packet_count > (CFG_CLASSIFICATION_THRESHOLD * 2)) {
        return 0;
    }

    return 1;
}

int udp_post_classification_function(ipacket_t * ipacket, unsigned index) {
    int a;
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
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
        //BW - TODO: We should have different strategies: best_effort = we can affort a number of missclassifications, etc.  
        /* The protocol is unkown and we reached the classification threshold! Try with IP addresses and port numbers before setting it as unkown */
        retval.proto_id = get_proto_id_from_address(ipacket);
        if (retval.proto_id == PROTO_UNKNOWN) {
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
                    retval.offset = 0; //From the second proto the offset is the same! //TODO: check this out
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


