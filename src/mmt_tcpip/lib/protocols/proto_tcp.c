#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "tcp.h"

int tcp_data_offset_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);

    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    *((unsigned char *) extracted_data->data) = tcp_hdr->doff; //Already aligned to the correct bit ordering
    return 1;
}

int tcp_fin_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    // if (tcp_hdr->fin) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->fin; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_syn_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    // if (tcp_hdr->syn) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->syn; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_rst_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    // if (tcp_hdr->rst) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->rst; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_psh_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    // if (tcp_hdr->psh) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->psh; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_ack_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    // if (tcp_hdr->ack) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->ack; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_urg_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    // if (tcp_hdr->urg) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->urg; //Already aligned to the correct bit ordering
        return 1;
    // }
    // return 0;
}

int tcp_ece_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

#ifndef _WIN32
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    if (( tcp_hdr->res2 & 0x01 ) != 0 ) {
        *((unsigned char *) extracted_data->data) = 1; //Already aligned to the correct bit ordering
        return 1;
    }
#endif
    return 0;
}

int tcp_cwr_flag_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

#ifndef _WIN32
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    if (( tcp_hdr->res2 & 0x02 ) != 0 ) {
        *((unsigned char *) extracted_data->data) = 1; //Already aligned to the correct bit ordering
        return 1;
    }
#endif
    return 0;
}

int tcp_flags_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
    *((unsigned char *) extracted_data->data) = *((unsigned char *) & packet->data[proto_offset + attribute_offset]);
    return 1;
}

int tcp_payload_len_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    // if(ipacket->internal_packet->payload_packet_len){
        // Check padding packet
        if(ipacket->internal_packet->iph==NULL){
            *((uint32_t*) extracted_data->data) = ipacket->internal_packet->payload_packet_len;    
            return 1;
        }
        
        if((ntohs(ipacket->internal_packet->iph->tot_len) + ipacket->internal_packet->payload_packet_len + 14 != 60)){
            *((uint32_t*) extracted_data->data) = ipacket->internal_packet->payload_packet_len;    
            return 1;
        }
    // }
    return 0;
}

int tcp_retransmission_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    if(ipacket->internal_packet){
        *((uint32_t*) extracted_data->data) = ipacket->internal_packet->tcp_retransmission;
        return 1;
    }
    return 0;
}

int tcp_outoforder_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    if(ipacket->internal_packet){
        *((uint32_t*) extracted_data->data) = ipacket->internal_packet->tcp_outoforder;
        return 1;
    }
    return 0;
}


int tcp_session_retransmission_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    *((uint32_t*) extracted_data->data) = ipacket->session->tcp_retransmissions;
    return 1;
}

// int tcp_session_outoforder_extraction(const ipacket_t * ipacket, unsigned proto_index,
//     attribute_t * extracted_data){

//     if(ipacket->internal_packet->payload_packet_len){
//         *((uint32_t*) extracted_data->data) = ipacket->session->tcp_outoforder;
//         return 1;
//     }
//     return 0;
// }

int tcp_session_rtt_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    if(ipacket->session){
        memcpy(extracted_data->data, & ipacket->session->rtt, sizeof (struct timeval));
        // (struct timeval *)extracted_data->data = ;
        return 1;
    }
    return 0;
}
static attribute_metadata_t tcp_attributes_metadata[TCP_ATTRIBUTES_NB] = {
    {TCP_SRC_PORT, TCP_SRC_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 0, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_DEST_PORT, TCP_DEST_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_SEQ_NB, TCP_SEQ_NB_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {TCP_ACK_NB, TCP_ACK_NB_ALIAS, MMT_U32_DATA, sizeof (int), 8, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {TCP_DATA_OFF, TCP_DATA_OFF_ALIAS, MMT_U8_DATA, sizeof (char), 12, SCOPE_PACKET, tcp_data_offset_extraction},
    {TCP_FLAGS, TCP_FLAGS_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_flags_extraction},
    {TCP_FIN, TCP_FIN_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_fin_flag_extraction},
    {TCP_SYN, TCP_SYN_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_syn_flag_extraction},
    {TCP_RST, TCP_RST_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_rst_flag_extraction},
    {TCP_PSH, TCP_PSH_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_psh_flag_extraction},
    {TCP_ACK, TCP_ACK_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_ack_flag_extraction},
    {TCP_URG, TCP_URG_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_urg_flag_extraction},
    {TCP_ECE, TCP_ECE_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_ece_flag_extraction},
    {TCP_CWR, TCP_CWR_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, tcp_cwr_flag_extraction},
    {TCP_WINDOW, TCP_WINDOW_ALIAS, MMT_U16_DATA, sizeof (short), 14, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_CHECKSUM, TCP_CHECKSUM_ALIAS, MMT_U16_DATA, sizeof (short), 16, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_URG_PTR, TCP_URG_PTR_ALIAS, MMT_U16_DATA, sizeof (short), 18, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {TCP_RTT, TCP_RTT_ALIAS, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_session_rtt_extraction},
    {TCP_SYN_RCV, TCP_SYN_RCV_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_syn_flag_extraction},//TODO: extract function not correct
    {TCP_PAYLOAD_LEN, TCP_PAYLOAD_LEN_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_payload_len_extraction},
    {TCP_RETRANSMISSION, TCP_RETRANSMISSION_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_retransmission_extraction},
    {TCP_OUTOFORDER, TCP_OUTOFORDER_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_outoforder_extraction},
    {TCP_SESSION_RETRANSMISSION, TCP_SESSION_RETRANSMISSION_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_retransmission_extraction},
    // {TCP_SESSION_OUTOFORDER, TCP_SESSION_OUTOFORDER_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_outoforder_extraction},
    {TCP_CONN_ESTABLISHED, TCP_CONN_ESTABLISHED_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_ack_flag_extraction},
};

int tcp_pre_classification_function(ipacket_t * ipacket, unsigned index) {
    // printf("TEST: Enter TCP packet of packet %"PRIu64" at index: %d\n",ipacket->packet_id,index);
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    int l4_offset = get_packet_offset_at_index(ipacket, index);
    if (packet->iphv6) {
        packet->l4_packet_len = (ipacket->p_hdr->caplen - l4_offset);
    }

    ////////////////////////////////////////////////
    packet->tcp = (struct tcphdr *) & ipacket->data[l4_offset];
    packet->udp = NULL;

    if (likely(packet->flow)) {
        mmt_set_flow_protocol_to_packet(packet->flow, packet);
    } else {
        mmt_reset_internal_packet_protocol(packet);
    }

    // This is a TCP flow, get the offset
    uint16_t tcphdr_len = packet->tcp->doff * 4; //TCP header length

    packet->l4_protocol = 6; /* TCP for sure ;) */

    if( packet->l4_packet_len < tcphdr_len ) {
        MMT_LOG( PROTO_TCP, MMT_LOG_DEBUG, "*** Warning: malformed packet (tcp length mismatch)\n" );
        return 0;
    }

    packet->payload_packet_len = packet->l4_packet_len - tcphdr_len;
    packet->actual_payload_len = packet->payload_packet_len;
    packet->payload = ((uint8_t *) packet->tcp) + tcphdr_len;
    packet->https_server_name.ptr = NULL;
    packet->https_server_name.len = 0;

    /* check for new tcp syn packets, here
     * idea: reset detection state if a connection is unknown
     */
     if (packet->tcp->syn != 0
        && packet->tcp->ack == 0
        && packet->flow != NULL
        && ipacket->session->packet_count == 0 /*First packet of the flow*/
        && packet->flow->detected_protocol_stack[0] == PROTO_UNKNOWN) {

        memset(packet->flow, 0, sizeof (*(packet->flow))); //BW - TODO: Is this memset needed? the syn should be
        //seen at the start of the flow, this should have been set to zero
        //at the creation of the flow!!! Check this out
        MMT_LOG(PROTO_UNKNOWN, packet,
                MMT_LOG_DEBUG,
                "%s:%u: tcp syn packet for unknown protocol, reset detection state\n", __FUNCTION__, __LINE__);
        }

    mmt_connection_tracking(ipacket, index);

    if (packet->flow == NULL && packet->tcp != NULL) {
        return 0; //TODO: replace with a definition
    }

    //Set the offset for the next proto anyway! we might not get there
    ipacket->proto_headers_offset->proto_path[index + 1] = tcphdr_len;

    MMT_SAVE_AS_BITMASK(packet->detection_bitmask, packet->detected_protocol_stack[0]);

    /* build selction packet bitmask */
    packet->mmt_selection_packet |= (MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

    if (packet->payload_packet_len != 0) {
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;
    }

    if (packet->tcp_retransmission == 0) {
        packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;
    }

    // if (ipacket->session->packet_count > CFG_CLASSIFICATION_THRESHOLD) {
    //    return 0;
    // }
    
    return 1;
}

int tcp_post_classification_function(ipacket_t * ipacket, unsigned index) {
    int a;
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    classified_proto_t retval;
    retval.offset = 0;
    retval.proto_id = 0;
    retval.status = NonClassified;
    retval.offset = packet->tcp->doff * 4; //TCP header length

    a = packet->detected_protocol_stack[0];
    ////////////////////////////////////////////////
    retval.proto_id = a;

    int new_retval = 0;
    // if (retval.proto_id == PROTO_UNKNOWN && ipacket->session->packet_count >= CFG_CLASSIFICATION_THRESHOLD) {
    if (retval.proto_id == PROTO_UNKNOWN) {
        // LN: Check if the protocol id in the last index of protocol hierarchy is not PROTO_UDP -> do not try to classify more - external classification
        if(ipacket->proto_hierarchy->proto_path[ipacket->proto_hierarchy->len - 1]!=PROTO_TCP){
            return new_retval;
        }
        //BW - TODO: We should have different strategies: best_effort = we can affort a number of missclassifications, etc.
        /* The protocol is unkown and we reached the classification threshold! Try with IP addresses and port numbers before setting it as unkown */
        retval.proto_id = get_proto_id_from_address(ipacket);
        if(retval.proto_id == PROTO_UNKNOWN) {
            retval.proto_id =  mmt_guess_protocol_by_port_number(ipacket);
        }
        if (retval.proto_id != PROTO_UNKNOWN){
            retval.status = Classified;
            new_retval = set_classified_proto(ipacket, index + 1, retval);}
        else{
            //LN: Add protocol unknown after TCP
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

int init_proto_tcp_struct() {

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TCP, PROTO_TCP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < TCP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &tcp_attributes_metadata[i]);
        }

        register_pre_post_classification_functions(protocol_struct, tcp_pre_classification_function, tcp_post_classification_function);
        return register_protocol(protocol_struct, PROTO_TCP);
    } else {
        return 0;
    }
}

// int cleanup_proto_tcp_struct(){
//     debug("Cleanup tcp protocol");
//     return 1;
// }
// 
