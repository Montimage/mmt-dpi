#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "tcp.h"
#include "tcp_segment.h"

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

int tcp_established_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {
    struct mmt_internal_tcpip_session_struct *flow = packet->internal_packet->flow;
    *((unsigned char *) extracted_data->data) = flow->l4.tcp.seen_ack;
    return 1;
}

int tcp_connection_closed_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {
    struct mmt_internal_tcpip_session_struct *flow = packet->internal_packet->flow;
    *((unsigned char *) extracted_data->data) = flow->l4.tcp.seen_fin_ack;
    return 1;
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

int tcp_session_payload_up_len_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    *((uint32_t*) extracted_data->data) = ipacket->session->session_payload_len[ipacket->session->setup_packet_direction];
    return 1;
}

int tcp_session_payload_up_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    if (ipacket->session){
        uint8_t up_direction = ipacket->session->setup_packet_direction;
        uint32_t payload_len = ipacket->session->session_payload_len[up_direction];
        if ( payload_len > 0){
            if (ipacket->session->session_payload[up_direction]) {
                free(ipacket->session->session_payload[up_direction]);
            }
            ipacket->session->session_payload[up_direction] = (uint8_t*) malloc(sizeof(uint8_t) * payload_len);
            tcp_seg_reassembly(
                ipacket->session->session_payload[up_direction],
                ipacket->session->tcp_segment_list[up_direction],
                payload_len
            );

            extracted_data->data = (void*) ipacket->session->session_payload[up_direction];
            return 1;
        }
    }

    return 0;
}

int tcp_session_payload_down_len_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){

    *((uint32_t*) extracted_data->data) = ipacket->session->session_payload_len[!ipacket->session->setup_packet_direction];
    return 1;
}

int tcp_session_payload_down_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    if (ipacket->session){
        uint8_t down_direction = !ipacket->session->setup_packet_direction;
        uint32_t payload_len = ipacket->session->session_payload_len[down_direction];
        if ( payload_len > 0){
            if (ipacket->session->session_payload[down_direction]) {
                free(ipacket->session->session_payload[down_direction]);
            }
            ipacket->session->session_payload[down_direction] = (uint8_t*) malloc(sizeof(uint8_t) * payload_len);
            tcp_seg_reassembly(
                ipacket->session->session_payload[down_direction],
                ipacket->session->tcp_segment_list[down_direction],
                payload_len
            );

            extracted_data->data = (void*) ipacket->session->session_payload[down_direction];
            return 1;
        }
    }

    return 0;
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

int tcp_option_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t * extracted_data){
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & ipacket->data[proto_offset];
    int data_offset = tcp_hdr->doff;
    //no optional fields
    if( data_offset <= 5 )
       return 0;
    //tcp data offset specifies the size of tcp header length in 32-bit words
    //its value is from 5 (no option fields) to 15
    int option_offset = proto_offset + (5*4); //5 words of tcp header
    int end_of_option = proto_offset + data_offset * 4;

    //structure of a tcp option field
    struct tcp_option{
        uint8_t kind;
        uint8_t length; //indicates the total length of the option
        uint8_t data[];
    } *opt_field;
    struct timestamp_option_field{
        uint32_t tsval;
        uint32_t tserc;
    } *ts_field;

    while( option_offset < end_of_option ){
        opt_field = (struct tcp_option *) &ipacket->data[ option_offset ];
        switch( opt_field->kind ){
        case 0: //end of option list
            return 0;
        case 1: //no option: not have an Option-Length or Option-Data fields following it.
            option_offset += 1; //jump over this option
            break;
        case 2: //Maximum segment size
            option_offset += opt_field->length; //jump over this option
            break;
        case 3: //Window scale
            option_offset += opt_field->length; //jump over this option
            break;
        case 4: //Selective Acknowledgement permitted
            option_offset += opt_field->length; //jump over this option
            break;
        case 5: //Selective ACKnowledgement (SACK)
            option_offset += opt_field->length; //jump over this option
            break;
        case 8: //Timestamp and echo of previous timestamp
            option_offset += opt_field->length; //jump over this option
            ts_field = (struct timestamp_option_field *) opt_field->data;
            //depending on which attribute we are extracting
            switch( extracted_data->field_id ){
            case TCP_TSVAL:
                *((uint32_t*) extracted_data->data) = ntohl(ts_field->tsval);
                return 1; //we got the value
            case TCP_TSECR:
                *((uint32_t*) extracted_data->data) = ntohl(ts_field->tserc);
                return 1; //we got the value
            default:
                break;
            }
            break;
        default:
            option_offset += opt_field->length; //jump over this option
            break;
        }
    }
    //do we need to set the value to zero when not found ???
    switch( extracted_data->field_id ){
        case TCP_TSVAL:
        *((uint32_t*) extracted_data->data) = 0;
        break;
    case TCP_TSECR:
        *((uint32_t*) extracted_data->data) = 0;
        break;
    default:
        break;
    }
    return 0; //no value for the attribute to be extracted
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
    {TCP_SESSION_PAYLOAD_UP_LEN, TCP_SESSION_PAYLOAD_UP_LEN_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_payload_up_len_extraction},
    {TCP_SESSION_PAYLOAD_UP, TCP_SESSION_PAYLOAD_UP_ALIAS, MMT_DATA_POINTER, sizeof (void*), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_payload_up_extraction},
    {TCP_SESSION_PAYLOAD_DOWN_LEN, TCP_SESSION_PAYLOAD_DOWN_LEN_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_payload_down_len_extraction},
    {TCP_SESSION_PAYLOAD_DOWN, TCP_SESSION_PAYLOAD_DOWN_ALIAS, MMT_DATA_POINTER, sizeof (void*), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_payload_down_extraction},
    // {TCP_SESSION_OUTOFORDER, TCP_SESSION_OUTOFORDER_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_session_outoforder_extraction},
    {TCP_CONN_ESTABLISHED, TCP_CONN_ESTABLISHED_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_established_extraction},
    {TCP_CONN_CLOSED, TCP_CONN_CLOSED_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_connection_closed_extraction},
	{TCP_TSVAL, TCP_TSVAL_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_option_extraction},
	{TCP_TSECR, TCP_TSECR_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, tcp_option_extraction},
};

void clean_session_payload(mmt_session_t * session, unsigned index){
    tcp_seg_free_list(session->tcp_segment_list[session->last_packet_direction]);
    tcp_seg_free_list(session->tcp_segment_list[!session->last_packet_direction]);
    if (session->session_payload[session->last_packet_direction] ) free(session->session_payload[session->last_packet_direction]);
    if (session->session_payload[!session->last_packet_direction] ) free(session->session_payload[!session->last_packet_direction]);
}

int tcp_pre_classification_function(ipacket_t * ipacket, unsigned index) {
    debug("[tcp_pre_classification_function] packet %"PRIu64" at index: %d\n",ipacket->packet_id,index);
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
     if (packet->tcp!=NULL
        && packet->tcp->syn != 0
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

int tcp_pre_classification_function_with_reassemble(ipacket_t * ipacket, unsigned index) {
    debug("[tcp_pre_classification_function_with_reassemble] packet %"PRIu64" at index: %d\n",ipacket->packet_id,index);
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
     if (packet->tcp!=NULL
        && packet->tcp->syn != 0
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
    // Update segment list
    if (packet->payload_packet_len > 0) {
        // Copy data
        uint8_t * data = (uint8_t * )malloc(packet->payload_packet_len * sizeof(uint8_t));
        memcpy(data, packet->payload, packet->payload_packet_len);
        // Create a new segment
        tcp_seg_t * new_seg = tcp_seg_new(ipacket->packet_id, ntohl(packet->tcp->seq), ntohl(packet->tcp->seq) + packet->payload_packet_len, ntohl(packet->tcp->ack) ,packet->payload_packet_len, data);
        if (new_seg != NULL){
            if (ipacket->session->tcp_segment_list[ipacket->session->last_packet_direction] == NULL){
                ipacket->session->tcp_segment_list[ipacket->session->last_packet_direction] = (void*) new_seg;
                ipacket->session->session_payload_len[ipacket->session->last_packet_direction] += packet->payload_packet_len;
            } else {
                tcp_seg_t * root = tcp_seg_insert((tcp_seg_t *) ipacket->session->tcp_segment_list[ipacket->session->last_packet_direction], new_seg);
                if ( root == NULL){
                    // Cannot insert new segment, need to do something
                    // fprintf(stderr,"[tcp_pre_classification_function] Cannot insert new segment: %lu\n",ipacket->packet_id);
                    tcp_seg_free(new_seg);
                } else {
                    // Do something if success
                    ipacket->session->tcp_segment_list[ipacket->session->last_packet_direction] = root;
                    ipacket->session->session_payload_len[ipacket->session->last_packet_direction] += packet->payload_packet_len;
                    // tcp_seg_show_list(root);
                }
            }
        }
        debug("[tcp_pre_classification_function_with_reassemble] %u\n",ipacket->session->session_payload_len[ipacket->session->last_packet_direction]);
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
    // retval.offset = 0;
    // retval.proto_id = 0;
    retval.status = NonClassified;
    retval.offset = packet->tcp->doff * 4; //TCP header length

    a = packet->detected_protocol_stack[0];
    ////////////////////////////////////////////////
    retval.proto_id = a;

    int new_retval = 0;
    // if (retval.proto_id == PROTO_UNKNOWN && ipacket->session->packet_count >= CFG_CLASSIFICATION_THRESHOLD) {
    if (retval.proto_id == PROTO_UNKNOWN || retval.proto_id == PROTO_GTP) {
        // LN: Check if the protocol id in the last index of protocol hierarchy is not PROTO_UDP -> do not try to classify more - external classification
        if(ipacket->proto_hierarchy->proto_path[ipacket->proto_hierarchy->len - 1]!=PROTO_TCP){
            return new_retval;
        }
        //BW - TODO: We should have different strategies: best_effort = we can affort a number of missclassifications, etc.
        /* The protocol is unkown and we reached the classification threshold! Try with IP addresses and port numbers before setting it as unkown */
        if (ipacket->mmt_handler->ip_address_classify == 1){
            retval.proto_id = get_proto_id_from_address(ipacket);
        }
        if(retval.proto_id == PROTO_UNKNOWN && ipacket->mmt_handler->port_classify != 0) {
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

int update_tcp_protocol(int action_id){
    protocol_t * protocol_struct = get_protocol_struct_by_id(PROTO_TCP);
    switch (action_id)
    {
        case TCP_ENABLE_REASSEMBLE:
        // Enable tcp_action
            printf("[active_tcp_reassembly] action_id: %d", action_id);
            register_session_data_cleanup_function(protocol_struct, clean_session_payload);
            register_pre_post_classification_functions(protocol_struct, tcp_pre_classification_function_with_reassemble, tcp_post_classification_function);
            return 1;
        case TCP_DISABLE_REASSEMBLE:
            printf("[active_tcp_reassembly] action_id: %d", action_id);
            register_session_data_cleanup_function(protocol_struct, NULL);
            register_pre_post_classification_functions(protocol_struct, tcp_pre_classification_function, tcp_post_classification_function);
            return 1;
        default:
            printf("[active_tcp_reassembly] Not implemented yet! %d", action_id);
            break;
    }
    return 0;
}

int init_proto_tcp_struct() {

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TCP, PROTO_TCP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < TCP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &tcp_attributes_metadata[i]);
        }
        register_pre_post_classification_functions(protocol_struct, tcp_pre_classification_function, tcp_post_classification_function);
        protocol_struct->update_protocol_fct = &update_tcp_protocol;
        return register_protocol(protocol_struct, PROTO_TCP);
    } else {
        return 0;
    }
}
