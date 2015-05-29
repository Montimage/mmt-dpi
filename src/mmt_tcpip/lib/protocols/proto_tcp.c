#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "tcp.h"

////////////// LIBNTOH LIBRARY INTEGRATION CODE /////////////////
#include <libntoh/libntoh.h>

typedef struct libntoh_packet_t
{
    ipacket_t *ipacket;
    size_t total_len;
    // struct pkthdr *ipacket_header;
    unsigned index;
} libntoh_packet_t , *plibntoh_packet_t;

#define RECV_CLIENT 1
#define RECV_SERVER 2
void ntoh_tcp_callback ( pntoh_tcp_stream_t stream , pntoh_tcp_peer_t orig , pntoh_tcp_peer_t dest , pntoh_tcp_segment_t seg , int reason , int extra );
int tcp_pre_classification_function(ipacket_t * ipacket, unsigned index);
/* capture handle */
pntoh_tcp_session_t     tcp_session = 0;
unsigned short          receive = 0;
/**
 * @brief Returns a struct which stores some peer information
 */

plibntoh_packet_t copy_packet_to_buffer (ipacket_t * ipacket, size_t total_len,unsigned index)
{
    plibntoh_packet_t ret = 0;
    
    /* gets peer information */
    ret = (plibntoh_packet_t) calloc ( 1 , sizeof ( libntoh_packet_t ) );

    ret->total_len = total_len;
    ret->index=index;
    ret->ipacket = (ipacket_t *) calloc ( ipacket->p_hdr->len , sizeof ( ipacket_t ) );
    ret->ipacket->extra = mmt_malloc(sizeof(extra_t));
    memcpy ( ret->ipacket , ipacket , sizeof(*ipacket));
    // memcpy (ret->ipacket->extra,ipacket->extra)
    return ret;
}

/**
 * @brief Frees the plibntoh_packet_t struct
 */
void free_peer_info ( plibntoh_packet_t pinfo )
{
    if ( ! pinfo )
        return;
    free ( pinfo->ipacket);
    free ( pinfo );

    return;
}

ipacket_t* get_ipacket_from_segment(pntoh_tcp_segment_t seg){
    if(seg!=0){
        plibntoh_packet_t info;
        info=(plibntoh_packet_t) seg->user_data;
        if(info!=0){
            return info->ipacket;
        }else{
            // printf("TEST: get_ipacket_from_segment: NO INFO \n");
            return NULL;
        }
    }else{
        // printf("TEST: get_ipacket_from_segment: NO SEGMENT \n");
        return NULL;
    }
}

void callback_packet_handler(ipacket_t* ipacket){
    //Update next_process
    // printf("TEST: callback_packet_handler of packet %"PRIu64" is called at index:%d\n",ipacket->packet_id,ipacket->extra->index);
    ipacket->extra->status=MMT_CONTINUE;
    ipacket->extra->next_process(ipacket,ipacket->extra->parent_stats,ipacket->extra->index);
}

 
/**
 * @brief Send a TCP segment to libntoh
 */
void ntoh_send_tcp_segment ( ipacket_t *ipacket, unsigned index)
{
    // printf("TEST:ntoh_send_tcp_segment %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra->index,index,ipacket->p_hdr->len);
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    int l3_offset = get_packet_offset_at_index(ipacket,index-1);
    packet->iph = (struct iphdr*)&ipacket->data[l3_offset];

    plibntoh_packet_t       pinfo;
    ntoh_tcp_tuple5_t   tcpt5;
    pntoh_tcp_stream_t  stream;
    struct tcphdr       *tcp;
    size_t              size_ip;
    size_t              total_len;
    size_t              size_tcp;
    // size_t              size_payload;
    int                 ret;
    unsigned int        error;
    struct ip* iphdr =(struct ip*)packet->iph;
    size_ip = iphdr->ip_hl * 4;
    total_len = ntohs( iphdr->ip_len );
    // // tcp header
    tcp = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
    if ( (size_tcp = tcp->th_off * 4) < sizeof(struct tcphdr))
        return ;
    // size_payload = total_len - ( size_ip + size_tcp );
    ntoh_tcp_get_tuple5 ( iphdr , tcp , &tcpt5 );
    // /* Find a stream */
    if ( !( stream = ntoh_tcp_find_stream( tcp_session , &tcpt5 ) ) ){
        // fprintf(stderr, "\n[i] Create new stream");
        if ( ! ( stream = ntoh_tcp_new_stream( tcp_session , &tcpt5, ntoh_tcp_callback , 0 , &error , 1 , 1 ) ) )
        {
            fprintf ( stderr , "\n[e] Error %d creating new stream: %s" , error , ntoh_get_errdesc ( error ) );
            callback_packet_handler(ipacket);
            return;
        }else{
                // printf("\n\t******************************************");
                // printf("\n\t*\t\t\t NEW STREAM \t\t\t*");
                // // print_tcp_tuple5(tcpt5);
                // printf("\n\t******************************************");
        }
    }else{
        // fprintf(stderr, "\n[i] Continue with an existing stream");
    } 
    pinfo = copy_packet_to_buffer ( ipacket , total_len,index);  
    // if ( size_payload > 0 )
    //     pinfo = copy_packet_to_buffer ( ipacket , total_len,index);
    // else
    // //     // ack
    //     {
    //         printf("TEST: WILL BE pinfo=0 %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra->index,index,ipacket->p_hdr->len);
    //         pinfo = 0;
    //     }
    switch ( ( ret = ntoh_tcp_add_segment( tcp_session , stream, iphdr, total_len, (void*)pinfo ) ) )
    {
        case NTOH_OK:
            // printf("TEST: ret=NTOH_OK after calling ntoh_tcp_add_segment: %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra->index,index,ipacket->p_hdr->len);
            return;

        case NTOH_SYNCHRONIZING:
            // printf("TEST: ret=NTOH_SYNCHRONIZING after calling ntoh_tcp_add_segment: %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra->index,index,ipacket->p_hdr->len);
            // callback_packet_handler(ipacket);
            // free_peer_info ( pinfo );
            return;

        default:
            // printf("TEST: ret=ERROR after calling ntoh_tcp_add_segment: %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra->index,index,ipacket->p_hdr->len);
            // callback_packet_handler(ipacket);
            fprintf( stderr, "\n[e] Error %d adding segment: %s", ret, ntoh_get_retval_desc( ret ) );
            // free_peer_info ( pinfo );
            return;
    }
}


void ntoh_tcp_callback ( pntoh_tcp_stream_t stream , pntoh_tcp_peer_t orig , pntoh_tcp_peer_t dest , pntoh_tcp_segment_t seg , int reason , int extra )
{
    if(seg==0){
        // printf("TEST: no segment!\n");
    }
    ipacket_t* ipacket;
    ipacket = get_ipacket_from_segment(seg);
    if(ipacket!=NULL){
        // printf("TEST: ntoh_tcp_callback is called: with ipacket\n");
        callback_packet_handler(ipacket);
    }else{
        // printf("TEST: ntoh_tcp_callback is called: No ipacket\n");
    }
    
    // // printf("MYLOG: ntoh_tcp_callback():\n");
    // // fprintf(stderr, "\n[i] TCP callback for origin: %lu and dest: %lu\n",orig->next_seq,dest->next_seq);
    // /* receive data only from the peer given by the user */
    // if ( receive == RECV_CLIENT && stream->server.receive )
    // {
    //     stream->server.receive = 0;
    //     return;
    // }else if ( receive == RECV_SERVER && stream->client.receive )
    // {
    //     stream->client.receive = 0;
    //     return;
    // }

    // fprintf ( stderr , "\n[%s] %s:%d (%s | Window: %lu) ---> " , ntoh_tcp_get_status ( stream->status ) , inet_ntoa( *(struct in_addr*) &orig->addr ) , ntohs(orig->port) , ntoh_tcp_get_status ( orig->status ) , orig->totalwin );
    // fprintf ( stderr , "%s:%d (%s | Window: %lu)\n\t" , inet_ntoa( *(struct in_addr*) &dest->addr ) , ntohs(dest->port) , ntoh_tcp_get_status ( dest->status ) , dest->totalwin );

    // if ( seg != 0 ){
    //     // printf("\n\t TCP callback: %lu | %lu\n",seg->seq,seg->ack);
    //     fprintf ( stderr , "SEQ: %lu ACK: %lu Next SEQ: %lu" , seg->seq , seg->ack , orig->next_seq );
    // }

    // switch ( reason )
    // {
    //     case NTOH_REASON_SYNC:
    //         switch ( extra )
    //         {
    //             case NTOH_REASON_MAX_SYN_RETRIES_REACHED:
    //             case NTOH_REASON_MAX_SYNACK_RETRIES_REACHED:
    //             case NTOH_REASON_HSFAILED:
    //             case NTOH_REASON_EXIT:
    //             case NTOH_REASON_TIMEDOUT:
    //             case NTOH_REASON_CLOSED:
    //                 if ( extra == NTOH_REASON_CLOSED )
    //                     fprintf ( stderr , "\n\t+ Connection closed by %s (%s)" , stream->closedby == NTOH_CLOSEDBY_CLIENT ? "Client" : "Server" , inet_ntoa( *(struct in_addr*) &(stream->client.addr) ) );
    //                 else
    //                     fprintf ( stderr , "\n\t+ %s/%s - %s" , ntoh_get_reason ( reason ) , ntoh_get_reason ( extra ) , ntoh_tcp_get_status ( stream->status ) );

    //                 break;
    //         }

    //         break;

    //     /* Data segment */
    //     case NTOH_REASON_DATA:
    //         fprintf ( stderr , " | Data segment | Bytes: %i" , seg->payload_len );

    //         /* write data */
    //         send_ordered_packet_to_mmt( (plibntoh_packet_t) seg->user_data,seg->seq,orig->next_seq);

    //         if ( extra != 0 )
    //                 fprintf ( stderr , "- %s" , ntoh_get_reason ( extra ) );

    //         break;
    // }

    if ( seg != 0 )
        free_peer_info ( (plibntoh_packet_t) seg->user_data );

    // fprintf ( stderr , "\n" );

    return;
}

// END OF LIBNTOH CODE
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

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
    if (tcp_hdr->fin) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->fin; //Already aligned to the correct bit ordering
        return 1;
    }
    return 0;
}

int tcp_syn_flag_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    if (tcp_hdr->syn) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->syn; //Already aligned to the correct bit ordering
        return 1;
    }
    return 0;
}

int tcp_rst_flag_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    if (tcp_hdr->rst) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->rst; //Already aligned to the correct bit ordering
        return 1;
    }
    return 0;
}

int tcp_psh_flag_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    if (tcp_hdr->psh) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->psh; //Already aligned to the correct bit ordering
        return 1;
    }
    return 0;
}

int tcp_ack_flag_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    if (tcp_hdr->ack) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->ack; //Already aligned to the correct bit ordering
        return 1;
    }
    return 0;
}

int tcp_urg_flag_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    struct tcphdr * tcp_hdr = (struct tcphdr *) & packet->data[proto_offset];
    if (tcp_hdr->urg) {
        *((unsigned char *) extracted_data->data) = tcp_hdr->urg; //Already aligned to the correct bit ordering
        return 1;
    }
    return 0;
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
    {TCP_RTT, TCP_RTT_ALIAS, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_syn_flag_extraction},//TODO: extract function not correct
    {TCP_SYN_RCV, TCP_SYN_RCV_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_syn_flag_extraction},
    {TCP_CONN_ESTABLISHED, TCP_CONN_ESTABLISHED_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_EVENT, tcp_ack_flag_extraction},
};

int tcp_pre_classification_function(ipacket_t * ipacket, unsigned index) {
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    int l4_offset = get_packet_offset_at_index(ipacket, index);
    if (packet->iphv6) {
        packet->l4_packet_len = (ipacket->p_hdr->caplen - l4_offset);
    } else {
        //Do nothing! this is done in ip.c
    }

    ////////////////////////////////////////////////
    packet->tcp = (struct tcphdr *) & ipacket->data[l4_offset];
    packet->udp = NULL;

    if (packet->flow) {
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

    if (ipacket->session->packet_count > CFG_CLASSIFICATION_THRESHOLD) {
        return 0;
    }
    // INJECT LIBNOTH PROCESS //
    // printf("TEST: before entry point: %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra->index,index,ipacket->p_hdr->len);
    ipacket->extra->status=MMT_SKIP;
    ntoh_send_tcp_segment(ipacket,index);
    // printf("TEST: after entry point: %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra->index,index,ipacket->p_hdr->len);
    // END OF INJECTING LIBNTOH PROCESS
    return 1;
}

int tcp_post_classification_function(ipacket_t * ipacket, unsigned index) {
    int a;
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;
    retval.offset = packet->tcp->doff * 4; //TCP header length

    a = packet->detected_protocol_stack[0];
    ////////////////////////////////////////////////
    retval.proto_id = a;

    int new_retval = 0;
    if (retval.proto_id == PROTO_UNKNOWN && ipacket->session->packet_count >= CFG_CLASSIFICATION_THRESHOLD) {
        //BW - TODO: We should have different strategies: best_effort = we can affort a number of missclassifications, etc.
        /* The protocol is unkown and we reached the classification threshold! Try with IP addresses and port numbers before setting it as unkown */
        retval.proto_id = get_proto_id_from_address(ipacket);
        if(retval.proto_id == PROTO_UNKNOWN) {
            retval.proto_id =  mmt_guess_protocol_by_port_number(ipacket);
        }

        retval.status = Classified;
        new_retval = set_classified_proto(ipacket, index + 1, retval);
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
    
    // INITIALIZE LIBNTOH

    unsigned int libntoh_error = 0;
    printf("MYLOG: libntoh version: %s\n",ntoh_version());
    
    /* Initializes libntoh TCP*/
    
    ntoh_tcp_init();
    // ntoh_tcp_exit();
    printf("MYLOG: Creates a new TCP session\n");
    
    /* Creates a new TCP session  */
    
    if(!(tcp_session=ntoh_tcp_new_session(0,0,&libntoh_error))){
        printf("\n[e] Error %d creating the TCP session: %s",libntoh_error,ntoh_get_errdesc(libntoh_error));
        ntoh_tcp_exit();
    }else{
        printf("MYLOG: Now you can using libntoh in mmt\n");
        printf("MYLOG: Max TCP streams allowd: %d\n", ntoh_tcp_get_size(tcp_session));
    }

    // END OF INITIALIZING LIBNTOH

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

