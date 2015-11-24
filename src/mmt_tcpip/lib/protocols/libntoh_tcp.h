/* Generated with MMT Plugin Generator */

#ifndef LIBNTOH_TCP_H
#define LIBNTOH_TCP_H
#ifdef	__cplusplus
extern "C" {
#endif

#include "libntoh.h"

	pntoh_tcp_session_t get_tcp_session(ipacket_t *ipacket, unsigned index){
		protocol_instance_t * configured_protocol = &(ipacket->mmt_handler)
		->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
		return (pntoh_tcp_session_t)configured_protocol->args;
	}

	void process_ipacket_next_process(ipacket_t* ipacket, int status)
	{
		debug("process_ipacket_next_process of packet %"PRIu64" is called at index:%d\n",ipacket->packet_id,ipacket->extra.index);
		ipacket->extra.status = status;
		ipacket->extra.next_process(ipacket,ipacket->extra.parent_stats,ipacket->extra.index);
	}

	void ntoh_tcp_callback ( pntoh_tcp_stream_t stream , pntoh_tcp_peer_t orig , pntoh_tcp_peer_t dest , pntoh_tcp_segment_t seg , int reason , int extra )
	{
		debug("ntoh_tcp_callback");
		debug("\n[%s] %s:%d (%s | Window: %lu) ---> " , ntoh_tcp_get_status ( stream->status ) , inet_ntoa( *(struct in_addr*) &orig->addr ) , ntohs(orig->port) , ntoh_tcp_get_status ( orig->status ) , orig->totalwin );
		debug("%s:%d (%s | Window: %lu)\n\t" , inet_ntoa( *(struct in_addr*) &dest->addr ) , ntohs(dest->port) , ntoh_tcp_get_status ( dest->status ) , dest->totalwin );

		if ( seg != 0 )
			debug("SEQ: %lu ACK: %lu Next SEQ: %lu" , seg->seq , seg->ack , orig->next_seq );
		switch(reason){
			case NTOH_REASON_SYNC:
			switch(extra){
				case NTOH_REASON_MAX_SYN_RETRIES_REACHED:
				case NTOH_REASON_MAX_SYNACK_RETRIES_REACHED:
				case NTOH_REASON_HSFAILED:
				case NTOH_REASON_EXIT:
				case NTOH_REASON_TIMEDOUT:
				case NTOH_REASON_CLOSED:
				if(extra == NTOH_REASON_CLOSED){
					debug("connection closed by %s (%s)",stream->closedby == NTOH_CLOSEDBY_CLIENT?"Client":"Server",inet_ntoa(*(struct in_addr*)&(stream->client.addr)));
				}else{
					debug("%s/%s - %s",ntoh_get_reason(reason),ntoh_get_reason(extra),ntoh_tcp_get_status(stream->status)); 
				}
				break;
			}
			break;
			case NTOH_REASON_DATA:
			debug("Segment payload len: %i",seg->payload_len);
                // Out of order
			if(extra == NTOH_REASON_OOO){
				debug("Out of order - Drop the packet");
				process_ipacket_next_process((ipacket_t *)seg->user_data, MMT_DROP);    
				break;
			}else{
				process_ipacket_next_process((ipacket_t *)seg->user_data, MMT_CONTINUE);    
			}
			
			if(extra!=0){
				debug(" Reason: %s",ntoh_get_reason(extra));
			}
			break;
		}
		return;
	}

    /**
     * @brief Send a TCP segment to libntoh
     * - Need to analysis the ipacket to extract tcp header information
     * - Extract struct ip data to put as input of libntoh
     * - 
     */
     int ntoh_packet_process ( ipacket_t *ipacket, unsigned index)
     {
     	pntoh_tcp_session_t tcp_session;
     	tcp_session = get_tcp_session(ipacket,index);

     	debug("ntoh_packet_process of ipacket: %"PRIu64" at index %d\n",ipacket->packet_id,index);
     	debug("Number of stored streams: %d\n",ntoh_tcp_count_streams(tcp_session));
     	
     	ntoh_tcp_tuple5_t   tcpt5;
     	pntoh_tcp_stream_t  stream = NULL;
     	struct tcphdr       *tcp = NULL;
     	struct ip           *iphdr = NULL;
     	size_t              size_ip;
     	size_t              total_len;
     	size_t              size_tcp;
     	size_t              size_payload;
     	int                 ret;
     	unsigned int        error;

     	int ip_proto_index = get_packet_offset_at_index(ipacket,index-1);
     	iphdr = (struct ip*)&ipacket->data[ip_proto_index];

     	size_ip = iphdr->ip_hl * 4;

     	total_len = ntohs( iphdr->ip_len );
     	
     	tcp = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
     	size_tcp = tcp->doff * 4;
     	size_payload = total_len - ( size_ip + size_tcp );
     	ntoh_tcp_get_tuple5 ( iphdr , tcp , &tcpt5 );
        // printf("\nTuple5 of packet: %p\n",ipacket);
     	
        /* Find a stream */
     	if ( !(stream = ntoh_tcp_find_stream( tcp_session , &tcpt5 ))){
            /*Create a new stream*/
     		if (!(stream = ntoh_tcp_new_stream( tcp_session , &tcpt5, ntoh_tcp_callback , 0 , &error , 1 , 1 )) ){
     			fprintf ( stderr , "\n[e] Error %d creating new stream: %s" , error , ntoh_get_errdesc ( error ) );
     			ipacket->extra.status = MMT_CONTINUE;
     			return 1;
     		}
     	}

     	if ( size_payload > 0 )
     		ret = ntoh_tcp_add_segment( tcp_session , stream, iphdr, total_len, (void*)ipacket);
     	else
     		ret = ntoh_tcp_add_segment( tcp_session , stream, iphdr, total_len, 0);
     	switch (ret)
     	{
     		case NTOH_OK:
     		debug("ret=NTOH_OK after calling ntoh_tcp_add_segment: %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra.index,index,ipacket->p_hdr->len);
     		if(ipacket->extra.index - index > 1){
     			debug("Index has changed!");
     			return 0;
     		}
     		return 1;

     		case NTOH_SYNCHRONIZING:
     		debug("ret=NTOH_SYNCHRONIZING after calling ntoh_tcp_add_segment: %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra.index,index,ipacket->p_hdr->len);
     		ipacket->extra.status = MMT_CONTINUE;
     		return 1;

     		default:
     		debug("ret=ERROR after calling ntoh_tcp_add_segment: %"PRIu64" index: %d/%d, len: %d\n",ipacket->packet_id,ipacket->extra.index,index,ipacket->p_hdr->len);
     		fprintf( stderr, "\n[e] Error %d adding segment: %s", ret, ntoh_get_retval_desc( ret ) );
     		ipacket->extra.status = MMT_CONTINUE;
     		return 1;
     	}
     }
     void tcp_context_cleanup(void * proto_context, void * args) {
     	ntoh_tcp_free_session((pntoh_tcp_session_t)((protocol_instance_t *) proto_context)->args);
     	debug("TCP: protocol context cleanup\n");
     }

     void * setup_tcp_context(void * proto_context, void * args) {
     	unsigned int libntoh_error = 0;
     	debug("Creates a new TCP session\n");
     	return (void *) ntoh_tcp_new_session(0,0,&libntoh_error);
     }
#ifdef	__cplusplus
 }
#endif
#endif	/* LIBNTOH_TCP_H */


