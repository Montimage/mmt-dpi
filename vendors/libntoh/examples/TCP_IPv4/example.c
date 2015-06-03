/********************************************************************************
 * Copyright (c) 2011, Chema Garcia                                             *
 * All rights reserved.                                                         *
 *                                                                              *
 * Redistribution and use in source and binary forms, with or                   *
 * without modification, are permitted provided that the following              *
 * conditions are met:                                                          *
 *                                                                              *
 *    * Redistributions of source code must retain the above                    *
 *      copyright notice, this list of conditions and the following             *
 *      disclaimer.                                                             *
 *                                                                              *
 *    * Redistributions in binary form must reproduce the above                 *
 *      copyright notice, this list of conditions and the following             *
 *      disclaimer in the documentation and/or other materials provided         *
 *      with the distribution.                                                  *
 *                                                                              *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
 * POSSIBILITY OF SUCH DAMAGE.                                                  *
 ********************************************************************************/

/*
 * This example save the data sent by each peer in a separated file called: [src_ip]:[src_port]-[dst_ip]:[dst_port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <libntoh.h>

typedef struct
{
	// unsigned char *data;
	size_t total_len;
	char *path;
	struct ip *iphdr;
} peer_info_t , *ppeer_info_t;

#define RECV_CLIENT	1
#define RECV_SERVER	2

void print_ip_header(struct ip *iph){
    printf("\n\t-------------------IP header----------------------");
    printf("\n\t %d | %d | %d | %d",iph->ip_v,iph->ip_hl,iph->ip_tos,iph->ip_len);
    printf("\n\t %d | flag | %d",iph->ip_id,iph->ip_off);
    printf("\n\t %d | %d | %d",iph->ip_ttl,iph->ip_p,iph->ip_sum);
    printf("\n\t %s ",inet_ntoa(iph->ip_src));
    printf("\n\t %s ",inet_ntoa(iph->ip_dst));   
}


char * print_tcp_flag(int flg){
    if(flg&TH_FIN) return "FIN";
    if(flg&TH_SYN) return "SYN";
    if(flg&TH_RST) return "RST";
    if(flg&TH_PUSH) return "PUSH";
    if(flg&TH_ACK) return "ACK";
    if(flg&TH_URG) return "URG";
    // if(flg&TH_NS) return "NS";
    // if(flg&TH_CWR) return "CWR";
    // if(flg&TH_ECE) return "ECE";
    return "UNKNOWN";
}

void print_tcp_header(struct tcphdr *tcph){
    printf("\n\t-------------------TCP header----------------------");
    printf("\n\t %d | %d ",ntohs(tcph->th_sport),ntohs(tcph->th_dport));
    printf("\n\t %d",ntohl(tcph->th_seq));
    printf("\n\t %d",ntohl(tcph->th_ack));
    printf("\n\t %d | %s | %d",tcph->th_off,print_tcp_flag(tcph->th_flags),tcph->th_win);
    printf("\n\t %d | %d",tcph->th_sum,tcph->th_urp);
}

void print_tcp_segment(pntoh_tcp_segment_t seg){
    printf("\n\t ----------------------------");
    printf("\n\t | %lu | %lu | %s | %d | %d |",seg->seq,seg->ack,print_tcp_flag(seg->flags),seg->payload_len,seg->origin);
    printf("\n\t ----------------------------");
} 

void  print_int_to_ip_addr(int num){
    unsigned char bytes[4];
    bytes[0] = num & 0xFF;
    bytes[1] = (num>>8) & 0xFF;
    bytes[2] = (num>>16) & 0xFF;
    bytes[3] = (num>>24) & 0xFF;
    printf(" %d.%d.%d.%d",bytes[0],bytes[1],bytes[2],bytes[3]);
}

void print_tcp_tuple5(ntoh_tcp_tuple5_t tcpt5){
    printf("\n\t %s:%d <->",inet_ntoa(*(struct in_addr*)&tcpt5.source),ntohs(tcpt5.sport));
    printf(" %s:%d |",inet_ntoa(*(struct in_addr*)&tcpt5.destination),ntohs(tcpt5.dport));
    printf(" %d",tcpt5.protocol);
}

void print_tcp_peer(ntoh_tcp_peer_t peer){
    printf("\n\t %s:%d ",inet_ntoa(*(struct in_addr*)&peer.addr),ntohs(peer.port));
    printf("\n\t %lu | %lu",peer.isn, peer.ian);
    printf("\n\t %lu | %lu",peer.next_seq,peer.final_seq);
    printf("\n\t %d",peer.wsize);
    printf("\n\t %s",ntoh_tcp_get_status(peer.status));
    printf("\n\t %d | %d | %d | %lu | %d | %d\n",peer.mss, peer.sack, peer.wscale,peer.totalwin,peer.lastts,peer.receive);
    if(peer.segments){
        pntoh_tcp_segment_t seg=peer.segments; 
        printf("\n\t*** Segment *** ");
        print_tcp_segment(seg);
        while(seg->next){
        	// printf("\n\t FOUND SOME \n");
            seg=seg->next;
            print_tcp_segment(seg);
        }
    }
    
}
void print_tcp_stream(pntoh_tcp_stream_t ptcpstream){
    printf("\n\t-------------------TCP stream----------------------");
    print_tcp_tuple5(ptcpstream->tuple);
    printf("\n\t %s",ntoh_tcp_get_status(ptcpstream->status));
    printf("\n\t client");
    print_tcp_peer(ptcpstream->client);
    printf("\n\t Server");
    print_tcp_peer(ptcpstream->server);
    printf("\n\t--------------------End of stream------------------");
}

/* capture handle */
pcap_t 					*handle = 0;
pntoh_tcp_session_t		tcp_session = 0;
pntoh_ipv4_session_t	ipv4_session = 0;
unsigned short			receive = 0;
unsigned short nbSegments = 0;

/**
 * @brief Exit function (closes the capture handle and releases all resource from libntoh)
 */
void shandler ( int sign )
{
	if ( sign != 0 )
		signal ( sign , &shandler );

	pcap_close( handle );

	ntoh_exit();

	fprintf( stderr, "\n\n[+] Capture finished!\n" );
	exit( sign );
}

/**
 * @brief Returns a struct which stores some peer information
 */
// ppeer_info_t get_peer_info ( unsigned char *payload , size_t payload_len , pntoh_tcp_tuple5_t tuple )
// {
// 	ppeer_info_t ret = 0;
// 	size_t len = 0;
// 	char path[1024] = {0};

// 	/* gets peer information */
// 	ret = (ppeer_info_t) calloc ( 1 , sizeof ( peer_info_t ) );
// 	ret->data_len = payload_len;
// 	ret->data = (unsigned char*) calloc ( ret->data_len , sizeof ( unsigned char ) );
// 	memcpy ( ret->data , payload , ret->data_len );

// 	snprintf ( path , sizeof(path) , "%s:%d-" , inet_ntoa ( *(struct in_addr*)&(tuple->source) ) , ntohs(tuple->sport) );
// 	len = strlen(path);
// 	snprintf ( &path[len] , sizeof(path) - len, "%s:%d" , inet_ntoa ( *(struct in_addr*)&(tuple->destination) ) , ntohs(tuple->dport) );

// 	ret->path = strndup ( path , sizeof(path) );

// 	return ret;
// }

ppeer_info_t get_peer_info ( struct ip *iphdr,size_t total_len, pntoh_tcp_tuple5_t tuple)
{
	ppeer_info_t ret = 0;
	size_t len = 0;
	char path[1024] = {0};

	/* gets peer information */
	ret = (ppeer_info_t) calloc ( 1 , sizeof ( peer_info_t ) );
	ret->total_len = total_len;
	ret->iphdr = (struct ip*) calloc ( ret->total_len , sizeof ( struct ip ) );
	memcpy ( ret->iphdr , iphdr , ret->total_len );

	snprintf ( path , sizeof(path) , "%s:%d-" , inet_ntoa ( *(struct in_addr*)&(tuple->source) ) , ntohs(tuple->sport) );
	len = strlen(path);
	snprintf ( &path[len] , sizeof(path) - len, "%s:%d" , inet_ntoa ( *(struct in_addr*)&(tuple->destination) ) , ntohs(tuple->dport) );

	ret->path = strndup ( path , sizeof(path) );

	return ret;
}

/**
 * @brief Frees the ppeer_info_t struct
 */
void free_peer_info ( ppeer_info_t pinfo )
{
	/* free peer info data */
	if ( ! pinfo )
		return;

	free ( pinfo->iphdr );
	free ( pinfo->path );
	free ( pinfo );

	return;
}

/**
 * @brief Returns the name of a protocol
 */
inline char *get_proto_description ( unsigned short proto )
{
	switch ( proto )
	{
		case IPPROTO_ICMP:
			return "ICMP";

		case IPPROTO_TCP:
			return "TCP";

		case IPPROTO_UDP:
			return "UDP";

		case IPPROTO_IGMP:
			return "IGMP";

		case IPPROTO_IPV6:
			return "IPv6";

		case IPPROTO_FRAGMENT:
			return "IPv6 Fragment";

		default:
			return "Undefined";
	}
}

/**
 * @brief Writes the ppeer_info_t data field to disk
 */
void write_data ( ppeer_info_t info,int seg_seq, unsigned long next_seq)
{
	nbSegments++;
	int fd = 0;

	if ( !info )
		return;

	if ( (fd = open ( info->path , O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO )) < 0 )
	{
		fprintf ( stderr , "\n[e] Error %d writting data to \"%s\": %s" , errno , info->path , strerror( errno ) );
		return;
	}
	struct tcphdr 		*tcp;
	size_t 				size_ip;
	size_t				total_len;
	size_t				size_tcp;
	size_t				size_payload;
	unsigned char		*payload;
	// ip header
	size_ip = info->iphdr->ip_hl * 4;
	total_len = info->total_len;
	print_ip_header(info->iphdr);
	// tcp header
	tcp = (struct tcphdr*)((unsigned char*)(info->iphdr) + size_ip);
	if ( (size_tcp = tcp->th_off * 4) < sizeof(struct tcphdr) )
		return;
	print_tcp_header(tcp);
	// data payload
	payload = (unsigned char *)(info->iphdr) + size_ip + size_tcp;
	size_payload = total_len - ( size_ip + size_tcp );
	write ( fd , payload ,size_payload);
	close ( fd );
	printf("\nWrite data to: %s\n. Data: Segment SEQ: %d | Next Peer SEQ: %lu", info->path,seg_seq,next_seq);
	return;
}

/**
 * @brief Send a TCP segment to libntoh
 */
void send_tcp_segment ( struct ip *iphdr , pntoh_tcp_callback_t callback )
{
	// printf("\n\t SEND TCP SEGMENT\n");
	ppeer_info_t		pinfo;
	ntoh_tcp_tuple5_t	tcpt5;
	pntoh_tcp_stream_t	stream;
	struct tcphdr 		*tcp;
	size_t 				size_ip;
	size_t				total_len;
	size_t				size_tcp;
	size_t				size_payload;
	unsigned char		*payload;
	int					ret;
	unsigned int		error;
	// ip header
	size_ip = iphdr->ip_hl * 4;
	total_len = ntohs( iphdr->ip_len );
	// print_ip_header(iphdr);
	// tcp header
	tcp = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
	if ( (size_tcp = tcp->th_off * 4) < sizeof(struct tcphdr) )
		return;
	// print_tcp_header(tcp);
	// data payload
	payload = (unsigned char *)iphdr + size_ip + size_tcp;
	size_payload = total_len - ( size_ip + size_tcp );

	ntoh_tcp_get_tuple5 ( iphdr , tcp , &tcpt5 );

	/* Find a stream */
	if ( !( stream = ntoh_tcp_find_stream( tcp_session , &tcpt5 ) ) ){
		fprintf(stderr, "\n[i] Create new stream");
		if ( ! ( stream = ntoh_tcp_new_stream( tcp_session , &tcpt5, callback , 0 , &error , 1 , 1 ) ) )
		{
			fprintf ( stderr , "\n[e] Error %d creating new stream: %s" , error , ntoh_get_errdesc ( error ) );
			return;
		}else{
				printf("\n\t******************************************");
                printf("\n\t*\t\t\t NEW STREAM \t\t\t*");
                print_tcp_tuple5(tcpt5);
                printf("\n\t******************************************");
		}
	}else{
		fprintf(stderr, "\n[i] Continue with an existing stream");
	}	
		
	// size_payload: size of data
	if ( size_payload > 0 )
		// data segment
		// pinfo = get_peer_info ( payload , size_payload , &tcpt5 );
		pinfo = get_peer_info ( iphdr,total_len,&tcpt5);
	else
		// ack
		pinfo = 0;
	// printf("\n\t TCP Header: %d | %d\n",ntohl(tcp->th_seq),ntohl(tcp->th_ack));
	switch ( ( ret = ntoh_tcp_add_segment( tcp_session , stream, iphdr, total_len, (void*)pinfo ) ) )
	{
		case NTOH_OK:
			break;

		case NTOH_SYNCHRONIZING:
			free_peer_info ( pinfo );
			break;

		default:
			fprintf( stderr, "\n[e] Error %d adding segment: %s", ret, ntoh_get_retval_desc( ret ) );
			free_peer_info ( pinfo );
			break;
	}
	print_tcp_stream(stream);
	return;
}


void tcp_callback ( pntoh_tcp_stream_t stream , pntoh_tcp_peer_t orig , pntoh_tcp_peer_t dest , pntoh_tcp_segment_t seg , int reason , int extra )
{
	/* receive data only from the peer given by the user */
	if ( receive == RECV_CLIENT && stream->server.receive )
	{
		stream->server.receive = 0;
		return;
	}else if ( receive == RECV_SERVER && stream->client.receive )
	{
		stream->client.receive = 0;
		return;
	}

	fprintf ( stderr , "\n[%s] %s:%d (%s | Window: %lu) ---> " , ntoh_tcp_get_status ( stream->status ) , inet_ntoa( *(struct in_addr*) &orig->addr ) , ntohs(orig->port) , ntoh_tcp_get_status ( orig->status ) , orig->totalwin );
	fprintf ( stderr , "%s:%d (%s | Window: %lu)\n\t" , inet_ntoa( *(struct in_addr*) &dest->addr ) , ntohs(dest->port) , ntoh_tcp_get_status ( dest->status ) , dest->totalwin );

	if ( seg != 0 ){
		// printf("\n\t TCP callback: %lu | %lu\n",seg->seq,seg->ack);
		fprintf ( stderr , "SEQ: %lu ACK: %lu Next SEQ: %lu" , seg->seq , seg->ack , orig->next_seq );
	}

	switch ( reason )
	{
		case NTOH_REASON_SYNC:
	        switch ( extra )
	        {
	            case NTOH_REASON_MAX_SYN_RETRIES_REACHED:
	            case NTOH_REASON_MAX_SYNACK_RETRIES_REACHED:
	            printf("finished something!\n");
	            break;
	            case NTOH_REASON_HSFAILED:
	            case NTOH_REASON_EXIT:
	            case NTOH_REASON_TIMEDOUT:
	            case NTOH_REASON_CLOSED:
	                if ( extra == NTOH_REASON_CLOSED )
	                    fprintf ( stderr , "\n\t+ Connection closed by %s (%s)" , stream->closedby == NTOH_CLOSEDBY_CLIENT ? "Client" : "Server" , inet_ntoa( *(struct in_addr*) &(stream->client.addr) ) );
	                else
	                    fprintf ( stderr , "\n\t+ %s/%s - %s" , ntoh_get_reason ( reason ) , ntoh_get_reason ( extra ) , ntoh_tcp_get_status ( stream->status ) );

	                break;
	        }

	        break;

		/* Data segment */
		case NTOH_REASON_DATA:
			fprintf ( stderr , " | Data segment | Bytes: %i" , seg->payload_len );

			/* write data */
			write_data( (ppeer_info_t) seg->user_data,seg->seq,orig->next_seq);

			if ( extra != 0 )
					fprintf ( stderr , "- %s" , ntoh_get_reason ( extra ) );

			break;
	}

	if ( seg != 0 )
		free_peer_info ( (ppeer_info_t) seg->user_data );

	fprintf ( stderr , "\n" );

	return;
}


/**
 * @brief Sends a IPv4 fragment to libntoh
 */
void send_ipv4_fragment ( struct ip *iphdr , pipv4_dfcallback_t callback )
{
	ntoh_ipv4_tuple4_t 	ipt4;
	pntoh_ipv4_flow_t 	flow;
	size_t			total_len;
	int 			ret;
	unsigned int		error;

	// Get total length - ip header
	total_len = ntohs( iphdr->ip_len );

	ntoh_ipv4_get_tuple4 ( iphdr , &ipt4 );
	// Find an IPv4 flow: (pntoh_ipv4_session_t session, pntoh_ipv4_tuple4_t tuple4)
	if ( !( flow = ntoh_ipv4_find_flow( ipv4_session , &ipt4 ) ) )
		// create a new flow: (pntoh_ipv4_session_t session,pntoh_ipv4_tuple4_t tuple4, pipv4_dfcallback_t function, void *udata, usigned int *error)
		if ( ! (flow = ntoh_ipv4_new_flow( ipv4_session , &ipt4, callback, 0 , &error )) )
		{
			fprintf ( stderr , "\n[e] Error %d creating new IPv4 flow: %s" , error , ntoh_get_errdesc ( error ) );
			return;
		}
	if ( ( ret = ntoh_ipv4_add_fragment( ipv4_session , flow, iphdr, total_len ) ) )
		fprintf( stderr, "\n[e] Error %d adding IPv4: %s", ret, ntoh_get_retval_desc( ret ) );

	return;
}
/**
 * @brief IPv4 callback
 * @details be called each time new flow is created
 * 
 * @param flow Ipv4 flow where the defragmented datagrams of the sent datagram where stored
 * @param tuple tuple4 identifying the flow
 * @param char defragmented datagram
 * @param len total length of the defragmented datagram (IPv4 header + payload)
 * @param short reason why the datagram is sent
 * value of reason: NTOH_REASON_DEFRAGMENTED_DATAGRAM or NTOH_REASON_TIMEDOUT_FRAGMENTS
 */
void ipv4_callback ( pntoh_ipv4_flow_t flow , pntoh_ipv4_tuple4_t tuple , unsigned char *data , size_t len , unsigned short reason )
{
	unsigned int i = 0;

	fprintf( stderr, "\n\n[i] Got an IPv4 datagram! (%s) %s --> ", ntoh_get_reason(reason) , inet_ntoa( *(struct in_addr*) &tuple->source ) );
	fprintf( stderr, "%s | %i/%i bytes - Key: %04x - ID: %02x - Proto: %d (%s)\n\n", inet_ntoa( *(struct in_addr*) &tuple->destination ), len, flow->total , flow->key, ntohs( tuple->id ), tuple->protocol, get_proto_description( tuple->protocol ) );

	if ( tuple->protocol == IPPROTO_TCP )
		send_tcp_segment ( (struct ip*) data , &tcp_callback );
	else
		for ( i = 0; i < flow->total ; i++ )
			fprintf( stderr, "%02x ", data[i] );

	fprintf( stderr, "\n" );

	return;
}

int main ( int argc , char *argv[] )
{
	/* parameters parsing */
	int c;

	/* pcap */
	char 				errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program 	fp;
	char 				filter_exp[] = "ip";
	char 				*source = 0;
	char 				*filter = filter_exp;
	const unsigned char *packet = 0;
	struct pcap_pkthdr 	header;

	/* packet dissection */
	struct ip		*ip;
	unsigned int	error;

	/* extra */
	unsigned int ipf,tcps;

	fprintf( stderr, "\n###########################" );
	fprintf( stderr, "\n#     libntoh Example     #" );
	fprintf( stderr, "\n# ----------------------- #" );
	fprintf( stderr, "\n# Written by Chema Garcia #" );
	fprintf( stderr, "\n# ----------------------- #" );
	fprintf( stderr, "\n#  http://safetybits.net  #" );
	fprintf( stderr, "\n#   chema@safetybits.net  #" );
	fprintf( stderr, "\n#   sch3m4@brutalsec.net  #" );
	fprintf( stderr, "\n###########################\n" );

	fprintf( stderr, "\n[i] libntoh version: %s\n", ntoh_version() );

	if ( argc < 3 )
	{
		fprintf( stderr, "\n[+] Usage: %s <options>\n", argv[0] );
		fprintf( stderr, "\n+ Options:" );
		fprintf( stderr, "\n\t-i | --iface <val> -----> Interface to read packets from" );
		fprintf( stderr, "\n\t-f | --file <val> ------> File path to read packets from" );
		fprintf( stderr, "\n\t-F | --filter <val> ----> Capture filter (must contain \"tcp\" or \"ip\")" );
		fprintf( stderr, "\n\t-c | --client ----------> Receive client data only");
		fprintf( stderr, "\n\t-s | --server ----------> Receive server data only\n\n");
		exit( 1 );
	}

	/* check parameters */
	while ( 1 )
	{
		int option_index = 0;
		static struct option long_options[] =
		{
		{ "iface" , 1 , 0 , 'i' } ,
		{ "file" , 1 , 0 , 'f' } ,
		{ "filter" , 1 , 0 , 'F' } ,
		{ "client" , 0 , 0 , 'c' },
		{ "server" , 0 , 0 , 's' },
		{ 0 , 0 , 0 , 0 } };

		if ( ( c = getopt_long( argc, argv, "i:f:F:cs", long_options, &option_index ) ) < 0 )
			break;

		switch ( c )
		{
			case 'i':
				source = optarg;
				handle = pcap_open_live( optarg, 65535, 1, 0, errbuf );
				break;

			case 'f':
				source = optarg;
				handle = pcap_open_offline( optarg, errbuf );
				break;

			case 'F':
				filter = optarg;
				break;

			case 'c':
				receive |= RECV_CLIENT;
				break;

			case 's':
				receive |= RECV_SERVER;
				break;
		}
	}

	if ( !receive )
		receive = (RECV_CLIENT | RECV_SERVER);

	if ( !handle )
	{
		fprintf( stderr, "\n[e] Error loading %s: %s\n", source, errbuf );
		exit( -1 );
	}

	if ( pcap_compile( handle, &fp, filter, 0, 0 ) < 0 )
	{
		fprintf( stderr, "\n[e] Error compiling filter \"%s\": %s\n\n", filter, pcap_geterr( handle ) );
		pcap_close( handle );
		exit( -2 );
	}

	if ( pcap_setfilter( handle, &fp ) < 0 )
	{
		fprintf( stderr, "\n[e] Cannot set filter \"%s\": %s\n\n", filter, pcap_geterr( handle ) );
		pcap_close( handle );
		exit( -3 );
	}
	pcap_freecode( &fp );

	/* verify datalink */
	if ( pcap_datalink( handle ) != DLT_EN10MB )
	{
		fprintf ( stderr , "\n[e] libntoh is independent from link layer, but this example only works with ethernet link layer\n");
		pcap_close ( handle );
		exit ( -4 );
	}

	fprintf( stderr, "\n[i] Source: %s / %s", source, pcap_datalink_val_to_description( pcap_datalink( handle ) ) );
	fprintf( stderr, "\n[i] Filter: %s", filter );

	fprintf( stderr, "\n[i] Receive data from client: ");
	if ( receive & RECV_CLIENT )
		fprintf( stderr , "Yes");
	else
		fprintf( stderr , "No");

	fprintf( stderr, "\n[i] Receive data from server: ");
	if ( receive & RECV_SERVER )
		fprintf( stderr , "Yes");
	else
		fprintf( stderr , "No");

	signal( SIGINT, &shandler );
	signal( SIGTERM, &shandler );

	/*******************************************/
	/** libntoh initialization process starts **/
	/*******************************************/

	// Initialize the library (TCP and IPv4)
	ntoh_init ();

	/* Create new TCP session: 
	pntoh_tcp_session_t ntoh_tcp_new_session ( unsigned int max_streams , unsigned int max_timewait , unsigned int *error );

    max_streams: Maximum number of allowed streams in this session
    max_timewait: Maximum number of streams with TIME-WAIT status in this session
    *error: Returned error code

	*/
	if ( ! (tcp_session = ntoh_tcp_new_session ( 0 , 0 , &error ) ) )
	{
		fprintf ( stderr , "\n[e] Error %d creating TCP session: %s" , error , ntoh_get_errdesc ( error ) );
		exit ( -5 );
	}

	fprintf ( stderr , "\n[i] Max. TCP streams allowed: %d" , ntoh_tcp_get_size ( tcp_session ) );

	// Create new IPv4 session: pntoh_ipv4_session_t ntoh_ipv4_new_session(unsigned int max_flows, unsigned long max_mem, unsigned int *error)
	if ( ! (ipv4_session = ntoh_ipv4_new_session ( 0 , 0 , &error )) )
	{	
		/*Free session: 
		void ntoh_tcp_free_session(pntoh_tcp_session_t session)
		*/
		ntoh_tcp_free_session ( tcp_session );
		fprintf ( stderr , "\n[e] Error %d creating IPv4 session: %s" , error , ntoh_get_errdesc ( error ) );
		exit ( -6 );
	}

	fprintf ( stderr , "\n[i] Max. IPv4 flows allowed: %d\n\n" , ntoh_ipv4_get_size ( ipv4_session ) );
	int count=0;
	/* capture starts */
	while ( ( packet = pcap_next( handle, &header ) ) != 0 && count<100)
	{
		printf("\n\n\n\t**************");
        printf("\n\t* NEW PACKET %d*",count);
        printf("\n\t**************");
		count++;
		/* get packet headers */
		/*Check IP header*/
		ip = (struct ip*) ( packet + sizeof ( struct ether_header ) );
		if ( (ip->ip_hl * 4 ) < sizeof(struct ip) )
			continue;
		
		/* it is an IPv4 fragment */
		/** Macro to check if an IPv4 datagram is part of a fragment datagram
		#define NTOH_IPV4_IS_FRAGMENT(off)          ( ( (8*(ntohs(off) & 0x1FFF)) > 0 || (ntohs(off) & 0x2000) ) && !(ntohs(off) & 0x4000) )
		*/
		if ( NTOH_IPV4_IS_FRAGMENT(ip->ip_off) )
			send_ipv4_fragment ( ip , &ipv4_callback );
		/* or a TCP segment */
		else if ( ip->ip_p == IPPROTO_TCP )
			send_tcp_segment ( ip , &tcp_callback );
		// Get the number of stored streams in a session
		tcps = ntoh_tcp_count_streams( tcp_session );
		//Get the number of stored IPv4 flows in a session
		ipf = ntoh_ipv4_count_flows ( ipv4_session );
		/* no streams left */
		fprintf( stderr, "\n\n[+] There are currently %i stored TCP stream(s) and %i IPv4 flow(s)\n" , tcps , ipf );
	}
	printf("Total number of ordered packet with data: %d\n", nbSegments);
	// Get the number of stored streams in a session
	tcps = ntoh_tcp_count_streams( tcp_session );
	//Get the number of stored IPv4 flows in a session
	ipf = ntoh_ipv4_count_flows ( ipv4_session );

	/* no streams left */
	if ( ipf + tcps > 0 )
	{
		fprintf( stderr, "\n\n[+] There are currently %i stored TCP stream(s) and %i IPv4 flow(s). You can wait them to get closed or press CTRL+C\n" , tcps , ipf );
		pause();
	}

	shandler( 0 );

	//dummy return
	return 0;
}
