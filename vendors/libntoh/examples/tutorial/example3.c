#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <pcap.h>
#include <libntoh.h>

#define SIZE_ETHERNET 14

typedef struct{
    unsigned long client;
    unsigned long server;
} byte_count_t,*pbyte_count_t;

pcap_t *handle;

void shandler(int s){
    if(s!=0)
        signal(s,&shandler);
    pcap_close(handle);
    ntoh_exit();
    fprintf(stderr, "\n\n");
    exit(s);
}

void print_ip_header(struct ip *iph){
    // printf("\n\t - ** IP HEADER ** - \n");
    // printf("\nVersion: %c",iph->ip_vhl);
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
    return "UNKNOWN";
}

void print_tcp_header(struct tcphdr *tcph){
    printf("\n\t-------------------TCP header----------------------");
    printf("\n\t %d | %d ",ntohs(tcph->th_sport),ntohs(tcph->th_dport));
    printf("\n\t %d",tcph->th_seq);
    printf("\n\t %d",tcph->th_ack);
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
    printf("\n\t %d [%s]",peer.status,ntoh_tcp_get_status(peer.status));
    printf("\n\t %d | %d | %d | %lu | %d | %d\n",peer.mss, peer.sack, peer.wscale,peer.totalwin,peer.lastts,peer.receive);
    if(peer.segments){
        pntoh_tcp_segment_t seg=peer.segments; 
        printf("\n\t*** Segment *** ");
        print_tcp_segment(seg);
        while(seg->next){
            seg=seg->next;
            print_tcp_segment(seg);
        }
    }
    
}
void print_tcp_stream(pntoh_tcp_stream_t ptcpstream){
    printf("\n\t-------------------TCP stream----------------------");
    printf("\n\t*** Tuple 5 *** ");
    print_tcp_tuple5(ptcpstream->tuple);
    printf("\n\t*** Status *** ");
    printf("\n\t %d [%s]",ptcpstream->status,ntoh_tcp_get_status(ptcpstream->status));
    printf("\n\t*** Client *** ");
    print_tcp_peer(ptcpstream->client);
    printf("\n\t*** Server *** ");
    print_tcp_peer(ptcpstream->server);
    printf("\n\t--------------------End of stream------------------");
}
void tcp_callback(pntoh_tcp_stream_t stream, pntoh_tcp_peer_t orig, pntoh_tcp_peer_t dest, pntoh_tcp_segment_t seg, int reason, int extra){
    
    pbyte_count_t btcount = (pbyte_count_t)(stream->udata);
    fprintf(stderr, "\n [%s] %s:%d (%s) -->",ntoh_tcp_get_status(stream->status),inet_ntoa(*(struct in_addr*)&orig->addr),ntohs(orig->port),ntoh_tcp_get_status(orig->status));
    fprintf(stderr, "%s:%d (%s)\n\t\n", inet_ntoa(*(struct in_addr*)&dest->addr),ntohs(dest->port),ntoh_tcp_get_status(dest->status));
    switch(reason){
        /* connection sinchronization */
        case NTOH_REASON_SYNC:
            if(extra){
                switch(extra){
                    case NTOH_REASON_MAX_SYN_RETRIES_REACHED:
                    case NTOH_REASON_MAX_SYNACK_RETRIES_REACHED:
                    case NTOH_REASON_HSFAILED:
                    case NTOH_REASON_EXIT:
                    case NTOH_REASON_TIMEDOUT:
                    case NTOH_REASON_CLOSED:
                        if(extra==NTOH_REASON_CLOSED){
                            fprintf(stderr, "\n[i] %s/%s - %s | Connection closed by %s (%s)",ntoh_get_reason(reason),ntoh_get_reason(extra),ntoh_tcp_get_status(stream->status),stream->closedby==NTOH_CLOSEDBY_CLIENT?"Client":"Server",inet_ntoa(*(struct in_addr*)&(stream->client.addr)));
                        }else {
                            fprintf(stderr, "\n\t + %s/%s - %s",ntoh_get_reason(reason),ntoh_get_reason(extra),ntoh_tcp_get_status(stream->status));
                        }
                        fprintf(stderr, "\n\t[i] Total transfered data:\n");
                        fprintf(stderr, "\n\t- Client: %lu bytes",btcount->client);
                        fprintf(stderr, "\n\t- Server: %lu bytes",btcount->server);
                        free(btcount);
                    break;
                }
            }
            break;
        case NTOH_REASON_DATA:
            fprintf(stderr, "\n\t+ Segment payload len: %i \n",seg->payload_len);
            // print_tcp_segment(seg);
            if(orig==&(stream->client))
            {
                btcount->client+=seg->payload_len;
            }
            else
            {
                btcount->server+=seg->payload_len;
            }
            
            break;
    }
}


int main ( int argc , char *argv[] )
{
    /* parameters parsing */
    int c;

    /* pcap */
    char            errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program  fp;
    char            filter_exp[] = "ip";
    char            *source = 0;
    char            *filter = filter_exp;
    const unsigned char     *packet = 0;
    struct pcap_pkthdr  header;

    /**TCP processing*/
    pntoh_tcp_session_t tcpsession = 0;
    ntoh_tcp_tuple5_t tcpt5={0};
    pntoh_tcp_stream_t tcpstream = 0;
    unsigned int error=0;
    int ret=0;
    pbyte_count_t btcount=0;

    /** TCP and IP headers dissection */
    struct ip *iphdr = 0;
    struct tcphdr *tcphdr = 0;
    size_t size_ip=0;
    size_t size_tcp=0;
    size_t size_total=0;
    fprintf(stderr, "\n\n**** LIBNTOH EXAMPLE 3 *** \n\n");
    fprintf( stderr, "\n[i] libntoh version: %s\n", ntoh_version() );
    fprintf( stderr, "\n[i] libpcap version: %s\n", pcap_lib_version());

    if ( argc < 3 )
    {
        fprintf( stderr, "\n[+] Usage: %s <options>\n", argv[0] );
        fprintf( stderr, "\n+ Options:" );
        fprintf( stderr, "\n\t-i | --iface <val> -----> Interface to read packets from" );
        fprintf( stderr, "\n\t-f | --file <val> ------> File path to read packets from" );
        fprintf( stderr, "\n\t-F | --filter <val> ----> Capture filter (must contain \"tcp\" or \"ip\")\n\n" );
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
        { 0 , 0 , 0 , 0 } };

        if ( ( c = getopt_long( argc, argv, "i:f:F:", long_options, &option_index ) ) < 0 )
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

            default:
                if ( handle != 0 )
                    pcap_close ( handle );
                exit ( -1 );
        }
    }

    if ( !handle )
    {
        fprintf( stderr, "\n[e] Error loading %s: %s\n", source, errbuf );
        exit( -2 );
    }

    if ( pcap_compile( handle, &fp, filter, 0, 0 ) < 0 )
    {
        fprintf( stderr, "\n[e] Error compiling filter \"%s\": %s\n\n", filter, pcap_geterr( handle ) );
        pcap_close( handle );
        exit( -3 );
    }

    if ( pcap_setfilter( handle, &fp ) < 0 )
    {
        fprintf( stderr, "\n[e] Cannot set filter \"%s\": %s\n\n", filter, pcap_geterr( handle ) );
        pcap_close( handle );
        exit( -4 );
    }
    pcap_freecode( &fp );

    /* verify datalink */
    if ( pcap_datalink( handle ) != DLT_EN10MB )
    {
        fprintf ( stderr , "\n[e] libntoh is independent from link layer, but this example only works with ethernet link layer\n");
        pcap_close ( handle );
        exit ( -5 );
    }

    signal ( SIGINT , &shandler );
    ntoh_init();
    /* creates a new TCP session*/
    if(!(tcpsession=ntoh_tcp_new_session(0,0,&error))){
        fprintf(stderr, "\n[e] Error %d creating the TCP session: %s",error,ntoh_get_errdesc(error));
        shandler(0);
    }else{
        printf("\n\t******************************************");
        printf("\n\t*\t\t\t NEW SESSION \t\t\t*");
        printf("\n\t******************************************");
    }
    // printf("\n[i] A TCP session is created successfully: ");
    int count=0;
    /* capture starts */
    while ( ( packet = pcap_next( handle, &header ) ) != 0 && count<1000)
    {
        count++;
        printf("\n\n\n\t**************");
        printf("\n\t* NEW PACKET %d*",count);
        printf("\n\t**************");
        /** Chec ip header */
        iphdr = (struct ip*)(packet+SIZE_ETHERNET);
        size_ip=iphdr->ip_hl*4;
        if((size_ip)<sizeof(struct ip))
        {
            fprintf(stderr, "\n Invalid ip header");
            continue;
        }
        // print_ip_header(iphdr);
        /* If it isn't a TCP segment */
        if(iphdr->ip_p!=IPPROTO_TCP)
        {   
            fprintf(stderr, "\n It is not TCP protocol");
            continue;
        }
        /*check TCP header */
        tcphdr = (struct tcphdr*)((unsigned char*)iphdr+size_ip);
        if((size_tcp=tcphdr->th_off*4)<sizeof(struct tcphdr))
        {
            fprintf(stderr, "\n Invalid TCP header");
            continue;
        }
        
        // print_tcp_header(tcphdr);

        size_total=ntohs(iphdr->ip_len);
        //fill TCP tuple5 fields 
        ntoh_tcp_get_tuple5(iphdr,tcphdr,&tcpt5);
        // print_tcp_tuple5(tcpt5);
        /* look for this TCP stream */
        if(!(tcpstream=ntoh_tcp_find_stream(tcpsession,&tcpt5))){

            fprintf(stderr, "\n[i] Creating a new stream");
            btcount=(pbyte_count_t) calloc(1,sizeof(byte_count_t));
            if(!(tcpstream=ntoh_tcp_new_stream(tcpsession,&tcpt5,&tcp_callback,(void*)btcount,&error,1,1)))
                fprintf(stderr, "\n[e] Error %d creating new stream: %s",error,ntoh_get_errdesc(error));
            else{
                printf("\n\t******************************************");
                printf("\n\t*\t\t\t NEW STREAM \t\t\t*");
                printf("\n\t******************************************");
                print_tcp_tuple5(tcpt5);
                fprintf(stderr, "\n[i] *** New stream added! %s:%d --> ",inet_ntoa(*(struct in_addr*)&tcpt5.source),ntohs(tcpt5.sport));
                fprintf(stderr, "%s:%d",inet_ntoa(*(struct in_addr*)&tcpt5.destination),ntohs(tcpt5.dport));
            }
        }else{
            fprintf(stderr, "\n[i] Continue with stream %s:%d --> ",inet_ntoa(*(struct in_addr*)&tcpt5.source),ntohs(tcpt5.sport));
            fprintf(stderr, "%s:%d",inet_ntoa(*(struct in_addr*)&tcpt5.destination),ntohs(tcpt5.dport));
        }
        ret=ntoh_tcp_add_segment(tcpsession,tcpstream,iphdr,size_total,0);
        // print_tcp_session(tcpsession);
        switch(ret){
            case NTOH_OK:
            case NTOH_SYNCHRONIZING:
            break;

            default:
            fprintf(stderr, "\n[e] Error %d adding segment: %s",ret,ntoh_get_retval_desc(ret));
            break;
        }
        print_ip_header(iphdr);
        print_tcp_header(tcphdr);
        print_tcp_stream(tcpstream);
        count++;
    }
    // print_tcp_stream(tcpstream);
    // pntoh_tcp_stream_t stream = tcpstream;
    // while(stream->next){
    //     stream = tcpstream->next;
    //     print_tcp_stream(stream);
    // }

    printf("No more packet\n");
    shandler(0);
    // printf("\n WHAT EVER!\n");
    return 0;
}

/**Command to compile: 
* $ gcc example2.c -o example2 -Wall -lpcap $(pkg-config ntoh --cflags --libs)
* $ sudo ./example2 -i eth0 -F "tcp"
* Result should be:
    [i] libntoh version: 0.4a

    [i] libpcap version: libpcap version 1.7.2

    Got a packet!
    [i] New stream added! 10.0.2.15:53777 --> 93.184.220.20:80
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!^C
     something happening header
*/ 