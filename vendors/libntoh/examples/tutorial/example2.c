#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <pcap.h>
#include <libntoh.h>

#define SIZE_ETHERNET 14

pcap_t *handle;

void shandler(int s){
    if(s!=0)
        signal(s,&shandler);
    pcap_close(handle);
    ntoh_exit();
    fprintf(stderr, "\n\n");
    exit(s);
}

void tcp_callback(pntoh_tcp_stream_t stream, pntoh_tcp_peer_t orig, pntoh_tcp_peer_t dest, pntoh_tcp_segment_t seg, int reason, int extra){
    fprintf(stderr, "\n something happening header");
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

    /** TCP and IP headers dissection */
    struct ip *iphdr = 0;
    struct tcphdr *tcphdr = 0;
    size_t size_ip=0;
    size_t size_tcp=0;

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
    }
    /* capture starts */
    while ( ( packet = pcap_next( handle, &header ) ) != 0 )
    {
        fprintf ( stderr , "\nGot a packet!");
        /** Chec ip header */
        iphdr = (struct ip*)(packet+SIZE_ETHERNET);
        size_ip=iphdr->ip_hl*4;
        if((size_ip)<sizeof(struct ip))
            continue;
        /* If it isn't a TCP segment */
        if(iphdr->ip_p!=IPPROTO_TCP)
            continue;
        /*check TCP header */
        tcphdr = (struct tcphdr*)((unsigned char*)iphdr+size_ip);
        if((size_tcp=tcphdr->th_off*4)<sizeof(struct tcphdr))
            continue;
        //fill TCP tuple5 fields 
        ntoh_tcp_get_tuple5(iphdr,tcphdr,&tcpt5);

        /* look for this TCP stream */
        if(!(tcpstream=ntoh_tcp_find_stream(tcpsession,&tcpt5))){
            if(!(tcpstream=ntoh_tcp_new_stream(tcpsession,&tcpt5,&tcp_callback,0,&error,1,1)))
                fprintf(stderr, "\n[e] Error %d creating new stream: %s",error,ntoh_get_errdesc(error));
            else{
                fprintf(stderr, "\n[i] New stream added! %s:%d --> ",inet_ntoa(*(struct in_addr*)&tcpt5.source),ntohs(tcpt5.sport));
                fprintf(stderr, "%s:%d",inet_ntoa(*(struct in_addr*)&tcpt5.destination),ntohs(tcpt5.dport));
            }
        }
    }

    shandler(0);
    //dummy return
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