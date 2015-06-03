#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <pcap.h>
#include "libntoh/libntoh.h"

#define SIZE_ETHERNET 14

pcap_t *handle;

void shandler ( int s )
{
    if ( s != 0 )
        signal ( s , &shandler );

    pcap_close ( handle );
    fprintf ( stderr , "\n\n" );
    exit ( s );
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
    /* capture starts */
    while ( ( packet = pcap_next( handle, &header ) ) != 0 )
    {
        fprintf ( stderr , "\nGot a packet!");
    }

    shandler(0);
    //dummy return
    return 0;
}

/**Command to compile: 
* $ gcc example1.c -o example1 -Wall -lpcap $(pkg-config ntoh --cflags --libs)
* $ sudo ./example1 -i eth0
* Result should be:
    [i] libntoh version: 0.4a


    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
    Got a packet!
*/ 