/**
 * This example is intended to extract everything from a pcap file (or from an interface)! 
 * This means all the attributes of all registered protocols will be registed for extraction. 
 * When a packet is processed, the attributes found in the packet will be print out.
 * 
 * Compile this example with:
 * 
 * $ gcc -g -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 *   
 * Then execute the program:
 * 
 * -> Extract from a pcap file
 * $ ./extract_all -t tcp_plugin_image.pcap > exta_output.txt
 *
 * -> Extract from an interface
 * $ ./extract_all -i eth0 > exta_output.txt
 * 
 * -> Test with valgrind tool:
 * valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all ./extract_all -t tcp_plugin_image.pcap 2> valgrind_test_.txt
 * You can see the example result in file: exta_output.txt
 *
 * You can see the example result in file: exta_live_output.txt
 * That is it!
 * 
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
#include <pcap.h>
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2

mmt_handler_t *mmt_handler;// MMT handler
pcap_t *pcap; // Pcap handler
struct pcap_stat pcs; /* packet capture filter stats */
int pcap_bs = 0;
/**
 * Initialize a pcap handler
 * @param  iname       interface name
 * @param  buffer_size buffer size (MB)
 * @param  snaplen     packet snaplen
 * @return             NULL if cannot create pcap handler
 *                     a pointer points to a new pcap handle
 */
pcap_t * init_pcap(char *iname, uint16_t buffer_size, uint16_t snaplen){
    pcap_t * my_pcap;
    char errbuf[1024];
    my_pcap = pcap_create(iname, errbuf);
    if (my_pcap == NULL) {
        fprintf(stderr, "[error] Couldn't open device %s\n", errbuf);
        exit(0);
    }
    pcap_set_snaplen(my_pcap, snaplen);
    pcap_set_promisc(my_pcap, 1);
    pcap_set_timeout(my_pcap, 0);
    pcap_set_buffer_size(my_pcap, buffer_size * 1000 * 1000);
    pcap_activate(my_pcap);

    if (pcap_datalink(my_pcap) != DLT_EN10MB) {
        fprintf(stderr, "[error] %s is not an Ethernet (Make sure you run with administrator permission! )\n", iname);
        exit(0);
    }
    return my_pcap;
}

/**
 * Show help message
 * @param prg_name program name
 */
void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

/**
 * parser input parameter
 * @param argc     number of parameter
 * @param argv     parameter string
 * @param filename input source -> file name or interaface name
 * @param type     TRACE_FILE or LIVE_INTERFACE
 */
void parseOptions(int argc, char ** argv, char * filename, int * type) {
    int opt, optcount = 0;
    while ((opt = getopt(argc, argv, "t:i:b:h")) != EOF) {
        switch (opt) {
            case 't':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = TRACE_FILE;
            break;
            case 'i':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = LIVE_INTERFACE;
            break;
            
            case 'b':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            pcap_bs = atoi(optarg);
            break;

            case 'h':
            default: usage(argv[0]);
        }
    }

    if (filename == NULL || strcmp(filename, "") == 0) {
        if (*type == TRACE_FILE) {
            fprintf(stderr, "Missing trace file name\n");
        }
        if (*type == LIVE_INTERFACE) {
            fprintf(stderr, "Missing network interface name\n");
        }
        usage(argv[0]);
    }

    return;
}

/**
 * Register extraction attributes
 * @param attribute attribute to extract
 * @param proto_id  protocol id
 * @param args     user argument
 */
void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
    register_extraction_attribute(args, proto_id, attribute->id);
}

/**
 * Interate through all protocol attributes
 * @param proto_id protocol id
 * @param args     user argument
 */
void protocols_iterator(uint32_t proto_id, void * args) {
    iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
}

/**
 * Analyse from an interface
 * @param user     user argument
 * @param p_pkthdr pcap header
 * @param data     packet data
 */
void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
    mmt_handler_t *mmt = (mmt_handler_t*)user;
    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;
    // header.probe_id = 4;
    // header.source_id = 10;
    if (!packet_process(mmt, &header, data)) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}

/**
 * Clean resource when the program finished
 */
void clean() {
    printf("\n[info] Cleaning....\n");
    
    //Close the MMT handler
    mmt_close_handler(mmt_handler);
    printf("[info] Closed mmt_handler\n");
    
    //Close MMT
    close_extraction();
    printf("[info] Closed extraction \n");

    // Show pcap statistic if capture from an interface
    if (pcap_stats(pcap, &pcs) < 0) {
        printf("[info] pcap_stats does not exist\n");
        (void) printf("[info] pcap_stats: %s\n", pcap_geterr(pcap));
    } else {
        (void) printf("[info] \n%12d packets received by filter\n", pcs.ps_recv);
        (void) printf("[info] %12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
        (void) printf("[info] %12d packets dropped by driver (%3.2f%%)\n", pcs.ps_ifdrop, pcs.ps_ifdrop * 100.0 / pcs.ps_recv);
        fflush(stderr);
    }
    
    printf("[info] Closing pcaps...!\n");
    if (pcap != NULL) pcap_close(pcap);
    printf("[info] Finished cleaning....\n");
}

/**
 * Handler signals during excutation time
 * @param type signal type
 */
void signal_handler(int type) {
    printf("\n[info] reception of signal %d\n", type);
    fflush( stderr );
    clean();
}

/**
 * Main program start from here
 * @param  argc [description]
 * @param  argv [description]
 * @return      [description]
 */
int main(int argc, char ** argv) {
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");  
    printf("|\t\t MONTIMAGE\n");
    printf("|\t MMT-SDK version: %s\n",mmt_version());
    printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
    printf("|\t http://montimage.com\n");
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");  
    sigset_t signal_set;

    char mmt_errbuf[1024];
    char filename[MAX_FILENAME_SIZE + 1]; // interface name or path to pcap file
    int type; // Online or offline mode

    // Parse option
    parseOptions(argc, argv, filename, &type);

    //Initialize MMT
    init_extraction();

    //Initialize MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) {
        fprintf(stderr, "[error] MMT handler init failed for the following reason: %s\n", mmt_errbuf );
        return EXIT_FAILURE;
    }

    // Interate throught protocols to register extract all attributes of all protocols
    iterate_through_protocols(protocols_iterator, mmt_handler);

    // Register packet handler function
    register_packet_handler(mmt_handler, 1, debug_extracted_attributes_printout_handler, NULL);

    // Handle signal
    sigfillset(&signal_set);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);

    if (type == TRACE_FILE) {
        // OFFLINE mode
        struct pkthdr header; // MMT packet header
        struct pcap_pkthdr p_pkthdr;
        pcap = pcap_open_offline(filename, mmt_errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason\n");
            return EXIT_FAILURE;
        }
        const u_char *data = NULL;
        while ((data = pcap_next(pcap, &p_pkthdr))) {
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            // header.probe_id = 4;
            // header.source_id = 10;
            if (!packet_process(mmt_handler, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
        }
    } else {
        if(pcap_bs == 0){
            printf("[info] Use default buffer size: 50 (MB)\n");
        }else{
            printf("[info] Use buffer size: %d (MB)\n",pcap_bs);
        }
        // ONLINE MODE
        pcap = init_pcap(filename,pcap_bs,65535);

        if (!pcap) {
            fprintf(stderr, "[error] creating pcap failed for the following reason: %s\n", mmt_errbuf);
            return EXIT_FAILURE;
        }
        (void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
    }

    clean();

    return EXIT_SUCCESS;

}
