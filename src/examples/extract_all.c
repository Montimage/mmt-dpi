/**
 * This example is intended to extract everything from a pcap file! This means all the attributes of all registered protocols will be registed for extraction. When a packet is processed, the attributes found in the packet will be print out.
 * To run this example, mmt-sdk installing is required. After installing mmt-sdk, add the mmt library to project library path by following command:
 * 
 * $ export LD_LIBRARY_PATH=/opt/mmt/lib:/usr/local/lib:$LD_LIBRARY_PATH
 * 
 * Compile this example with:
 * 
 * $ gcc -g -I/opt/mmt/include -o extract_all extract_all.c -L/opt/mmt/lib -lmmt_core -ldl -lpcap -lpthread
 *   
 * 
 * Also need to copy TCPIP plugin to plugins folder:
 * 
 * $ mkdir plugins
 * 
 * $ cp /opt/mmt/lib/libmmt_tcpip.so.0.100 plugins/libmmt_tcpip.so
 * 
 * And get a data file (.pcap file) by using wireShark application to capture some packet.
 * 
 * Then execute the program:
 * 
 * -> Extract from a pcap file
 * $ ./extract_all -t tcp_plugin_image.pcap > exta_output.txt
 * 
 * -> Test with valgrind tool:
 * valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all ./extract_all -t tcp_plugin_image.pcap 2> valgrind_test_.txt
 * You can see the example result in file: exta_output.txt
 * 
 * -> Extract from live streaming
 * 
 * Need sudo permission:
 * $ sudo -i
 * $ export LD_LIBRARY_PATH=/opt/mmt/lib:/usr/local/lib:$LD_LIBRARY_PATH
 * $ ./extract_all -i eth0 > extra_live_output.txt
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

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <unistd.h>
#include "mmt_core.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define MTU_BIG (16 * 1024)

static int quiet;

void write_data_ipacket(const ipacket_t *ipacket){

    int l3_offset = 0;
    int i = 0;
    for (; i <= 2; i++) {
        l3_offset += ipacket->proto_headers_offset->proto_path[i];
    }
    struct tcphdr       *tcp;
    size_t              size_ip;
    size_t              total_len;
    size_t              size_tcp;
    size_t              size_payload;
    unsigned char       *payload;

    struct ip* iphdr =(struct ip*)(struct iphdr*)&ipacket->data[l3_offset];
    size_ip = iphdr->ip_hl * 4;
    total_len = ntohs( iphdr->ip_len );
    
    tcp = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
    if ( (size_tcp = tcp->th_off * 4) < sizeof(struct tcphdr))
        return ;
    payload =(unsigned char*)iphdr + size_ip + size_tcp;
    size_payload = total_len - (size_ip + size_tcp);
    if(size_payload>0){
        int fd = 0;
        char path[1024] ={0};
        int len=0;
        snprintf ( path , sizeof(path) , "%s:%d-" , inet_ntoa ( *(struct in_addr*)&(iphdr->ip_src.s_addr) ) , ntohs(tcp->th_sport) );
        len=strlen(path);
        snprintf ( &path[len] , sizeof(path) - len, "%s:%d" , inet_ntoa ( *(struct in_addr*)&(iphdr->ip_dst.s_addr) ) , ntohs(tcp->th_dport) );
        char *filename;
        filename = strndup(path,sizeof(path));
        if((fd = open(filename, O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO ))<0){
            fprintf(stderr, "\n[e] Error %d writting data to %s: %s \n",errno,filename,strerror(errno));
            return;   
        }
        write(fd,payload,size_payload);
        close(fd);
        free(filename);
        return;
    }
    
}

void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-q             : Be quiet (no output whatsoever, helps profiling).\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

void parseOptions(int argc, char ** argv, char * filename, int * type) {
    int opt, optcount = 0;
    while ((opt = getopt(argc, argv, "t:i:qh")) != EOF) {
        switch (opt) {
            case 't':
                optcount++;
                if (optcount > 1) {
                    usage(argv[0]);
                }
                strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
                *type = TRACE_FILE;
                break;
            case 'i':
                optcount++;
                if (optcount > 1) {
                    usage(argv[0]);
                }
                strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
                *type = LIVE_INTERFACE;
                break;
            case 'q':
                quiet = 1;
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

int proto_hierarchy_ids_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest) {
    int offset = 0;
    if (proto_hierarchy->len < 1) {
        offset += sprintf(dest, ".");
    } else {
        int index = 1;
        offset += sprintf(dest, "%u", proto_hierarchy->proto_path[index]);
        index++;
        for (; index < proto_hierarchy->len && index < 16; index++) {
            offset += sprintf(&dest[offset], ".%u", proto_hierarchy->proto_path[index]);
        }
    }
    return offset;
}

void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
    register_extraction_attribute(args, proto_id, attribute->id);
}

void protocols_iterator(uint32_t proto_id, void * args) {
    iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
}

void protocols_stats_iterator(uint32_t proto_id, void * args) {
    const ipacket_t * ipacket = (ipacket_t *) args;
    if (proto_id <= 1) return; //ignor META and UNknown protocols
    proto_statistics_t * proto_stats = get_protocol_stats(ipacket->mmt_handler, proto_id);
    proto_hierarchy_t proto_hierarchy = {0};
    while (proto_stats != NULL) {
        get_protocol_stats_path(ipacket->mmt_handler, proto_stats, &proto_hierarchy);
        char path[128];
        //proto_hierarchy_to_str(&proto_hierarchy, path);
        proto_hierarchy_ids_to_str(&proto_hierarchy, path);
        proto_statistics_t children_stats = {0};
        get_children_stats(proto_stats, & children_stats);
        if( !quiet ) {
            if ((children_stats.packets_count != 0) && ((proto_stats->packets_count - children_stats.packets_count) != 0)) {
                //The stats instance has children, report the global stats first
                printf("%u,%lu.%lu,%u,%s,%u,"
                        "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n", 99, ipacket->p_hdr->ts.tv_sec, ipacket->p_hdr->ts.tv_usec, proto_id, path, 0,
                        proto_stats->sessions_count - proto_stats->timedout_sessions_count,
                        proto_stats->data_volume, proto_stats->payload_volume, proto_stats->packets_count);

                printf("%u,%lu.%lu,%u,%s,%u,"
                        "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n", 99, ipacket->p_hdr->ts.tv_sec, ipacket->p_hdr->ts.tv_usec, proto_id, path, 1,
                        (proto_stats->sessions_count) ? (proto_stats->sessions_count - proto_stats->timedout_sessions_count) - (children_stats.sessions_count - children_stats.timedout_sessions_count) : 0,
                        proto_stats->data_volume - children_stats.data_volume,
                        proto_stats->payload_volume - children_stats.payload_volume,
                        proto_stats->packets_count - children_stats.packets_count);
            } else {
                printf("%u,%lu.%lu,%u,%s,%u,"
                       "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n", 99, ipacket->p_hdr->ts.tv_sec, ipacket->p_hdr->ts.tv_usec, proto_id, path, 1,
                        proto_stats->sessions_count - proto_stats->timedout_sessions_count,
                        proto_stats->data_volume, proto_stats->payload_volume, proto_stats->packets_count);
            }
        }

        reset_statistics(proto_stats);
        proto_stats = proto_stats->next;
    }
}

void packet_handler(const ipacket_t * ipacket, void * args) {
    debug("packet_handler of %"PRIu64" index: %d\n",ipacket->packet_id,ipacket->extra.index);
    // write_data_ipacket(ipacket);
    static time_t last_report_time = 0;
    if (last_report_time == 0) {
        last_report_time = ipacket->p_hdr->ts.tv_sec;
        return;
    }

    if ((ipacket->p_hdr->ts.tv_sec - last_report_time) >= 1) {
        iterate_through_protocols(protocols_stats_iterator, (void *) ipacket);
        last_report_time = ipacket->p_hdr->ts.tv_sec;
    }
}

void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
    mmt_handler_t *mmt = (mmt_handler_t*)user;
    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;
    if (!packet_process( mmt, &header, data )) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}

int main(int argc, char** argv) {
    printf("**** WELCOME TO EXTRACT ALL ****\n");
    mmt_handler_t *mmt_handler;
    char mmt_errbuf[1024];

    pcap_t *pcap;
    const unsigned char *data;
    struct pcap_pkthdr p_pkthdr;
    char errbuf[1024];
    char filename[MAX_FILENAME_SIZE + 1];
    int type;

    struct pkthdr header;

    quiet = 0;
    parseOptions(argc, argv, filename, &type);

    init_extraction();

    //Initialize an MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) { /* pcap error ? */
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
        return EXIT_FAILURE;
    }

    iterate_through_protocols(protocols_iterator, mmt_handler);

    //Register a packet handler, it will be called for every processed packet
    //register_packet_handler(mmt_handler, 1, debug_extracted_attributes_printout_handler /* built in packet handler that will print all of the attributes */, &quiet);

    //Register a packet handler to periodically report protocol statistics
    register_packet_handler(mmt_handler, 1, packet_handler /* built in packet handler that will print all of the attributes */, mmt_handler);

    if (type == TRACE_FILE) {
        pcap = pcap_open_offline(filename, errbuf); // open offline trace
        if (!pcap) { /* pcap error ? */
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }

        while ((data = pcap_next(pcap, &p_pkthdr))) {
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            if (!packet_process(mmt_handler, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
        }
    } else {
        pcap = pcap_open_live(filename, MTU_BIG, 1, 1000, errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        (void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
    }

    mmt_close_handler(mmt_handler);

    close_extraction();

    pcap_close(pcap);

    return EXIT_SUCCESS;
}

