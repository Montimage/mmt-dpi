/**
 * This example is intended to extract everything from a pcap file! This means all the attributes of all registered protocols will be registed for extraction. When a packet is processed, the attributes found in the packet will be print out.
 * To run this example, mmt-sdk installing is required. After installing mmt-sdk, add the mmt library to project library path by following command:
 * 
 * $ export LD_LIBRARY_PATH=/opt/mmt/lib:/usr/local/lib:$LD_LIBRARY_PATH
 * 
 * Compile this example with:
 * 
 * $ gcc -g -I/opt/mmt/include -o extract_all extract_all.c -L/opt/mmt/lib -lmmt_core -ldl -lpcap
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

void packet_handler(const ipacket_t * ipacket, u_char * args) {
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
    register_packet_handler(mmt_handler, 1, debug_extracted_attributes_printout_handler /* built in packet handler that will print all of the attributes */, &quiet);

    //Register a packet handler to periodically report protocol statistics
    //register_packet_handler(mmt_handler, 2, packet_handler /* built in packet handler that will print all of the attributes */, mmt_handler);

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

