/**
 * This example is intended to extract everything from a pcap file! This means all the attributes of all registered protocols will be registed for extraction. When a packet is processed, the attributes found in the packet will be print out.
 *
 * Compile this example with:
 *
 * Linux:
 * $ gcc -g -o simple_traffic_reporting simple_traffic_reporting.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 *
 * macOS (from MMT-DPI root directory):
 * $ clang -o simple_traffic_reporting src/examples/simple_traffic_reporting.c \
 *     -I sdk/include -I sdk/include/tcpip \
 *     -I /opt/homebrew/opt/libpcap/include \
 *     -L sdk/lib -L /opt/homebrew/opt/libpcap/lib \
 *     -lmmt_core -lpcap -ldl \
 *     -Wl,-rpath,sdk/lib
 *
 * macOS (if installed in /opt/mmt):
 * $ clang -o simple_traffic_reporting simple_traffic_reporting.c \
 *     -I /opt/mmt/dpi/include -I /opt/mmt/dpi/include/tcpip \
 *     -L /opt/mmt/dpi/lib -lmmt_core -lpcap -ldl \
 *     -Wl,-rpath,/opt/mmt/dpi/lib
 *
 * And get a data file (.pcap file) by using wireShark application to capture some packet.
 *
 * Then execute the program:
 *
 * IMPORTANT for macOS: Set the environment before running:
 * $ export MMT_PLUGINS_PATH=/path/to/mmt-dpi/sdk/lib
 * $ export DYLD_LIBRARY_PATH=/path/to/mmt-dpi/sdk/lib:$DYLD_LIBRARY_PATH
 *
 * $ ./simple_traffic_reporting tcp_plugin_image.pcap > simple_traffic_reporting.txt
 *
 * You can see the example result in file: simple_traffic_reporting.txt
 * Debug with Valgrind:
 * valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all ./simple_traffic_reporting tcp_plugin_image.pcap 2> simple_valgrind.txt
 * That is it!
 *
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#ifdef WIN32
#include <ws2tcpip.h>
#include <windows.h>
#ifndef socklen_t
typedef int socklen_t;
#define socklen_t socklen_t
#endif
#else
#include <netinet/in.h>
#endif
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
    typedef struct ipv4_ipv6_id_struct {
        union {
            uint32_t ipv4;
            uint8_t ipv6[16];
        };
    } ipv4_ipv6_id_t;
    typedef struct internal_session_struct {
        ipv4_ipv6_id_t ipclient;
        ipv4_ipv6_id_t ipserver;
        uint16_t clientport;
        uint16_t serverport;
        uint8_t proto;
        uint8_t ipversion;
    } internal_session_struct_t;
#define TIMEVAL_2_MSEC(tval) ((tval.tv_sec << 10) + (tval.tv_usec >> 10))
void usage(const char *prg_name) {
    fprintf(stderr, "%s <pcap file>\n", prg_name);
}
int proto_hierarchy_names_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest) {
    int offset = 0;
    if (proto_hierarchy->len < 1) {
        offset += sprintf(dest, ".");
    } else {
        int index = 1;
        offset += sprintf(dest, "%s", get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
        index++;
        for (; index < proto_hierarchy->len && index < 16; index++) {
            offset += sprintf(&dest[offset], ".%s", get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
        }
    }
    return offset;
}
void new_flow_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    if (attribute->data == NULL) {
        return; //This should never happen! check it anyway
    }
    internal_session_struct_t *temp_session = (internal_session_struct_t*)mmt_malloc(sizeof (internal_session_struct_t));
    if (temp_session == NULL) {
        return;
    }
    memset(temp_session, '\0', sizeof (internal_session_struct_t));
    // Flow extraction
    int ipindex = get_protocol_index_by_id(ipacket, PROTO_IP);
    //Process IPv4 flows
    if (ipindex != -1) {
        uint32_t * ip_src = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SRC);
        uint32_t * ip_dst = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_DST);
        if (ip_src) {
            temp_session->ipclient.ipv4 = (*ip_src);
        }
        if (ip_dst) {
            temp_session->ipserver.ipv4 = (*ip_dst);
        }
        uint8_t * proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_PROTO_ID);
        if (proto_id != NULL) {
            temp_session->proto = *proto_id;
        } else {
            temp_session->proto = 0;
        }
        temp_session->ipversion = 4;
        uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_CLIENT_PORT);
        uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SERVER_PORT);
        if (cport) {
            temp_session->clientport = *cport;
        }
        if (dport) {
            temp_session->serverport = *dport;
        }
    } else {
        void * ipv6_src = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SRC);
        void * ipv6_dst = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_DST);
        if (ipv6_src) {
            memcpy(&temp_session->ipclient.ipv6, ipv6_src, 16);
        }
        if (ipv6_dst) {
            memcpy(&temp_session->ipserver.ipv6, ipv6_dst, 16);
        }
        uint8_t * proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_NEXT_PROTO);
        if (proto_id != NULL) {
            temp_session->proto = *proto_id;
        } else {
            temp_session->proto = 0;
        }
        temp_session->ipversion = 6;
        uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_CLIENT_PORT);
        uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SERVER_PORT);
        if (cport) {
            temp_session->clientport = *cport;
        }
        if (dport) {
            temp_session->serverport = *dport;
        }
    }
    set_user_session_context_for_packet(ipacket,temp_session);
    // ipacket->session->user_data = temp_session;
}
void session_expiry_handle(const mmt_session_t * expired_session, void * args) {
    FILE * out_file = (args != NULL) ? args : stdout;
    int keep_direction = 1;
    internal_session_struct_t * temp_session = get_user_session_context(expired_session);
    if (temp_session == NULL) {
        return;
    }
    //IP strings
    char ip_src_str[46];
    char ip_dst_str[46];
    if (temp_session->ipversion == 4) {
        inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
        //keep_direction = is_local_net(temp_session->ipclient.ipv4);
    } else {
        inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
    }
    uint32_t rtt_ms = TIMEVAL_2_MSEC(get_session_rtt(expired_session));
    char path[512];
    proto_hierarchy_names_to_str(get_session_protocol_hierarchy(expired_session), path);
    int proto_index = ((get_session_protocol_hierarchy(expired_session))->len <= 16) ? ((get_session_protocol_hierarchy(expired_session))->len - 1) : (16 - 1);
    int proto_id = (get_session_protocol_hierarchy(expired_session))->proto_path[proto_index];
    fprintf(out_file, "%"PRIu64",%lu.%lu,%lu.%lu,"
            "%u,%s,%s,%hu,%hu,%hu,"
            "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%s,%s"
            "\n",
            get_session_id(expired_session),
            (get_session_last_activity_time(expired_session)).tv_sec, (get_session_last_activity_time(expired_session)).tv_usec,
            (get_session_init_time(expired_session)).tv_sec, (get_session_init_time(expired_session)).tv_usec,
            (int) temp_session->ipversion,
            ip_dst_str, ip_src_str,
            temp_session->serverport, temp_session->clientport, (unsigned short) temp_session->proto,
            (keep_direction) ? get_session_ul_packet_count(expired_session) : get_session_dl_packet_count(expired_session),
            (keep_direction) ? get_session_dl_packet_count(expired_session) : get_session_ul_packet_count(expired_session),
            (keep_direction) ? get_session_ul_byte_count(expired_session): get_session_dl_byte_count(expired_session),
            (keep_direction) ? get_session_dl_byte_count(expired_session) : get_session_ul_byte_count(expired_session),
            rtt_ms, get_session_retransmission_count(expired_session),
            // get_application_class_name_by_protocol_id(proto_id),
            path, get_protocol_name_by_id(proto_id)
            );
}
int main(int argc, const char **argv) {
    mmt_handler_t *mmt_handler, *m1;
    char mmt_errbuf[1024];
    int packets_count = 0;
    pcap_t *pcap;
    const u_char *data;
    struct pkthdr header;
    struct pcap_pkthdr pkthdr;
    char errbuf[1024];
    int ret;
    //flows = NULL;
    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    pcap = pcap_open_offline(argv[1], errbuf); // open offline trace
    //pcap = pcap_open_offline("../mmt_dpi_test/imesh_p2p.pcap", errbuf); // open offline trace
    if (!pcap) { /* pcap error ? */
        fprintf(stderr, "pcap_open: %s\n", errbuf);
        return EXIT_FAILURE;
    }
    if (!init_extraction()) { // general ixE initialization
        fprintf(stderr, "MMT extract init error\n");
        return EXIT_FAILURE;
    }
    //Initialize an MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) { /* pcap error ? */
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
        return EXIT_FAILURE;
    }
    // customized packet and session handling functions are then registered
    register_session_timeout_handler(mmt_handler, session_expiry_handle, NULL);
    register_extraction_attribute(mmt_handler, PROTO_IP, IP_SRC);
    register_extraction_attribute(mmt_handler, PROTO_IP, IP_DST);
    register_extraction_attribute(mmt_handler, PROTO_IP, IP_PROTO_ID);
    register_extraction_attribute(mmt_handler, PROTO_IP, IP_SERVER_PORT);
    register_extraction_attribute(mmt_handler, PROTO_IP, IP_CLIENT_PORT);
    register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_SRC_PORT);
    register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_DEST_PORT);
    register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_NEXT_PROTO);
    register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_SRC);
    register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_DST);
    register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_SERVER_PORT);
    register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_CLIENT_PORT);
    register_attribute_handler(mmt_handler, PROTO_IP, PROTO_SESSION, new_flow_handle, NULL, NULL);
    register_attribute_handler(mmt_handler, PROTO_IPV6, PROTO_SESSION, new_flow_handle, NULL, NULL);
    printf("Start timestamp, End timestamp, Flow id, "
            "IP version, Server IP, Client IP, Server Port, Client Port, "
            "Proto, UL Packets, DL Packets, UL Volume, DL Volume, "
            "RTT, TCP retransmissions, Application Class, Proto Path, Application\n");
    struct timeval tval;
    gettimeofday(&tval, NULL);
    fprintf(stderr, "Time %lu.%06lu\n", tval.tv_sec, tval.tv_usec);
    while ((data = pcap_next(pcap, &pkthdr))) {
        header.ts = pkthdr.ts;
        header.caplen = pkthdr.caplen;
        header.len = pkthdr.len;
        //header.msg_type = 0;
        //if(0) {
        if (!packet_process(mmt_handler, &header, data)) {
            fprintf(stderr, "Error 106: Packet data extraction failure.\n");
        }
        packets_count++;
    }
    mmt_close_handler(mmt_handler);
    gettimeofday(&tval, NULL);
    fprintf(stderr, "Time %lu.%06lu\n", tval.tv_sec, tval.tv_usec);
    close_extraction();
    pcap_close(pcap);
    printf("Process Terimated successfully\n");
    return EXIT_SUCCESS;
}
