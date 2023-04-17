[TOC]

------------------



To run these example,`mmt-sdk` installing is required (see [compilation and installation instructions](Compilation-and-Installation-Instructions.md)).

Now you can use `mmt-sdk` library. All the source code of example can see in `mmt-sdk/sdk/examples/`

## Attributes Listing ##
This example is intended to provide the list of available protocols and for each protocol, the list of its attributes.

```c
#include <stdio.h>
#include <stdlib.h>
#include "mmt_core.h"

void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
  //Print the attribute ID and Name
  printf("\tAttribute id %i --- Name %s \n", attribute->id, attribute->alias);
}

void protocols_iterator(uint32_t proto_id, void * args) {
  //Print the protocol ID and Name (get_protocol_name_by_id)
  printf("Protocol id %i --- Name %s\n", proto_id, get_protocol_name_by_id(proto_id));
  //Iterate through the attributes of this protocol
  iterate_through_protocol_attributes(proto_id, attributes_iterator, NULL);
}
int main(int argc, char** argv) {
  init_extraction(); //Initialize MMT

  iterate_through_protocols(protocols_iterator, NULL); //Iterate through all registered protocols

  close_extraction();//We are done, close MMT
  return (EXIT_SUCCESS);
}
```

Compile the example:
```sh
gcc -o proto_attributes_iterator proto_attributes_iterator.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpthread

```

Run the example:
```sh
./proto_attributes_iterator
```
The output is the list of available protocols and for each protocol, the list of its attributes.

If you want to test your own plugins, you need to copy your plugins to `/opt/mmt/plugins` or you can create a `plugins` folder in the same directory with the example file, then copy your plugin to `plugins` folder.
```sh
mkdir plugins
cp /opt/mmt/lib/libmmt_tcpip.so.0.100 plugins/libmmt_tcpip.so
```

## Extract All ##
This example is intended to extract everything! This means all the attributes of all registered protocols will be registered for extraction. When a packet is processed, the attributes found in the packet will be printed out.

```c
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

void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
    //Register for extraction the attribute identified by the given protocol and attribute ids
    register_extraction_attribute(args, proto_id, attribute->id);
}

void protocols_iterator(uint32_t proto_id, void * args) {
    //Iterate through the attributes of the protocol with the given ID. For every attribute call the given callback function
    iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
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
    mmt_handler_t *mmt_handler; //MMT handler
    char mmt_errbuf[1024];
    struct pkthdr header; //MMT packet header

    pcap_t *pcap;
    const unsigned char *data;
    struct pcap_pkthdr p_pkthdr;
    char errbuf[1024];
    char filename[MAX_FILENAME_SIZE + 1];
    int type;

    quiet = 0;
    parseOptions(argc, argv, filename, &type);

    //First of all initialize MMT
    init_extraction();

    //Initialize an MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) { /* pcap error ? */
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
        return EXIT_FAILURE;
    }

    //Iterate through registered protocols and call the given function for every one
    iterate_through_protocols(protocols_iterator, mmt_handler);

    //Register a packet handler, it will be called for every processed packet
    register_packet_handler(mmt_handler, 1, debug_extracted_attributes_printout_handler /* built in packet handler that will print all of the attributes */, &quiet);

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

    //Close the MMT handler.
    mmt_close_handler(mmt_handler);

    //Close MMT.
    close_extraction();

    pcap_close(pcap);

    return EXIT_SUCCESS;
}
```
To compile the example:
```sh
gcc -g -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
```
We can extract from a `.pcap` file, which can be generated by using [WireShark tool ](https://www.wireshark.org/).
```sh
./extract_all -t pcapfile.pcap
```

We also can extract from live stream. Need sudo permission

```sh
sudo ./extract_all -i eth0
```
The output is all the attributes of al registered protocols.

## Packet Handler ##
This example is intended to show a simple packet handler. That is a callback function that will be called after the processing of every packet by the MMT core.

```c
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "mmt_core.h"

void packet_handler(const ipacket_t * ipacket, void * user_args) {
    uint32_t * p_len # (uint32_t *) get_attribute_extracted_data_by_name(ipacket, "META", "PACKET_LEN"); //The names are case insensitive
    if(p_len) {
        printf("Received packet of size %u\n", *p_len);
    }
}

int main(int argc, char** argv) {
    mmt_handler_t *mmt_handler; //MMT Handler
    struct pkthdr header; //MMT packet header
    char mmt_errbuf[1024];

    pcap_t *pcap;
    const unsigned char *data;
    struct pcap_pkthdr p_pkthdr;
    char errbuf[1024];

    //First of all initialize the extraction engine
    init_extraction();

    //Initialize the MMT handler
    mmt_handler # mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) {
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
        return EXIT_FAILURE;
    }

    //Register the protocol attributes we need
    register_extraction_attribute_by_name(mmt_handler, "META", "PACKET_LEN"); //request the packet length. This is a META attribute.

    //Register a packet handler, it will be called for every processed packet
    register_packet_handler(mmt_handler, 1, packet_handler, NULL);

    pcap # pcap_open_offline(argv[1], errbuf); // open offline trace
    if (!pcap) { /* pcap error ? */
        fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
        return EXIT_FAILURE;
    }
    while ((data # pcap_next(pcap, &p_pkthdr))) {
        header.ts # p_pkthdr.ts;
        header.caplen # p_pkthdr.caplen;
        header.len # p_pkthdr.len;
        if (!packet_process(mmt_handler, &header, data)) {
            fprintf(stderr, "Packet data extraction failure.\n");
            return EXIT_FAILURE;
        }
    }
    //Close the MMT handler
    mmt_close_handler(mmt_handler);

    //At the end close the extraction engine
    close_extraction();

    pcap_close(pcap);
    return EXIT_SUCCESS;
}
```

Compile this example with:
```sh
gcc -g -o packet_handler packet_handler.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
```
Execute the program:
```sh
./packet_handler pcapDataFile.pcap
```
The output is the size of received packets.

## Attribute Handler (Sessions counter) ##
This example is intended to show a simple attribute handler - count number of session.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "mmt_core.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

void session_attr_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
  *(uint64_t*) user_args # *(uint64_t*) user_args +1;
  printf("Session with id # %"PRIu64" is detected --- Total number of sessions is %"PRIu64"\n", ipacket->session->session_id, *(uint64_t *) user_args);
  // The session id is also accessible through: (uint64_t *) attribute->data
}

int main(int argc, char** argv) {
  mmt_handler_t *mmt_handler;
  struct pkthdr header;
  char mmt_errbuf[1024];

  pcap_t *pcap;
  const unsigned char *data;
  struct pcap_pkthdr p_pkthdr;
  char errbuf[1024];

  uint64_t sessions_count # 0;

  //First of all initialize the extraction engine
  init_extraction();

  //Initialize an MMT handler
  mmt_handler # mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
  if (!mmt_handler) { /* pcap error ? */
    fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
    return EXIT_FAILURE;
  }

  //Register an attribute handler, it will be called for every time the indicated attribute is detected
  register_attribute_handler_by_name(
    mmt_handler,
    "IP", "SESSION",
    session_attr_handler,
    NULL /* Will be ignored, should be set to NULL */,
    &sessions_count
  );

  pcap # pcap_open_offline(argv[1], errbuf); // open offline trace
  if (!pcap) { /* pcap error ? */
    fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  while ((data # pcap_next(pcap, &p_pkthdr))) {
    header.ts # p_pkthdr.ts;
    header.caplen # p_pkthdr.caplen;
    header.len # p_pkthdr.len;
    if (!packet_process(mmt_handler, &header, data)) {
      fprintf(stderr, "Packet data extraction failure.\n");
    }
  }

  //Close the MMT handler
  mmt_close_handler(mmt_handler);

  //At the end close the extraction engine
  close_extraction();

  pcap_close(pcap);
  return EXIT_SUCCESS;
}
```
Compile the example:
```sh
gcc -o attribute_handler_session_counter attribute_handler_session_counter.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
```

Execute the example:
```sh
./attribute_handler pcapDataFile.pcap
```
The output is the number of session

## Simple Traffic Reporting ##
This example is intended to extract the statisitic of all stream: TODO

```c
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include "mmt_core.h"
#include "mmt/tcpip/mmt_tcpip.h"
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
    internal_session_struct_t *temp_session = malloc(sizeof (internal_session_struct_t));
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
            "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%s,%s,%s"
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
            get_application_class_name_by_protocol_id(proto_id),
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
    fprintf(stderr, "Time %lu.%lu\n", tval.tv_sec, tval.tv_usec);
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
    fprintf(stderr, "Time %lu.%lu\n", tval.tv_sec, tval.tv_usec);
    close_extraction();
    pcap_close(pcap);
    printf("Process Terimated successfully\n");
    return EXIT_SUCCESS;
}
```
Compile this example with:
```sh
gcc -o simple_traffic_reporting simple_traffic_reporting.c -lmmt_core -lmmt_tcpip -ldl -lpcap
```

To test example:
```sh
./simple_traffic_reporting pcapDataFile.pcap > simple_traffic_reporting.txt
```