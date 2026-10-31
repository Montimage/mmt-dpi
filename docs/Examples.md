---
layout: default
title: "Examples"
---

* TOC
{:toc}

------------------



To run these examples, `mmt-dpi` must be installed first (see [Compilation and Installation](Compilation-and-Installation-Instructions.md)).

All example source code is in `src/examples/` (root of the repo). This page
walks through five of the seven examples there; `MAC_extraction.c` and
`mmt_export_info.c` — the latter advertised in the
[README](https://github.com/montimage-projects/mmt-dpi/blob/main/README.md) —
are not covered by the walkthroughs below.

Each listing is the code of the example file it compiles, from the first line
after the file's header comment, so the page and the installed sources cannot
drift apart: `scripts/validate-doc-drift.sh` fails when a listing differs from
its `src/examples/` file, and `tools/ci/compile-doc-listings.sh` compiles every
listing with the command shown under it, and every `src/examples/*.c` file,
against an installed SDK with `-Werror=return-type` and the diagnostics GCC 14
makes errors by default (issue #581).

## Attributes Listing ##
This example is intended to provide the list of available protocols and for each protocol, the list of its attributes.

```c
#include <stdio.h>
#include <stdlib.h>
#include "mmt_core.h"

void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
	printf("\tAttribute id %i --- Name %s \n", attribute->id, attribute->alias);
}

void protocols_iterator(uint32_t proto_id, void * args) {
	printf("Protocol id %u --- Name %s\n", proto_id, get_protocol_name_by_id(proto_id));
	iterate_through_protocol_attributes(proto_id, attributes_iterator, NULL);
}

int main(int argc, char** argv) {
	printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");  
	printf("|\t\t MONTIMAGE\n");
	printf("|\t MMT-SDK version: %s\n",mmt_version());
	printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
	printf("|\t http://montimage.eu\n");
	printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");  	
	
	if(!init_extraction()){
		fprintf(stderr, "MMT extraction init failed\n");
		return EXIT_FAILURE;
	}

	iterate_through_protocols(protocols_iterator, NULL);

	close_extraction();

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

If you want to test with your own plugins, place them in `/opt/mmt/plugins` (the default plugin directory — the prefix contract is stated once, in [Agent Environment Notes §4](./AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior)) or point `MMT_DPI_PLUGINS_DIR` at an absolute directory holding them (see the same section).

## Extract All ##
This example is intended to extract everything! This means all the attributes of all registered protocols will be registered for extraction. When a packet is processed, the attributes found in the packet will be printed out.

```c
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
//#include <nghttp2/nghttp2.h>
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
/* Set by the signal handler — the only work done there (issue #211). */
static volatile sig_atomic_t stop_flag = 0;
/**
 * Initialize a pcap handler
 * @param  iname       interface name
 * @param  buffer_size buffer size (MB)
 * @param  snaplen     packet snaplen
 * @return             NULL if the pcap handler cannot be created or activated,
 *                     or the interface is not Ethernet; else the new handle
 */
pcap_t * init_pcap(char *iname, uint16_t buffer_size, uint16_t snaplen){
    pcap_t * my_pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    my_pcap = pcap_create(iname, errbuf);
    if (my_pcap == NULL) {
        fprintf(stderr, "[error] Couldn't open device %s\n", errbuf);
        return NULL;
    }
    pcap_set_snaplen(my_pcap, snaplen);
    pcap_set_promisc(my_pcap, 1);
    pcap_set_timeout(my_pcap, 0);
    pcap_set_buffer_size(my_pcap, buffer_size * 1000 * 1000);
    if (pcap_activate(my_pcap) < 0) {
        fprintf(stderr, "[error] Couldn't activate %s: %s\n", iname, pcap_geterr(my_pcap));
        pcap_close(my_pcap);
        return NULL;
    }

    if (pcap_datalink(my_pcap) != DLT_EN10MB) {
        fprintf(stderr, "[error] %s is not an Ethernet (Make sure you run with administrator permission! )\n", iname);
        pcap_close(my_pcap);
        return NULL;
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
            filename[MAX_FILENAME_SIZE] = '\0';
            *type = TRACE_FILE;
            break;
            case 'i':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            filename[MAX_FILENAME_SIZE] = '\0';
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

    /* Reject an unset mode instead of branching on uninitialised storage
       later (issue #211, F-BUG-105). */
    if (*type != TRACE_FILE && *type != LIVE_INTERFACE) {
        fprintf(stderr, "Missing input: pass -t <trace file> or -i <interface>\n");
        usage(argv[0]);
    }
    if (filename[0] == '\0') {
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
    register_extraction_attribute((mmt_handler_t *)args, proto_id, attribute->id);
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
    memset(&header, 0, sizeof(header)); // no stale metadata fields
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
    if (pcap == NULL) {
        printf("[info] no pcap handle\n");
    } else if (pcap_stats(pcap, &pcs) < 0) {
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
 * Handler signals during excutation time.
 * Async-signal-safe by design (issue #211, F-BUG-105): it only sets the stop
 * flag and asks pcap to break its loop — printf-based cleanup is not
 * signal-safe and running it here could also execute it twice (once from the
 * handler, once at the end of main). The real cleanup runs once, in main,
 * after the capture loop observes the flag.
 * @param type signal type
 */
void signal_handler(int type) {
    (void) type;
    stop_flag = 1;
    if (pcap != NULL) {
        pcap_breakloop(pcap);
    }
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
    printf("|\t http://montimage.eu\n");
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");  

    char mmt_errbuf[1024];
    char filename[MAX_FILENAME_SIZE + 1] = {0}; // interface name or path to pcap file
    int type = 0; // Online or offline mode — 0 means "unset"

    // Parse option
    parseOptions(argc, argv, filename, &type);

    //Initialize MMT
    if (!init_extraction()) {
        fprintf(stderr, "[error] MMT extraction init failed\n");
        return EXIT_FAILURE;
    }

    //Initialize MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) {
        fprintf(stderr, "[error] MMT handler init failed for the following reason: %s\n", mmt_errbuf );
        close_extraction();
        return EXIT_FAILURE;
    }

    // Interate throught protocols to register extract all attributes of all protocols
    iterate_through_protocols(protocols_iterator, mmt_handler);

    // Register packet handler function
    if (!register_packet_handler(mmt_handler, 1, debug_extracted_attributes_printout_handler, NULL)) {
        fprintf(stderr, "[error] MMT packet handler registration failed\n");
        mmt_close_handler(mmt_handler);
        close_extraction();
        return EXIT_FAILURE;
    }

    // Handle signals: the handler only flags the stop and breaks the pcap
    // loop, so clean-up below runs exactly once (issue #211, F-BUG-105).
    // SIGSEGV/SIGABRT keep their default action — unwinding a crash through
    // printf/pcap cleanup is not async-signal-safe.
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (type == TRACE_FILE) {
        // OFFLINE mode
        struct pkthdr header; // MMT packet header
        struct pcap_pkthdr p_pkthdr;
        pcap = pcap_open_offline(filename, mmt_errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", mmt_errbuf);
            mmt_close_handler(mmt_handler);
            close_extraction();
            return EXIT_FAILURE;
        }
        const u_char *data = NULL;
        while (!stop_flag && (data = pcap_next(pcap, &p_pkthdr))) {
            memset(&header, 0, sizeof(header)); // no stale metadata fields
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
            fprintf(stderr, "[error] creating pcap on %s failed\n", filename);
            mmt_close_handler(mmt_handler);
            close_extraction();
            return EXIT_FAILURE;
        }
        (void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
    }

    clean();

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
#include <string.h>
#include <pcap.h>
#include "mmt_core.h"

int packet_handler(const ipacket_t * ipacket, void * user_args){
	uint32_t * p_len = (uint32_t *) get_attribute_extracted_data_by_name(ipacket,"META","PACKET_LEN");
	if(p_len){
        printf("Received packet of size %u\n",*p_len);
	}
	return 0; // generic_packet_handler_callback is int-returning; 1 ends packet processing early
}

int main(int argc, char ** argv){
	mmt_handler_t *mmt_handler;// MMT handler
	char mmt_errbuf[1024];
	struct pkthdr header; // MMT packet header

	pcap_t *pcap;
	const unsigned char *data;
	struct pcap_pkthdr p_pkthdr;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(argc != 2){
		fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* Embedding lifecycle (docs/USER_GUIDE.md, section 3):
	 *   1. init_extraction()   once per process, before any handler exists
	 *   2. mmt_init_handler()  one handler per worker (here: one)
	 *   3. register attributes/handlers, then packet_process() per packet
	 *   4. mmt_close_handler() for every handler created in step 2
	 *   5. close_extraction()  last, once no handler is in use
	 * Every failure path below releases exactly what was acquired so far,
	 * in the reverse order. */

	//Initialize MMT (global state: protocol registry and plugins)
	if(!init_extraction()){
		fprintf(stderr, "MMT extraction init failed\n");
		return EXIT_FAILURE;
	}

	//Initialize MMT handler
	mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
	if(!mmt_handler){
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
		close_extraction();
		return EXIT_FAILURE;
	}

	//Register the protocol attributes we need
	//Request packet length. This is a META attribute
	if(!register_extraction_attribute_by_name(mmt_handler, "META", "PACKET_LEN")
		//Register a packet handler, it will be called for every processed packet
		|| !register_packet_handler(mmt_handler, 1, packet_handler, NULL)){
		fprintf(stderr, "MMT attribute/packet handler registration failed\n");
		mmt_close_handler(mmt_handler);
		close_extraction();
		return EXIT_FAILURE;
	}

	pcap = pcap_open_offline(argv[1], errbuf); // open offline trace
	if(!pcap){ /* pcap error? */
		fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
		mmt_close_handler(mmt_handler);
		close_extraction();
		return EXIT_FAILURE;
	}

	while((data=pcap_next(pcap,&p_pkthdr))){
		memset(&header, 0, sizeof(header)); // no stale metadata fields
		header.ts = p_pkthdr.ts;
		header.caplen = p_pkthdr.caplen;
		header.len = p_pkthdr.len;
		if(!packet_process(mmt_handler,&header,data)){
			fprintf(stderr, "Packet data extraction failure\n");
		}
	}

	pcap_close(pcap);

	//Close the MMT handler (before the global teardown)
	mmt_close_handler(mmt_handler);

	//Close MMT (global teardown, last)
	close_extraction();

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

#define _STDC_FORMAT_MARCROS
#include <inttypes.h>

void session_attr_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
  *(uint64_t*) user_args = *(uint64_t*) user_args +1;
  printf("Session with id=%"PRIu64" is detected --- Total number of session is %"PRIu64"\n", get_session_id_from_packet(ipacket),*(uint64_t*)user_args);
}

int main(int argc, char ** argv){
	mmt_handler_t *mmt_handler;// MMT handler
	char mmt_errbuf[1024];
	struct pkthdr header; // MMT packet header

	pcap_t *pcap;
	const unsigned char *data;
	struct pcap_pkthdr p_pkthdr;
	char errbuf[PCAP_ERRBUF_SIZE];

	uint64_t session_count=0;

	if(argc != 2){
		fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	//Initialize MMT
	if(!init_extraction()){
		fprintf(stderr, "MMT extraction init failed\n");
		return EXIT_FAILURE;
	}

	//Initialize MMT handler
	mmt_handler =mmt_init_handler(DLT_EN10MB,0,mmt_errbuf);
	if(!mmt_handler){
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n",mmt_errbuf );
		close_extraction();
		return EXIT_FAILURE;
	}

	// Register an attribute handler, it will be called for every time the indicated attribute  is detected
	if(!register_attribute_handler_by_name(
		mmt_handler,
		"IP","SESSION",
		session_attr_handler,
		NULL/*will be ignored, should be set to NULL*/,
		&session_count
	)){
		fprintf(stderr, "MMT attribute handler registration failed\n");
		mmt_close_handler(mmt_handler);
		close_extraction();
		return EXIT_FAILURE;
	}

	pcap = pcap_open_offline(argv[1],errbuf); // open offline trace
	if(!pcap){ /* pcap error? */
		fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
		mmt_close_handler(mmt_handler);
		close_extraction();
		return EXIT_FAILURE;
	}

	while((data=pcap_next(pcap,&p_pkthdr))){
		memset(&header, 0, sizeof(header)); // no stale metadata fields
		header.ts = p_pkthdr.ts;
		header.caplen = p_pkthdr.caplen;
		header.len = p_pkthdr.len;
		if(!packet_process(mmt_handler,&header,data)){
			fprintf(stderr, "Packet data extraction failure\n");
		}
	}

	pcap_close(pcap);

	//Close the MMT handler
	mmt_close_handler(mmt_handler);

	//Close MMT
	close_extraction();

	return EXIT_SUCCESS;

}
```
Compile the example:
```sh
gcc -o attribute_handler_session_counter attribute_handler_session_counter.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
```

Execute the example:
```sh
./attribute_handler_session_counter pcapDataFile.pcap
```
The output is the number of session

## Simple Traffic Reporting ##
This example is intended to extract the statistics of all streams.

```c
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include <netinet/in.h>
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
/* The hierarchy path is rendered with proto_hierarchy_to_str_with_size()
   (public API, capacity-checked) — the local unbounded sprintf loop it
   replaced could overflow the caller's buffer and mis-printed an empty
   hierarchy (issue #211, F-BUG-104). */
void new_flow_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    if (attribute->data == NULL) {
        return; //This should never happen! check it anyway
    }
    if (get_user_session_context(ipacket->session) != NULL) {
        return; // already recorded (IP and IPv6 both report a tunnelled session)
    }
    internal_session_struct_t *temp_session = (internal_session_struct_t*)mmt_malloc(sizeof (internal_session_struct_t));
    if (temp_session == NULL) {
        return;
    }
    memset(temp_session, '\0', sizeof (internal_session_struct_t));
    // Flow extraction
    unsigned ipindex = get_protocol_index_by_id(ipacket, PROTO_IP);
    //Process IPv4 flows
    if (ipindex != MMT_NO_PROTO_INDEX) {
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
    const proto_hierarchy_t *hier = get_session_protocol_hierarchy(expired_session);
    proto_hierarchy_to_str_with_size(hier, path, sizeof(path));
    /* get_application_name() returns the name of the last protocol in the
       hierarchy, or NULL for an empty one — clamping what the old manual
       `len - 1` index computed as proto_path[-1] (issue #211, F-BUG-104). */
    const char *app_name = get_application_name(hier);
    if (app_name == NULL) {
        app_name = "unknown";
    }
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
            path, app_name
            );
    // The record was mmt_malloc()ed in new_flow_handle(); every session
    // expires once, at the latest in mmt_close_handler(), so free it here.
    mmt_free(temp_session);
}
int main(int argc, const char **argv) {
    mmt_handler_t *mmt_handler;
    char mmt_errbuf[1024];
    int packets_count = 0;
    pcap_t *pcap;
    const u_char *data;
    struct pkthdr header;
    struct pcap_pkthdr pkthdr;
    char errbuf[PCAP_ERRBUF_SIZE];
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
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    //Initialize an MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) { /* pcap error ? */
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
        close_extraction();
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    // customized packet and session handling functions are then registered
    if (!register_session_timeout_handler(mmt_handler, session_expiry_handle, NULL)
        || !register_attribute_handler(mmt_handler, PROTO_IP, PROTO_SESSION, new_flow_handle, NULL, NULL)
        || !register_attribute_handler(mmt_handler, PROTO_IPV6, PROTO_SESSION, new_flow_handle, NULL, NULL)) {
        fprintf(stderr, "MMT session handler registration failed\n");
        mmt_close_handler(mmt_handler);
        close_extraction();
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
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
    printf("Start timestamp, End timestamp, Flow id, "
            "IP version, Server IP, Client IP, Server Port, Client Port, "
            "Proto, UL Packets, DL Packets, UL Volume, DL Volume, "
            "RTT, TCP retransmissions, Application Class, Proto Path, Application\n");
    struct timeval tval;
    gettimeofday(&tval, NULL);
    fprintf(stderr, "Time %lu.%06lu\n", tval.tv_sec, tval.tv_usec);
    while ((data = pcap_next(pcap, &pkthdr))) {
        memset(&header, 0, sizeof(header)); // no stale metadata fields
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
```
Compile this example with:
```sh
gcc -o simple_traffic_reporting simple_traffic_reporting.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
```

To test example:
```sh
./simple_traffic_reporting pcapDataFile.pcap > simple_traffic_reporting.txt
```