/**
 * This example is intended to show a simple session handler - count number of session. 
 * 
 * To run this example, mmt-sdk installing is required. After installing mmt-sdk, add the mmt library to project library path by following command:
 * 
 * $ export LD_LIBRARY_PATH=/opt/mmt/lib:/usr/local/lib:$LD_LIBRARY_PATH
 * 
 * Compile this example with:
 * 
 * $ gcc -I/opt/mmt/include -o attribute_handler_session_counter attribute_handler_session_counter.c -L/opt/mmt/lib -lmmt_core -ldl -lpcap
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
 * $ ./attribute_handler_session_counter tcp_plugin_image.pcap
 * 
 * The example output result:
 * $ ./attribute_handler_session_counter tcp_plugin_image.pcap
 *  Session with id=0 is detected --- Total number of session is 1
	Session with id=1 is detected --- Total number of session is 2
	Session with id=2 is detected --- Total number of session is 3
	Session with id=3 is detected --- Total number of session is 4
	Session with id=4 is detected --- Total number of session is 5
	Session with id=5 is detected --- Total number of session is 6
	Session with id=6 is detected --- Total number of session is 7
	Session with id=7 is detected --- Total number of session is 8
	Session with id=8 is detected --- Total number of session is 9
	...
 * That is it!
 *
 */
 
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
	char errbuf[1024];

	uint64_t session_count=0;

	//Initialize MMT
	init_extraction();

	//Initialize MMT handler
	mmt_handler =mmt_init_handler(DLT_EN10MB,0,mmt_errbuf);
	if(!mmt_handler){
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n",mmt_errbuf );
		return EXIT_FAILURE;
	}

	// Register an attribute handler, it will be called for every time the indicated attribute  is detected
	register_attribute_handler_by_name(
		mmt_handler,
		"IP","SESSION",
		session_attr_handler,
		NULL/*will be ignored, should be set to NULL*/,
		&session_count
	);

	pcap = pcap_open_offline(argv[1],errbuf); // open offline trace
	if(!pcap){ /* pcap error? */
		fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
		return;
	}

	while((data=pcap_next(pcap,&p_pkthdr))){
		header.ts = p_pkthdr.ts;
		header.caplen = p_pkthdr.caplen;
		header.len = p_pkthdr.len;
		if(!packet_process(mmt_handler,&header,data)){
			fprintf(stderr, "Packet data extraction failure\n");
		}
	}

	//Close the MMT handler
	mmt_close_handler(mmt_handler);

	//Close MMT
	close_extraction();

	pcap_close(pcap);

	return EXIT_SUCCESS;

}