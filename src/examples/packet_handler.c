/**
 * This example is intended to show a simple packet handler - show the size of received packets. That is a callback function that will be called after the processing of every packet by the MMT core
 * 
 * 
 * Compile this example with:
 * 
 * $ gcc -g -o packet_handler packet_handler.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 *
 * (replace /opt/mmt with your MMT_BASE install prefix when it differs)
 * 
 * 
 * And get a data file (.pcap file) by using wireShark application to capture some packet.
 * 
 * Then execute the program:
 * 
 * $ ./packet_handler google-fr.pcap > packhdler_output.txt
 * 
 * The example output result in the file: packhdler_output.txt
 * 
 * That is it!
 * 
 */
 
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
