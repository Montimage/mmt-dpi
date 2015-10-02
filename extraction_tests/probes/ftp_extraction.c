/**
 * This example is intended to show a simple packet handler - show the size of received packets. That is a callback function that will be called after the processing of every packet by the MMT core
 * 
 * 
 * Compile this example with:
 * 
 * $ gcc -g -o ftp_extraction ftp_extraction.c -lmmt_core -ldl -lpcap -lpthread
 * 
 * 
 * And get a data file (.pcap file) by using wireShark application to capture some packet.
 * 
 * Then execute the program:
 * 
 * $ ./ftp_extraction -t ftp_trace.pcap > output.xls
 * 
 * The example output result in the file: output.xls
 * 
 * That is it!
 * 
 */
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <pcap.h>
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
 #include "mmt_core.h"
 #include "mmt/tcpip/mmt_tcpip.h"
 #include "mmt_test_utils.h"

 #define MAX_FILENAME_SIZE 256
 #define TRACE_FILE 1
 #define LIVE_INTERFACE 2
 #define MTU_BIG (16 * 1024)

 static int quiet;

 void packet_handler(const ipacket_t * ipacket, void * user_args){
	// uint16_t * ip_identification = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_IDENTIFICATION); //Request IP packet identification
	uint16_t* ip_client_port = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_CLIENT_PORT);
	uint16_t * ip_server_port = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_SERVER_PORT);
	
	// uint32_t * tcp_seq_nb = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_SEQ_NB);
	// uint32_t * tcp_ack_nb = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_ACK_NB);	
	// uint8_t * tcp_data_offset = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_DATA_OFF); //Request TCP data offset
	// uint8_t * tcp_flags = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_FLAGS); //Request TCP flags
	// uint8_t * tcp_fin = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_FIN); //Request TCP fin flag
	// uint8_t * tcp_syn = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_SYN); //Request TCP syn flag
	// uint8_t * tcp_rst = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_RST); //Request TCP ACK number
	// uint8_t * tcp_psh = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_PSH); //Request TCP ACK number
	// uint8_t * tcp_ack = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_ACK); //Request TCP ACK number
	// uint8_t * tcp_urg = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_URG); //Request TCP ACK number
	// uint8_t * tcp_ece = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_ECE); //Request TCP ACK number
	// uint8_t * tcp_cwr = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_CWR); //Request TCP ACK number
	// uint16_t * tcp_window = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_WINDOW); //Request TCP ACK number
	// uint16_t * tcp_checksum = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_CHECKSUM); //Request TCP ACK number
	// uint16_t * tcp_urg_ptr = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_URG_PTR); //Request TCP ACK number
	// struct timeval * tcp_rtt = (struct timeval *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_RTT); //Request TCP ACK number
	// uint32_t * tcp_syn_rcv = (uint32_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_SYN_RCV); //Request TCP ACK number
	// uint32_t * tcp_conn_established = (uint32_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_CONN_ESTABLISHED); //Request TCP ACK number

	printf("%lu,", ipacket->packet_id);
	// printValue(2,ip_identification);
	// printValue(6,ip_client_addr);
	printValue(2,ip_client_port);
	// printValue(6,ip_server_addr);
	printValue(2,ip_server_port);
	// printValue(1,tcp_seq_nb);
	// printValue(1,tcp_ack_nb);
	// printValue(3,tcp_data_offset);
	// printValue(3,tcp_flags);
	// printValue(3,tcp_urg);
	// printValue(3,tcp_ack);
	// printValue(3,tcp_psh);
	// printValue(3,tcp_rst);
	// printValue(3,tcp_syn);
	// printValue(3,tcp_fin);
	// printValue(3,tcp_ece);
	// printValue(3,tcp_cwr);
	// printValue(2,tcp_window);
	// printValue(2,tcp_checksum);
	// printValue(2,tcp_urg_ptr);

	// // These attributes bellow are "POSITION_NOT_KNOWN"
	// printValue(1,tcp_syn_rcv);
	// printValue(1,tcp_conn_established);
	// printValue(4,tcp_rtt);
	printf("\n");
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


int main(int argc, char ** argv){
	mmt_handler_t *mmt_handler;// MMT handler
	char mmt_errbuf[1024];
	struct pkthdr header; // MMT packet header

	char filename[MAX_FILENAME_SIZE + 1];
    int type;

	pcap_t *pcap;
	const unsigned char *data;
	struct pcap_pkthdr p_pkthdr;
	char errbuf[1024];

	quiet = 0;
	parseOptions(argc, argv, filename, &type);

	//Initialize MMT
	init_extraction();

	//Initialize MMT handler
	mmt_handler =mmt_init_handler(DLT_EN10MB,0,mmt_errbuf);
	if(!mmt_handler){
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n",mmt_errbuf );
		return EXIT_FAILURE;
	}

	// register_extraction_attribute(mmt_handler,PROTO_IP,IP_CLIENT_ADDR); //Request client address
	// register_extraction_attribute(mmt_handler,PROTO_IP,IP_SERVER_ADDR); // Request server address
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_CLIENT_PORT); //Request client port
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_SERVER_PORT);  // Request server port
	// {IP_CLIENT_ADDR, IP_CLIENT_ADDR_ALIAS, MMT_DATA_IP_ADDR, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_client_addr_extraction},
	//Register the protocol attributes we need
	
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_SRC_PORT); //Request TCP source port
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_DEST_PORT); //Request TCP destination port 
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_SEQ_NB); //Request TCP sequence number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_ACK_NB); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_DATA_OFF); //Request TCP data offset
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_FLAGS); //Request TCP flags
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_FIN); //Request TCP fin flag
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_SYN); //Request TCP syn flag
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_RST); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_PSH); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_ACK); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_URG); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_ECE); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_CWR); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_WINDOW); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_CHECKSUM); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_URG_PTR); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_RTT); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_SYN_RCV); //Request TCP ACK number
	// register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_CONN_ESTABLISHED); //Request TCP ACK number

	//Register a packet handler, it will be called for every processed packet
	register_packet_handler(mmt_handler,1,packet_handler, NULL);
	// printf("packet_id,ip->ip_id,tcp_src_port,tcp_dest_port,tcp_seq_nb,tcp_ack_nb,tcp_data_offset,tcp_flags,tcp_fin,tcp_syn,tcp_rst,tcp_psh,tcp_ack,tcp_urg,tcp_ece,tcp_cwr,tcp_window,tcp_checksum,tcp_urg_ptr,tcp_syn_rcv,tcp_conn_established,tcp_rtt->tv_sec,tcp_rtt->tv_usec\n");
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

		//Close the MMT handler
	mmt_close_handler(mmt_handler);

		//Close MMT
	close_extraction();

	pcap_close(pcap);

	return EXIT_SUCCESS;

}
