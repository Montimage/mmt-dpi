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
	uint16_t* packet_type = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_TYPE);
	char * packet_request = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_REQUEST);
	char * packet_request_parameter = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_REQUEST_PARAMETER);
	uint16_t * packet_response = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_RESPONSE_CODE);
	char * packet_response_value = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_RESPONSE_VALUE);
	uint32_t * packet_data_offset = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_DATA_OFFSET);
	uint32_t * packet_data_len = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_DATA_LEN);
	if(packet_type){
		printf("%lu,%d",ipacket->packet_id,*packet_type);
		if(packet_request){
			printf(",%s",packet_request);
			if(packet_request_parameter){
				printf(",%s",packet_request_parameter );
			}
		}
		if(packet_response){
			printf(",%d",*packet_response);
			if(packet_response_value){
				printf(",%s",packet_response_value);
			}
		}
		if(packet_data_offset){
			printf(",%d",*packet_data_offset);
		}
		if(packet_data_len){
			printf(",%d",*packet_data_len);
		}
	}
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
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_TYPE); //Request client port
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_REQUEST);  // Request server port
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_REQUEST_PARAMETER); 
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_RESPONSE_CODE);  
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_RESPONSE_VALUE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_DATA_OFFSET);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_DATA_LEN);  
	register_packet_handler(mmt_handler,1,packet_handler, NULL);
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
