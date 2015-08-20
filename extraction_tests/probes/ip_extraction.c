/**
 * This example is intended to show a simple packet handler - show the size of received packets. That is a callback function that will be called after the processing of every packet by the MMT core
 * 
 * 
 * Compile this example with:
 * 
 * $ gcc -g -o packet_handler packet_handler.c -lmmt_core -ldl -lpcap
 * 
 * 
 * And get a data file (.pcap file) by using wireShark application to capture some packet.
 * 
 * Then execute the program:
 * 
 * $ ./packet_handler tcp_plugin_image.pcap > packhdler_output.txt
 * 
 * The example output result in the file: packhdler_output.txt
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

void packet_handler(const ipacket_t * ipacket, void * user_args){

	uint8_t* ip_version = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_VERSION);
	uint8_t * ip_header_len = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_HEADER_LEN);
	uint8_t * ip_proto_tos = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_PROTO_TOS);
	uint16_t * ip_tot_len = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_TOT_LEN);	
	uint16_t * ip_identification = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_IDENTIFICATION); //Request TCP data offset
	uint8_t * ip_df_flag = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_DF_FLAG); //Request TCP flags
	uint8_t * ip_mf_flag = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_MF_FLAG); //Request TCP fin flag
	uint16_t * ip_frag_offset = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_FRAG_OFFSET); //Request TCP syn flag
	uint8_t * ip_proto_ttl = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_PROTO_TTL); //Request TCP ACK number
	uint8_t * ip_proto_id = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_PROTO_ID); //Request TCP ACK number
	uint16_t * ip_checksum = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_CHECKSUM); //Request TCP ACK number
	
	int * ip_src = (int *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_SRC); //Request TCP ACK number
	int * ip_dst = (int *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_DST); //Request TCP ACK number
	int * ip_client_addr = (int *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_CLIENT_ADDR); //Request TCP ACK number
	int * ip_server_addr = (int *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_SERVER_ADDR); //Request TCP ACK number
	
	uint16_t * ip_client_port = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_CLIENT_PORT); //Request TCP ACK number
	uint16_t * ip_server_port = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_SERVER_PORT); //Request TCP ACK number

	
	printf("%lu,", ipacket->packet_id);
	printValue(3,ip_version);
	printValue(3,ip_header_len);
	printValue(3,ip_proto_tos);
	printValue(2,ip_tot_len);
	printValue(2,ip_identification);
	printValue(3,ip_df_flag);
	printValue(3,ip_mf_flag);
	printValue(3,ip_frag_offset);
	printValue(3,ip_proto_ttl);
	printValue(3,ip_proto_id);
	printValue(2,ip_checksum);
	printValue(5,ip_src);
	printValue(5,ip_dst);
	printValue(5,ip_client_addr);
	printValue(5,ip_server_addr);
	printValue(2,ip_client_port);
	printValue(2,ip_server_port);
	printf("\n");
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
	
	//Register the protocol attributes we need
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_VERSION); //Request TCP source port
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_HEADER_LEN); //Request TCP destination port 
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_PROTO_TOS); //Request TCP sequence number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_TOT_LEN); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_IDENTIFICATION); //Request TCP data offset
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_DF_FLAG); //Request TCP flags
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_MF_FLAG); //Request TCP fin flag
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_FRAG_OFFSET); //Request TCP syn flag
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_PROTO_TTL); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_PROTO_ID); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_CHECKSUM); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_SRC); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_DST); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_CLIENT_ADDR); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_SERVER_ADDR); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_CLIENT_PORT); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_SERVER_PORT); //Request TCP ACK number
	//Register a packet handler, it will be called for every processed packet
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
