/**
 * Reconstruct the files which are transferred by FTP
 * To compile:
 * gcc -o ftp_reconstruct_file ftp_reconstruct_file.c -lmmt_core -ldl -lpcap -lpthread
 *
 * To test:
 * ./ftp_reconstruct_file -t pcap_file.pcap
 *
 * Expected output:
 *
 * File to be reconstructed
 * 
 */
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <pcap.h>
 #include <string.h>
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
 #include <fcntl.h>
 #define MAX_FILENAME_SIZE 256
 #define TRACE_FILE 1
 #define LIVE_INTERFACE 2
 #define MTU_BIG (16 * 1024)

 static int quiet;

 /**
 * Writes @len bytes from @content to the filename @path.
 */
void ftp_write_data (const char * path, const char * content, int len) {
  int fd = 0;
  if(path[0]=='/'){
  	path=path+1;	
  }
  if ( (fd = open ( path , O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO )) < 0 )
  {
    fprintf ( stderr , "\n[e] Error %d writting data to \"%s\": %s" , errno , path , strerror( errno ) );
    return;
  }

  if(len>0){
  	printf("Going to write to file: %s\n",path);
	  printf("Data: \n%s\n",content);
	  printf("Data len: %d\n",len);
	  write ( fd , content , len );
  }
  
  close ( fd );
}

 void packet_handler(const ipacket_t * ipacket, void * user_args){
 	// printf("\nPACKET: %lu\n", ipacket->packet_id);
 	
 	unsigned int * ip_client_addr = (int *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_CLIENT_ADDR); 
	unsigned int * ip_server_addr = (int *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_SERVER_ADDR); 
	unsigned short * ip_client_port = (unsigned short *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_CLIENT_PORT); 
	unsigned short * ip_server_port = (unsigned short *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_SERVER_PORT);
	uint16_t * ip_tot_len = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_TOT_LEN);	 
	uint8_t * ip_header_len = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_IP,IP_HEADER_LEN);
	uint8_t * tcp_data_off = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_DATA_OFF);

	char * ftp_payload = (char*)get_attribute_extracted_data(ipacket,PROTO_FTP,PROTO_PAYLOAD);
	uint16_t* packet_type = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_TYPE);

	int payload_len = 0;
	if(tcp_data_off)
	 	payload_len = *ip_tot_len - *ip_header_len - (*tcp_data_off)*4;


	// char * tcp_payload = (char*)get_attribute_extracted_data(ipacket,PROTO_TCP,PROTO_PAYLOAD);


	printf("%lu,",ipacket->packet_id);
	printValue(5,ip_client_addr);
	printValue(5,ip_server_addr);
	printValue(2,ip_client_port);
	printValue(2,ip_server_port);
	printValue(2,ip_tot_len);
	printValue(3,ip_header_len);
	printValue(3,tcp_data_off);
	printValue(2,packet_type);

	if(ftp_payload && payload_len>0){
		printf("%d,",payload_len);
		printf("%s\n",ftp_payload);
	}
	else{
		printf("\n");
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

	// Extract server_address and client_address from IP protocol
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_CLIENT_ADDR);
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_SERVER_ADDR);
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_CLIENT_PORT);
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_SERVER_PORT);
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_TOT_LEN);
	register_extraction_attribute(mmt_handler,PROTO_IP,IP_HEADER_LEN);
	// Extract from TCP protocol
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_DATA_OFF);
	// Extract payload data of FTP packet from FTP protocol
	register_extraction_attribute(mmt_handler,PROTO_FTP,PROTO_PAYLOAD);

	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_DATA_TYPE); //Request client port
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SESSION_MODE); //Request client port
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SESSION_STATUS);
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SESSION_FEATURES);
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_USERNAME);
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PASSWORD);
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_FILE_NAME);
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_FILE_DIR);
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_FILE_LAST_MODIFIED);
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_FILE_SIZE);
	// // PACKET ATTRIBUTE
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_TYPE); //Request client port
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_REQUEST);  // Request server port
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_REQUEST_PARAMETER); 
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_RESPONSE_CODE);  
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_RESPONSE_VALUE);
	// // register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_DATA_OFFSET);
	// register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_DATA_LEN);  
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
