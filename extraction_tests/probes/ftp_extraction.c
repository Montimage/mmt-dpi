/**
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

/**
 * Packet handler
 * @param ipacket   packet
 * @param user_args user data
 */
 void packet_handler(const ipacket_t * ipacket, void * user_args){
	// SESSION ATTRIBUTES
	// CONTROL CONNECTION ATTRIBUTES
	uint8_t * session_conn_type = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_SESSION_CONN_TYPE);
	uint32_t * server_cont_addr = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_SERVER_CONT_ADDR);
	uint16_t * server_cont_port = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_SERVER_CONT_PORT);
	uint32_t * client_cont_addr = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_CLIENT_CONT_ADDR);
	uint16_t * client_cont_port = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_CLIENT_CONT_PORT);
	char * username = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_USERNAME);
	char * password = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PASSWORD);
	char * session_feats = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_SESSION_FEATURES);
	char * syst = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_SYST);
	uint16_t * status = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_STATUS);
	ftp_command_t * last_command = (ftp_command_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_LAST_COMMAND);
	ftp_response_t * last_response = (ftp_response_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_LAST_RESPONSE_CODE);
	char * current_dir = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_CURRENT_DIR);
	// DATA CONNECTION ATTRIBUTES
	uint32_t * server_data_addr = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_SERVER_DATA_ADDR);
	uint16_t * server_data_port = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_SERVER_DATA_PORT);
	uint32_t * client_data_addr = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_CLIENT_DATA_ADDR);
	uint16_t * client_data_port = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_CLIENT_DATA_PORT);
	uint8_t * data_type = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_DATA_TYPE);
	char * data_transfer_type = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_DATA_TRANSFER_TYPE);
	uint8_t * data_mode = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_DATA_MODE);
	uint8_t * data_direction = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_DATA_DIRECTION);
	char * file_name = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_FILE_NAME);
	uint32_t * file_size = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_FILE_SIZE);
	char * file_last_modified = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_FILE_LAST_MODIFIED);
	// PACKET ATTRIBUTES
	uint8_t * packet_type = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_TYPE);
	char * request = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_REQUEST);
	char * request_parameter = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_REQUEST_PARAMETER);
	uint16_t * response = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_RESPONSE_CODE);
	char * response_value = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_RESPONSE_VALUE);
	uint32_t * data_len = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_DATA_LEN);
	printf("\n%lu,",ipacket->packet_id);
	printValue(session_conn_type,3);
	printValue(server_cont_addr,5);
	printValue(server_cont_port,2);
	printValue(client_cont_addr,5);
	printValue(client_cont_port,2);
	printValue(username,0);
	printValue(password,0);
	printValue(session_feats,0);
	printValue(syst,0);
	printValue(status,2);
	printValue(last_command,6);
	printValue(last_response,7);
	printValue(current_dir,0);
	printValue(server_data_addr,5);
	printValue(server_data_port,2);
	printValue(client_data_addr,5);
	printValue(client_data_port,2);	
	printValue(data_type,3);
	printValue(data_transfer_type,0);
	printValue(data_mode,3);
	printValue(data_direction,3);
	printValue(file_name,0);
	printValue(file_size,1);
	printValue(file_last_modified,0);
	printValue(packet_type,3);
	printValue(request,0);
	printValue(request_parameter,0);
	printValue(response,2);
	printValue(response_value,0);
	printValue(data_len,1);
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

	// SESSION ATTRIBUTES
	// CONTROL CONNECTION ATTRIBUTES
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SESSION_CONN_TYPE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SERVER_CONT_ADDR);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SERVER_CONT_PORT);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_CLIENT_CONT_ADDR);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_CLIENT_CONT_PORT);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_USERNAME);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PASSWORD);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SESSION_FEATURES);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SYST);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_STATUS);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_LAST_COMMAND);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_LAST_RESPONSE_CODE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_CURRENT_DIR);
	// DATA CONNECTION ATTRIBUTES
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SERVER_DATA_ADDR);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_SERVER_DATA_PORT);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_CLIENT_DATA_ADDR);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_CLIENT_DATA_PORT);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_DATA_TYPE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_DATA_TRANSFER_TYPE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_DATA_MODE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_DATA_DIRECTION);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_FILE_NAME);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_FILE_SIZE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_FILE_LAST_MODIFIED);
	// PACKET ATTRIBUTES
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_TYPE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_REQUEST);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_REQUEST_PARAMETER);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_RESPONSE_CODE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_RESPONSE_VALUE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_PACKET_DATA_LEN);
	printf("id,session_conn_type,s_control_addr,s_control_port,c_data_addr,c_dara_port,username,password,session_feats,sys,status,last_command,last_response,current_dir,");
	printf("s_data_addr,s_data_port,c_data_addr,c_data_port,data_type,data_transfer_type,data_mode,data_direction,file_name,file_size,file_last_modified,");
	printf("packet_type,request,request_parameter,response,response_value,data_len\n");
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
