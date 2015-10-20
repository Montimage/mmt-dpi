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
  * Replace character in a string
  * @param  str string
  * @param  c1  character is going to be replaced
  * @param  c2  replacing character
  * @return     new string
  */
char * str_replace_all_char(const char *str,int c1, int c2){
    char *new_str;
    new_str = (char*)malloc(strlen(str)+1);
    memcpy(new_str,str,strlen(str));
    new_str[strlen(str)] = '\0';
    int i;
    for(i=0;i<strlen(str);i++){
        if((int)new_str[i]==c1){
            new_str[i]=(char)c2;
        }
    }
    return new_str;
}

 /**
 * Writes @len bytes from @content to the filename @path.
 */
void write_data_to_file (const char * path, const char * content, int len) {
  int fd = 0;
  // Replace path by file name
  path = str_replace_all_char(path,'/','_');
  if ( (fd = open ( path , O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO )) < 0 )
  {
    fprintf ( stderr , "\n[e] Error %d writting data to \"%s\": %s" , errno , path , strerror( errno ) );
    return;
  }

  if(len>0){
  	printf("Going to write to file: %s\n",path);
	  // printf("Data: \n%s\n",content);
	  printf("Data len: %d\n",len);
	  write ( fd , content , len );
  }
  
  close ( fd );
}

 void packet_handler(const ipacket_t * ipacket, void * user_args){
 	
 	// Get data type - only reconstruct the FILE data
	uint8_t * data_type = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_DATA_TYPE);
	int d_type = -1;
	if(data_type){
		d_type = *data_type;
	}

	// Get file name
	char * file_name = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_FILE_NAME);
	
	// Get packet len
	uint32_t * data_len = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_DATA_LEN);
	int len = 0;
	if(data_len){
		len = *data_len;
	}

	// Get packet payload pointer - after TCP
	char * data_payload = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,PROTO_PAYLOAD);
	if(len>0 && file_name && data_payload && d_type==1){
		printf("Going to write data of packet %lu\n",ipacket->packet_id);
		write_data_to_file(file_name,data_payload,len);
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
	register_extraction_attribute(mmt_handler,PROTO_FTP,PROTO_PAYLOAD);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_DATA_TYPE);
	register_extraction_attribute(mmt_handler,PROTO_FTP,FTP_FILE_NAME);
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
