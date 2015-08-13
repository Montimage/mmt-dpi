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
 #include "mmt_core.h"
 #include "mmt/tcpip/mmt_tcpip.h"
 #include "mmt_test_utils.h"
 
// #include "../src/mmt_tcpip/lib/mmt_tcpip_plugin_structs.h"
void packet_handler(const ipacket_t * ipacket, void * user_args){
	// log_info("packet_handler is called for packet %lu",ipacket->packet_id);
	uint16_t* tcp_src_port = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_SRC_PORT);
	uint16_t * tcp_dest_port = (uint16_t *) get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_DEST_PORT);
	uint32_t * tcp_seq_nb = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_SEQ_NB);
	uint32_t * tcp_ack_nb = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_ACK_NB);	
	uint8_t * tcp_data_offset = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_DATA_OFF); //Request TCP data offset
	uint8_t * tcp_flags = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_FLAGS); //Request TCP flags
	uint8_t * tcp_fin = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_FIN); //Request TCP fin flag
	uint8_t * tcp_syn = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_SYN); //Request TCP syn flag
	uint8_t * tcp_rst = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_RST); //Request TCP ACK number
	uint8_t * tcp_psh = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_PSH); //Request TCP ACK number
	uint8_t * tcp_ack = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_ACK); //Request TCP ACK number
	uint8_t * tcp_urg = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_URG); //Request TCP ACK number
	uint8_t * tcp_ece = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_ECE); //Request TCP ACK number
	uint8_t * tcp_cwr = (uint8_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_CWR); //Request TCP ACK number
	uint16_t * tcp_window = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_WINDOW); //Request TCP ACK number
	uint16_t * tcp_checksum = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_CHECKSUM); //Request TCP ACK number
	uint16_t * tcp_urg_ptr = (uint16_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_URG_PTR); //Request TCP ACK number
	struct timeval * tcp_rtt = (struct timeval *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_RTT); //Request TCP ACK number
	uint32_t * tcp_syn_rcv = (uint32_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_SYN_RCV); //Request TCP ACK number
	uint32_t * tcp_conn_established = (uint32_t *)get_attribute_extracted_data(ipacket,PROTO_TCP,TCP_CONN_ESTABLISHED); //Request TCP ACK number

	//if(p_len){
        //	printf("Received packet of size %u\n",*p_len);
	//}
	// if(tcp_src_port && tcp_dest_port && tcp_seq_nb && tcp_ack_nb){
 	//      printf("%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%ld,%ld,%u,%u\n",ipacket->packet_id,*tcp_src_port,*tcp_dest_port,*tcp_seq_nb,*tcp_ack_nb,*tcp_data_offset,*tcp_flags,*tcp_fin,*tcp_syn,*tcp_rst,*tcp_psh,*tcp_ack,*tcp_urg,*tcp_ece,*tcp_ece,*tcp_cwr,*tcp_window,*tcp_checksum,*tcp_urg_ptr,(long)tcp_rtt->tv_sec,(long)tcp_rtt->tv_usec,*tcp_syn_rcv,*tcp_conn_established);
	// }
	//struct mmt_tcpip_internal_packet_struct *packet = (mmt_tcpip_internal_packet_t *) ipacket->internal_packet;
	//printf("Outoforder: %lu : %i\n",ipacket->packet_id,packet->tcp_outoforder);
	printf("%lu,", ipacket->packet_id);
	printValue(2,tcp_src_port);
	printValue(2,tcp_dest_port);
	printValue(1,tcp_seq_nb);
	printValue(1,tcp_ack_nb);
	printValue(3,tcp_data_offset);
	printValue(3,tcp_flags);
	// tcp_flags is calculated from tcp_urg->tcp_fin
	// Examples: tcp_flags == 2 -> 000010 (tcp_syn = 1)
	// 			 tcp_flags == 16 -> 010000	(tcp_ack = 1)
	// 			 tcp_flags == 24 -> 011000 (tcp_ack and tcp_psh)
	// 			 tcp_flags == 17 -> 010001 (tcp_ack and tcp_fin)
	printValue(3,tcp_urg);
	printValue(3,tcp_ack);
	printValue(3,tcp_psh);
	printValue(3,tcp_rst);
	printValue(3,tcp_syn);
	printValue(3,tcp_fin);

	printValue(3,tcp_ece);
	printValue(3,tcp_cwr);
	printValue(2,tcp_window);
	printValue(2,tcp_checksum);
	printValue(2,tcp_urg_ptr);

	// These attributes bellow are "POSITION_NOT_KNOWN"
	printValue(1,tcp_syn_rcv);
	printValue(1,tcp_conn_established);
	printValue(4,tcp_rtt);
	printf("\n");
}

int main(int argc, char ** argv){
	mmt_handler_t *mmt_handler;// MMT handler
	char mmt_errbuf[1024];
	struct pkthdr header; // MMT packet header

	pcap_t *pcap;
	const unsigned char *data;
	struct pcap_pkthdr p_pkthdr;
	char errbuf[1024];

	//Initialize MMT
	init_extraction();

	//Initialize MMT handler
	mmt_handler =mmt_init_handler(DLT_EN10MB,0,mmt_errbuf);
	if(!mmt_handler){
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n",mmt_errbuf );
		return EXIT_FAILURE;
	}
	//Register the protocol attributes we need
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_SRC_PORT); //Request TCP source port
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_DEST_PORT); //Request TCP destination port 
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_SEQ_NB); //Request TCP sequence number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_ACK_NB); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_DATA_OFF); //Request TCP data offset
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_FLAGS); //Request TCP flags
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_FIN); //Request TCP fin flag
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_SYN); //Request TCP syn flag
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_RST); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_PSH); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_ACK); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_URG); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_ECE); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_CWR); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_WINDOW); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_CHECKSUM); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_URG_PTR); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_RTT); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_SYN_RCV); //Request TCP ACK number
	register_extraction_attribute(mmt_handler,PROTO_TCP,TCP_CONN_ESTABLISHED); //Request TCP ACK number
	//Register a packet handler, it will be called for every processed packet
	register_packet_handler(mmt_handler,1,packet_handler, NULL);

	pcap = pcap_open_offline(argv[1],errbuf); // open offline trace
	if(!pcap){ /* pcap error? */
		fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
		return;
	}
	printf("packet_id,tcp_src_port,tcp_dest_port,tcp_seq_nb,tcp_ack_nb,tcp_data_offset,tcp_flags,tcp_fin,tcp_syn,tcp_rst,tcp_psh,tcp_ack,tcp_urg,tcp_ece,tcp_cwr,tcp_window,tcp_checksum,tcp_urg_ptr,tcp_syn_rcv,tcp_conn_established,tcp_rtt->tv_sec,tcp_rtt->tv_usec\n");
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
